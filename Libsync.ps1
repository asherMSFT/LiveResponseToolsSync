# Cmd line parameters
param(
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$LibraryManifestPath = "librarymanifest.json"
)

# For better performance, you can use server closer to your geo location:
# api-us.securitycenter.microsoft.com
# api-eu.securitycenter.microsoft.com
# api-uk.securitycenter.microsoft.com 

$BaseURL = "api.securitycenter.microsoft.com"

# small delay to avoid any API call thresholds (100 calls per minute & 1500 per hour)
$SleepDelay = 0.7   #increase the number to 2.5 if your library is big enough to hit 1500 calls per hour limit


function Get-Token {
    param (
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [Parameter(Mandatory)][string]$TenantId
    )
    
    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $authBody = [Ordered] @{
        resource = "$resourceAppIdUri"
        client_id = "$ClientId"
        client_secret = "$ClientSecret"
        grant_type = 'client_credentials'
    }

    # small delay to avoid API call thresholds
    Start-Sleep -Seconds $SleepDelay

    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $token = $authResponse.access_token
        
    return $token
}

function Get-LibraryFiles {
    param (
        [string]$Token
    )

    $Uri = "https://$BaseURL/api/libraryfiles"

    # Set the WebRequest headers
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token"
    }

    # small delay to avoid API call thresholds
    Start-Sleep -Seconds $SleepDelay

    # Send the webrequest and get the results.
    $response = Invoke-WebRequest -Method Get -Uri $Uri -Headers $headers -ErrorAction Stop

    $LibraryFilesList = ($response | ConvertFrom-Json).value | ConvertTo-Json
    return $LibraryFilesList | ConvertFrom-Json
}

function Add-LibraryFile {
    param (
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Description="",
        [string]$Parameters = "",
        [bool]$OverrideIfExists = $false,        
        [Parameter(Mandatory)][string]$Token
    )
    
    $Uri = "https://$BaseURL/api/libraryfiles";

    $Headers = @{
        Authorization = "Bearer $token"
    }

    # Limitations: (https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/upload-library)
    # File max size limitation is 20MB.    
        
    $Form = @{        
        Description   = $Description;
        OverrideIfExists = $OverrideIfExists;
    }

    $file  = Get-Item -Path $FilePath;
    
    if ($file.Length -gt 20MB) {
        $errormsg = @{
            StatusCode        = 400;
            StatusDescription = "File is greater than 20MB";            
        }
        return [pscustomobject]$errormsg
    } else {
        $Form["File"] = $file
    }

    if ($Parameters -ne "") {
        $Form["HasParameters"] = "true";
        $Form["ParametersDescription"] = $Parameters;
    }    
    
    # small delay to avoid API call thresholds
    Start-Sleep -Seconds $SleepDelay

    try {
        $Result = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers -Form $Form -ErrorAction Ignore        
    }
    catch {                
        $errormsg = @{
            StatusCode = ($_ | ConvertFrom-Json).error.code;
            StatusDescription = ($_ | ConvertFrom-Json).error.message;            
        }
        return [pscustomobject]$errormsg
    }
    
    return $Result
}

function Remove-LibraryFile {
    param (
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Token
    )    

    $Uri = "https://$BaseURL/api/libraryfiles/" + $FileName;    

    $Headers = @{
        Authorization = "Bearer $token"
    }

    # small delay to avoid API call thresholds
    Start-Sleep -Seconds $SleepDelay

    try {
        $Result = Invoke-WebRequest -Uri $Uri -Method Delete -Headers $Headers
    }
    catch { 
        $errormsg = @{
            StatusCode = ($_ | ConvertFrom-Json).error.code;
            StatusDescription = ($_ | ConvertFrom-Json).error.message;            
        }
        return [pscustomobject]$errormsg
    }

    return $Result    
}

function Get-LibraryManifestLocal {
    param (
        [Parameter(Mandatory)][string]$ManifestPath
    )
    
    $Manifest = Get-Content -Path $ManifestPath -ErrorAction Stop | ConvertFrom-Json 
    $Manifest | Add-Member -MemberType NoteProperty -Name 'sha256' -Value ''
    
    foreach ($file in $Manifest) {

        $file.sha256 = (Get-FileHash -Path ("./Library/" + $file.fileName)).Hash
        if ($file.description -eq '') { $file.description = $null }
        if ($file.parametersDescription -eq '') { $file.parametersDescription = $null }        
    }

    return $Manifest
}

function Sync-LibraryFiles {
    param (
        [string]$LibraryManifestPath
    )

    $token = Get-Token -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId
    
    $LibraryManifestLocal = Get-LibraryManifestLocal -ManifestPath $LibraryManifestPath
    $LibraryManifestOnline = Get-LibraryFiles -Token $token

    # clean up orphaned online files
    foreach ($fileOnline in $LibraryManifestOnline) {    
        
        $file = $null
        $file = $LibraryManifestLocal | Where-Object {$_.fileName -eq $fileOnline.fileName}        

        if ($file -eq $null)
        {
            # File not found in local manifest, removing the file from Live Response library
            "Online file " + $fileOnline.fileName + " not found in local manifest, removing the file from Live Response library." | Write-Host -NoNewline
            $response = Remove-LibraryFile -FileName $fileOnline.fileName -Token $token
            if ($response.StatusCode -eq 204)
            {
                "...........OK" | Write-Host -ForegroundColor Green
            } else {
                "...........FAILED [" + $response.StatusDescription + "]" | Write-Host -ForegroundColor Red
            }
        }                
    }

    # compare local and online manifest for changes
    foreach ($fileLocal in $LibraryManifestLocal) {
        
        $filepath = "./Library/" + $fileLocal.fileName

        $file = $null
        $file = $LibraryManifestOnline | Where-Object {$_.fileName -eq $fileLocal.fileName}
        
        if ($file)
        {                     
            # check if files the same (description, params etc.)
            if (($fileLocal.sha256 -eq $file.sha256) `
                -and (($fileLocal.description -eq $file.description) ) `
                -and ($fileLocal.parametersDescription -eq $file.parametersDescription)
            ) {
                # Skipping identical files.
                $file.fileName + " already exists in the Live Response library" | Write-Host -NoNewline
                "............SKIPPED" | Write-Host -ForegroundColor Yellow
            } else {
                # some attributes are not the same - updating the file
                "Updating " + $file.fileName + " in the Live Response library." | Write-Host -NoNewline
                $response = Add-LibraryFile -FilePath $filepath -Description $fileLocal.description -Parameters $fileLocal.parametersDescription -OverrideIfExists $true -Token $token                
                switch ($response.StatusCode) {
                    200 { "...........OK" | Write-Host -ForegroundColor Green }
                    400 { "...........SKIPPED [" + $response.StatusDescription + "]" | Write-Host -ForegroundColor Yellow }
                    Default { "...........FAILED [" + $response.StatusDescription + "]" | Write-Host -ForegroundColor Red }
                }
            }           

        } else {
            #  file is not in the Live Response library
            "Adding " + $fileLocal.fileName + " to the Live Response library." | Write-Host -NoNewline
            $response = Add-LibraryFile -FilePath $filepath -Description $fileLocal.description -Parameters $parametersDescription -Token $token

            switch ($response.StatusCode) {
                200 { "...........OK" | Write-Host -ForegroundColor Green }
                400 { "...........SKIPPED [" + $response.StatusDescription + "]" | Write-Host -ForegroundColor Yellow }
                Default {}
            }            
        }
    }
}

Sync-LibraryFiles -LibraryManifestPath $LibraryManifestPath