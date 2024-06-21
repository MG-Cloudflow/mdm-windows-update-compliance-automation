# Define some parameters and default values for the script
$miAppId = ""  # Application ID for Azure AD
$cpprefix = "CP-OS-Update"  # Prefix for compliance policy names
$windowsupdateringname = "Windows Update Ring 1"  # Prefix for Windows Update ring names
$OsNames = @("Win10", "Win11")  # Operating system names to process (default is Win10 if not stated)
$osversion = "*"  # OS version (mandatory parameter, e.g., 22H2)
$latestreleases = "1"  # Number of latest releases to consider (default is 2)

# Log in to Azure AD using the provided application ID
Write-Output "Connecting to azure via Connect-AzAccount -Identity -AccountId $miAppId..."
Connect-AzAccount -Identity -AccountId $miAppId | Out-Null

# Function to get an access token for Microsoft Graph API using managed identity
function Get-GraphAPIAccessTokenPost {
    $url = $env:IDENTITY_ENDPOINT
    $headers = @{
        'Metadata'= 'True'
        'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
    }
    $body = @{
        'resource'='https://graph.microsoft.com'
        'client_id'= $miAppId
    }
    # Send POST request to get access token
    $accessToken = Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body
    Write-Output $accessToken.access_token 
}

# Function to get data from Microsoft Graph API
function Get-graphdata {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,
        [string] $url
    )
    $authHeader = @{
        'Authorization' = "$graphToken"
        'Content-Type'  = 'application/json'
    }
    $retryCount = 0
    $maxRetries = 3
    $Results = @()

    # Loop to handle retries
    while ($retryCount -le $maxRetries) {
        try {
            do {
                # Send GET request to Microsoft Graph API
                $response = Invoke-WebRequest -Uri $url -Method Get -Headers $authHeader -UseBasicParsing
                $pageResults = $response.Content | ConvertFrom-Json
                $retryCount = 0
                if ($pageResults.'@odata.nextLink' -ne $null) {
                    $url = $pageResults.'@odata.nextLink'
                    $results += $pageResults
                } else {
                    $results += $pageResults
                    return $results
                }
            } while ($pageResults.'@odata.nextLink')
        } catch {
            $statusCode = $_.Exception.Response.StatusCode

            if ($statusCode -in $retryStatusCodes) {
                $retryCount++
                $retryAfter = [int]($_.Exception.Response.Headers.'Retry-After')
                $sleepcount = if ($retryAfter) { $retryAfter } else { $retryCount * $global:apiTtimeout }
                Start-Sleep -Seconds $sleepcount
            } elseif ($statusCode -in $statusCodesObject.code) {
                return $null
            } else {
                Write-Error "$($_.Exception)"
                return $null
            }
        }
    }
}

# Function to delete data using DELETE method in Microsoft Graph API
function Delete-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,

        [Parameter(Mandatory=$true)]
        [string] $url
    )
    $authHeader = @{
        'Authorization' = "$graphToken"
        'Content-Type'  = 'application/json'
    }
    $retryCount = 0
    $maxRetries = 3

    # Loop to handle retries
    while ($retryCount -le $maxRetries) {
        try {
            # Send DELETE request to Microsoft Graph API
            $response = Invoke-RestMethod -Uri $url -Method DELETE -Headers $authHeader -Body $body -ContentType "application/json"
            return $response
        } catch {
            $statusCode = $_.Exception.Response.StatusCode
            if ($statusCode -eq 429) { # Too many requests
                $retryCount++
                $retryAfter = [int]($_.Exception.Response.Headers.'Retry-After')
                $sleepcount = if ($retryAfter) { $retryAfter } else { $retryCount * 10 } # Default backoff if Retry-After not available
                Write-Warning "API call returned error $statusCode. Too many requests. Retrying in $($sleepcount) seconds."
                Start-Sleep -Seconds $sleepcount
            } elseif ($statusCode -eq 503) { # Service unavailable
                $retryCount++
                $sleepcount = $retryCount * 10
                Write-Warning "API call returned error $statusCode. Service unavailable. Retrying in $($sleepcount) seconds."
                Start-Sleep -Seconds $sleepcount
            } else {
                Write-Error "API call returned error $statusCode."
                return $null
            }
        }
    }
    Write-Warning "Max retry attempts reached."
    return $null
}


$WindowUpdateCatalog = $OsNames | ForEach-Object {
    $os = $_
    $osbuilds = Get-LatestOSBuild -OSName $os -OSversion $osversion -LatestReleases $latestreleases -ExcludePreview
    $osbuilds | ForEach-Object {
        $osVersions = $_.Version.Substring(8, 4)
        $osVersions | ForEach-Object {
            $osbuild = Get-LatestOSBuild -OSName $os -OSversion $_ -LatestReleases 1 -ExcludePreview
            $osbuild | ForEach-Object {
                [PSCustomObject]@{
                    os = $os
                    Version = $_.Version
                    qualityUpdateVersion = "10.0."+$_.Build
                    Availability_date = $_.'Availability date'
                    Preview = $_.'Preview'
                    'Out-of-band' = $_.'Out-of-band'
                    Servicing_option = $_.'Servicing option'
                    KB_article = $_.'KB article'
                    KB_URL = $_.'KB URL'
                    Catalog_URL = $_.'Catalog URL'
                }
            }
        }
    }
}

# Filter the OS builds to include only those in the General Availability Channel
$SupportedWindowsGA = $WindowUpdateCatalog | Where-Object {$_.Servicing_option -like "*General Availability Channel*"}

# Get the Graph API access token
$graphToken = Get-GraphAPIAccessTokenPost -TenantID $tenantId -ClientID $app_id -ClientSecret $app_secret
# Retrieve all device compliance policies from Graph API
$allcompliancypollicy = Get-graphdata -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?&`$expand=assignments"

# Filter to get only Windows 10 compliance policies that match the compliance policy prefix
$windowsupdatecompliancepllicy = $allcompliancypollicy.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.windows10CompliancePolicy" -and $_.displayName -like "*$($cpprefix)*"}

# Retrieve all assignment filters from Graph API
$allfilters = (Get-graphdata -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters").value

# Filter the assignment filters to include only those for specific OS versions
$osversionfilters = $allfilters | Where-Object {$_.displayName -like "Win11-Version*" -or $_.displayName -like "Win10-Version*" -and $_.displayName -like "*(OS build*"}


$windowsupdatecompliancepllicy | ForEach-Object{
    Delete-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($_.id)"  
}

$osversionfilters | ForEach-Object{
    Delete-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$($_.id)"  
}
