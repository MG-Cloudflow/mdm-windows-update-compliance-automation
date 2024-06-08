<#
.SYNOPSIS
    This script manages Windows Update compliance policies using Microsoft Graph API.

.DESCRIPTION
    The script authenticates to Microsoft Graph API using a specified Azure AD application ID. It retrieves the latest OS builds from the Windows Update Catalog and ensures that compliance policies and update rings for Windows 10 and Windows 11 devices are up-to-date. The script performs the following actions:
    - Connects to Azure AD and retrieves an access token for Microsoft Graph API.
    - Fetches the latest OS builds and filters them for the General Availability Channel.
    - Retrieves existing compliance policies and assignment filters from Microsoft Graph API.
    - Deletes deprecated compliance policies that are no longer supported.
    - Creates or updates compliance policies based on the latest OS build information.
    - Manages assignment filters to target specific OS versions.

.PARAMETER miAppId
    The Application ID for Azure AD.

.PARAMETER cpprefix
    The prefix for compliance policy names. Default is "CP-OS-Update".

.PARAMETER windowsupdateringname
    The prefix for Windows Update ring names. Default is "Windows Update Ring 1".

.PARAMETER OsNames
    The operating system names to process. Default is @("Win10", "Win11").

.PARAMETER osversion
    The OS version to consider (e.g., "22H2").

.PARAMETER latestreleases
    The number of latest releases to include. Default is "1".

.EXAMPLE
    .\Update-CompliancePolicies.ps1 -miAppId "your-app-id" -cpprefix "CP-OS-Update" -windowsupdateringname "Windows Update Ring 1" -OsNames @("Win10", "Win11") -osversion "22H2" -latestreleases "1"

.NOTES
    Version:        1.0
    Author:         Maxime Guillemin
    Creation Date:  08/06/2024
    Purpose/Change: Demo Version
#>


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

# Function to update data using PATCH method in Microsoft Graph API
function Patch-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,

        [Parameter(Mandatory=$true)]
        [string] $url,

        [Parameter(Mandatory=$true)]
        [string] $body
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
            # Send PATCH request to Microsoft Graph API
            $response = Invoke-RestMethod -Uri $url -Method Patch -Headers $authHeader -Body $body -ContentType "application/json"
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

# Function to post new data using POST method in Microsoft Graph API
function Post-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,

        [Parameter(Mandatory=$true)]
        [string] $url,

        [Parameter(Mandatory=$true)]
        [string] $body
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
            # Send POST request to Microsoft Graph API
            $response = Invoke-RestMethod -Uri $url -Method POST -Headers $authHeader -Body $body -ContentType "application/json"
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

# Retrieve the latest OS builds from the update catalog for each specified OS
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

# Retrieve all Windows Update policies from Graph API
$WindowsUpdatePolicy = (Get-graphdata -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof(%27microsoft.graph.windowsUpdateForBusinessConfiguration%27)&`$expand=assignments").value | Where-Object {$_.displayName -like "*$($windowsupdateringname)*"}

# Generate display names for the supported Windows GA builds
$SupportedWindowsGADisplaynames = $SupportedWindowsGA | ForEach-Object {
    $osVersion = $_
        $compliancedisplayname = "$($cpprefix)-$($osVersion.os)-$($osVersion.version)-$($windowsupdateringname)"
        [PSCustomObject]@{
            compliancedisplayname= $compliancedisplayname
        }
}

# Delete deprecated compliance policies that are no longer supported
$windowsupdatecompliancepllicy| ForEach-Object {
    if($SupportedWindowsGADisplaynames.compliancedisplayname -notcontains $_.displayName){
        Write-Output "delete deprecated Major Os Release $($_.displayName)"
        Delete-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($_.id)"
        #TODO delete major os release filter
    }
}

# Process each supported Windows GA build
$SupportedWindowsGA | ForEach-Object {
    $osVersion = $_
    $lastDotIndex = $osVersion.qualityUpdateVersion.LastIndexOf('.')
    $majorversion = $osVersion.qualityUpdateVersion.Substring(0, $lastDotIndex)
    $filterdisplayname = "$($osVersion.os)-$($osVersion.version)"
    
    # Create a new filter if it does not already exist
    if ($osversionfilters.displayName -notcontains $filterdisplayname){
        $body = @"
        {
            "displayName": "$filterdisplayname",
            "description": "",
            "platform": "Windows10AndLater",
            "rule": "(device.osVersion -startsWith \"$majorversion\")",
            "roleScopeTags": [
                "0"
            ]
        }
"@
        Write-Output "Create new filter $filterdisplayname"
        Post-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters" -body $body
        Start-Sleep -Seconds 5
        $allfilters = (Get-graphdata -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters").value
        $osversionfilters = $allfilters | Where-Object {$_.displayName -like "Win11-Version*" -or $_.displayName -like "Win10-Version*" -and $_.displayName -like "*(OS build*"}
    } else {
        Write-Output "filter already exists $filterdisplayname"
    }
    
    # Process each update ring (Ring 1, Ring 2, Ring 3)
        $compliancedisplayname = "$($cpprefix)-$($osVersion.os)-$($osVersion.version)-$($windowsupdateringname)"
        $windowsupdatering = $WindowsUpdatePolicy | Where-Object {$_.displayName -like "*$($windowsupdateringname)*"}
        $complincepolicytoupdate =  $windowsupdatecompliancepllicy | Where-Object {$_.displayName -eq $compliancedisplayname}
        $deadlineint = $windowsupdatering.qualityUpdatesDeferralPeriodInDays + $windowsupdatering.deadlineForQualityUpdatesInDays + $windowsupdatering.deadlineGracePeriodInDays
        $Availability_date = Get-Date $osVersion.Availability_date
        $deadline_date = $Availability_date.AddDays($deadlineint)
        $Current_date = Get-Date -Hour 0 -Minute 0 -Second 0
        Write-Output $windowsupdatering.displayName
        Write-Output $windowsupdatering.assignments.target.groupid

        $filter = $osversionfilters | Where-Object {$_.displayName -eq $filterdisplayname}
        
        # Check if compliance policy needs to be updated
        if($windowsupdatecompliancepllicy.displayName -contains $compliancedisplayname ){
            $body = @"
            {
                "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
                "osMinimumVersion": "$($osVersion.qualityUpdateVersion)"
            }
"@
            Write-Output "Checcking Compliance Setting in $($complincepolicytoupdate.displayName)"
            if ($Current_date -ge $deadline_date -and $osVersion.qualityUpdateVersion -ne $complincepolicytoupdate.osMinimumVersion) {
                Write-Output "compliance pollicy to update Setting in $($complincepolicytoupdate.displayName)"
                Patch-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($complincepolicytoupdate.id)" -body $body
            } else {
                Write-Output "No updated need in compliance policy $($complincepolicytoupdate.displayName)"
            }
            
            # Check if compliance policy assignments need to be updated
            $assignmentmatch = Compare-Object -ReferenceObject $windowsupdatering.assignments.target.groupid -DifferenceObject $complincepolicytoupdate.assignments.target.groupid
            if ($assignmentmatch) {
                Write-Output "compliance pollicy to update Assignments in $($complincepolicytoupdate.displayName)" # There are differences
                $assignments = @()
                
                # Populate the assignments array based on group IDs
                foreach ($groupId in $windowsupdatering.assignments.target.groupid) {
                    $assignment = @{
                        target = @{
                            '@odata.type' = "#microsoft.graph.groupAssignmentTarget"
                            groupId = $groupId
                            deviceAndAppManagementAssignmentFilterId = $filter.id
                            deviceAndAppManagementAssignmentFilterType = "include"
                        }
                    }
                    $assignments += $assignment
                }

                # Create the body object for assignments
                $bodyObject = @{
                    assignments = $assignments
                }

                # Convert the body object to a JSON string
                $Body = $bodyObject | ConvertTo-Json -Depth 10
                Write-Output $body
                Post-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($complincepolicytoupdate.id)/microsoft.graph.assign" -body $body

            } else {
                Write-Output "Assignments are correct no update needed" # They are the same
            }
        } else {
            # Create a new compliance policy if it does not exist
            $body = @"
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "displayName": "$($cpprefix)-$($osVersion.os)-$($osVersion.version)-$($windowsupdateringname)",
                "roleScopeTagIds": [
                    "0"
                ],
                "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
                "scheduledActionsForRule": [
                    {
                        "ruleName": "PasswordRequired",
                        "scheduledActionConfigurations": [
                            {
                                "actionType": "block",
                                "gracePeriodHours": 48,
                                "notificationTemplateId": "",
                                "notificationMessageCCList": []
                            }
                        ]
                    }
                ],
                "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
                "passwordRequiredType": "deviceDefault",
                "osMinimumVersion": "$($osVersion.qualityUpdateVersion)",
                "deviceThreatProtectionEnabled": false
            }
"@

            Write-Output "Create compliance policy $compliancedisplayname "
            $result = Post-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -body $body
            Start-Sleep -Seconds 5
            
            # Populate the assignments array based on group IDs
            $assignments = @()
            foreach ($groupId in $windowsupdatering.assignments.target.groupid) {
                $assignment = @{
                    target = @{
                        '@odata.type' = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupId
                        deviceAndAppManagementAssignmentFilterId = $filter.id
                        deviceAndAppManagementAssignmentFilterType = "include"
                    }
                }
                $assignments += $assignment
            }

            # Create the body object for assignments
            $bodyObject = @{
                assignments = $assignments
            }

            # Convert the body object to a JSON string
            $Body = $bodyObject | ConvertTo-Json -Depth 10

            Post-GraphData -graphToken $graphToken -url "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($result.id)/microsoft.graph.assign" -body $body
        }
}
