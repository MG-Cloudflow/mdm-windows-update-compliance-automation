# README for Windows Update Compliance Policy Script

## Overview

This PowerShell script automates the management of compliance policies and update rings for Windows 10 and Windows 11 devices using Microsoft Graph API. It ensures that devices meet the required compliance standards by creating, updating, or deleting policies as necessary based on the latest OS builds.

## Prerequisites

- Azure AD Application ID
- Appropriate permissions to access and modify device compliance policies and configurations in Microsoft Graph API
- Installed Azure PowerShell module

## Parameters

- `$miAppId`: Azure AD Application ID (required)
- `$cpprefix`: Prefix for compliance policy names (default: "CP-OS-Update")
- `$windowsupdateringname`: Prefix for Windows Update ring names (default: "Windows Update Ring 1")
- `$OsNames`: Operating system names to process (default: `@("Win10", "Win11")`)
- `$osversion`: OS version to consider (e.g., "22H2") (mandatory parameter)
- `$latestreleases`: Number of latest releases to consider (default: "1")

## Functions

### Connect to Azure AD
```powershell
Write-Output "Connecting to azure via Connect-AzAccount -Identity -AccountId $miAppId..."
Connect-AzAccount -Identity -AccountId $miAppId | Out-Null
```

### Get-GraphAPIAccessTokenPost
Retrieves an access token for Microsoft Graph API using managed identity.
```powershell
function Get-GraphAPIAccessTokenPost {
    # Function details...
}
```

### Get-graphdata
Fetches data from Microsoft Graph API.
```powershell
function Get-graphdata {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,
        [string] $url
    )
    # Function details...
}
```

### Patch-GraphData
Updates data using PATCH method in Microsoft Graph API.
```powershell
function Patch-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,
        [Parameter(Mandatory=$true)]
        [string] $url,
        [Parameter(Mandatory=$true)]
        [string] $body
    )
    # Function details...
}
```

### Post-GraphData
Posts new data using POST method in Microsoft Graph API.
```powershell
function Post-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,
        [Parameter(Mandatory=$true)]
        [string] $url,
        [Parameter(Mandatory=$true)]
        [string] $body
    )
    # Function details...
}
```

### Delete-GraphData
Deletes data using DELETE method in Microsoft Graph API.
```powershell
function Delete-GraphData {
    param(
        [Parameter(Mandatory=$true)]
        [string] $graphToken,
        [Parameter(Mandatory=$true)]
        [string] $url
    )
    # Function details...
}
```

## Workflow

1. **Connect to Azure AD**:
   The script begins by logging into Azure AD using the provided Application ID.

2. **Retrieve OS Builds**:
   The script fetches the latest OS builds from the Windows Update Catalog for each specified OS and filters them to include only those in the General Availability Channel.

3. **Get Graph API Access Token**:
   An access token is retrieved to authenticate subsequent Microsoft Graph API calls.

4. **Retrieve Compliance Policies and Assignment Filters**:
   The script retrieves all existing compliance policies and assignment filters, filtering them based on the specified criteria.

5. **Delete Deprecated Policies**:
   Compliance policies that are no longer supported are identified and deleted.

6. **Create or Update Compliance Policies**:
   For each supported Windows GA build, the script:
   - Creates a new filter if it does not already exist.
   - Checks if a compliance policy needs to be created or updated based on the latest OS build information.
   - Updates assignments for compliance policies if necessary.

## Usage

1. **Set Parameters**:
   Configure the necessary parameters at the beginning of the script, including the Azure AD Application ID and other settings.

2. **Run the Script**:
   Execute the script in a PowerShell environment with the necessary permissions and modules installed.

```powershell
.\Update-CompliancePolicies.ps1
```

## Error Handling

The script includes error handling for API calls, with retry logic for common HTTP errors such as `429 Too Many Requests` and `503 Service Unavailable`. If the maximum number of retries is reached, the script will log a warning and proceed.

## Logging

The script outputs progress and error messages to the console, providing visibility into the operations being performed and any issues encountered.

## Conclusion

This script automates the management of Windows compliance policies and update rings, ensuring that devices are kept up-to-date and compliant with the latest OS builds. By leveraging Microsoft Graph API and Azure AD, it provides a robust solution for maintaining device compliance in an enterprise environment.