<#
.SYNOPSIS
    This script assigns Microsoft Graph API permissions to a managed identity in Azure AD.

.DESCRIPTION
    The script authenticates to Azure AD using a specified tenant ID and assigns a set of permissions to a managed identity service principal for Microsoft Graph API. It performs the following actions:
    - Connects to Azure AD using the provided tenant ID.
    - Retrieves the service principal ID for the managed identity.
    - Assigns the specified permissions to the managed identity by updating the service principal.

.PARAMETER TenantID
    The tenant ID of your Azure AD directory.

.PARAMETER principalId
    The service principal ID of the managed identity for the web app.

.PARAMETER permissions
    An array of Microsoft Graph API permissions to assign to the managed identity. Default permissions are:
    - "APIConnectors.ReadWrite.All"
    - "DeviceManagementConfiguration.ReadWrite.All"
    - "DeviceManagementManagedDevices.Read.All"
    - "User.Read.All"

.EXAMPLE
    .\Assign-MI-Permissions.ps1 -TenantID "your-tenant-id" -principalId "your-principal-id" -permissions @("APIConnectors.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementManagedDevices.Read.All", "User.Read.All")

.NOTES
    Version:        1.0
    Author:         Maxime Guillemin & Dieter Kempeneers
    Creation Date:  08/06/2024
    Purpose/Change: Demo Version
#>


# Install the module. (You need admin on the machine.)
# Install-Module AzureAD.
Import-Module AzureAD



# Your tenant ID (in the Azure portal, under Azure Active Directory > Overview).
$TenantID=""
$principalId=""


Connect-AzureAD -TenantId $TenantID
# Get the ID of the managed identity for the web app.
$spID = $principalId

# Check the Microsoft Graph documentation for the permission you need for the operation.

$permissions = @(
    "APIConnectors.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "User.Read.All"
)



# Get the service principal for Microsoft Graph.
# First result should be AppId 00000003-0000-0000-c000-000000000000
$GraphServicePrincipal = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" | Select-Object -first 1

# Assign permissions to the managed identity service principal.
foreach ($p in $permissions) {
    $AppRole = $GraphServicePrincipal.AppRoles | `
    Where-Object {$_.Value -eq $p -and $_.AllowedMemberTypes -contains "Application"}
    New-AzureAdServiceAppRoleAssignment -ObjectId $spID -PrincipalId $spID -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
}


