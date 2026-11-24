# Reusable APIM inventory

This read-only exporter inventories one specified Azure APIM service. It has no default subscription, tenant, resource group, or APIM name. Its scope is global/service-level configuration, not workspaces or every APIM in a subscription.

## Sharing

Share these files together in the same directory:

- [Export-ApimSecurityInventory.ps1](Export-ApimSecurityInventory.ps1)
- [ApimSecurity.Common.ps1](ApimSecurity.Common.ps1)
- These usage instructions


## Prerequisites

- PowerShell 7 or later and Azure CLI installed.
- An existing Azure CLI login authorized for the target subscription/tenant. Use your organization's approved sign-in workflow; the script does not sign in or change the active CLI account.
- ARM read permissions for the specified APIM configuration. Service Health security notices can require additional permissions; missing/unavailable data is reported in `CoverageIssues`.
- ImportExcel installed through an approved PowerShell repository. No desktop Excel installation is required.

For an approved repository, the tested module version can be installed with:

```powershell
Install-Module -Name ImportExcel -RequiredVersion 7.8.10 -Scope CurrentUser
```

## Select The APIM

Run from the directory containing the scripts. Replace the placeholder values with the colleague's target configuration. No script edits are required.

```powershell
.\Export-ApimSecurityInventory.ps1 `
    -SubscriptionId '<subscription-guid>' `
    -ResourceGroupName '<resource-group>' `
    -ServiceName '<apim-service-name>'
```

`-ApimName` is an alias for `-ServiceName`. The alternative is the full APIM ARM resource ID:

```powershell
.\Export-ApimSecurityInventory.ps1 `
    -ServiceResourceId '/subscriptions/<subscription-guid>/resourceGroups/<resource-group>/providers/Microsoft.ApiManagement/service/<apim-service-name>' `
    -OutputPath './apim-inventory.xlsx'
```

Use either the resource ID or the three name-based parameters, not both. Authentication targets the subscription derived from these inputs, including a subscription different from the colleague's active CLI selection when their login has access.

## Output And Options

Without `-OutputPath`, the script creates `<apim-name>-security-inventory-<UTC-timestamp>.xlsx` in PowerShell's current working directory. Explicit relative paths also follow that directory. The output directory must exist, and existing workbooks are never intentionally overwritten.

The workbook contains service metadata, named values, identity/OpenID/OAuth providers, subscriptions, direct-management/Git configuration, backends, loggers, Service Health, summary, actions, and coverage issues. Secret values, subscription keys, client secrets, and tokens are not exported. Spreadsheet formulas and credential-bearing URL components are excluded/protected.

Item worksheets and the action list use `Name` instead of full ARM resource-ID columns; `DisplayName` remains where available. Linked resources and owner references use their short resource names/identifiers, and subscription scopes show labels such as `All APIs`, `API: orders`, or `Product: premium`. Owner references are not directory-resolved display names. Service/resource-group names and the Azure subscription GUID identify the target; client/principal GUIDs and Key Vault secret URLs remain as useful metadata. The returned PowerShell summary still includes the target ARM ID for programmatic use; names are a workbook presentation change only.

The `Service` worksheet contains only `ServiceName`, `ResourceGroupName`, `SubscriptionId`, `Location`, `Sku`, `PlatformVersion`, `ProvisioningState`, `GatewayUrl`, and `ManagedIdentityType`. Identity principal, incident-assessment, collection-time, scope, secret-export-status, runtime, patch-status, and historical-exposure columns are omitted from this worksheet. Other worksheets and internal checks are unchanged. Run the exporter again to create a workbook with this layout; saved workbooks are not modified.

- `-CheckRuntimeVersion`: optionally checks the selected service's default gateway status endpoint. Unavailable/unrecognized observations are recorded in `CoverageIssues`; runtime/patch columns are not exported on the simplified `Service` worksheet.
- `-SkipServiceHealth`: omits the subscription-level notice lookup and records the coverage limitation.
- `-IncidentTrackingId`: changes the incident being looked up; the default is `MZK9-GH0`.

This remains a current-configuration inventory, not proof of compromise, historical credential exposure, runtime safety, or completed credential rotation. Check coverage issues before interpreting an empty worksheet. Sovereign-cloud endpoints are not supported by this helper.

Reference: [Microsoft named-value guidance](https://learn.microsoft.com/azure/api-management/api-management-howto-properties).