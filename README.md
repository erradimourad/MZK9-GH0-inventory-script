# MZK9-GH0 APIM Inventory

Read-only PowerShell inventory of global Azure API Management credential-configuration metadata. The exported workbook uses resource names and omits secret values, client secrets, subscription keys, and tokens.

The scripts target the APIM supplied by the caller; no subscription, tenant, resource group, or APIM instance is configured by default. Azure public cloud is supported. Workspaces are not inventoried.

## Requirements

- PowerShell 7 or later.
- Azure CLI with an authorized login for the target subscription.
- ARM read permissions for the target APIM; Service Health notices can require additional permissions.
- ImportExcel, tested with version 7.8.10, installed from an approved PowerShell repository.

Desktop Excel and Key Vault secret permissions are not required for inventory.

## Run

From this repository in PowerShell 7:

```powershell
Install-Module -Name ImportExcel -RequiredVersion 7.8.10 -Scope CurrentUser

.\Export-ApimSecurityInventory.ps1 `
    -SubscriptionId '<subscription-guid>' `
    -ResourceGroupName '<resource-group>' `
    -ServiceName '<apim-service-name>'
```

Keep [ApimSecurity.Common.ps1](ApimSecurity.Common.ps1) alongside [Export-ApimSecurityInventory.ps1](Export-ApimSecurityInventory.ps1). See the [usage guide](Export-ApimSecurityInventory.md) for resource-ID input, output paths, and optional runtime/Service Health checks.

## Handling The Results

The workbook is created in the current working directory with an APIM-named UTC timestamp. Review `CoverageIssues` before interpreting an empty worksheet. Generated reports and credential files are excluded from Git by default; do not force-add them.

This is a current-configuration inventory, not proof of exploitation, historical exposure, or completed credential rotation. The default incident reference `MZK9-GH0` is configurable. No migration or credential rotation is performed.

## Author

[erradimourad](https://github.com/erradimourad)