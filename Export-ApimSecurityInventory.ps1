#Requires -Version 7.0

<#
.SYNOPSIS
Exports global APIM credential-exposure metadata to an Excel workbook, without secrets.
.DESCRIPTION
Uses ARM GET requests only. No listValue/listSecrets calls, no key rotation, no
workspace enumeration, and no plaintext credentials in the workbook or console.
This current-configuration inventory does not establish historical exploitation.
Targets one specified APIM in Azure public cloud, with no environment-specific
defaults. Keep ApimSecurity.Common.ps1 alongside this script when sharing it.
.PARAMETER ServiceResourceId
Full ARM resource ID of the APIM to inventory. Alternatively supply SubscriptionId,
ResourceGroupName, and ServiceName together.
.PARAMETER OutputPath
Optional fresh workbook path. Defaults to an APIM-named, timestamped workbook in
the current working directory.
.EXAMPLE
.\Export-ApimSecurityInventory.ps1 -ServiceResourceId $serviceId -OutputPath .\apim-security.xlsx
.EXAMPLE
.\Export-ApimSecurityInventory.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000001' -ResourceGroupName 'api-rg' -ServiceName 'team-apim'
.NOTES
Requires the ImportExcel module. Treat workbook metadata as restricted operational
information. Review MZK9-GH0 in Service Health/Microsoft Support and rotate affected
credentials separately; copying a value into Key Vault does not invalidate it.
#>
[CmdletBinding(DefaultParameterSetName = 'ByResourceId')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByResourceId')][ValidateNotNullOrEmpty()][string]$ServiceResourceId,
    [Parameter(Mandatory, ParameterSetName = 'ByName')][guid]$SubscriptionId,
    [Parameter(Mandatory, ParameterSetName = 'ByName')][ValidatePattern('^[^/\\?#]+$')][string]$ResourceGroupName,
    [Parameter(Mandatory, ParameterSetName = 'ByName')][ValidatePattern('^[A-Za-z0-9-]+$')][Alias('ApimName')][string]$ServiceName,
    [ValidatePattern('\.xlsx$')][string]$OutputPath,
    [string]$IncidentTrackingId = 'MZK9-GH0',
    [switch]$SkipServiceHealth,
    [switch]$CheckRuntimeVersion,
    [string]$ManagementApiVersion = '2024-05-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ApimSecurity.Common.ps1')
$targetResourceId = if ($PSCmdlet.ParameterSetName -eq 'ByName') { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.ApiManagement/service/$ServiceName" } else { $ServiceResourceId }
$context = New-ApimSecurityContext $targetResourceId $ManagementApiVersion
if (!$OutputPath) {
    $targetName = $context.ServiceId.Split('/')[-1]
    $OutputPath = "$targetName-security-inventory-$([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff')).xlsx"
}
$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if (Test-Path -LiteralPath $output) { throw 'OutputPath already exists. Choose a fresh inventory file.' }
if (!(Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($output)))) { throw 'The output directory must already exist.' }
Import-Module ImportExcel -ErrorAction Stop
$issues = [System.Collections.Generic.List[object]]::new()
$actions = [System.Collections.Generic.List[object]]::new()
$sheets = [ordered]@{}

function Read-InventoryCollection([string]$Kind) {
    try { return @(Get-ApimSecurityCollection $context "$($context.ServiceId)/$Kind") }
    catch {
        $issues.Add([pscustomobject]@{ Area = $Kind; Status = 'ReadFailed'; Message = $_.Exception.Message; RequiredFollowUp = 'Resolve permissions/endpoint availability and repeat inventory. No exposure conclusion is possible for this area.' })
        return @()
    }
}

function Get-InventoryEndpoint([AllowNull()][string]$Value) {
    if (!$Value) { return '' }
    $uri = $null
    if (![Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return '[non-URL or unresolved reference; review in portal]' }
    $builder = [UriBuilder]::new($uri)
    $builder.UserName = ''; $builder.Password = ''; $builder.Query = ''; $builder.Fragment = ''
    return $builder.Uri.GetLeftPart([UriPartial]::Path)
}

function Get-InventoryResourceName([AllowNull()][string]$Value) {
    if (!$Value) { return '' }
    $uri = $null
    if ($Value.StartsWith('/')) { $uri = [Uri]('https://management.azure.com' + $Value) }
    elseif (![Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $Value }
    return [Uri]::UnescapeDataString($uri.AbsolutePath.TrimEnd('/').Split('/')[-1])
}

function Get-InventoryScopeName([AllowNull()][string]$Value) {
    if (!$Value) { return '' }
    if ($Value.TrimEnd('/') -eq "$($context.ServiceId)/apis") { return 'All APIs' }
    $name = Get-InventoryResourceName $Value
    if ($Value -match '/apis/[^/]+/?$') { return "API: $name" }
    if ($Value -match '/products/[^/]+/?$') { return "Product: $name" }
    return $name
}

function Add-InventoryAction([string]$Category, [string]$Name, [string]$Action) {
    $actions.Add([pscustomobject]@{ Category = $Category; Name = $Name; ExposureAssessment = 'Potential exposure category; access/compromise not established'; RequiredAction = $Action; Owner = ''; RotationStatus = 'Not verified'; EvidenceReference = ''; CompletionUtc = '' })
}

function Export-InventorySheet([string]$Name, [object[]]$Rows) {
    if ($Name -eq 'Service') {
        $Rows = @($Rows | Select-Object ServiceName, ResourceGroupName, SubscriptionId, Location, Sku, PlatformVersion, ProvisioningState, GatewayUrl, ManagedIdentityType)
    }
    if (!$Rows.Count) { $Rows = @([pscustomobject]@{ Information = 'No resources returned. Check CoverageIssues for failures before interpreting this as absence.' }) }
    $safeRows = @(foreach ($row in $Rows) {
            $safe = [ordered]@{}
            foreach ($property in $row.PSObject.Properties) { $safe[$property.Name] = Protect-ApimInventoryCell $property.Value }
            [pscustomobject]$safe
        })
    $safeRows | Export-Excel -Path $output -WorksheetName $Name -TableName "${Name}Table" -AutoSize -MaxAutoSizeRows 200 -FreezeTopRow -BoldTopRow -NoNumberConversion '*'
}

try {
    $service = (Invoke-ApimSecurityRequest $context GET $context.ServiceId).Data
    $sku = [string]$service.sku.name
    $tierAssessment = if ($sku -in @('Developer', 'Basic', 'Standard', 'Premium')) { 'Classic tier reported within affected families; exact notice membership/history still requires confirmation' } elseif ($sku -eq 'Consumption' -or $sku -match 'V2$') { 'Reported outside affected families; verify the customer notice and incident-period SKU' } else { 'Unknown tier family; verify Microsoft notice' }
    $sheets.Service = @([pscustomobject]@{
            ServiceName = $service.name; ResourceGroupName = $context.ServiceId.Split('/')[4]; SubscriptionId = $context.SubscriptionId
            Location = $service.location; Sku = $sku; PlatformVersion = $service.properties['platformVersion']
            ProvisioningState = $service.properties['provisioningState']; GatewayUrl = Get-InventoryEndpoint $service.properties['gatewayUrl']
            ManagedIdentityType = $(if ($service['identity']) { $service.identity['type'] } else { 'None' }); SystemIdentityPrincipalId = $(if ($service['identity']) { $service.identity['principalId'] } else { '' })
            IncidentTrackingId = $IncidentTrackingId; TierFamilyAssessment = $tierAssessment
            CollectedAtUtc = [DateTimeOffset]::UtcNow.ToString('o'); Scope = 'Global/service only'; SecretValuesExported = 'No'
            PatchStatus = 'Not proven by ARM provisioning state; verify Microsoft notice/NSM runtime guidance'
            RuntimeVersion = ''; RuntimeEvidence = 'Not collected'
            HistoricalExposure = 'Current inventory only. Deleted/rotated credentials and incident-period configuration require historical evidence.'
        })
    if ($CheckRuntimeVersion) {
        try {
            $gateway = [Uri]$service.properties['gatewayUrl']
            if ($gateway.Scheme -ne 'https' -or $gateway.Host -ne "$($service.name).azure-api.net" -or $gateway.Port -ne 443 -or $gateway.UserInfo -or $gateway.Query -or $gateway.Fragment -or $gateway.AbsolutePath -ne '/') { throw 'Gateway metadata did not match the selected public-Azure APIM default hostname.' }
            $status = Invoke-WebRequest -Method GET -Uri ($gateway.GetLeftPart([UriPartial]::Authority) + '/internal-status-0123456789abcdef') -MaximumRedirection 0 -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$status.StatusCode -ne 200) { throw "Runtime endpoint returned HTTP $([int]$status.StatusCode)." }
            $runtime = (ConvertFrom-Json -InputObject $status.Content -AsHashtable)['RuntimeVersion']
            if ($runtime -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') { throw 'Runtime endpoint returned an unrecognized version.' }
            $sheets.Service[0].RuntimeVersion = $runtime
            $sheets.Service[0].RuntimeEvidence = 'NSM-documented endpoint observation at inventory collection time; not evidence of historical exposure'
            if ($runtime -match '^0\.(52|53)\.(\d+)$') {
                $threshold = if ($Matches[1] -eq '52') { 31936 } else { 31938 }
                $sheets.Service[0].PatchStatus = if ([int]$Matches[2] -ge $threshold) { 'Meets the applicable NSM three-part runtime threshold; does not invalidate previously exposed credentials' } else { 'Below NSM runtime threshold; contact Microsoft immediately' }
            }
            else { $sheets.Service[0].PatchStatus = 'Threshold not applied to this runtime pattern. Confirm SKU/runtime and update status with Microsoft; four-part runtime alone does not prove this Classic service was unaffected.' }
        }
        catch { $issues.Add([pscustomobject]@{ Area = 'RuntimeVersion'; Status = 'ReadFailed'; Message = 'Runtime observation was unavailable or unrecognized; no patch-state conclusion made.'; RequiredFollowUp = 'Check NSM runtime guidance and Microsoft Support using the exact service/SKU.' }) }
    }

    $namedValues = @(Read-InventoryCollection 'namedValues')
    $sheets.NamedValues = @(foreach ($item in $namedValues) {
            $properties = $item.properties
            $keyVault = $properties['keyVault']
            $reference = if ($keyVault) { [string]$keyVault['secretIdentifier'] } else { '' }
            $secret = $properties['secret'] -eq $true
            $storage = if ($reference) { 'KeyVaultReference' } elseif ($secret) { 'InlineAPIMSecret' } else { 'NonSecretNamedValue' }
            if ($secret -or $reference) { Add-InventoryAction 'NamedValue' $item.name 'Review incident membership; rotate at the issuing system/vault, coordinate dependents, and migrate eligible inline secrets to Key Vault separately.' }
            [pscustomobject]@{ Name = $item.name; DisplayName = $properties['displayName']; Secret = $secret; Storage = $storage
                KeyVaultSecretIdentifier = Get-InventoryEndpoint $reference; KeyVaultIdentityClientId = $(if ($keyVault) { $keyVault['identityClientId'] } else { '' })
                KeyVaultLastStatus = $(if ($keyVault -and $keyVault['lastStatus']) { $keyVault.lastStatus['code'] } else { '' })
                MigrationCandidate = $secret -and !$reference; Tags = (@($properties['tags']) -join ', '); Value = '[NOT EXPORTED]'
            }
        })

    foreach ($kind in @('identityProviders', 'openidConnectProviders', 'authorizationServers')) {
        $rows = @(foreach ($item in @(Read-InventoryCollection $kind)) {
                $properties = $item.properties
                Add-InventoryAction $kind $item.name 'Identify the owning application and identity provider; rotate/revoke its client secret at the issuer and coordinate APIM/dependent configuration. This export does not retrieve the secret or prove it exists.'
                [pscustomobject]@{ Name = $item.name; DisplayName = $properties['displayName']; ProviderType = $properties['type']; ClientId = $properties['clientId']
                    MetadataEndpoint = Get-InventoryEndpoint $properties['metadataEndpoint']; AuthorizationEndpoint = Get-InventoryEndpoint $properties['authorizationEndpoint']; TokenEndpoint = Get-InventoryEndpoint $properties['tokenEndpoint']
                    ClientSecretAssessment = 'Not retrieved; confirm issuer/app-registration configuration'; ClientSecret = '[NOT EXPORTED]'
                }
            })
        $sheets[$kind] = $rows
    }

    $subscriptions = @(Read-InventoryCollection 'subscriptions')
    $sheets.Subscriptions = @(foreach ($item in $subscriptions) {
            Add-InventoryAction 'SubscriptionKeys' $item.name 'Coordinate rotation of BOTH primary and secondary keys with consumers; retain key-ID/scope evidence, monitor use, and invalidate old keys. Built-in/service-wide subscriptions require special care.'
            [pscustomobject]@{ Name = $item.name; DisplayName = $item.properties['displayName']; Scope = Get-InventoryScopeName $item.properties['scope']; State = $item.properties['state']; Owner = Get-InventoryResourceName $item.properties['ownerId']; CreatedDate = $item.properties['createdDate']; StartDate = $item.properties['startDate']; EndDate = $item.properties['endDate']; PrimaryKey = '[NOT EXPORTED]'; SecondaryKey = '[NOT EXPORTED]' }
        })

    $management = @()
    foreach ($name in @('access', 'gitAccess')) {
        try {
            $response = Invoke-ApimSecurityRequest $context GET "$($context.ServiceId)/tenant/$name" -AllowNotFound
            if ($response) {
                Add-InventoryAction 'DirectManagement' $name 'Review/disable unused retired direct Management API access; rotate tenant signing keys and revoke/replace potentially exposed SAS tokens. Issued tokens cannot be enumerated from this configuration snapshot.'
                $management += [pscustomobject]@{ Name = $name; Enabled = $response.Data.properties['enabled']; PrincipalId = $response.Data.properties['principalId']; SigningKeys = '[NOT EXPORTED]'; IssuedTokens = 'Not enumerable by this ARM inventory; review issuance records and dependent clients' }
            }
            else { $issues.Add([pscustomobject]@{ Area = "tenant/$name"; Status = 'NotAvailable'; Message = 'Endpoint returned 404'; RequiredFollowUp = 'Confirm legacy/direct-management settings in portal or Microsoft Support.' }) }
        }
        catch { $issues.Add([pscustomobject]@{ Area = "tenant/$name"; Status = 'ReadFailed'; Message = $_.Exception.Message; RequiredFollowUp = 'Review this area independently; do not assume direct management is disabled.' }) }
    }
    $sheets.DirectManagement = $management

    foreach ($kind in @('backends', 'loggers')) {
        $sheets[$kind] = @(foreach ($item in @(Read-InventoryCollection $kind)) {
                $credentials = $item.properties['credentials']
                $hasCredentials = $null -ne $credentials -and $credentials.Count -gt 0
                if ($hasCredentials) { Add-InventoryAction $kind $item.name 'Review linked credential owners and rotate possibly exposed credentials at their issuer. Credential values/expressions are intentionally omitted.' }
                [pscustomobject]@{ Name = $item.name; Type = $item.properties['loggerType']; BackendUrl = Get-InventoryEndpoint $item.properties['url']; LinkedResourceName = Get-InventoryResourceName $item.properties['resourceId']; CredentialConfigurationPresent = $hasCredentials; Credentials = '[NOT EXPORTED]' }
            })
    }

    $events = @()
    if (!$SkipServiceHealth) {
        try {
            foreach ($healthEvent in @(Get-ApimSecurityCollection $context "/subscriptions/$($context.SubscriptionId)/providers/Microsoft.ResourceHealth/events?api-version=2025-04-01")) {
                if ($healthEvent.name -eq $IncidentTrackingId -or $healthEvent.properties['trackingId'] -eq $IncidentTrackingId) {
                    $events += [pscustomobject]@{ Name = $healthEvent.name; TrackingId = $IncidentTrackingId; EventType = $healthEvent.properties['eventType']; Status = $healthEvent.properties['status']; StartTime = $healthEvent.properties['impactStartTime']; EndTime = $healthEvent.properties['impactMitigationTime']; NoticeMembership = 'Matching subscription event; affected-resource scope must be confirmed in restricted details/support' }
                }
            }
            if (!$events.Count) { $issues.Add([pscustomobject]@{ Area = 'ServiceHealth'; Status = 'NoMatchingEvent'; Message = 'No matching visible event was returned.'; RequiredFollowUp = 'Absence is not proof of safety. Verify security-advisory access, retention, and customer/Microsoft notification.' }) }
        }
        catch { $issues.Add([pscustomobject]@{ Area = 'ServiceHealth'; Status = 'ReadFailed'; Message = $_.Exception.Message; RequiredFollowUp = 'Get the exact customer notice/affected-resource list through Service Health or Microsoft Support.' }) }
    }
    else { $issues.Add([pscustomobject]@{ Area = 'ServiceHealth'; Status = 'Skipped'; Message = 'Skipped by operator.'; RequiredFollowUp = 'Verify exact incident membership independently.' }) }
    $sheets.ServiceHealth = $events
    $sheets.Summary = @(foreach ($name in $sheets.Keys) { [pscustomobject]@{ Area = $name; ResourceRows = @($sheets[$name]).Count; ReadStatus = $(if (@($issues | Where-Object Area -eq $name).Count) { 'Incomplete; see CoverageIssues' } else { 'Current metadata returned; not historical exposure evidence' }) } })
    $sheets.Actions = @($actions.ToArray())
    $sheets.CoverageIssues = @($issues.ToArray())
    foreach ($name in $sheets.Keys) { Export-InventorySheet $name @($sheets[$name]) }
    [pscustomobject]@{ OutputPath = $output; ServiceResourceId = $context.ServiceId; Scope = 'Global/service only'; NamedValues = $namedValues.Count; InlineSecretNamedValues = @($sheets.NamedValues | Where-Object MigrationCandidate -eq $true).Count; Subscriptions = $subscriptions.Count; Actions = $actions.Count; CoverageIssueCount = $issues.Count; SecretValuesExported = $false }
}
finally { Clear-ApimSecurityContext $context }