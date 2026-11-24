#Requires -Version 7.0

function New-ApimSecurityContext {
    param([Parameter(Mandatory)][string]$ServiceResourceId, [string]$ApiVersion = '2024-05-01')
    $id = $ServiceResourceId.TrimEnd('/')
    if ($id -notmatch '^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/[^/]+/providers/Microsoft\.ApiManagement/service/[A-Za-z0-9-]+$') {
        throw 'ServiceResourceId must be a full public-Azure APIM service ARM ID.'
    }
    return @{ ServiceId = $id; SubscriptionId = $Matches[1]; ApiVersion = $ApiVersion; Tokens = @{}; AllowWrites = $false; AllowSecretReads = $false; AllowedVaultHosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
}

function Get-ApimSecurityToken {
    param([hashtable]$Context, [ValidateSet('https://management.azure.com/', 'https://vault.azure.net')][string]$Audience)
    if (!$Context.Tokens.ContainsKey($Audience) -or $Context.Tokens[$Audience].RefreshAt -le [DateTimeOffset]::UtcNow) {
        $null = Get-Command az -ErrorAction Stop
        $output = az account get-access-token --subscription $Context.SubscriptionId --resource $Audience --output json --only-show-errors
        if ($LASTEXITCODE -ne 0) { throw 'Azure CLI authentication failed. Sign in to the intended tenant/subscription using your approved workflow.' }
        try { $token = ($output -join "`n") | ConvertFrom-Json -AsHashtable } catch { throw 'Azure CLI returned invalid token JSON; output is omitted.' }
        if (!$token['accessToken']) { throw 'Azure CLI did not provide an access token.' }
        $Context.Tokens[$Audience] = @{ Value = [string]$token.accessToken; RefreshAt = [DateTimeOffset]::UtcNow.AddMinutes(20) }
        $output = $null
    }
    return $Context.Tokens[$Audience].Value
}

function Invoke-ApimSecurityRequest {
    param(
        [hashtable]$Context,
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH')][string]$Method,
        [string]$Path,
        [hashtable]$Body,
        [string]$IfMatch,
        [switch]$AllowNotFound,
        [switch]$Vault,
        [switch]$Sensitive
    )
    # Never attach a bearer token before checking the final URI, including pagination links.
    if ($Path.StartsWith('/')) { $Path = 'https://management.azure.com' + $Path }
    $uri = [Uri]$Path
    if (!$uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment) { throw 'Refusing an unexpected Azure endpoint.' }
    $decodedPath = [Uri]::UnescapeDataString($uri.AbsolutePath)
    if ($decodedPath -match '(^|/)\.\.?(/|$)') { throw 'Refusing an Azure resource path with traversal segments.' }
    if ($decodedPath -match '/workspaces(?:/|$)') { throw 'These security scripts are restricted to global/service-level resources.' }
    if ($Method -in @('PUT', 'PATCH') -and !$Context.AllowWrites) { throw 'Azure writes require an approved Apply operation.' }
    if ($Sensitive -and !$Context.AllowSecretReads) { throw 'Secret-value reads require an approved Apply operation.' }
    if ($IfMatch -eq '*') { throw 'Unconditional APIM updates are not allowed by these security scripts.' }
    if ($Method -eq 'POST' -and (!$Sensitive -or $decodedPath -notmatch ('^' + [regex]::Escape($Context.ServiceId) + '/namedValues/[^/]+/(listValue|refreshSecret)$'))) { throw 'Only approved named-value secret reads/refresh actions are allowed.' }
    if ($Vault) {
        if (!$Context.AllowedVaultHosts.Contains($uri.Host) -or $decodedPath -notmatch '^/secrets(?:/[A-Za-z0-9-]+(?:/[A-Za-z0-9]+)?)?$') { throw 'Refusing a Key Vault URL outside the explicitly approved vault/secret paths.' }
        if ($Method -notin @('GET', 'PUT')) { throw 'Only secret metadata/read/set operations are allowed in Key Vault.' }
        if ($Method -eq 'GET' -and $decodedPath -ne '/secrets' -and (!$Sensitive -or !$Context.AllowSecretReads)) { throw 'Key Vault secret-value reads require an approved Apply operation.' }
        $audience = 'https://vault.azure.net'
    } else {
        $subscriptionRoot = "/subscriptions/$($Context.SubscriptionId)"
        if ($uri.Host -ne 'management.azure.com' -or !$decodedPath.StartsWith("$subscriptionRoot/", [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing an ARM URL outside the selected subscription.' }
        $insideService = $decodedPath.Equals($Context.ServiceId, [StringComparison]::OrdinalIgnoreCase) -or $decodedPath.StartsWith("$($Context.ServiceId)/", [StringComparison]::OrdinalIgnoreCase)
        $vaultMetadata = $decodedPath -match ('^' + [regex]::Escape($subscriptionRoot) + '/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]+$')
        $healthMetadata = $decodedPath -match ('^' + [regex]::Escape($subscriptionRoot) + '/providers/Microsoft\.ResourceHealth/events(?:/[^/]+)?$')
        $operationMetadata = $decodedPath -match ('^' + [regex]::Escape($subscriptionRoot) + '/providers/Microsoft\.ApiManagement/locations/[^/]+/(operationResults|operationStatuses|operations)/[^/]+$')
        if ($Method -eq 'GET' -and !$insideService -and !$vaultMetadata -and !$healthMetadata -and !$operationMetadata) { throw 'ARM metadata reads must stay within the selected service, destination vault metadata, or incident/operation status endpoints.' }
        $audience = 'https://management.azure.com/'
        if ($Method -ne 'GET' -and !$decodedPath.StartsWith("$($Context.ServiceId)/", [StringComparison]::OrdinalIgnoreCase)) { throw 'ARM writes/secret reads must remain inside the selected APIM service.' }
        if ($Method -in @('PUT', 'PATCH') -and ($Method -ne 'PATCH' -or $decodedPath -notmatch ('^' + [regex]::Escape($Context.ServiceId) + '/namedValues/[^/]+$'))) { throw 'ARM writes are restricted to existing global named-value reference updates.' }
        if ($Method -eq 'GET' -and $decodedPath -match '/(listValue|listSecrets)$') { throw 'Secret-retrieval endpoints are not permitted in metadata GET requests.' }
    }
    $requestUri = $uri.AbsoluteUri
    if ($uri.Query -notmatch '(^|[?&])api-version=') {
        $separator = if ($uri.Query) { '&' } else { '?' }
        $version = if ($Vault) { '7.4' } else { $Context.ApiVersion }
        $requestUri += "${separator}api-version=$version"
    }
    $headers = @{ Authorization = 'Bearer ' + (Get-ApimSecurityToken $Context $audience) }
    if ($IfMatch) {
        if ($IfMatch -eq '*') { throw 'Unconditional APIM updates are not allowed by these security scripts.' }
        $headers['If-Match'] = $IfMatch
    }
    $parameters = @{ Method = $Method; Uri = $requestUri; Headers = $headers; SkipHttpErrorCheck = $true; TimeoutSec = 120; MaximumRedirection = 0 }
    if ($null -ne $Body) { $parameters.ContentType = 'application/json'; $parameters.Body = ConvertTo-Json -InputObject $Body -Depth 50 -Compress }
    try {
        try { $response = Invoke-WebRequest @parameters } catch { throw "Azure transport failed for $Method. Response bodies, URLs, credentials, and request values are omitted." }
        $status = [int]$response.StatusCode
        if ($status -eq 404 -and $AllowNotFound) { return $null }
        if ($status -lt 200 -or $status -ge 300) { throw "Azure returned HTTP $status for $Method. Use restricted Azure activity logs for diagnosis; response/request bodies are omitted." }
        try { $data = if ([string]::IsNullOrWhiteSpace($response.Content)) { @{} } else { ConvertFrom-Json -InputObject $response.Content -AsHashtable } }
        catch { throw 'Azure returned invalid JSON; contents are omitted.' }
        return @{ Data = $data; ETag = @($response.Headers['ETag'])[0]; Status = $status; AsyncOperation = @($response.Headers['Azure-AsyncOperation'])[0]; Location = @($response.Headers['Location'])[0] }
    } finally { $headers = $null; $parameters.Body = $null; $response = $null }
}

function Get-ApimSecurityCollection {
    param([hashtable]$Context, [string]$Path, [switch]$Vault)
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $initialUri = [Uri]$(if ($Path.StartsWith('/')) { 'https://management.azure.com' + $Path } else { $Path })
    while ($Path) {
        if (!$visited.Add($Path)) { throw 'Azure returned a repeated pagination URL.' }
        $pageUri = [Uri]$(if ($Path.StartsWith('/')) { 'https://management.azure.com' + $Path } else { $Path })
        if ($pageUri.Host -ne $initialUri.Host -or !$pageUri.AbsolutePath.Equals($initialUri.AbsolutePath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Azure pagination left the requested metadata collection.' }
        $response = Invoke-ApimSecurityRequest $Context GET $Path -Vault:$Vault
        if (!$response.Data.ContainsKey('value') -or $response.Data['value'] -isnot [array]) { throw 'Azure returned invalid collection metadata; completeness cannot be established.' }
        foreach ($item in $response.Data['value']) { Write-Output $item }
        $Path = [string]$response.Data['nextLink']
    }
}

function Clear-ApimSecurityContext {
    param([hashtable]$Context)
    if ($null -ne $Context) { $Context.Tokens.Clear() }
}

function Protect-ApimInventoryCell {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    # Preserve literal values in spreadsheets; resource-controlled text must not become a formula.
    if ($text -match '^\s*[=+@-]') { return "'$text" }
    return $text
}