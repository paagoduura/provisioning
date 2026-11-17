[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedApiOrigin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$accessToken = [Environment]::GetEnvironmentVariable('SUPABASE_ACCESS_TOKEN', 'Process')
if ([string]::IsNullOrWhiteSpace($accessToken)) {
    throw 'Set SUPABASE_ACCESS_TOKEN in this PowerShell process to a valid Supabase user access token.'
}
if ([string]::IsNullOrWhiteSpace($ExpectedApiOrigin)) {
	throw 'ExpectedApiOrigin is required to prevent checking an unintended deployment.'
}

$apiUri = $null
$expectedUri = $null
if (-not [Uri]::TryCreate($ApiBaseUrl, [UriKind]::Absolute, [ref]$apiUri) -or
    $apiUri.Scheme -ne 'https' -or
    [string]::IsNullOrWhiteSpace($apiUri.Host) -or
    -not [string]::IsNullOrEmpty($apiUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($apiUri.Query) -or
    -not [string]::IsNullOrEmpty($apiUri.Fragment) -or
    $apiUri.AbsolutePath.Trim('/') -ne '') {
    throw 'ApiBaseUrl must be an HTTPS origin without credentials, path, query, or fragment.'
}
if (-not [Uri]::TryCreate($ExpectedApiOrigin, [UriKind]::Absolute, [ref]$expectedUri) -or
    $expectedUri.Scheme -ne 'https' -or
    [string]::IsNullOrWhiteSpace($expectedUri.Host) -or
    -not [string]::IsNullOrEmpty($expectedUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($expectedUri.Query) -or
    -not [string]::IsNullOrEmpty($expectedUri.Fragment) -or
    $expectedUri.AbsolutePath.Trim('/') -ne '') {
	throw 'ExpectedApiOrigin must be an HTTPS origin without credentials, path, query, or fragment.'
}
if (-not [string]::Equals($apiUri.GetLeftPart([UriPartial]::Authority), $expectedUri.GetLeftPart([UriPartial]::Authority), [StringComparison]::OrdinalIgnoreCase)) {
	throw 'ApiBaseUrl does not match ExpectedApiOrigin; no request was made.'
}

$base = $apiUri.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
$authorizedHeaders = @{ Authorization = "Bearer $accessToken"; Accept = 'application/json' }

function Invoke-PreflightGet([string]$Name, [string]$Uri, [hashtable]$Headers) {
    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
    }
    catch {
        $status = 'unknown'
        if ($null -ne $_.Exception.Response) {
            try { $status = [string][int]$_.Exception.Response.StatusCode } catch { }
        }
        throw "$Name failed (HTTP $status). Response content is suppressed to avoid disclosing sensitive server details."
    }
}

try {
    $health = Invoke-PreflightGet 'health check' "$base/healthz" @{}
    if ($health.status -ne 'ok') {
        throw 'Health endpoint did not report status=ok.'
    }
    Write-Output 'PASS: HTTPS API health endpoint.'

    $ready = Invoke-PreflightGet 'readiness check' "$base/readyz" @{}
    if ($ready.status -ne 'ok') {
        $failedNames = @()
        if ($null -ne $ready.checks) {
            foreach ($property in $ready.checks.PSObject.Properties) {
                if ($property.Value.status -ne 'ok') { $failedNames += $property.Name }
            }
        }
        $failed = $failedNames -join ', '
        if ([string]::IsNullOrWhiteSpace($failed)) { $failed = 'unreported required check' }
        throw "API is not ready; failed readiness check(s): $failed. No response details were logged."
    }
    $checkNames = @()
    if ($null -ne $ready.checks) {
        foreach ($property in $ready.checks.PSObject.Properties) {
            if ($property.Value.status -eq 'ok') { $checkNames += $property.Name }
        }
    }
    Write-Output ('PASS: API readiness checks: ' + ($checkNames -join ', '))

    # This authenticated GET is intentionally read-only. Discard the device list;
    # it may contain user-specific metadata and is not acceptance evidence.
    $null = Invoke-PreflightGet 'authenticated API access check' "$base/v1/devices" $authorizedHeaders
    Write-Output 'PASS: Supabase bearer token accepted for an authenticated read-only API request.'
}
finally {
    $authorizedHeaders.Clear()
    $accessToken = $null
    $health = $null
    $ready = $null
}

Write-Output 'PREFLIGHT PASS: no provisioning session, device, token, webhook, APDU, or card artifact was created or changed.'
Write-Output 'LIMITATION: this confirms deployment health/readiness and authenticated read access only; it is not live provider, genuine-device, card, or end-to-end acceptance.'
