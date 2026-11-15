[CmdletBinding()]
param(
    [string]$AwsProfile = $env:AWS_PROFILE,
    [string]$AwsRegion = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { 'eu-north-1' }),
    [string]$KmsKeyId = $env:AWS_KMS_KEY_ID,
    [string]$SigningAlgorithm = $(if ($env:AWS_KMS_SIGNING_ALGORITHM) { $env:AWS_KMS_SIGNING_ALGORITHM } else { 'RSASSA_PKCS1_V1_5_SHA_256' })
)

$ErrorActionPreference = 'Stop'

if ($MyInvocation.InvocationName -ne '.') {
    throw 'Dot-source this script into the PowerShell session that will run the API: . .\scripts\set-staging-env.ps1'
}

function Get-RequiredSetting([string]$Name, [string]$Prompt, [switch]$Secret) {
    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($Secret) {
            $secureValue = Read-Host -Prompt $Prompt -AsSecureString
            if ($null -eq $secureValue -or $secureValue.Length -eq 0) {
                throw "$Name is required."
            }
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
            try {
                $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            }
            finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
                $secureValue.Dispose()
            }
        }
        else {
            $value = (Read-Host -Prompt $Prompt).Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Name is required."
    }
    if (-not $Secret) { $value = $value.Trim() }
    return $value
}

function Assert-AbsoluteUri([string]$Name, [string]$Value, [string[]]$Schemes, [switch]$DisallowUserInfo) {
    $parsedUri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsedUri) -or
        $parsedUri.Scheme -notin $Schemes -or
        [string]::IsNullOrWhiteSpace($parsedUri.Host)) {
        $schemeText = $Schemes -join ' or '
        throw "$Name must be an absolute URI using $schemeText."
    }
    if ($DisallowUserInfo -and -not [string]::IsNullOrEmpty($parsedUri.UserInfo)) {
        throw "$Name must not embed credentials; configure credentials in the dedicated secret fields."
    }
}

$databaseUrl = Get-RequiredSetting 'DATABASE_URL' 'Supabase PostgreSQL connection URI (hidden)' -Secret
$redisUrl = Get-RequiredSetting 'REDIS_URL' 'Staging Redis URI, including credentials if required (hidden)' -Secret
$tokenUrl = Get-RequiredSetting 'INTERSWITCH_TOKEN_URL' 'InterSwitch OAuth token endpoint HTTPS URL'
$requestUrl = Get-RequiredSetting 'INTERSWITCH_REQUEST_URL' 'InterSwitch token request endpoint HTTPS URL'
$clientId = Get-RequiredSetting 'INTERSWITCH_CLIENT_ID' 'InterSwitch client ID (hidden)' -Secret
$clientSecret = Get-RequiredSetting 'INTERSWITCH_CLIENT_SECRET' 'InterSwitch client secret (hidden)' -Secret
$webhookSecret = Get-RequiredSetting 'INTERSWITCH_WEBHOOK_SECRET' 'InterSwitch webhook signing secret (hidden)' -Secret

Assert-AbsoluteUri 'DATABASE_URL' $databaseUrl @('postgres', 'postgresql')
Assert-AbsoluteUri 'REDIS_URL' $redisUrl @('redis', 'rediss')
Assert-AbsoluteUri 'INTERSWITCH_TOKEN_URL' $tokenUrl @('https') -DisallowUserInfo
Assert-AbsoluteUri 'INTERSWITCH_REQUEST_URL' $requestUrl @('https') -DisallowUserInfo

if ([string]::IsNullOrWhiteSpace($AwsProfile)) {
    $AwsProfile = (Read-Host -Prompt 'AWS CLI profile name (leave blank to use the default credential chain)').Trim()
}
if ([string]::IsNullOrWhiteSpace($AwsRegion)) { throw 'AWS_REGION is required.' }
if ([string]::IsNullOrWhiteSpace($KmsKeyId)) {
    $KmsKeyId = (Read-Host -Prompt 'AWS_KMS_KEY_ID (staging asymmetric KMS key ARN or ID)').Trim()
}
if ([string]::IsNullOrWhiteSpace($KmsKeyId)) { throw 'AWS_KMS_KEY_ID is required.' }
if ([string]::IsNullOrWhiteSpace($SigningAlgorithm)) { throw 'AWS_KMS_SIGNING_ALGORITHM is required.' }

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw 'AWS CLI was not found. Install/configure AWS CLI before staging setup.'
}
$awsArgs = @()
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) { $awsArgs += @('--profile', $AwsProfile) }
$awsArgs += @('--region', $AwsRegion, 'kms', 'describe-key', '--key-id', $KmsKeyId, '--query', 'KeyMetadata.Enabled', '--output', 'text')
$kmsEnabled = & aws @awsArgs 2>$null
if ($LASTEXITCODE -ne 0 -or [string]$kmsEnabled -ne 'True') {
    throw 'AWS could not confirm that the configured staging KMS key is enabled; verify the profile, IAM permissions, region, and key ID.'
}

# Persist only non-secret selectors. Credentials and service URLs remain scoped to
# this PowerShell process and its child API process; use a deployment secret store
# for managed staging/production deployments.
$nonSecretUserSettings = @{
    ENVIRONMENT = 'staging'
    AWS_REGION = $AwsRegion
    AWS_KMS_KEY_ID = $KmsKeyId
    AWS_KMS_SIGNING_ALGORITHM = $SigningAlgorithm
    ATTESTATION_PROVIDER = 'aws-kms'
}
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) {
    $nonSecretUserSettings['AWS_PROFILE'] = $AwsProfile
}
foreach ($setting in $nonSecretUserSettings.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($setting.Key, $setting.Value, 'User')
}

$env:ENVIRONMENT = 'staging'
$env:DATABASE_URL = $databaseUrl
$env:REDIS_URL = $redisUrl
$env:INTERSWITCH_TOKEN_URL = $tokenUrl
$env:INTERSWITCH_REQUEST_URL = $requestUrl
$env:INTERSWITCH_CLIENT_ID = $clientId
$env:INTERSWITCH_CLIENT_SECRET = $clientSecret
$env:INTERSWITCH_WEBHOOK_SECRET = $webhookSecret
$env:AWS_REGION = $AwsRegion
$env:AWS_KMS_KEY_ID = $KmsKeyId
$env:AWS_KMS_SIGNING_ALGORITHM = $SigningAlgorithm
$env:ATTESTATION_PROVIDER = 'aws-kms'
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) { $env:AWS_PROFILE = $AwsProfile }
if ([string]::IsNullOrWhiteSpace($env:INTERSWITCH_SUPPORTS_IDEMPOTENCY_KEY)) {
    $env:INTERSWITCH_SUPPORTS_IDEMPOTENCY_KEY = 'false'
}

Write-Output 'Staging configuration is complete for this PowerShell process.'
Write-Output 'Configured: PostgreSQL, Redis, InterSwitch OAuth/request/webhook settings, and an enabled AWS KMS key.'
Write-Output 'Secrets were not echoed or written to persistent user environment variables.'
Write-Output 'Start the API and staging walkthrough from this same PowerShell session.'
