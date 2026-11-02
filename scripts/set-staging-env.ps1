[CmdletBinding()]
param(
    [string]$AwsProfile = $(if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { 'chris-stev' }),
    [string]$AwsRegion = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { 'eu-north-1' }),
    [string]$KmsKeyId = $(if ($env:AWS_KMS_KEY_ID) { $env:AWS_KMS_KEY_ID } else { 'arn:aws:kms:eu-north-1:091914201470:key/86ed62d9-29d0-425a-97b4-9c7336db13ff' }),
    [string]$SigningAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_256'
)

$ErrorActionPreference = 'Stop'

Write-Output 'Supabase DATABASE_URL is required for staging.'
Write-Output 'Paste the full PostgreSQL connection URI from Supabase. It will not be written to a file or echoed.'
$secureUri = Read-Host 'Supabase DATABASE_URL' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUri)
try {
    $databaseUrl = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}

if ([string]::IsNullOrWhiteSpace($databaseUrl) -or $databaseUrl -notmatch '^postgres(ql)?://') {
    throw 'DATABASE_URL must be a PostgreSQL URI beginning with postgres:// or postgresql://.'
}

[Environment]::SetEnvironmentVariable('DATABASE_URL', $databaseUrl, 'User')
[Environment]::SetEnvironmentVariable('ENVIRONMENT', 'staging', 'User')
[Environment]::SetEnvironmentVariable('AWS_PROFILE', $AwsProfile, 'User')
[Environment]::SetEnvironmentVariable('AWS_REGION', $AwsRegion, 'User')
[Environment]::SetEnvironmentVariable('AWS_KMS_KEY_ID', $KmsKeyId, 'User')
[Environment]::SetEnvironmentVariable('AWS_KMS_SIGNING_ALGORITHM', $SigningAlgorithm, 'User')

$env:DATABASE_URL = $databaseUrl
$env:ENVIRONMENT = 'staging'
$env:AWS_PROFILE = $AwsProfile
$env:AWS_REGION = $AwsRegion
$env:AWS_KMS_KEY_ID = $KmsKeyId
$env:AWS_KMS_SIGNING_ALGORITHM = $SigningAlgorithm

Write-Output 'Staging variables configured for the current PowerShell process and future user sessions.'
Write-Output 'The DATABASE_URL value was not displayed.'
Write-Output 'Start the API from this same PowerShell window so the current process receives the configured secret.'
