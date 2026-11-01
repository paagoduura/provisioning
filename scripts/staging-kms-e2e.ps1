[CmdletBinding()]
param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$KmsKeyId = $env:AWS_KMS_KEY_ID,
    [string]$AwsRegion = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { "eu-north-1" }),
    [string]$AwsProfile = $env:AWS_PROFILE,
    [string]$SigningAlgorithm = $(if ($env:AWS_KMS_SIGNING_ALGORITHM) { $env:AWS_KMS_SIGNING_ALGORITHM } else { "RSASSA_PKCS1_V1_5_SHA_256" }),
    [string]$DatabaseUrl = $env:DATABASE_URL,
    [switch]$SkipDatabaseCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "E2E validation failed: $Message"
}

function Assert-Equal([object]$Actual, [object]$Expected, [string]$Message) {
    if ($Actual -ne $Expected) {
        Fail "$Message (expected '$Expected', got '$Actual')"
    }
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Invoke-Json([string]$Method, [string]$Uri, [object]$Body = $null, [hashtable]$Headers = @{}) {
    $params = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        ContentType = "application/json"
        ErrorAction = "Stop"
    }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }
    return Invoke-RestMethod @params
}

function Assert-RequiredTables([string]$ConnectionString) {
    if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
        Fail "psql is required for migration inspection, or rerun with -SkipDatabaseCheck"
    }

    $query = @"
SELECT required_table
FROM unnest(ARRAY['provisioning_sessions','audit_events','attestation_challenges','device_attestations','device_key_revocations']::text[]) AS required(required_table)
WHERE to_regclass(format('public.%s', required_table)) IS NOT NULL
ORDER BY required_table;
"@
    $result = & psql $ConnectionString --no-psqlrc --tuples-only --no-align --command $query 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "read-only migration inspection could not connect: $result"
    }
    $resultText = $result -join "`n"
    foreach ($table in @("provisioning_sessions", "audit_events", "attestation_challenges", "device_attestations", "device_key_revocations")) {
        $pattern = "(?m)^\s*" + [regex]::Escape($table) + "\s*$"
        if ($resultText -notmatch $pattern) {
            Fail "required migration table is missing: $table"
        }
    }
    Write-Host "PASS migration inspection: all required tables exist"
}

if ([string]::IsNullOrWhiteSpace($KmsKeyId)) {
    Fail "-KmsKeyId or AWS_KMS_KEY_ID is required"
}
if (-not $SkipDatabaseCheck -and [string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    Fail "-DatabaseUrl or DATABASE_URL is required unless -SkipDatabaseCheck is explicitly supplied"
}
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Fail "AWS CLI is required"
}

$BaseUrl = $BaseUrl.TrimEnd('/')
if (-not $SkipDatabaseCheck) {
    Assert-RequiredTables $DatabaseUrl
}

$nonce = [Guid]::NewGuid().ToString("N")
$idempotencyKey = "staging-kms-e2e-$nonce"
$requestHash = "staging-request-$nonce"
$counter = 1

$session = Invoke-Json "POST" "$BaseUrl/v1/provisioning-sessions" @{
    user_id = "staging-e2e-user"
    device_uid = "staging-e2e-device-$nonce"
    device_model = "staging-e2e-model"
    transport = "ble"
} @{ "Idempotency-Key" = $idempotencyKey }
if ([string]::IsNullOrWhiteSpace($session.id)) { Fail "session creation returned no id" }
Write-Host "PASS session creation: $($session.id)"

$discovered = Invoke-Json "POST" "$BaseUrl/v1/provisioning-sessions/$($session.id)/device-discovery"
Assert-Equal $discovered.state "DEVICE_DISCOVERED" "device discovery state"
Write-Host "PASS device discovery"

$challenge = Invoke-Json "POST" "$BaseUrl/v1/provisioning-sessions/$($session.id)/attestation-challenges" @{ request_hash = $requestHash }
if ([string]::IsNullOrWhiteSpace($challenge.id) -or [string]::IsNullOrWhiteSpace($challenge.challenge)) {
    Fail "challenge response is incomplete"
}
Write-Host "PASS challenge issuance: $($challenge.id)"

$canonical = "$($challenge.challenge)`n$requestHash`n$($session.id)`n$counter"
$messagePath = Join-Path ([IO.Path]::GetTempPath()) "provisioning-kms-$nonce.bin"
$signaturePath = Join-Path ([IO.Path]::GetTempPath()) "provisioning-kms-$nonce.sig"
$awsArgs = @("kms", "sign", "--region", $AwsRegion, "--key-id", $KmsKeyId, "--message", "fileb://$messagePath", "--message-type", "RAW", "--signing-algorithm", $SigningAlgorithm, "--output", "json")
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) {
    $awsArgs = @("--profile", $AwsProfile) + $awsArgs
}
try {
    [IO.File]::WriteAllBytes($messagePath, [Text.UTF8Encoding]::new($false).GetBytes($canonical))
    $signJson = & aws @awsArgs 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "AWS KMS Sign failed: $signJson" }
    $signResult = $signJson | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($signResult.Signature)) { Fail "AWS KMS Sign returned no signature" }
    $signatureBytes = [Convert]::FromBase64String($signResult.Signature)
    [IO.File]::WriteAllBytes($signaturePath, $signatureBytes)

    $verifyArgs = @("kms", "verify", "--region", $AwsRegion, "--key-id", $KmsKeyId, "--message", "fileb://$messagePath", "--message-type", "RAW", "--signature", "fileb://$signaturePath", "--signing-algorithm", $SigningAlgorithm, "--query", "SignatureValid", "--output", "text")
    if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) {
        $verifyArgs = @("--profile", $AwsProfile) + $verifyArgs
    }
    $verifyResult = (& aws @verifyArgs 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { Fail "AWS KMS Verify failed: $verifyResult" }
    if ($verifyResult -ne "True") { Fail "AWS KMS Verify returned '$verifyResult' for the exact canonical message" }
    Write-Host "PASS direct AWS KMS verification"
} finally {
    Remove-Item -LiteralPath $messagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $signaturePath -Force -ErrorAction SilentlyContinue
}

$assertionJson = (@{ signature = (ConvertTo-Base64Url $signatureBytes); counter = $counter } | ConvertTo-Json -Compress)
$assertion = ConvertTo-Base64Url ([Text.UTF8Encoding]::new($false).GetBytes($assertionJson))
Write-Host "PASS KMS signing and canonical message construction"

$attested = Invoke-Json "POST" "$BaseUrl/v1/provisioning-sessions/$($session.id)/attestation" @{
    challenge_id = $challenge.id
    provider = "aws-kms"
    key_id = $KmsKeyId
    assertion = $assertion
    request_hash = $requestHash
}
Assert-Equal $attested.provider "aws-kms" "attestation provider"
Assert-Equal $attested.key_id $KmsKeyId "attestation key binding"
Assert-Equal ([int]$attested.counter) $counter "attestation counter"
Assert-Equal $attested.trust_level "aws-kms-hsm-verified" "attestation trust level"
Write-Host "PASS API KMS verification"

$final = Invoke-Json "GET" "$BaseUrl/v1/provisioning-sessions/$($session.id)"
Assert-Equal $final.state "DEVICE_ATTESTED" "final session state"
Write-Host "PASS final attested response: session is DEVICE_ATTESTED"
Write-Host "Staging KMS E2E validation completed successfully."
