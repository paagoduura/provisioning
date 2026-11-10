[CmdletBinding()]
param(
    [string]$ApiBaseUrl = $(if ($env:OTA_API_BASE_URL) { $env:OTA_API_BASE_URL } else { 'http://127.0.0.1:8080' }),
    [string]$AwsProfile = $(if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { 'chris-stev' }),
    [string]$AwsRegion = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { 'eu-north-1' }),
    [string]$KmsKeyId = $env:AWS_KMS_KEY_ID,
    [string]$SigningAlgorithm = $(if ($env:AWS_KMS_SIGNING_ALGORITHM) { $env:AWS_KMS_SIGNING_ALGORITHM } else { 'RSASSA_PKCS1_V1_5_SHA_256' })
)

$ErrorActionPreference = 'Stop'
$SupabaseAccessToken = $env:SUPABASE_ACCESS_TOKEN
if ([string]::IsNullOrWhiteSpace($SupabaseAccessToken)) {
    throw 'Set SUPABASE_ACCESS_TOKEN to a valid Supabase Auth user access token before running this walkthrough.'
}
$ApiAuthHeaders = @{ Authorization = "Bearer $SupabaseAccessToken" }

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Invoke-JsonPost([string]$Uri, [object]$Body, [hashtable]$Headers = @{}) {
    $json = $Body | ConvertTo-Json -Compress -Depth 8
    $requestHeaders = @{ Authorization = "Bearer $SupabaseAccessToken" }
    foreach ($headerName in $Headers.Keys) { $requestHeaders[$headerName] = $Headers[$headerName] }
    try {
        return Invoke-RestMethod -Method Post -Uri $Uri -Headers $requestHeaders -ContentType 'application/json' -Body $json
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            $reader.Dispose()
            if ([string]::IsNullOrWhiteSpace($errorBody) -and $_.ErrorDetails.Message) {
                $errorBody = $_.ErrorDetails.Message
            }
            throw "POST $Uri failed with HTTP $([int]$response.StatusCode): $errorBody"
        }
        throw
    }
}

function Invoke-ExpectedReplay([string]$Uri, [object]$Body) {
    $json = $Body | ConvertTo-Json -Compress -Depth 8
    try {
        Invoke-RestMethod -Method Post -Uri $Uri -Headers $ApiAuthHeaders -ContentType 'application/json' -Body $json | Out-Null
        throw 'Replay request unexpectedly succeeded.'
    }
    catch {
        $response = $_.Exception.Response
        if ($null -eq $response) { throw }
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $errorBody = $reader.ReadToEnd()
        $reader.Dispose()
        if ([int]$response.StatusCode -ne 409) {
            throw "Replay request returned HTTP $([int]$response.StatusCode), expected 409: $errorBody"
        }
		$errorResult = $errorBody | ConvertFrom-Json
		$failureCode = [string]$errorResult.failure_code
		if ([string]::IsNullOrWhiteSpace($failureCode)) {
			$failureCode = [string]$errorResult.FailureCode
		}
		if ([string]::IsNullOrWhiteSpace($failureCode)) {
			throw "Replay response did not contain failure_code: $errorBody"
		}
		return [pscustomobject]@{ failure_code = $failureCode }
	}
}

function Invoke-ExpectedFailure([string]$Uri, [object]$Body, [int]$ExpectedStatus, [string]$ExpectedCode) {
	$json = $Body | ConvertTo-Json -Compress -Depth 8
	try {
        Invoke-RestMethod -Method Post -Uri $Uri -Headers $ApiAuthHeaders -ContentType 'application/json' -Body $json | Out-Null
		throw "Negative request unexpectedly succeeded: $ExpectedCode"
	}
	catch {
		$response = $_.Exception.Response
		if ($null -eq $response) { throw }
		$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
		$errorBody = $reader.ReadToEnd()
		$reader.Dispose()
		if ([int]$response.StatusCode -ne $ExpectedStatus) {
			throw "Negative request returned HTTP $([int]$response.StatusCode), expected ${ExpectedStatus}: $errorBody"
		}
		$errorResult = $errorBody | ConvertFrom-Json
		$failureCode = [string]$errorResult.failure_code
		if ([string]::IsNullOrWhiteSpace($failureCode)) {
			$failureCode = [string]$errorResult.FailureCode
		}
		if ($failureCode -ne $ExpectedCode) {
			throw "Negative request returned $failureCode, expected ${ExpectedCode}: $errorBody"
		}
		return [pscustomobject]@{ failure_code = $failureCode }
	}
}

if ([string]::IsNullOrWhiteSpace($KmsKeyId)) {
    throw 'AWS_KMS_KEY_ID must be set to the staging asymmetric KMS key ARN or ID.'
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('ota-kms-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$messagePath = Join-Path $temporaryDirectory 'canonical-message.bin'
$signaturePath = Join-Path $temporaryDirectory 'signature.b64'
$signatureBytesPath = Join-Path $temporaryDirectory 'signature.bin'

try {
    $health = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/healthz"
    if ($health.status -ne 'ok') { throw 'API health check did not return status=ok.' }

    $ready = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/readyz"
    if ($ready.status -ne 'ready') { throw 'API readiness check did not return status=ready.' }

    $runId = [guid]::NewGuid().ToString('N')
    $idempotencyKey = "staging-kms-e2e-$runId"
    $requestHash = "staging-kms-e2e-request-$runId"
    $keyId = $KmsKeyId

    $session = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions" @{
        device_uid = "staging-e2e-device-$runId"
        device_model = 'wearable-staging-fixture'
        transport = 'ble'
    } @{ 'Idempotency-Key' = $idempotencyKey }

    $sessionId = [string]$session.id
    if ([string]::IsNullOrWhiteSpace($sessionId)) { throw 'Session response did not contain an id.' }

    Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$sessionId/device-discovery" @{} | Out-Null

    $challengeResponse = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$sessionId/attestation-challenges" @{ request_hash = $requestHash }
    $challengeId = [string]$challengeResponse.id
    $challengeValue = [string]$challengeResponse.challenge
    if ([string]::IsNullOrWhiteSpace($challengeId) -or [string]::IsNullOrWhiteSpace($challengeValue)) {
        throw 'Challenge response did not contain the required fields.'
    }

    $counter = 1
    $canonicalMessage = "$challengeValue`n$requestHash`n$sessionId`n$counter"
    $canonicalBytes = [Text.Encoding]::UTF8.GetBytes($canonicalMessage)
    $canonicalDigest = [Security.Cryptography.SHA256]::Create().ComputeHash($canonicalBytes)
    Write-Output ("canonical_sha256=" + ([BitConverter]::ToString($canonicalDigest).Replace('-', '').ToLowerInvariant()))
    [IO.File]::WriteAllBytes($messagePath, $canonicalBytes)

    & aws kms sign --profile $AwsProfile --region $AwsRegion --key-id $keyId --message "fileb://$messagePath" --message-type RAW --signing-algorithm $SigningAlgorithm --query Signature --output text | Out-File -Encoding ascii -NoNewline $signaturePath
    if ($LASTEXITCODE -ne 0) { throw 'AWS KMS sign command failed.' }

    $signatureB64 = (Get-Content -Raw $signaturePath).Trim()
    if ([string]::IsNullOrWhiteSpace($signatureB64)) { throw 'AWS KMS returned an empty signature.' }
    [IO.File]::WriteAllBytes($signatureBytesPath, [Convert]::FromBase64String($signatureB64))

    $directVerify = & aws kms verify --profile $AwsProfile --region $AwsRegion --key-id $keyId --message "fileb://$messagePath" --message-type RAW --signature "fileb://$signatureBytesPath" --signing-algorithm $SigningAlgorithm --query SignatureValid --output text
    if ($LASTEXITCODE -ne 0 -or $directVerify.Trim() -ne 'True') {
        throw "Direct AWS KMS verification failed: $($directVerify.Trim())"
    }

    $signatureUrl = ConvertTo-Base64Url ([IO.File]::ReadAllBytes($signatureBytesPath))
    $signatureRoundTrip = $signatureUrl.Replace('-', '+').Replace('_', '/')
    while (($signatureRoundTrip.Length % 4) -ne 0) { $signatureRoundTrip += '=' }
    [IO.File]::WriteAllBytes($signatureBytesPath, [Convert]::FromBase64String($signatureRoundTrip))
    $roundTripVerify = & aws kms verify --profile $AwsProfile --region $AwsRegion --key-id $keyId --message "fileb://$messagePath" --message-type RAW --signature "fileb://$signatureBytesPath" --signing-algorithm $SigningAlgorithm --query SignatureValid --output text
    if ($LASTEXITCODE -ne 0 -or $roundTripVerify.Trim() -ne 'True') {
        throw "Base64url signature round-trip verification failed: $($roundTripVerify.Trim())"
    }
    $assertionJson = @{ signature = $signatureUrl; counter = $counter } | ConvertTo-Json -Compress
    $assertion = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($assertionJson))

    $submission = @{
        challenge_id = $challengeId
        provider = 'aws-kms'
        key_id = $keyId
        assertion = $assertion
        request_hash = $requestHash
    }
    $result = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$sessionId/attestation" $submission

    if ($result.provider -ne 'aws-kms') { throw "Unexpected provider: $($result.provider)" }
    if ($result.key_id -ne $keyId) { throw 'KMS key binding did not match the configured key.' }
    if ([int]$result.counter -ne $counter) { throw 'Unexpected attestation counter.' }
    if ($result.trust_level -ne 'aws-kms-hsm-verified') { throw "Unexpected trust level: $($result.trust_level)" }

    $replay = Invoke-ExpectedReplay "$ApiBaseUrl/v1/provisioning-sessions/$sessionId/attestation" $submission
    if ($replay.failure_code -ne 'ATTESTATION_CHALLENGE_REPLAY') {
        throw "Unexpected replay failure code: $($replay.failure_code)"
    }

	$finalSession = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/v1/provisioning-sessions/$sessionId" -Headers $ApiAuthHeaders
	if ($finalSession.state -ne 'device_attested') {
		throw "Session did not transition to device_attested: $($finalSession.state)"
	}

	# Use a fresh session/challenge for negative cryptographic and binding tests.
	$negativeRunId = [guid]::NewGuid().ToString('N')
	$negativeSession = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions" @{
		device_uid = "staging-e2e-negative-device-$negativeRunId"
		device_model = 'wearable-staging-fixture'
		transport = 'ble'
	} @{ 'Idempotency-Key' = "staging-kms-e2e-negative-$negativeRunId" }
	$negativeSessionId = [string]$negativeSession.id
	Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$negativeSessionId/device-discovery" @{} | Out-Null
	$negativeRequestHash = "staging-kms-e2e-negative-request-$negativeRunId"
	$negativeChallenge = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$negativeSessionId/attestation-challenges" @{ request_hash = $negativeRequestHash }
	$negativeMessage = "$($negativeChallenge.challenge)`n$negativeRequestHash`n$negativeSessionId`n1"
	$negativeMessagePath = Join-Path $temporaryDirectory 'negative-message.bin'
	$negativeSignaturePath = Join-Path $temporaryDirectory 'negative-signature.b64'
	$negativeSignatureBytesPath = Join-Path $temporaryDirectory 'negative-signature.bin'
	[IO.File]::WriteAllBytes($negativeMessagePath, [Text.Encoding]::UTF8.GetBytes($negativeMessage))
	& aws kms sign --profile $AwsProfile --region $AwsRegion --key-id $keyId --message "fileb://$negativeMessagePath" --message-type RAW --signing-algorithm $SigningAlgorithm --query Signature --output text | Out-File -Encoding ascii -NoNewline $negativeSignaturePath
	if ($LASTEXITCODE -ne 0) { throw 'AWS KMS negative-test sign command failed.' }
	$negativeSignatureB64 = (Get-Content -Raw $negativeSignaturePath).Trim()
	$negativeSignatureBytes = [Convert]::FromBase64String($negativeSignatureB64)
	$negativeSignatureBytes[0] = $negativeSignatureBytes[0] -bxor 1
	[IO.File]::WriteAllBytes($negativeSignatureBytesPath, $negativeSignatureBytes)
	$alteredAssertionJson = @{ signature = (ConvertTo-Base64Url $negativeSignatureBytes); counter = 1 } | ConvertTo-Json -Compress
	$alteredAssertion = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($alteredAssertionJson))
	Invoke-ExpectedFailure "$ApiBaseUrl/v1/provisioning-sessions/$negativeSessionId/attestation" @{
		challenge_id = $negativeChallenge.id
		provider = 'aws-kms'
		key_id = $keyId
		assertion = $alteredAssertion
		request_hash = $negativeRequestHash
	} 422 'ATTESTATION_KMS_SIGNATURE_INVALID' | Out-Null

	$bindingRequestHash = "$negativeRequestHash-2"
	$bindingChallenge = Invoke-JsonPost "$ApiBaseUrl/v1/provisioning-sessions/$negativeSessionId/attestation-challenges" @{ request_hash = $bindingRequestHash }
	$bindingAssertionJson = @{ signature = (ConvertTo-Base64Url $negativeSignatureBytes); counter = 1 } | ConvertTo-Json -Compress
	$bindingAssertion = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($bindingAssertionJson))
	Invoke-ExpectedFailure "$ApiBaseUrl/v1/provisioning-sessions/$negativeSessionId/attestation" @{
		challenge_id = $bindingChallenge.id
		provider = 'aws-kms'
		key_id = $keyId
		assertion = $bindingAssertion
		request_hash = "$bindingRequestHash-tampered"
	} 400 'ATTESTATION_REQUEST_BINDING_MISMATCH' | Out-Null

	Write-Output 'PASS: live KMS-to-API attestation succeeded; durable state, replay protection, altered-signature rejection, and request binding passed.'
}
finally {
    if (Test-Path $temporaryDirectory) {
        Remove-Item -Recurse -Force $temporaryDirectory
    }
}
