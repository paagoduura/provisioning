[CmdletBinding()]
param(
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$PublishableKey = $env:SUPABASE_PUBLISHABLE_KEY,
    [string]$ApiBaseUrl = $(if ($env:OTA_API_BASE_URL) { $env:OTA_API_BASE_URL } else { 'http://127.0.0.1:8080' })
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SupabaseUrl) -or [string]::IsNullOrWhiteSpace($PublishableKey)) {
    throw 'Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in the environment before running this test.'
}

try {
    $parsedSupabaseUrl = [Uri]$SupabaseUrl
} catch {
    throw 'SUPABASE_URL must be a valid HTTPS URL.'
}
if ($parsedSupabaseUrl.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($parsedSupabaseUrl.Host)) {
    throw 'SUPABASE_URL must be a valid HTTPS URL.'
}

$email = Read-Host 'Email address for the real OTP test'
if ([string]::IsNullOrWhiteSpace($email) -or $email -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
    throw 'Enter a valid email address.'
}

$authHeaders = @{
    apikey = $PublishableKey
    'Content-Type' = 'application/json'
}
$authBase = $SupabaseUrl.TrimEnd('/') + '/auth/v1'
$otpRequest = @{
    email = $email
    create_user = $true
} | ConvertTo-Json -Compress

Write-Host 'Requesting a real Supabase email OTP. This sends an email and may create the user when the code is verified.'
try {
    Invoke-RestMethod -Method Post -Uri "$authBase/otp" -Headers $authHeaders -Body $otpRequest | Out-Null
} catch {
    $status = 'unknown'
    if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
    throw "Supabase did not accept the OTP request (HTTP $status). Check the project's email/SMTP configuration and Auth rate limits; response details are intentionally not printed."
}

$secureCode = Read-Host -AsSecureString 'Enter the one-time code delivered to your email'
$codePointer = [IntPtr]::Zero
try {
    $codePointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCode)
    $code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($codePointer)
} finally {
    if ($codePointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($codePointer)
    }
    if ($null -ne $secureCode) { $secureCode.Dispose() }
}
if ([string]::IsNullOrWhiteSpace($code)) { throw 'The one-time code cannot be empty.' }

$verifyRequest = @{
    email = $email
    token = $code
    type = 'email'
} | ConvertTo-Json -Compress
$code = $null
$authSession = $null
try {
    $authSession = Invoke-RestMethod -Method Post -Uri "$authBase/verify" -Headers $authHeaders -Body $verifyRequest
} catch {
    $status = 'unknown'
    if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
    throw "Supabase OTP verification failed (HTTP $status). The response body and code are intentionally not printed."
} finally {
    $verifyRequest = $null
}

$accessToken = [string]$authSession.access_token
if ([string]::IsNullOrWhiteSpace($accessToken)) {
    throw 'Supabase verification succeeded without returning an access token.'
}
$apiHeaders = @{ Authorization = "Bearer $accessToken" }
$runId = [guid]::NewGuid().ToString('N')
$createBody = @{
    device_uid = "email-otp-e2e-$runId"
    device_model = 'auth-e2e'
    transport = 'ble'
} | ConvertTo-Json -Compress

try {
    $created = Invoke-RestMethod -Method Post -Uri "$($ApiBaseUrl.TrimEnd('/'))/v1/provisioning-sessions" -Headers ($apiHeaders + @{
        'Content-Type' = 'application/json'
        'Idempotency-Key' = "email-otp-e2e-$runId"
    }) -Body $createBody
} catch {
    $status = 'unknown'
    if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
    $accessToken = $null
    $authSession = $null
    $apiHeaders.Clear()
    throw "The token was issued, but the API session-creation request failed (HTTP $status). Token and response details are intentionally not printed."
}

$sessionId = [string]$created.id
if ([string]::IsNullOrWhiteSpace($sessionId)) {
    $accessToken = $null
    $authSession = $null
    $apiHeaders.Clear()
    throw 'The API did not return a session ID.'
}
try {
    $readBack = Invoke-RestMethod -Method Get -Uri "$($ApiBaseUrl.TrimEnd('/'))/v1/provisioning-sessions/$sessionId" -Headers $apiHeaders
} catch {
    $status = 'unknown'
    if ($_.Exception.Response) { $status = [string][int]$_.Exception.Response.StatusCode }
    $accessToken = $null
    $authSession = $null
    $apiHeaders.Clear()
    throw "The API session was created but could not be read back by its authenticated owner (HTTP $status). Token and response details are intentionally not printed."
}

if ([string]$readBack.id -ne $sessionId) {
    throw 'The authenticated session read-back returned an unexpected session.'
}
$accessToken = $null
$authSession = $null
$apiHeaders.Clear()
$verifyRequest = $null
$createBody = $null
Write-Output 'PASS: real Supabase Email OTP sign-in returned a user session; the API accepted the bearer token, created a provisioning session, and allowed its owner to read it back.'
Write-Output "session_id=$sessionId"
