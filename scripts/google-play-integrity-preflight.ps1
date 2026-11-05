[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectId,
    [string]$PackageName = $env:GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME,
    [string]$CredentialsFile = $env:GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE
)

$ErrorActionPreference = 'Stop'

Write-Output 'Google Play Integrity read-only preflight'
Write-Output 'No resources will be created, changed, linked, enabled, or deleted.'

if ([string]::IsNullOrWhiteSpace($PackageName)) {
    throw 'PackageName is required. Set GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME or pass -PackageName.'
}
if ([string]::IsNullOrWhiteSpace($CredentialsFile)) {
    Write-Warning 'GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE is not configured. This is required for live server verification.'
} elseif (-not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf)) {
    throw "Credential file does not exist: $CredentialsFile"
} else {
    Write-Output "Credential file exists: $CredentialsFile"
}

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Warning 'gcloud is not installed; cloud-side read-only checks were skipped.'
    exit 0
}

Write-Output "Project: $ProjectId"
Write-Output '--- Project identity (read-only) ---'
gcloud projects describe $ProjectId --format='value(projectId,projectNumber)' --quiet

Write-Output '--- Enabled Play Integrity API (read-only) ---'
$enabled = gcloud services list --enabled --project $ProjectId --filter='config.name=playintegrity.googleapis.com' --format='value(config.name)' --quiet
if ([string]::IsNullOrWhiteSpace($enabled)) {
    Write-Warning 'Play Integrity API is not listed as enabled in this project.'
} else {
    Write-Output $enabled
}

Write-Output '--- Service accounts (read-only; key material is never displayed) ---'
gcloud iam service-accounts list --project $ProjectId --format='table(email,disabled)' --quiet

Write-Output '--- External gates not observable from Google Cloud project metadata ---'
Write-Output '1. Play Console must link the exact package name and signing certificate.'
Write-Output '2. The Android application must produce a real standard Play Integrity token.'
Write-Output '3. A valid token fixture must be submitted through the local E2E harness.'
Write-Output '4. IAM must grant only the approved decode permission to the runtime identity.'
Write-Output 'No Google Cloud or Play Console changes were performed.'
