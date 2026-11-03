[CmdletBinding()]
param(
    [string]$ApiBaseUrl = $(if ($env:OTA_API_BASE_URL) { $env:OTA_API_BASE_URL } else { 'http://127.0.0.1:8080' }),
    [string]$ApiExe = '.\provisioning-api.exe',
    [int]$StartupTimeoutSeconds = 30,
    [switch]$SkipDatabaseCheck,
    [switch]$KeepApiRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw "Slice 3 acceptance gate failed: $Message"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$apiUrl = $ApiBaseUrl.TrimEnd('/')
$apiPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $ApiExe))
$logDirectory = Join-Path ([IO.Path]::GetTempPath()) ('slice3-kms-gate-' + [guid]::NewGuid().ToString('N'))
$stdoutPath = Join-Path $logDirectory 'api.stdout.log'
$stderrPath = Join-Path $logDirectory 'api.stderr.log'
$apiProcess = $null

try {
    New-Item -ItemType Directory -Path $logDirectory | Out-Null

    $head = (& git -C $repoRoot rev-parse HEAD 2>&1).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) {
        Fail "could not determine the repository revision"
    }
    Write-Host "Acceptance commit: $head"

    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Fail 'Go is required to rebuild the API from the checked-out source'
    }
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
        Fail 'AWS CLI is required for KMS signing'
    }
    if ([string]::IsNullOrWhiteSpace($env:AWS_KMS_KEY_ID)) {
        Fail 'AWS_KMS_KEY_ID must be set'
    }
    if ([string]::IsNullOrWhiteSpace($env:DATABASE_URL) -and -not $SkipDatabaseCheck) {
        Fail 'DATABASE_URL must be set unless -SkipDatabaseCheck is explicitly supplied'
    }

    $port = ([Uri]$apiUrl).Port
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        $owners = ($listeners | Select-Object -ExpandProperty OwningProcess -Unique) -join ', '
        Fail "TCP port $port is already in use by process id(s): $owners. Stop the existing API before running this gate."
    }

    Write-Host 'Building API from the checked-out source...'
    & go build -o $apiPath (Join-Path $repoRoot 'cmd\api')
    if ($LASTEXITCODE -ne 0) {
        Fail 'go build failed'
    }
    if (-not (Test-Path $apiPath -PathType Leaf)) {
        Fail "go build completed but API executable was not created at $apiPath"
    }

    $env:AWS_EC2_METADATA_DISABLED = 'true'
    $env:ENVIRONMENT = 'staging'
    $apiProcess = Start-Process -FilePath $apiPath -WorkingDirectory $repoRoot -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    Write-Host "Started fresh API process: $($apiProcess.Id)"

    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($apiProcess.HasExited) {
            Fail "API exited during startup. Logs: $stdoutPath and $stderrPath"
        }
        try {
            $health = Invoke-RestMethod -Method Get -Uri "$apiUrl/healthz" -TimeoutSec 3
            $readiness = Invoke-RestMethod -Method Get -Uri "$apiUrl/readyz" -TimeoutSec 3
            if ($health.status -eq 'ok' -and $readiness.status -eq 'ready') {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        Fail "API did not become healthy within $StartupTimeoutSeconds seconds. Logs: $stdoutPath and $stderrPath"
    }
    Write-Host 'PASS fresh API health and readiness'

    $e2eArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts\staging-kms-e2e.ps1'), '-BaseUrl', $apiUrl)
    if ($SkipDatabaseCheck) {
        $e2eArgs += '-SkipDatabaseCheck'
    }
    & powershell @e2eArgs
    if ($LASTEXITCODE -ne 0) {
        Fail "staging-kms-e2e.ps1 failed. API logs: $stdoutPath and $stderrPath"
    }
    Write-Host 'PASS: Slice 3 staging acceptance gate completed successfully.'
}
catch {
    Write-Error $_
    if (Test-Path $stdoutPath) {
        Write-Host '--- API stdout ---'
        Get-Content $stdoutPath
    }
    if (Test-Path $stderrPath) {
        Write-Host '--- API stderr ---'
        Get-Content $stderrPath
    }
    exit 1
}
finally {
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited -and -not $KeepApiRunning) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "Stopped fresh API process: $($apiProcess.Id)"
    }
    if ($KeepApiRunning) {
        Write-Host "API left running by request: $($apiProcess.Id)"
        Write-Host "Logs: $stdoutPath and $stderrPath"
    } elseif (Test-Path $logDirectory) {
        Remove-Item -Recurse -Force $logDirectory -ErrorAction SilentlyContinue
    }
}
