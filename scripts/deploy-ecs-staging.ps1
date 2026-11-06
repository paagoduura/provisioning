[CmdletBinding()]
param(
    [string]$AwsProfile = $env:AWS_PROFILE,
    [string]$AwsRegion = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { "eu-north-1" }),
    [string]$StackName = "provisioning-staging",
    [string]$RepositoryName = "provisioning-api",
    [string]$DatabaseSecretName = "provisioning/staging/database-url",
    [string]$DatabaseUrl = $env:DATABASE_URL,
    [string]$KmsKeyArn = $env:AWS_KMS_KEY_ID,
    [string]$AppleAppID = $env:APPLE_APP_ID,
    [string]$AppleEnvironment = $(if ($env:APPLE_APP_ATTEST_ENVIRONMENT) { $env:APPLE_APP_ATTEST_ENVIRONMENT } else { "production" }),
    [string]$AppleRootCertificateSecretArn = $env:APPLE_APP_ATTEST_ROOT_CERT_SECRET_ARN,
    [string]$AndroidPackageName = $env:ANDROID_PACKAGE_NAME,
    [string]$AndroidCloudProjectNumber = $env:ANDROID_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER,
    [string]$AndroidMode = $(if ($env:ANDROID_PLAY_INTEGRITY_MODE) { $env:ANDROID_PLAY_INTEGRITY_MODE } else { "standard" }),
    [string]$AndroidServiceAccountSecretArn = $env:ANDROID_PLAY_INTEGRITY_SERVICE_ACCOUNT_SECRET_ARN,
    [switch]$SkipImageBuild
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Aws([string[]]$Arguments) {
    $global:LASTEXITCODE = 0
    $output = & aws @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "AWS command failed: aws $($Arguments -join ' ')`n$output"
    }
    return $output
}

function Aws-Args([string[]]$Arguments) {
    if ([string]::IsNullOrWhiteSpace($AwsProfile)) { return $Arguments }
    return @("--profile", $AwsProfile) + $Arguments
}

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required"
    }
}

Require-Command "aws"
Require-Command "docker"

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) { throw "DATABASE_URL or -DatabaseUrl is required" }
if ([string]::IsNullOrWhiteSpace($KmsKeyArn)) { throw "AWS_KMS_KEY_ID or -KmsKeyArn is required" }

$identity = Invoke-Aws (Aws-Args @("sts", "get-caller-identity", "--output", "json")) | ConvertFrom-Json
$accountId = $identity.Account
Write-Host "Using AWS account $accountId in $AwsRegion"

$defaultVpc = (Invoke-Aws (Aws-Args @("ec2", "describe-vpcs", "--region", $AwsRegion, "--filters", "Name=isDefault,Values=true", "--query", "Vpcs[0].VpcId", "--output", "text"))).Trim()
if ([string]::IsNullOrWhiteSpace($defaultVpc) -or $defaultVpc -eq "None") { throw "No default VPC exists in $AwsRegion" }

$subnetJson = Invoke-Aws (Aws-Args @("ec2", "describe-subnets", "--region", $AwsRegion, "--filters", "Name=vpc-id,Values=$defaultVpc", "Name=map-public-ip-on-launch,Values=true", "--query", "Subnets | sort_by(@, &AvailabilityZone)[0:2].{Id:SubnetId,Az:AvailabilityZone}", "--output", "json"))
$subnets = ($subnetJson -join "") | ConvertFrom-Json
if ($subnets.Count -lt 2) { throw "At least two public subnets are required in the default VPC" }
$subnetA = $subnets[0].Id
$subnetB = $subnets[1].Id
Write-Host "Using VPC $defaultVpc with subnets $subnetA and $subnetB"

$repoExists = $true
try {
    Invoke-Aws (Aws-Args @("ecr", "describe-repositories", "--region", $AwsRegion, "--repository-names", $RepositoryName, "--output", "json")) | Out-Null
} catch {
    if ($_.Exception.Message -notmatch "RepositoryNotFoundException") { throw }
    $repoExists = $false
}
if (-not $repoExists) {
    Invoke-Aws (Aws-Args @("ecr", "create-repository", "--region", $AwsRegion, "--repository-name", $RepositoryName, "--image-scanning-configuration", "scanOnPush=true", "--output", "json")) | Out-Null
}
$ecrUri = (Invoke-Aws (Aws-Args @("ecr", "describe-repositories", "--region", $AwsRegion, "--repository-names", $RepositoryName, "--query", "repositories[0].repositoryUri", "--output", "text"))).Trim()

$secretExists = $true
try {
    Invoke-Aws (Aws-Args @("secretsmanager", "describe-secret", "--region", $AwsRegion, "--secret-id", $DatabaseSecretName, "--output", "json")) | Out-Null
} catch {
    if ($_.Exception.Message -notmatch "ResourceNotFoundException") { throw }
    $secretExists = $false
}
if (-not $secretExists) {
    Invoke-Aws (Aws-Args @("secretsmanager", "create-secret", "--region", $AwsRegion, "--name", $DatabaseSecretName, "--description", "Provisioning staging DATABASE_URL", "--secret-string", $DatabaseUrl, "--output", "json")) | Out-Null
} else {
    Invoke-Aws (Aws-Args @("secretsmanager", "put-secret-value", "--region", $AwsRegion, "--secret-id", $DatabaseSecretName, "--secret-string", $DatabaseUrl, "--output", "json")) | Out-Null
}
$secretArn = (Invoke-Aws (Aws-Args @("secretsmanager", "describe-secret", "--region", $AwsRegion, "--secret-id", $DatabaseSecretName, "--query", "ARN", "--output", "text"))).Trim()

$login = Invoke-Aws (Aws-Args @("ecr", "get-login-password", "--region", $AwsRegion))
$login | docker login --username AWS --password-stdin $ecrUri
if ($LASTEXITCODE -ne 0) { throw "Docker ECR login failed" }

$imageTag = "staging-$((git rev-parse --short HEAD).Trim())"
$imageUri = "$ecrUri`:$imageTag"
if (-not $SkipImageBuild) {
    docker build --pull -t $imageUri .
    if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }
    docker push $imageUri
    if ($LASTEXITCODE -ne 0) { throw "Docker push failed" }
}

$parameters = @(
    "VpcId=$defaultVpc",
    "PublicSubnetA=$subnetA",
    "PublicSubnetB=$subnetB",
    "ImageUri=$imageUri",
    "DatabaseSecretArn=$secretArn",
    "KmsKeyArn=$KmsKeyArn",
    "AppleAppID=$AppleAppID",
    "AppleEnvironment=$AppleEnvironment",
    "AppleRootCertificateSecretArn=$AppleRootCertificateSecretArn",
    "AndroidPackageName=$AndroidPackageName",
    "AndroidCloudProjectNumber=$AndroidCloudProjectNumber",
    "AndroidMode=$AndroidMode",
    "AndroidServiceAccountSecretArn=$AndroidServiceAccountSecretArn"
)
Invoke-Aws (Aws-Args @("cloudformation", "deploy", "--region", $AwsRegion, "--stack-name", $StackName, "--template-file", "infra/ecs-staging.yml", "--parameter-overrides") + $parameters + @("--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset")) | Out-Host

Write-Host "Deployment complete. Outputs:"
Invoke-Aws (Aws-Args @("cloudformation", "describe-stacks", "--region", $AwsRegion, "--stack-name", $StackName, "--query", "Stacks[0].Outputs", "--output", "table")) | Out-Host
