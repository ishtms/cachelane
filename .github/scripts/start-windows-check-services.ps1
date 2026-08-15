$ErrorActionPreference = "Stop"

$postgresService = "postgresql-x64-17"
$postgresPassword = "root"
$testDatabase = "faultlane_test"
$browserDatabase = "faultlane_browser"
$minioVersion = "RELEASE.2025-09-07T16-13-09Z"
$minioSha256 = "af709e6ba68488404e85acdd22a3030d0f5e56a108d4b27d744f18ceb50861b4"
$minioEndpoint = "http://127.0.0.1:59020"
$minioRootUser = "faultlane"
$minioRootPassword = "faultlane_dev_only"

Set-Service -Name $postgresService -StartupType Manual
Start-Service -Name $postgresService

$env:PGPASSWORD = $postgresPassword
foreach ($database in @($testDatabase, $browserDatabase)) {
    $existing = (& "$env:PGBIN\psql.exe" -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$database'" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "failed to inspect PostgreSQL databases"
    }
    if ($existing -ne "1") {
        & "$env:PGBIN\createdb.exe" -U postgres $database
        if ($LASTEXITCODE -ne 0) {
            throw "failed to create PostgreSQL database"
        }
    }
}

$minioDirectory = Join-Path $env:RUNNER_TEMP "faultlane-minio"
$minioPath = Join-Path $minioDirectory "minio.exe"
$minioData = Join-Path $minioDirectory "data"
New-Item -ItemType Directory -Force -Path $minioData | Out-Null

$minioUrl = "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.$minioVersion"
Invoke-WebRequest -Uri $minioUrl -OutFile $minioPath
$actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $minioPath).Hash.ToLowerInvariant()
if ($actualSha256 -ne $minioSha256) {
    throw "downloaded MinIO binary has an unexpected SHA-256"
}

$env:MINIO_ROOT_USER = $minioRootUser
$env:MINIO_ROOT_PASSWORD = $minioRootPassword
Start-Process `
    -FilePath $minioPath `
    -ArgumentList "server", $minioData, "--address", "127.0.0.1:59020", "--console-address", "127.0.0.1:59021" `
    -WindowStyle Hidden

$minioReady = $false
for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
    try {
        Invoke-WebRequest -Uri "$minioEndpoint/minio/health/live" -UseBasicParsing | Out-Null
        $minioReady = $true
        break
    }
    catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $minioReady) {
    throw "MinIO did not become ready"
}

$environment = @(
    "FAULTLANE_TEST_DATABASE_URL=postgres://postgres:$postgresPassword@127.0.0.1:5432/$testDatabase"
    "FAULTLANE_BROWSER_EXTERNAL_DATABASE_URL=postgres://postgres:$postgresPassword@127.0.0.1:5432/$browserDatabase"
    "FAULTLANE_BROWSER_EXTERNAL_OBJECT_STORE_ENDPOINT=$minioEndpoint"
    "FAULTLANE_BROWSER_EXTERNAL_OBJECT_STORE_BUCKET=faultlane-browser"
)
$environment | Add-Content -LiteralPath $env:GITHUB_ENV

Write-Host "Windows check services are ready"
