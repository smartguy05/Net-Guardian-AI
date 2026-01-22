# NetGuardian AI - Development Environment Startup Script
# Run this script from PowerShell (as Administrator for port forwarding)

param(
    [switch]$SeedData,
    [switch]$SkipContainers,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
NetGuardian AI Development Startup Script

Usage: .\scripts\start-dev.ps1 [options]

Options:
    -SeedData       Load demo data into the database
    -SkipContainers Skip starting containers (if already running)
    -Help           Show this help message

Examples:
    .\scripts\start-dev.ps1                    # Start everything
    .\scripts\start-dev.ps1 -SeedData          # Start and load demo data
    .\scripts\start-dev.ps1 -SkipContainers    # Only start backend/frontend
"@
    exit 0
}

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  NetGuardian AI - Development Startup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Start Podman machine
if (-not $SkipContainers) {
    Write-Host "[1/6] Starting Podman machine..." -ForegroundColor Yellow
    $null = podman machine start 2>&1
    Start-Sleep -Seconds 2
}

# Step 2: Start containers via WSL
if (-not $SkipContainers) {
    Write-Host "[2/6] Starting database and Redis containers..." -ForegroundColor Yellow

    # Check if containers exist
    $existingDb = wsl -d podman-machine-default -u root -- podman ps -a --format "{{.Names}}" 2>$null | Select-String "netguardian-db"
    $existingRedis = wsl -d podman-machine-default -u root -- podman ps -a --format "{{.Names}}" 2>$null | Select-String "netguardian-redis"

    if ($existingDb) {
        Write-Host "  Starting existing netguardian-db..." -ForegroundColor Gray
        wsl -d podman-machine-default -u root -- podman start netguardian-db 2>$null
    } else {
        Write-Host "  Creating netguardian-db..." -ForegroundColor Gray
        wsl -d podman-machine-default -u root -- podman run -d --name netguardian-db `
            -e POSTGRES_USER=netguardian `
            -e POSTGRES_PASSWORD=netguardian-dev-password `
            -e POSTGRES_DB=netguardian `
            -p 5432:5432 timescale/timescaledb:latest-pg16 2>$null
    }

    if ($existingRedis) {
        Write-Host "  Starting existing netguardian-redis..." -ForegroundColor Gray
        wsl -d podman-machine-default -u root -- podman start netguardian-redis 2>$null
    } else {
        Write-Host "  Creating netguardian-redis..." -ForegroundColor Gray
        wsl -d podman-machine-default -u root -- podman run -d --name netguardian-redis `
            -p 6379:6379 redis:7-alpine 2>$null
    }

    # Wait for containers to be ready
    Start-Sleep -Seconds 5
}

# Step 3: Set up port forwarding
Write-Host "[3/6] Setting up port forwarding..." -ForegroundColor Yellow
$wslIp = wsl -d podman-machine-default -- ip addr show eth0 2>$null | Select-String "inet " | ForEach-Object { ($_ -split '\s+')[2] -replace '/.*', '' }

if ($wslIp) {
    Write-Host "  WSL IP: $wslIp" -ForegroundColor Gray

    # Remove existing rules (ignore errors)
    $null = netsh interface portproxy delete v4tov4 listenport=5432 listenaddress=127.0.0.1 2>$null
    $null = netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1 2>$null

    # Add new rules
    netsh interface portproxy add v4tov4 listenport=5432 listenaddress=127.0.0.1 connectport=5432 connectaddress=$wslIp | Out-Null
    netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=$wslIp | Out-Null

    Write-Host "  Port forwarding configured" -ForegroundColor Green
} else {
    Write-Host "  Warning: Could not get WSL IP. Port forwarding may not work." -ForegroundColor Red
}

# Step 4: Ensure backend .env exists
Write-Host "[4/6] Checking backend configuration..." -ForegroundColor Yellow
$envFile = Join-Path $ProjectRoot "backend\.env"
if (-not (Test-Path $envFile)) {
    Write-Host "  Creating backend/.env..." -ForegroundColor Gray
    @"
DATABASE_URL=postgresql+asyncpg://netguardian:netguardian-dev-password@localhost:5432/netguardian
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-change-in-production-must-be-64-chars-hex
DEBUG=true
LOG_LEVEL=DEBUG
"@ | Out-File -FilePath $envFile -Encoding utf8
}
Write-Host "  Backend configuration ready" -ForegroundColor Green

# Step 5: Run migrations
Write-Host "[5/6] Running database migrations..." -ForegroundColor Yellow
Push-Location (Join-Path $ProjectRoot "backend")
$migrationResult = & alembic upgrade head 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Migrations complete" -ForegroundColor Green
} else {
    Write-Host "  Migration output: $migrationResult" -ForegroundColor Yellow
}

# Seed data if requested
if ($SeedData) {
    Write-Host "  Loading demo data..." -ForegroundColor Gray
    python scripts/seed_demo_data.py 2>&1 | Out-Null
    Write-Host "  Demo data loaded" -ForegroundColor Green
}
Pop-Location

# Step 6: Start servers
Write-Host "[6/6] Starting servers..." -ForegroundColor Yellow

# Start backend
Write-Host "  Starting backend on port 8000..." -ForegroundColor Gray
$backendJob = Start-Job -ScriptBlock {
    param($path)
    Set-Location $path
    & uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
} -ArgumentList (Join-Path $ProjectRoot "backend")

# Start frontend
Write-Host "  Starting frontend on port 5173..." -ForegroundColor Gray
$frontendJob = Start-Job -ScriptBlock {
    param($path)
    Set-Location $path
    & npm run dev
} -ArgumentList (Join-Path $ProjectRoot "frontend")

Start-Sleep -Seconds 5

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  NetGuardian AI is running!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Frontend:  http://localhost:5173" -ForegroundColor Cyan
Write-Host "  Backend:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  API Docs:  http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
if ($SeedData) {
    Write-Host "  Demo Credentials:" -ForegroundColor Yellow
    Write-Host "    Admin:    demo_admin / DemoAdmin123!" -ForegroundColor White
    Write-Host "    Operator: demo_operator / DemoOp123!" -ForegroundColor White
    Write-Host "    Viewer:   demo_viewer / DemoView123!" -ForegroundColor White
    Write-Host ""
}
Write-Host "  Press Ctrl+C to stop all servers" -ForegroundColor Gray
Write-Host ""

# Wait for user to cancel
try {
    while ($true) {
        Start-Sleep -Seconds 1

        # Check if jobs are still running
        $backendState = (Get-Job -Id $backendJob.Id).State
        $frontendState = (Get-Job -Id $frontendJob.Id).State

        if ($backendState -eq "Failed") {
            Write-Host "Backend crashed. Output:" -ForegroundColor Red
            Receive-Job -Job $backendJob
        }
        if ($frontendState -eq "Failed") {
            Write-Host "Frontend crashed. Output:" -ForegroundColor Red
            Receive-Job -Job $frontendJob
        }
    }
} finally {
    Write-Host "`nShutting down..." -ForegroundColor Yellow
    Stop-Job -Job $backendJob -ErrorAction SilentlyContinue
    Stop-Job -Job $frontendJob -ErrorAction SilentlyContinue
    Remove-Job -Job $backendJob -ErrorAction SilentlyContinue
    Remove-Job -Job $frontendJob -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
}
