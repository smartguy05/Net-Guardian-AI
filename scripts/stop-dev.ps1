# NetGuardian AI - Stop Development Environment
# Stops all servers and optionally containers

param(
    [switch]$StopContainers,
    [switch]$CleanPortForwarding
)

Write-Host "Stopping NetGuardian AI..." -ForegroundColor Yellow

# Kill backend (uvicorn)
$uvicornProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*uvicorn*" -or $_.CommandLine -like "*app.main*"
}
if ($uvicornProcesses) {
    $uvicornProcesses | Stop-Process -Force
    Write-Host "  Backend stopped" -ForegroundColor Green
}

# Kill frontend (node/vite)
$nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*vite*"
}
if ($nodeProcesses) {
    $nodeProcesses | Stop-Process -Force
    Write-Host "  Frontend stopped" -ForegroundColor Green
}

# Stop any processes on ports 5173 and 8000
$portsToKill = @(5173, 8000)
foreach ($port in $portsToKill) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

# Stop containers if requested
if ($StopContainers) {
    Write-Host "  Stopping containers..." -ForegroundColor Gray
    wsl -d podman-machine-default -u root -- podman stop netguardian-db netguardian-redis 2>$null
    Write-Host "  Containers stopped" -ForegroundColor Green
}

# Clean port forwarding if requested
if ($CleanPortForwarding) {
    Write-Host "  Removing port forwarding rules..." -ForegroundColor Gray
    netsh interface portproxy delete v4tov4 listenport=5432 listenaddress=127.0.0.1 2>$null
    netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1 2>$null
    Write-Host "  Port forwarding removed" -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Green
