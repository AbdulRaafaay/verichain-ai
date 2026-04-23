# VeriChain AI Unified Startup Script
# Usage: powershell -File start-all.ps1

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "VeriChain AI: Universal Startup Orchestrator" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Certificate Generation
Write-Host "`n[1/5] Checking Certificates..." -ForegroundColor Yellow
if (-not (Test-Path "certs\gateway-cert.pem")) {
    Write-Host "Certificates missing. Generating..." -ForegroundColor Gray
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        # Create certs directory if it doesn't exist
        if (-not (Test-Path "certs")) { New-Item -ItemType Directory -Path "certs" }
        
        # Simple OpenSSL generation for Windows compatibility
        openssl genrsa -out certs/ca-key.pem 2048
        openssl req -new -x509 -nodes -days 365 -key certs/ca-key.pem -out certs/ca-cert.pem -subj "/CN=VeriChainCA"
        
        openssl genrsa -out certs/gateway-key.pem 2048
        openssl req -new -key certs/gateway-key.pem -out certs/gateway-csr.pem -subj "/CN=localhost"
        openssl x509 -req -in certs/gateway-csr.pem -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/gateway-cert.pem -days 365
        
        Write-Host "Certificates generated successfully." -ForegroundColor Green
    } else {
        Write-Error "OpenSSL not found! Please install OpenSSL or Git Bash."
    }
} else {
    Write-Host "Certificates already exist. Skipping." -ForegroundColor Green
}

# 1.5. AI Model Dummy (Integrity Check)
Write-Host "`n[1.5/5] Checking AI Model Integrity Placeholder..." -ForegroundColor Yellow
if (-not (Test-Path "packages\ai-engine\model.pkl")) {
    Write-Host "AI model placeholder missing. Generating dummy..." -ForegroundColor Gray
    "VeriChain AI Mock Model" | Set-Content "packages\ai-engine\model.pkl"
    Write-Host "Model placeholder generated." -ForegroundColor Green
} else {
    Write-Host "Model placeholder exists." -ForegroundColor Green
}

# 2. Infrastructure
Write-Host "`n[2/5] Starting Infrastructure (Docker)..." -ForegroundColor Yellow
docker-compose up -d
Write-Host "Docker containers are running." -ForegroundColor Green

# 3. Smart Contracts
Write-Host "`n[3/5] Deploying Smart Contracts..." -ForegroundColor Yellow
Set-Location packages/contracts
npm install
npx hardhat run scripts/deploy.js --network localhost
Set-Location ../..
Write-Host "Contracts deployed." -ForegroundColor Green

# 4. Service Dependencies
Write-Host "`n[4/5] Installing Dependencies..." -ForegroundColor Yellow
npm install --workspaces
Write-Host "Dependencies installed." -ForegroundColor Green

# 5. Launch Services
Write-Host "`n[5/5] Launching Services..." -ForegroundColor Yellow

# Launch Gateway
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location packages/gateway; npm run dev" -WindowStyle Normal
Write-Host "-> Security Gateway starting..." -ForegroundColor Gray

# Launch Dashboard
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location packages/trust-dashboard; npm start" -WindowStyle Normal
Write-Host "-> Trust Dashboard starting..." -ForegroundColor Gray

# Launch Desktop Agent
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location packages/desktop-agent; npm start" -WindowStyle Normal
Write-Host "-> Desktop Agent starting..." -ForegroundColor Gray

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host "SYSTEM INITIALIZED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Gateway: https://localhost:8443/health"
Write-Host "Dashboard: http://localhost:3000"
Write-Host "=============================================" -ForegroundColor Green
