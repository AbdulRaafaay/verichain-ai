# VeriChain AI Unified Startup Script
# Usage: powershell -File start-all.ps1

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "VeriChain AI: Universal Startup Orchestrator" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Certificate Generation
Write-Host "`n[1/5] Regenerating Certificates (Deep Dive Mode)..." -ForegroundColor Yellow
# Remove old certs to ensure fresh ones
if (Test-Path "certs") { Remove-Item -Recurse -Force "certs" }
New-Item -ItemType Directory -Path "certs"

if (Get-Command openssl -ErrorAction SilentlyContinue) {
    Write-Host "Using local OpenSSL..." -ForegroundColor Gray
    # 1. CA
    openssl genrsa -out certs/ca.key 2048
    openssl req -new -x509 -nodes -days 365 -key certs/ca.key -out certs/ca.crt -subj "/CN=VeriChainCA"
    # 2. Gateway
    openssl genrsa -out certs/gateway.key 2048
    openssl req -new -key certs/gateway.key -out certs/gateway.csr -subj "/CN=localhost"
    openssl x509 -req -in certs/gateway.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/gateway.crt -days 365
    # 3. Client
    openssl genrsa -out certs/client.key 2048
    openssl req -new -key certs/client.key -out certs/client.csr -subj "/CN=desktop-agent"
    openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 365
} else {
    Write-Host "Using Docker OpenSSL..." -ForegroundColor Gray
    # We use --entrypoint sh because the image defaults to 'openssl'
    docker run --rm -v "${PWD}:/export" --entrypoint sh alpine/openssl -c "
        openssl genrsa -out /export/certs/ca.key 2048 && \
        openssl req -new -x509 -nodes -days 365 -key /export/certs/ca.key -out /export/certs/ca.crt -subj '/CN=VeriChainCA' && \
        openssl genrsa -out /export/certs/gateway.key 2048 && \
        openssl req -new -key /export/certs/gateway.key -out /export/certs/gateway.csr -subj '/CN=localhost' && \
        openssl x509 -req -in /export/certs/gateway.csr -CA /export/certs/ca.crt -CAkey /export/certs/ca.key -CAcreateserial -out /export/certs/gateway.crt -days 365 && \
        openssl genrsa -out /export/certs/client.key 2048 && \
        openssl req -new -key /export/certs/client.key -out /export/certs/client.csr -subj '/CN=desktop-agent' && \
        openssl x509 -req -in /export/certs/client.csr -CA /export/certs/ca.crt -CAkey /export/certs/ca.key -CAcreateserial -out /export/certs/client.crt -days 365
    "
}
Write-Host "Certificates regenerated." -ForegroundColor Green

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
Write-Host "`n[2/5] Starting Infrastructure (MongoDB, Redis, Blockchain, AI Engine)..." -ForegroundColor Yellow

# Clean up existing state to prevent "stuck" containers, port locks, or stale database volumes
Write-Host "Cleaning up previous Docker state (including volumes for fresh auth)..." -ForegroundColor Gray
$oldPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose down -v --remove-orphans 2>$null
docker compose stop gateway trust-dashboard nginx 2>$null
$ErrorActionPreference = $oldPreference

Write-Host "Launching background containers..." -ForegroundColor Gray
docker compose up -d mongodb redis blockchain
docker compose up -d --build ai-engine
Start-Sleep -Seconds 5
Write-Host "Infrastructure is running." -ForegroundColor Green

# 2.5. Service Dependencies
Write-Host "`n[2.5/5] Installing Dependencies (this may take 1-2 minutes)..." -ForegroundColor Yellow
Write-Host "Running 'npm install'..." -ForegroundColor Gray
npm install --no-audit --no-fund
Write-Host "Dependencies installed successfully." -ForegroundColor Green

# 3. Smart Contracts
Write-Host "`n[3/5] Deploying Smart Contracts..." -ForegroundColor Yellow
# Wait for blockchain container to be ready (port 8545)
Write-Host "Waiting for blockchain node at 127.0.0.1:8545..." -ForegroundColor Gray
$maxRetries = 30
$retryCount = 0
while ($retryCount -lt $maxRetries) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $connect = $tcp.BeginConnect("127.0.0.1", 8545, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne(500, $false)
    if ($wait -and $tcp.Connected) {
        $tcp.Close()
        break
    }
    $tcp.Close()
    Start-Sleep -Seconds 1
    $retryCount++
}

Set-Location packages/contracts
try {
    npx hardhat run scripts/deploy.js --network localhost
} catch {
    Write-Warning "Hardhat deployment failed. Ensure the blockchain container is healthy and all dependencies are installed."
    throw $_
}
Set-Location ../..

# READ DEPLOYED ADDRESSES
if (Test-Path "packages/contracts/deployment.json") {
    $deployData = Get-Content "packages/contracts/deployment.json" | ConvertFrom-Json
    $ACCESS_POLICY_ADDRESS = $deployData.accessPolicy
    $AUDIT_LEDGER_ADDRESS = $deployData.auditLedger
    Write-Host "Contracts deployed at: $ACCESS_POLICY_ADDRESS, $AUDIT_LEDGER_ADDRESS" -ForegroundColor Green
} else {
    Write-Error "Deployment failed! deployment.json not found."
}

# 4. Calculate mTLS Fingerprint
Write-Host "`n[4/5] Calculating mTLS Certificate Fingerprint..." -ForegroundColor Yellow

$fingerprintRaw = ""
if (Get-Command openssl -ErrorAction SilentlyContinue) {
    $fingerprintRaw = openssl x509 -noout -fingerprint -sha256 -in certs/gateway.crt
} else {
    Write-Host "Local OpenSSL not found. Using Docker to calculate fingerprint..." -ForegroundColor Gray
    # Use alpine/openssl to calculate fingerprint
    # Note: Using forward slashes for the internal path
    $fingerprintRaw = docker run --rm -v "${PWD}:/export" alpine/openssl x509 -noout -fingerprint -sha256 -in /export/certs/gateway.crt
}

# Format: SHA256 Fingerprint=AA:BB:CC... -> AABBCC...
if ($fingerprintRaw -match "SHA256 Fingerprint=(.*)") {
    $GATEWAY_FINGERPRINT = $matches[1].Replace(":", "").ToUpper().Trim()
    Write-Host "Fingerprint: $GATEWAY_FINGERPRINT" -ForegroundColor Green
} else {
    Write-Warning "Failed to calculate fingerprint. mTLS Pinning will be Disabled."
    $GATEWAY_FINGERPRINT = ""
}

# 5. Launch Services
Write-Host "`n[5/5] Launching Services..." -ForegroundColor Yellow

# Load secrets from .env — fail fast on missing keys or unfilled CHANGE_ME placeholders
if (-not (Test-Path ".env")) {
    Write-Error "`n.env not found. Copy .env.example to .env and fill in all CHANGE_ME values."
    exit 1
}
$envData = Get-Content ".env"

function Read-EnvKey {
    param([string]$keyName, [bool]$required = $true)
    $line = $envData | Select-String "^${keyName}=" | Select-Object -First 1
    if ($null -eq $line) {
        if ($required) {
            Write-Error "`nMissing required env key: ${keyName}. Add it to .env and re-run."
            exit 1
        }
        return $null
    }
    $value = $line.ToString().Split("=", 2)[1].Trim()
    if ($required -and ($value -eq "" -or $value -like "CHANGE_ME*")) {
        Write-Error "`nEnv key '${keyName}' is unset or still has the default CHANGE_ME placeholder."
        exit 1
    }
    return $value
}

$REDIS_PASS     = Read-EnvKey "REDIS_PASSWORD"
$MONGO_PASS     = Read-EnvKey "MONGO_ROOT_PASSWORD"
$AI_HMAC_SECRET = Read-EnvKey "AI_HMAC_SECRET"
$ADMIN_API_KEY  = Read-EnvKey "ADMIN_API_KEY"
$MONGO_USER     = Read-EnvKey "MONGO_ROOT_USER" $false
if ([string]::IsNullOrEmpty($MONGO_USER)) { $MONGO_USER = "admin" }

# Launch Gateway
# We must use 127.0.0.1 and include passwords
$rootPath = Get-Location
$certKey = Join-Path $rootPath "certs\gateway.key"
$certCrt = Join-Path $rootPath "certs\gateway.crt"
$caCrt = Join-Path $rootPath "certs\ca.crt"

# Use the new exposed ports and explicitly force direct connection for Docker
$ENCODED_MONGO_PASS = [uri]::EscapeDataString($MONGO_PASS)
$ENCODED_REDIS_PASS = [uri]::EscapeDataString($REDIS_PASS)

$MONGODB_URI_LOCAL = "mongodb://${MONGO_USER}:${ENCODED_MONGO_PASS}@127.0.0.1:27020/verichain?authSource=admin&directConnection=true"
$REDIS_URL_LOCAL = "redis://:${ENCODED_REDIS_PASS}@127.0.0.1:6380"

Write-Host "`nWaiting for MongoDB (Port 27020) and Redis (Port 6380) to wake up..." -ForegroundColor Gray
$services = @{ "MongoDB" = 27020; "Redis" = 6380 }
foreach ($svc in $services.GetEnumerator()) {
    $retry = 0
    while ($retry -lt 45) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $connect = $tcp.BeginConnect("127.0.0.1", $svc.Value, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne(500, $false)
            if ($wait -and $tcp.Connected) {
                $tcp.Close()
                Write-Host "$($svc.Key) is UP and accepting connections!" -ForegroundColor Green
                break
            }
        } catch {}
        if ($tcp) { $tcp.Close() }
        Start-Sleep -Seconds 1
        $retry++
    }
    if ($retry -eq 45) {
        Write-Error "`n$($svc.Key) failed to bind to port $($svc.Value)! The container likely crashed."
        Write-Error "Please open a terminal and run: docker logs verichain-ai-$($svc.Key.ToLower())-1"
        exit 1
    }
}

Write-Host "Debug: MONGO_USER='$MONGO_USER'" -ForegroundColor Gray
Write-Host "Debug: MONGO_PASS_LEN=$($MONGO_PASS.Length)" -ForegroundColor Gray
Write-Host "Gateway using DB: $($MONGODB_URI_LOCAL.Replace($ENCODED_MONGO_PASS, '****'))" -ForegroundColor Gray
Write-Host "Gateway using Redis: $($REDIS_URL_LOCAL.Replace($ENCODED_REDIS_PASS, '****'))" -ForegroundColor Gray

Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:ACCESS_POLICY_ADDRESS='$ACCESS_POLICY_ADDRESS';`$env:AUDIT_LEDGER_ADDRESS='$AUDIT_LEDGER_ADDRESS';`$env:GATEWAY_PRIVATE_KEY='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';`$env:BLOCKCHAIN_RPC='http://127.0.0.1:8545';`$env:MONGODB_URI='$MONGODB_URI_LOCAL';`$env:REDIS_URL='$REDIS_URL_LOCAL';`$env:AI_ENGINE_URL='http://127.0.0.1:5001';`$env:AI_HMAC_SECRET='$AI_HMAC_SECRET';`$env:ADMIN_API_KEY='$ADMIN_API_KEY';`$env:TRUST_DASHBOARD_ORIGIN='http://localhost:3005';`$env:GATEWAY_KEY_PATH='$certKey';`$env:GATEWAY_CERT_PATH='$certCrt';`$env:CA_CERT_PATH='$caCrt';Set-Location packages/gateway; npm run dev" -WindowStyle Normal
Write-Host "-> Security Gateway starting..." -ForegroundColor Gray

# Launch Dashboard
# Set PORT=3005 to avoid conflict with Desktop Agent (Vite) on 3000
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PORT='3005';`$env:REACT_APP_GATEWAY_URL='https://localhost:8443';`$env:REACT_APP_ADMIN_API_KEY='$ADMIN_API_KEY';Set-Location packages/trust-dashboard; npm start" -WindowStyle Normal
Write-Host "-> Trust Dashboard starting on port 3005..." -ForegroundColor Gray

# Launch Desktop Agent — also receives ADMIN_API_KEY so System Status can call /admin/system-status
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:GATEWAY_FINGERPRINT='$GATEWAY_FINGERPRINT';`$env:GATEWAY_CERT_PATH='$certCrt';`$env:REACT_APP_GATEWAY_URL='https://localhost:8443';`$env:ADMIN_API_KEY='$ADMIN_API_KEY';Set-Location packages/desktop-agent; npm start" -WindowStyle Normal
Write-Host "-> Desktop Agent starting..." -ForegroundColor Gray

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host "SYSTEM INITIALIZED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Gateway:   https://localhost:8443/health"
Write-Host "Dashboard: http://localhost:3005"
Write-Host "Agent:     (Starting in new window)"
Write-Host "=============================================" -ForegroundColor Green
