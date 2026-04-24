# VeriChain AI
**Secure Software Design — Spring 2026**  
**Assignment 3: Secure Implementation & Code Submission**

VeriChain AI is a zero-trust enterprise authentication platform that integrates Zero-Knowledge Proofs (ZKP), mutual TLS, AI-driven behavioral risk scoring, and blockchain-anchored audit trails. This project demonstrates a production-grade secure implementation based on the UMLsec designs from Deliverable 2, applying defensive programming and modular architecture.

---

## 🚀 Quick Start (One-Command Boot)

The easiest way to start the entire ecosystem (Gateway, Dashboard, AI Engine, Blockchain, and Agent) is using the Universal Orchestrator:

```powershell
# Start the entire ecosystem
powershell -File start-all.ps1
```

*This script handles certificate generation, Docker container orchestration, and launching the Desktop Agent automatically.*

---

## Architecture

```
┌─────────────────────┐     mTLS + ZKP     ┌──────────────────────────┐
│   Desktop Agent     │ ──────────────────► │   Security Gateway (PEP) │
│  (Electron + React) │                     │   (Express + TypeScript) │
└─────────────────────┘                     └────────────┬─────────────┘
                                                         │
                              ┌──────────────────────────┼────────────────────┐
                              │                          │                    │
                    ┌─────────▼────────┐   ┌────────────▼────────┐  ┌────────▼───────┐
                    │   AI Risk Engine  │   │   MongoDB + Redis   │  │  Blockchain    │
                    │   (Python/Flask)  │   │   (Audit + Sessions)│  │  (Hardhat/ETH) │
                    └──────────────────┘   └─────────────────────┘  └────────────────┘
                                                         │
                                            ┌────────────▼────────────┐
                                            │    Trust Dashboard      │
                                            │   (React + Socket.io)   │
                                            └─────────────────────────┘
```

### 🛠 Modular Architecture & Design

VeriChain AI follows a **Separation of Concerns (SoC)** principle across its modular packages:
- **`packages/gateway`**: The **Policy Enforcement Point (PEP)**. Handles mTLS, validation, and coordination.
- **`packages/ai-engine`**: The **Risk Engine**. Isolated Python service for ML-based anomaly detection.
- **`packages/contracts`**: The **Root of Trust**. Solidity contracts for immutable policy and audit anchoring.
- **`packages/desktop-agent`**: The **Prover**. Secure Electron client for ZKP and telemetry.
- **`packages/trust-dashboard`**: The **Auditor**. Real-time administrative monitoring.

### Components

| Package | Description | Tech |
|---|---|---|
| `packages/desktop-agent` | Electron app — ZKP authentication client | Electron 28, React 18, Vite, TypeScript |
| `packages/gateway` | Security Policy Enforcement Point | Express 4, TypeScript, mTLS, Zod, Redis |
| `packages/ai-engine` | Behavioral risk scoring microservice | Python 3.11, Flask, scikit-learn (Isolation Forest) |
| `packages/contracts` | On-chain session registry and access policy | Solidity 0.8.20, Hardhat, OpenZeppelin |
| `packages/trust-dashboard` | Admin monitoring dashboard | React 18, CRA, Recharts, Socket.io |

---

## Security Features

| Feature | Implementation |
|---|---|
| **Zero-Knowledge Proof auth** | Groth16 circuit (BN128) via snarkjs — proves identity without revealing secrets |
| **Mutual TLS (mTLS)** | All gateway traffic requires a valid client certificate signed by the internal CA |
| **AI Risk Scoring** | Isolation Forest detects behavioral anomalies (access velocity, device mismatch) |
| **Blockchain Audit Trail** | Every access decision is hashed into a Merkle tree and anchored to Ethereum |
| **Multi-Sig Policy Changes** | Access policy updates require 2-of-3 admin signatures via `AccessPolicy.sol` |
| **Nonce-based replay protection** | One-time nonces stored in Redis and burned on use |
| **Rate limiting** | Redis-backed per-IP rate limiting on `/auth/nonce`, `/auth/login`, `/heartbeat` |
| **Input validation** | Zod schema validation on all gateway endpoints |
| **Session heartbeat watchdog** | Inactive sessions auto-revoked after TTL expires |
| **Tamper detection** | Real-time Merkle root comparison — mismatches trigger `tamper_alert` via WebSocket |

---

## Prerequisites

- **Docker** ≥ 24 and **Docker Compose** ≥ 2.20
- **Node.js** ≥ 18.0
- **Python** ≥ 3.11
- **Hardhat** (installed via npm)

---

## Quick Start (Docker)

```bash
# 1. Clone and enter the repo
git clone <repo-url> && cd verichain-ai

# 2. Copy env template and fill in values
cp .env.example .env

# 3. Generate TLS certificates (dev only)
bash scripts/gen-certs.sh

# 4. Start all services
docker compose up --build

# Services:
#   Gateway      → https://localhost:8443
#   Trust Dashboard → http://localhost:3001
#   AI Engine    → http://localhost:5001 (internal)
#   MongoDB      → localhost:27017 (internal)
#   Redis        → localhost:6379 (internal)
```

---

## Manual Development Setup

### 1. Install root dependencies
```bash
npm install
```

### 2. Security Gateway
```bash
cd packages/gateway
npm install
cp .env.example .env   # fill in MONGODB_URI, REDIS_URL, etc.
npm run dev
```

### 3. Desktop Agent
```bash
cd packages/desktop-agent
npm install
npm run dev            # starts Vite dev server on :3000 + Electron
```

### 4. Trust Dashboard
```bash
cd packages/trust-dashboard
npm install
npm start              # CRA dev server on :3001
```

### 5. AI Risk Engine
```bash
cd packages/ai-engine
pip install -r requirements.txt
python app.py
```

### 6. Blockchain (local Hardhat node)
```bash
cd packages/contracts
npm install
npx hardhat node       # starts local chain on :8545
npx hardhat run scripts/deploy.js --network localhost
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_PORT` | `8443` | HTTPS port for the gateway |
| `MONGODB_URI` | `mongodb://mongodb:27017/verichain` | MongoDB connection string |
| `REDIS_URL` | `redis://redis:6379` | Redis connection URL |
| `BLOCKCHAIN_RPC` | `http://localhost:8545` | JSON-RPC endpoint for Hardhat/Ethereum |
| `GATEWAY_KEY_PATH` | `./certs/gateway.key` | Path to gateway private key |
| `GATEWAY_CERT_PATH` | `./certs/gateway.crt` | Path to gateway certificate |
| `CA_CERT_PATH` | `./certs/ca.crt` | Path to CA certificate (for mTLS) |
| `TRUST_DASHBOARD_ORIGIN` | `http://localhost:3001` | Allowed CORS origin for Socket.io |
| `AI_ENGINE_URL` | `http://ai-engine:5001` | Internal AI microservice URL |
| `HMAC_SECRET` | — | Shared secret for AI engine request signing |
| `REACT_APP_GATEWAY_URL` | `https://localhost:8443` | Gateway URL used by frontends |

---

## API Reference

### Authentication (Sequence 1)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/auth/nonce` | Request a one-time nonce (`?clientId=<id>`) |
| `POST` | `/api/auth/login` | Submit ZKP proof and receive a session ID |

### Resource Access (Sequence 2)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/resource/access` | Request access to a protected resource |

### Session Heartbeat (Sequence 3)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/heartbeat` | Keepalive ping — updates session TTL |

### Admin

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/overview` | List all active sessions |
| `POST` | `/api/admin/revoke` | Revoke a session by ID |
| `GET` | `/api/admin/audit-logs` | Fetch audit log entries |
| `GET` | `/api/admin/pending-policies` | List pending multi-sig proposals |
| `POST` | `/api/admin/propose-policy` | Propose a GRANT/REVOKE policy change |
| `POST` | `/api/admin/approve` | Sign and approve a pending proposal |

---

## Testing

```bash
# Smart contract tests
cd packages/contracts && npx hardhat test

# Gateway type-check
cd packages/gateway && npm run build

# Desktop agent type-check
cd packages/desktop-agent && npx tsc --noEmit
```

---

## Project Structure

```
verichain-ai/
├── packages/
│   ├── desktop-agent/          Electron + React client
│   │   ├── src/main/           Main process (IPC, mTLS, ZKP)
│   │   └── src/renderer/       React UI (Vite)
│   ├── gateway/                Express security gateway
│   │   ├── src/controllers/    Route handlers
│   │   ├── src/middleware/     mTLS, validation, rate limiting
│   │   ├── src/services/       Redis, blockchain, AI, session, audit
│   │   └── src/routes/         API router with Zod schemas
│   ├── ai-engine/              Python Flask risk scoring
│   ├── contracts/              Solidity smart contracts + Hardhat
│   └── trust-dashboard/        React admin dashboard
├── nginx/                      Reverse proxy config
├── docker-compose.yml          Production compose
├── docker-compose.dev.yml      Development compose
└── .github/workflows/          CI/CD pipeline
```

---

## License

Academic project — Secure Software Design, Semester 6.
