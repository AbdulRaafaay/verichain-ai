# VeriChain AI
**Secure Software Design — Spring 2026**  
**Assignment 3: Secure Implementation & Code Submission**

VeriChain AI is a zero-trust enterprise authentication platform integrating Zero-Knowledge Proofs (ZKP), mutual TLS (mTLS), AI-driven behavioral risk scoring via Isolation Forest, and blockchain-anchored audit trails. Every design decision maps directly to the UMLsec threat model from Deliverable 2.

---

## Quick Start

```powershell
powershell -File start-all.ps1
```

That is the only command needed. The script generates TLS certificates, starts all Docker containers (MongoDB, Redis, AI Engine, Blockchain node), deploys contracts, launches Trust-Dashboard, Gateway, and the Desktop Agent automatically.

---

## Architecture

```
┌─────────────────────┐     mTLS + ZKP     ┌──────────────────────────┐
│   Desktop Agent     │ ──────────────────► │   Security Gateway (PEP) │
│  (Electron + React) │                     │   (Express + TypeScript) │
└─────────────────────┘                     └────────────┬─────────────┘
                                                         │
                         ┌───────────────────────────────┼──────────────────────┐
                         │                               │                      │
               ┌─────────▼────────┐        ┌────────────▼────────┐  ┌──────────▼─────┐
               │  AI Risk Engine   │        │  MongoDB + Redis     │  │  Blockchain     │
               │  (Python/Flask)   │        │  (Audit + Sessions) │  │  (Hardhat/ETH)  │
               └──────────────────┘        └─────────────────────┘  └────────────────┘
                                                         │
                                            ┌────────────▼────────────┐
                                            │    Trust Dashboard       │
                                            │  (React + Socket.io)    │
                                            └─────────────────────────┘
```

### Packages

| Package | Role | Tech Stack |
|---|---|---|
| `packages/desktop-agent` | ZKP authentication client | Electron 28, React 18, Vite, TypeScript |
| `packages/gateway` | Policy Enforcement Point (PEP) | Express 4, TypeScript, mTLS, Zod, Redis |
| `packages/ai-engine` | Behavioral risk scoring | Python 3.11, Flask, scikit-learn (Isolation Forest) |
| `packages/contracts` | On-chain session registry & access policy | Solidity 0.8.20, Hardhat, OpenZeppelin |
| `packages/trust-dashboard` | Admin monitoring dashboard | React 18, CRA, Recharts, Socket.io |

---

## Component Overview

### Desktop Agent (`packages/desktop-agent`)

An Electron application that acts as the cryptographic prover. On first run it generates an Ed25519 key pair stored encrypted via `electron.safeStorage` (OS-level TPM/Keychain). Authentication follows three IPC-driven steps:

1. **Nonce fetch** — calls `GET /api/auth/nonce?clientId=<id>` to obtain a server-issued one-time nonce
2. **ZKP generation** — uses snarkjs (Groth16/BN128 circuit) to prove knowledge of the private key without transmitting it; the nonce is embedded in the circuit public input preventing replay
3. **Login** — submits the proof to `POST /api/auth/login`; on success stores the session UUID

The renderer UI exposes telemetry sliders (access velocity, context drift) for demo purposes. The `resource:access` IPC handler converts slider values into session metadata flags (`simulateAnomaly`, `simulateStepUp`) that the AI Engine interprets to produce reproducible risk scores during demos.

### Security Gateway (`packages/gateway`)

The Express server is the sole entry point for all agent traffic. Every layer is a distinct security control:

- **mTLS** — `https.createServer` with `requestCert: true`; the `mtlsVerify` middleware rejects any connection that lacks a valid CA-signed client certificate (health endpoint exempt)
- **Zod validation** — all request bodies and query strings pass through schema validators before reaching any controller; malformed input returns `400` before business logic runs
- **Rate limiting** — Redis-backed sliding-window limiter per IP; nonce endpoint capped at 20 req/min, login at 10 req/min
- **Admin auth** — all `/api/admin/*` routes protected by `requireAdmin` middleware using `crypto.timingSafeEqual` against `ADMIN_API_KEY`; fails closed if env var absent
- **CORS** — explicit origin allowlist (`TRUST_DASHBOARD_ORIGIN`); localhost variants permitted in development only

After login, the gateway orchestrates every access decision: calls the AI Engine (HMAC-signed), queries the on-chain `AccessPolicy.sol`, writes an audit log to MongoDB, and broadcasts real-time updates via Socket.io.

### AI Risk Engine (`packages/ai-engine`)

A Flask microservice that runs an **Isolation Forest** anomaly detector:

**Training (startup):** Synthetic baseline telemetry is generated to represent normal user behavior:
- `accessVelocity` ~ N(5, 2) — typical 5 requests/min
- `contextDrift` ~ N(1.0, 0.5) — small environment variation
- `requestFrequency` ~ N(3, 1)
- `timeOfDayScore` ~ N(0.7, 0.2)

`IsolationForest(n_estimators=100, contamination=0.05)` is trained on 1,000 synthetic normal samples. Contamination of 5% sets the anomaly threshold so roughly 1 in 20 training samples would be flagged, calibrated to real-world anomaly rates.

**Scoring (per request):**
1. The gateway calls `POST /score` with a JSON telemetry payload, authenticated via `X-HMAC-Signature: HMAC-SHA256(body, HMAC_SECRET)`
2. The engine validates the HMAC, extracts the four features, and runs `model.decision_function([features])`
3. The raw decision value (typically −0.2 to +0.2) is linearly mapped to 0–100: `score = clip((−raw + threshold) / scale × 100, 0, 100)`
4. Values above 75 → `REVOKE`; 50–75 → `STEP_UP` (re-authentication challenge); below 50 → `PERMIT`

Model file integrity is verified at startup via SHA-256 against the `MODEL_HASH` environment variable, preventing supply-chain substitution.

**Demo simulation:** If the gateway session metadata includes `simulateAnomaly: true`, the engine returns a fixed score of 92 (triggers REVOKE). `simulateStepUp: true` returns 65 (triggers STEP_UP). Normal desktop access with velocity=0 and drift=0 flows through the real Isolation Forest and consistently returns ≤50 (PERMIT).

### Smart Contracts (`packages/contracts`)

Two Solidity contracts deployed to the local Hardhat node:

**`AuditLedger.sol`** — append-only audit trail. `logEvent(bytes32 merkleRoot)` records Merkle roots on-chain. The `MerkleRootAnchored` event is indexed and queried by the gateway. Only addresses with `LOGGER_ROLE` (the gateway) can write.

**`AccessPolicy.sol`** — multi-signature access control registry. Policy changes (GRANT/REVOKE) require 2-of-3 admin approvals:
- `proposeChange(bytes32 changeHash)` — recorded on-chain
- `approveChange(...)` — increments approval counter; executes atomically at threshold 2
- `createSession(bytes32 sessionId, bytes32 userHash)` — called by the gateway after login; `SessionCreated` event emitted
- `checkAccess(bytes32 userHash, bytes32 resourceHash)` — view function queried on every access request

All contracts follow the Checks-Effects-Interactions (CEI) pattern and use OpenZeppelin `AccessControl` for role-based permissions.

### Merkle Audit Service (`packages/gateway/src/services/merkle.service.ts`)

Runs a 60-second batch cycle:
1. Queries all un-anchored `AuditLog` documents from MongoDB
2. SHA-256 hashes each document's canonical JSON representation
3. Builds a `merkletreejs` Merkle tree from the leaf hashes
4. Submits the root to `AuditLedger.sol` via `logEvent(root)`
5. Marks all included logs `anchored: true` and stores the root
6. **Tamper check** — immediately re-computes the root from the same logs and compares to the on-chain value; any mismatch emits `tamper_alert` via Socket.io and broadcasts a `TamperDetected` blockchain event
7. Emits `merkle_anchor` Socket.io event with `{ rootHash, blockNumber, logCount, timestamp, status }`

### Trust Dashboard (`packages/trust-dashboard`)

A React single-page application that connects to the gateway via both HTTP (shared `api` axios instance with `X-Admin-Key` header) and Socket.io for real-time push. Pages:

| Page | Data Source |
|---|---|
| Overview | `stats_update` socket + `/api/admin/overview` polling |
| Sessions | `session_update` / `session_revoked` socket + `/api/admin/overview` |
| Audit Logs | `/api/admin/audit-logs` |
| Merkle Chain | `merkle_anchor` socket + `/api/admin/blockchain-events` |
| Blockchain | `blockchain_event` socket + `/api/admin/blockchain-events` |
| Policy Manager | `/api/admin/pending-policies`, `/api/admin/propose-policy`, `/api/admin/approve` |
| Analytics | `/api/admin/audit-logs` (aggregated charting) |

---

## Security Features

| Feature | Implementation |
|---|---|
| Zero-Knowledge Proof auth | Groth16/BN128 via snarkjs — proves identity without transmitting secrets |
| Mutual TLS | All agent↔gateway traffic requires a valid CA-signed client certificate |
| AI Risk Scoring | Isolation Forest anomaly detection on four behavioral telemetry features |
| Blockchain Audit Trail | SHA-256 Merkle tree rooted on Ethereum every 60 seconds |
| Tamper Detection | Root recomputed post-anchor; mismatch triggers real-time dashboard alert |
| Multi-Sig Policy | GRANT/REVOKE changes require 2-of-3 admin signatures on-chain |
| Replay Protection | One-time nonces stored in Redis with 5-minute TTL, burned on use |
| Rate Limiting | Redis sliding-window per-IP limits on nonce, login, and heartbeat |
| Input Validation | Zod schemas on all endpoints — rejects before business logic |
| Admin Authentication | `X-Admin-Key` with `crypto.timingSafeEqual`; fails closed if env var unset |
| Key Protection | `electron.safeStorage` OS encryption; private key zeroed from memory after use |
| Body Size Limit | `express.json({ limit: '10kb' })` — prevents JSON bomb DoS |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_PORT` | `8443` | HTTPS port for the gateway |
| `MONGODB_URI` | `mongodb://mongodb:27017/verichain` | MongoDB connection string |
| `REDIS_URL` | `redis://redis:6379` | Redis connection URL |
| `BLOCKCHAIN_RPC` | `http://localhost:8545` | Hardhat/Ethereum JSON-RPC endpoint |
| `GATEWAY_KEY_PATH` | `./certs/gateway.key` | Gateway TLS private key |
| `GATEWAY_CERT_PATH` | `./certs/gateway.crt` | Gateway TLS certificate |
| `CA_CERT_PATH` | `./certs/ca.crt` | CA certificate for mTLS verification |
| `TRUST_DASHBOARD_ORIGIN` | `http://localhost:3005` | Allowed CORS origin |
| `AI_ENGINE_URL` | `http://ai-engine:5001` | Internal AI microservice URL |
| `HMAC_SECRET` | — | Shared secret for AI engine request signing |
| `ADMIN_API_KEY` | — | Secret key for `/api/admin/*` endpoints |
| `REACT_APP_GATEWAY_URL` | `https://localhost:8443` | Gateway URL used by dashboard |
| `REACT_APP_ADMIN_API_KEY` | `dev-admin-key` | Admin key sent by dashboard |
| `MODEL_HASH` | — | SHA-256 of `model.pkl` for integrity check |

---

## API Reference

### Authentication (Sequence 1)

| Method | Path | Auth |
|---|---|---|
| `GET` | `/api/auth/nonce?clientId=<id>` | mTLS |
| `POST` | `/api/auth/login` | mTLS |

### Resource Access (Sequence 2)

| Method | Path | Auth |
|---|---|---|
| `POST` | `/api/resource/access` | mTLS + Session |

### Heartbeat (Sequence 3)

| Method | Path | Auth |
|---|---|---|
| `POST` | `/api/heartbeat` | mTLS + Session |

### Admin (requires `X-Admin-Key`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/overview` | All sessions |
| `POST` | `/api/admin/revoke` | Revoke session by ID |
| `GET` | `/api/admin/audit-logs` | Audit log entries |
| `GET` | `/api/admin/blockchain-events` | On-chain event history |
| `GET` | `/api/admin/system-status` | Live 8-component health check |
| `GET` | `/api/admin/pending-policies` | Multi-sig proposals |
| `POST` | `/api/admin/propose-policy` | Submit GRANT/REVOKE proposal |
| `POST` | `/api/admin/approve` | Sign and approve a proposal |
| `POST` | `/api/admin/simulate-tamper` | Trigger tamper detection demo |

---

## Project Structure

```
verichain-ai/
├── packages/
│   ├── desktop-agent/          Electron + React ZKP client
│   │   ├── src/main/           Main process (IPC, mTLS, ZKP, key management)
│   │   └── src/renderer/       React UI (Vite)
│   ├── gateway/                Express security gateway (PEP)
│   │   ├── src/controllers/    Route handlers
│   │   ├── src/middleware/     mTLS, Zod validation, rate limiting, admin auth
│   │   ├── src/services/       Redis, blockchain, AI client, session, audit, Merkle
│   │   └── src/routes/         API router
│   ├── ai-engine/              Python Flask risk scoring microservice
│   ├── contracts/              Solidity contracts + Hardhat deployment
│   └── trust-dashboard/        React admin monitoring dashboard
├── nginx/                      Reverse proxy config
├── docker-compose.yml
├── start-all.ps1               Universal one-command orchestrator
└── .github/workflows/          CI pipeline
```

---

## License

Academic project