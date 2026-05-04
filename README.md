# VeriChain AI
**Secure Software Design — Spring 2026**  
**Assignment 3: Secure Implementation & Code Submission**

VeriChain AI is a zero-trust enterprise authentication platform integrating Zero-Knowledge Proofs (ZKP), mutual TLS (mTLS), AI-driven behavioral risk scoring via Isolation Forest, and blockchain-anchored audit trails. Every design decision maps directly to the UMLsec threat model from Deliverable 2.

---

## Prerequisites

Install the following before running the project:

| Tool | Minimum Version | Purpose |
|---|---|---|
| **Node.js** | 20.x LTS | Gateway, Trust Dashboard, Desktop Agent |
| **npm** | 10.x | Workspace dependency manager |
| **Python** | 3.11+ | AI Risk Engine (only inside Docker — host install not required) |
| **Docker Desktop** | 24+ | MongoDB, Redis, Blockchain, AI Engine containers |
| **PowerShell** | 5.1+ (Windows) | Startup orchestrator |
| **OpenSSL** | 3.x | mTLS certificate generation (falls back to Docker if absent) |

Disk: ~2 GB free for `node_modules` + Docker images.

---

## Setup Instructions

1. **Clone the repository** and enter the project root.

2. **Copy the environment template** and fill in values:
   ```powershell
   Copy-Item .env.example .env
   ```
   Open `.env` and replace every `CHANGE_ME_*` placeholder. At minimum set strong values for
   `JWT_SECRET`, `MONGO_ROOT_PASSWORD`, `REDIS_PASSWORD`, `AI_HMAC_SECRET`, and `ADMIN_API_KEY`
   (any 16+ byte hex string). The startup script refuses to run if any `CHANGE_ME` placeholder
   remains — this is a deliberate fail-fast guard against running with default secrets.

3. **Verify Docker is running**:
   ```powershell
   docker info
   ```

4. **Run the orchestrator**:
   ```powershell
   powershell -File start-all.ps1
   ```

   The script does the following automatically:
   - Generates self-signed mTLS certificates (`certs/ca.{key,crt}`, `certs/gateway.{key,crt}`, `certs/client.{key,crt}`)
   - Starts MongoDB, Redis, blockchain (Hardhat), and AI Engine via Docker Compose
   - Deploys `AccessPolicy.sol` and `AuditLedger.sol` to the local chain and writes addresses to `packages/contracts/deployment.json`
   - Launches the Gateway (Node), Trust Dashboard (React), and Desktop Agent (Electron) in three new PowerShell windows

5. **Verify the system is up**:
   - Gateway health: `https://localhost:8443/health` (browser will warn about the self-signed cert — accept it for the demo)
   - Trust Dashboard: `http://localhost:3005`
   - Desktop Agent: opens automatically as an Electron window

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

The renderer UI exposes telemetry sliders (access velocity, geo distance, download bytes, time since last access, etc.) whose values are sent as real session metadata to the AI Risk Engine on every `resource:access` IPC call. Scores are derived by the real Isolation Forest model — no simulation flags are used.

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

**Training (startup):** Synthetic baseline telemetry calibrated to realistic user behaviour. 2,000 normal samples drawn from:
- `accessVelocity` ~ N(5, 5) req/min — typical low single digits, occasional bursts
- `uniqueResources` ~ N(5, 3) files — small per-session working set
- `downloadBytes` ~ N(500 KB, 3 MB) — most pages small, occasional large fetches
- `geoDistanceKm` ~ N(10, 50) km — covers normal commute / regional travel
- `timeSinceLast` ~ N(300, 100) s — ~5 min between requests
- `deviceIdMatch` ~ 95% match / 5% mismatch — gives the feature real variance instead of being a dead constant

`IsolationForest(n_estimators=200, contamination=0.05)` is trained on the 2,000 normals. After training, `df_min`/`df_max` are calibrated from the actual training distribution and saved with the model — prevents score clustering and ensures the full 0–100 range is used.

**Validation (also at training time):** A held-out set of 250 synthetic attack samples covering five exfiltration / abuse patterns is scored to measure how well the model catches them:

| Pattern | Recall @ score ≥ 50 |
|---|---|
| Mass enumeration | 100% |
| Bulk download | 100% |
| Rapid-fire (credential stuffing) | 100% |
| Stolen device | 100% |
| Geographic anomaly (single feature) | 74% |
| **Overall** | **94.8% recall, 2.1% false-positive at score > 75** |

Metrics persist in `model.pkl` and are exposed via `GET /health`.

**Hybrid scoring layer:** Isolation Forest is known to saturate on extreme single-feature outliers, so a post-hoc z-score floor is applied. Any feature with `deviation > 4σ` in the anomaly direction lifts the score to at least 51 (STEP_UP); `deviation > 7σ` lifts to at least 76 (REVOKE). Combined with the IF, this gives an ensemble: IF catches multi-feature attacks, the floor catches single-feature extremes.

**Scoring (per request):**
1. Gateway calls `POST /score` with JSON telemetry, authenticated via `X-Internal-Auth: HMAC-SHA256(body, AI_HMAC_SECRET)`
2. AI engine validates HMAC, scales features, runs `decision_function`
3. Raw → 0–100 score via dynamic calibration; floor applied if any single-feature deviation crosses the threshold
4. Returns `{riskScore, reasons[], rawDecision, scoreFloor}` — `reasons` lists features with `|z|>1.5`, each tagged `concerning: true` (anomaly direction) or `false` (safe-direction outlier)
5. Gateway maps score → decision: `>75` REVOKE · `50–75` STEP_UP · `<50` PERMIT

**Fail-closed:** if the AI engine is unreachable, the client retries once on transient socket errors then returns score=100 (REVOKE) with a `engine_unreachable` system-fault reason. No request is ever granted without an explicit risk assessment.

**Model integrity (FR-09):** at startup the engine SHA-256s `model.pkl` and compares against `AccessPolicy.registeredModelHash`. On first boot (no model yet) the engine logs a warning and auto-trains a fresh baseline; on subsequent boots a hash mismatch aborts startup, preventing supply-chain substitution.

### Smart Contracts (`packages/contracts`)

Two Solidity contracts deployed to the local Hardhat node:

**`AuditLedger.sol`** — append-only audit trail. `anchorMerkleRoot(bytes32 root, uint256 logCount)` records Merkle roots on-chain. The `MerkleRootAnchored` event is indexed and queried by the gateway. Only addresses with `GATEWAY_ROLE` (the gateway signer) can write. Anchored roots cannot be deleted or overwritten.

**`AccessPolicy.sol`** — multi-signature access control registry with two roles (`ADMIN_ROLE`, `GATEWAY_ROLE`):
- `proposeChange(bytes32 changeHash)` — admin proposes a policy mutation
- `approveChange(bytes32 changeHash, bytes32 userHash, bytes32 resourceHash, bool grant)` — each call records `msg.sender` in the approval set; at threshold 2 the policy executes atomically in the same transaction
- `createSession(bytes32 sessionId, bytes32 userHash)` — gateway-only; emits `SessionCreated`
- `revokeSession(bytes32 sessionId, string reason)` — gateway-only; emits `SessionRevoked`
- `isAccessAllowed(bytes32 userHash, bytes32 resourceHash) view returns (bool)` — gas-free read used on every access request
- `checkAccess(bytes32 userHash, bytes32 resourceHash) returns (bool)` — state-changing variant that also emits an `AccessDecision` event for audit purposes

All contracts follow the Checks-Effects-Interactions (CEI) pattern, use OpenZeppelin `AccessControl` + `ReentrancyGuard` + `Pausable`, and never store plaintext identities — only `bytes32` hashes.

### Merkle Audit Service (`packages/gateway/src/services/merkle.service.ts`)

Runs a 60-second batch cycle:
1. Queries all un-anchored `AuditLog` documents from MongoDB
2. SHA-256 hashes each document's canonical JSON representation
3. Builds a `merkletreejs` Merkle tree from the leaf hashes
4. Submits the root to `AuditLedger.sol` via `anchorMerkleRoot(root, logCount)` through the serialised `sendTx` queue
5. Marks all included logs `anchored: true` and stores the root + tx hash
6. **Tamper check** — immediately re-computes the root from the same logs and compares to the on-chain value; any mismatch flips `IntegrityState` to `COMPROMISED`, emits `tamper_alert` via Socket.io, and fires `triggerAlert("MERKLE_MISMATCH", root)` on-chain
7. Emits `merkle_anchor` and `merkle_status` Socket.io events for the dashboard

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
| AI Risk Scoring | Isolation Forest anomaly detection on six behavioral telemetry features with dynamic score calibration |
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

## Dependencies

### Runtime dependencies (production)

| Package | Where used | Purpose |
|---|---|---|
| `express` 4.x | gateway | HTTP server |
| `helmet` | gateway | Security headers |
| `cors` | gateway | Origin allowlist |
| `zod` | gateway | Schema-based input validation |
| `mongoose` | gateway | MongoDB ODM (audit logs) |
| `redis` 4.x | gateway | Sessions + nonces + rate-limit counters |
| `ethers` 6.x | gateway | Smart-contract interaction |
| `merkletreejs` | gateway | Merkle root computation |
| `snarkjs` | gateway, agent | Groth16 ZKP verification + generation |
| `winston` | gateway, agent | Structured logging |
| `socket.io` 4.x | gateway, dashboard, agent | Real-time event push |
| `electron` 28 + `electron-store` | desktop-agent | Cross-platform shell + safeStorage |
| `react` 18 + `react-router-dom` | dashboard, agent renderer | UI framework |
| `recharts` | dashboard | Risk + analytics charts |
| `axios` | dashboard, agent | HTTP client with X-Admin-Key injection |
| `flask` 3 + `scikit-learn` 1.5 + `joblib` | ai-engine | Isolation Forest microservice |
| `web3.py` | ai-engine | Reads `registeredModelHash` from blockchain |
| `solidity 0.8.20` + `@openzeppelin/contracts` 5 + `hardhat` | contracts | EVM smart contracts + local node |

### Development tools

`typescript`, `nodemon`, `ts-node`, `vite`, `concurrently`, `cross-env`, `eslint`, `pytest` (optional).

Full lockfiles live in each package (`package-lock.json`, `requirements.txt`).

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
├── docker-compose.yml          Infrastructure only (mongodb, redis, blockchain, ai-engine)
├── start-all.ps1               Universal one-command orchestrator
└── .github/workflows/          CI pipeline
```

---

## License

Academic project