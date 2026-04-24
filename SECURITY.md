# Security Policy — VeriChain AI

This document describes the complete security architecture, controls, and threat mitigations implemented in VeriChain AI. It maps directly to the STRIDE threat model and OWASP Top 10 used during Deliverable 2 analysis.

---

## Authentication Model

VeriChain AI uses a **multi-factor, zero-knowledge authentication** model. No password or private key is ever transmitted over the network.

### Sequence 1 — Zero-Knowledge Proof Login

1. **Nonce Request** — The Desktop Agent calls `GET /api/auth/nonce?clientId=<id>`. The gateway generates a cryptographic nonce, stores it in Redis with a 5-minute TTL, and returns it.
2. **Proof Generation** — The Desktop Agent uses snarkjs (Groth16/BN128 circuit) to generate a ZK proof that it knows the private key corresponding to its enrolled identity, binding the nonce into the proof so it cannot be replayed.
3. **Proof Verification** — The gateway verifies the Groth16 proof against the compiled verification key (`verification_key.json`). The nonce is atomically burned from Redis on first use (replay protection).
4. **Session Creation** — On success, a UUID session ID is created in Redis with a 1-hour TTL, keyed to `session:<uuid>`. The Desktop Agent stores only this session ID.

All auth traffic travels over mTLS (see Transport Security below).

---

## Authorization Model

### Session-Based Access Control

Every API request beyond `/auth/` requires a valid session ID. The gateway validates the session exists in Redis before processing any resource request.

### AI Risk-Based Policy Enforcement

On every `POST /api/resource/access`:

1. The gateway calls the AI Risk Engine (authenticated via HMAC-SHA256 shared secret).
2. The Python microservice runs an **Isolation Forest** anomaly detector on behavioral telemetry: access velocity, device ID consistency, time-of-day patterns, and request frequency.
3. The engine returns a risk score (0–100). Scores above the configured threshold trigger **automatic session revocation** — the session is deleted from Redis and a `session_revoked` WebSocket event is broadcast to the Trust Dashboard.

### Blockchain Policy Check

After the risk check, the gateway queries `AccessPolicy.sol` on-chain:

```solidity
function checkAccess(bytes32 userHash, bytes32 resourceHash) external view returns (bool)
```

If the on-chain policy does not grant the user access to the resource, the request is denied regardless of risk score.

### Multi-Signature Policy Updates

Changing access policies requires **2-of-3 admin approvals** via `AccessPolicy.sol`:

- `proposeChange(bytes32 changeHash)` — recorded on-chain by an admin with `ADMIN_ROLE`
- `approveChange(bytes32 changeHash, bytes32 userHash, bytes32 resourceHash, bool grant)` — each approval increments the on-chain counter; at threshold the policy executes atomically

This prevents a single compromised admin account from modifying access control unilaterally (STRIDE: Elevation of Privilege).

---

## Transport Security

### Mutual TLS (mTLS)

All communication between the Desktop Agent and the Security Gateway uses mTLS:

- **Server certificate**: issued by the internal CA, pinned in the Desktop Agent's `tls.connect` call
- **Client certificate**: each Desktop Agent instance has a unique certificate signed by the internal CA
- The gateway is configured with `requestCert: true` and the `mtlsVerify` middleware rejects any request without a valid, CA-signed client certificate (except the `/health` endpoint)
- In production, `rejectUnauthorized: true` must be set; the current dev setting of `false` permits self-signed certs during local testing only

### Certificate Pinning

The Desktop Agent pins the CA certificate hash at build time. Any gateway certificate not signed by the pinned CA causes the TLS handshake to fail immediately, preventing MITM attacks.

---

## Encryption

| Data | At Rest | In Transit |
|---|---|---|
| Private keys (Desktop Agent) | `electron.safeStorage` (OS-level AES encryption) | Never transmitted |
| Session tokens | Redis (in-memory, optional Redis AUTH) | TLS 1.3 (mTLS) |
| Audit logs | MongoDB (optional encryption-at-rest) | TLS 1.3 |
| AI model | SHA-256 integrity check on load | HMAC-signed requests |
| Blockchain state | Ethereum node storage | HTTPS RPC |

---

## API Security Controls

### Input Validation

All gateway endpoints use **Zod schema validation** (`src/middleware/validate.ts`). Requests with missing or malformed fields receive a structured `400 Validation failed` response before any business logic executes. This prevents injection attacks and unexpected state.

Validated schemas:
- `NonceQuerySchema` — clientId length bounded
- `LoginSchema` — proof and publicSignals structure enforced
- `HeartbeatSchema` — sessionId must be a valid UUID
- `ResourceAccessSchema` — sessionId UUID, resourceId length bounded
- `RevokeSessionSchema`, `ProposePolicySchema`, `ApprovePolicySchema`

### Rate Limiting

Redis-backed per-IP sliding-window rate limits are applied to high-value endpoints:

| Endpoint | Window | Max requests |
|---|---|---|
| `GET /api/auth/nonce` | 60 s | 20 |
| `POST /api/auth/login` | 60 s | 10 |
| `POST /api/heartbeat` | 60 s | 120 |

Exceeding limits returns `429 Too many requests` with a `Retry-After` header. The limiter fails open if Redis is unavailable (availability over strict enforcement).

### Security Headers

`helmet` is applied globally, setting:
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`
- `X-XSS-Protection`

### CORS

CORS reflects the requesting `Origin` header back (required for `credentials: true` — wildcard origin is rejected by browsers in this mode). In production, the origin should be restricted to an explicit allowlist.

Socket.io CORS is restricted to `TRUST_DASHBOARD_ORIGIN` (default: `http://localhost:3001`).

### Body Size Limit

`express.json({ limit: '10kb' })` rejects oversized payloads before parsing, preventing JSON bomb / DoS attacks.

---

## Session Management

- Sessions are stored in Redis with a 1-hour TTL (`session:<uuid>` key)
- The Desktop Agent sends a heartbeat to `POST /api/heartbeat` every 30 seconds to renew the TTL
- The `SessionService.startHeartbeatWatchdog()` runs a server-side scan every 60 seconds to forcibly revoke sessions whose last heartbeat exceeded the configured threshold
- Revoked sessions are immediately deleted from Redis and broadcast via WebSocket so all Dashboard instances update in real time

---

## Audit Trail & Tamper Detection

Every authentication event, access decision, and session revocation is written to MongoDB as an `AuditLog` document containing:

```
{ action, timestamp, metadata: { userHash, resourceHash, riskScore, decision }, anchored, merkleRoot }
```

**Merkle anchoring** runs on a 5-minute batch cycle (`MerkleService.startBatcher()`):

1. All un-anchored logs are hashed with SHA-256 and assembled into a Merkle tree (merkletreejs)
2. The Merkle root is submitted to `AuditLogger.sol` on-chain via `logEvent(bytes32 root)`
3. Logs are marked `anchored: true` with the on-chain root stored for verification
4. Any subsequent modification of a log entry produces a different root — the mismatch is detectable by re-computing the tree and comparing against the on-chain record

Tamper events are emitted as `tamper_alert` Socket.io events to the Trust Dashboard.

---

## AI Model Integrity

The AI Risk Engine validates its own model file on startup:

```python
# model_integrity.py
expected_hash = os.environ['MODEL_HASH']
actual_hash   = sha256(open('model.pkl', 'rb').read()).hexdigest()
assert actual_hash == expected_hash, 'Model integrity check failed'
```

The expected hash is provided at container launch via the `MODEL_HASH` environment variable, preventing a supply-chain substitution attack on the model artifact.

---

## Key Management

| Key / Secret | Storage | Rotation |
|---|---|---|
| Desktop Agent private key | `electron.safeStorage` (per-device) | Re-enroll to rotate |
| mTLS certificates | Docker secrets / filesystem | CA-issued, 1-year validity |
| HMAC secret (AI engine) | Environment variable | Rotate via `.env` redeploy |
| Redis AUTH password | Environment variable | Rotate via `.env` redeploy |
| MongoDB credentials | Environment variable | Rotate via `.env` redeploy |

---

## STRIDE Threat Mitigations Summary

| Threat | Mitigation |
|---|---|
| **Spoofing** | ZKP (proves identity without secrets), mTLS client certificates |
| **Tampering** | Merkle-anchored audit logs, on-chain Merkle root verification |
| **Repudiation** | Immutable blockchain audit trail, every decision logged with userHash |
| **Information Disclosure** | ZKP (zero knowledge), mTLS encryption, safeStorage for keys |
| **Denial of Service** | Redis rate limiting, 10 kb body limit, heartbeat watchdog |
| **Elevation of Privilege** | Multi-sig policy changes (2/3), RBAC via `AccessPolicy.sol`, Zod validation |

---

## Reporting a Vulnerability

This is an academic project. For issues found in this codebase, open a GitHub issue with the label `security`.
