# Security Policy — VeriChain AI

This document describes the complete security architecture, threat mitigations, and defensive programming controls implemented in VeriChain AI. All controls map directly to the STRIDE threat model and OWASP Top 10 analysis from Deliverable 2, and satisfy the Assignment 3 secure implementation requirements.

---

## 1. Authentication Model

VeriChain AI uses a **multi-factor, zero-knowledge authentication** model. No password, private key, or identity secret is ever transmitted over the network.

### Sequence 1 — Zero-Knowledge Proof Login

1. **Nonce Request** — The Desktop Agent calls `GET /api/auth/nonce?clientId=<id>`. The gateway generates a 32-byte cryptographically random nonce (`crypto.randomBytes(32).toString('hex')`), stores it in Redis with a 5-minute TTL keyed to `nonce:<clientId>:<nonce>`, and returns it. The TTL prevents stale nonce accumulation.

2. **Proof Generation** — The Desktop Agent uses snarkjs (Groth16/BN128 circuit) to generate a zero-knowledge proof that it possesses the private key corresponding to its enrolled identity. The nonce is embedded into the circuit's public input vector — the proof is cryptographically bound to that specific nonce and cannot be replayed for a different request.

3. **Proof Verification** — The gateway calls `snarkjs.groth16.verify(vKey, publicSignals, proof)`. If verification returns `false`, the request is rejected with `401`. The nonce is **atomically burned** from Redis (DEL) on first use regardless of proof validity, preventing any replay attempt even with a valid proof.

4. **Session Creation** — On successful verification, a UUID v4 session ID is generated, stored in Redis as `session:<uuid>` with a 1-hour TTL, and returned to the Desktop Agent. The agent stores only the session ID — never the key pair. A non-blocking on-chain `createSession` call records `{sessionId, userHash}` in `AccessPolicy.sol`.

All auth traffic travels over mTLS (see Section 3).

**STRIDE coverage:** Spoofing (ZKP proves identity), Repudiation (on-chain session record), Information Disclosure (zero knowledge — private key never leaves the device).

---

## 2. Authorization Model

### 2.1 Session-Based Access Control

Every API request beyond `/auth/` and `/health` requires a valid `sessionId` field. The gateway validates the session exists in Redis before any business logic executes. Expired or revoked sessions return `401` immediately.

### 2.2 AI Risk-Based Policy Enforcement (Sequence 2)

On every `POST /api/resource/access`:

1. The gateway calls the AI Risk Engine at `POST /score`, authenticated via **HMAC-SHA256**: `X-HMAC-Signature = HMAC(body, HMAC_SECRET)`. The engine validates the signature before processing — requests with invalid signatures are rejected.

2. The Python microservice runs **Isolation Forest** on four behavioral telemetry features:
   - `accessVelocity` — requests per minute
   - `contextDrift` — environment consistency score
   - `requestFrequency` — requests per session
   - `timeOfDayScore` — expected working-hours score

3. The engine returns a risk score (0–100). The gateway enforces:
   - Score > 75 → **REVOKE**: session deleted from Redis, `session_revoked` WebSocket event broadcast
   - Score 50–75 → **STEP_UP**: access denied, step-up re-authentication required
   - Score < 50 → **PERMIT**: access granted

4. If the AI Engine is unreachable, the system **fails closed**: access is denied and the error is logged. No request is ever granted without an explicit risk assessment.

**STRIDE coverage:** Elevation of Privilege (anomaly detection blocks compromised sessions), Denial of Service (watchdog revokes stale sessions).

### 2.3 Blockchain Policy Check

After the risk check, the gateway queries `AccessPolicy.sol`:

```solidity
function checkAccess(bytes32 userHash, bytes32 resourceHash) external view returns (bool)
```

If the on-chain policy does not explicitly grant the user access to the requested resource, the request is denied regardless of risk score. Access is denied by default — no implicit grants exist.

### 2.4 Multi-Signature Policy Updates (NFR-11)

Changing access policies requires **2-of-3 admin approvals** enforced on-chain in `AccessPolicy.sol`:

- `proposeChange(bytes32 changeHash)` — submitted by an admin with `ADMIN_ROLE`; recorded on-chain
- `approveChange(bytes32 changeHash, bytes32 userHash, bytes32 resourceHash, bool grant)` — each call increments the approval counter; at threshold 2 the policy executes atomically in the same transaction

A single compromised admin account cannot unilaterally modify access control. The on-chain enforcement means gateway-side authorization cannot be bypassed.

**STRIDE coverage:** Elevation of Privilege (2-of-3 threshold prevents single-point compromise).

### 2.5 Admin API Authentication

All `/api/admin/*` routes are protected by the `requireAdmin` middleware ([packages/gateway/src/middleware/requireAdmin.ts](packages/gateway/src/middleware/requireAdmin.ts)):

```typescript
const match =
    providedBuf.length === expectedBuf.length &&
    crypto.timingSafeEqual(providedBuf, expectedBuf);
```

- **Timing-safe comparison** (`crypto.timingSafeEqual`) prevents timing-based secret enumeration attacks
- **Fails closed**: if `ADMIN_API_KEY` environment variable is not set, every admin request is rejected with `401` — there is no default key fallback
- Returns `401` (not `403`) so unauthenticated callers cannot learn whether the route exists (avoids information disclosure)
- The Trust Dashboard attaches `X-Admin-Key` via a shared axios instance (`src/api.ts`) — the key is set in one place and cannot be accidentally omitted

---

## 3. Transport Security

### 3.1 Mutual TLS (mTLS)

All communication between the Desktop Agent and the Security Gateway uses mTLS:

- The gateway runs an `https.createServer` with `requestCert: true` and a CA certificate (`ca.crt`) provided at startup
- The `mtlsVerify` middleware ([packages/gateway/src/middleware/mtlsVerify.ts](packages/gateway/src/middleware/mtlsVerify.ts)) rejects any request where the client certificate is absent or was not signed by the internal CA
- In production `rejectUnauthorized: true` is required; the dev value of `false` permits self-signed certs only during local testing
- The `/health` endpoint is explicitly exempt to support Docker health probes

### 3.2 Certificate Pinning

The Desktop Agent pins the CA certificate hash at the TLS connection level (`ca: fs.readFileSync(CA_CERT_PATH)`). Any gateway certificate not signed by the pinned CA causes the TLS handshake to fail immediately, preventing man-in-the-middle attacks.

### 3.3 Security Headers

`helmet` is applied globally to every response:

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | Default restrictive policy |
| `X-XSS-Protection` | `1; mode=block` |

---

## 4. Input Validation

All gateway endpoints enforce **Zod schema validation** before any business logic executes ([packages/gateway/src/middleware/validate.ts](packages/gateway/src/middleware/validate.ts)). Invalid requests receive a structured `400 Validation failed` response. This is a whitelist strategy — only explicitly expected fields and types are accepted.

Validated schemas:

| Schema | Key constraints |
|---|---|
| `NonceQuerySchema` | `clientId`: string, 1–128 chars |
| `LoginSchema` | `proof`: object with Groth16 structure; `publicSignals`: array of strings |
| `HeartbeatSchema` | `sessionId`: UUID v4 |
| `ResourceAccessSchema` | `sessionId`: UUID v4; `resourceId`: string 1–256 chars |
| `RevokeSessionSchema` | `sessionId`: UUID v4 |
| `ProposePolicySchema` | `userHash`, `resourceHash`: non-empty strings; `action`: enum `GRANT\|REVOKE` |
| `ApprovePolicySchema` | `changeHash`: non-empty string |

**Body size limit:** `express.json({ limit: '10kb' })` rejects oversized payloads before parsing — prevents JSON bomb / amplification DoS.

**STRIDE coverage:** Tampering (malformed input rejected before processing), Denial of Service (size limit).

---

## 5. Rate Limiting

Redis-backed per-IP sliding-window rate limits are applied at the route level:

| Endpoint | Window | Limit | Rationale |
|---|---|---|---|
| `GET /api/auth/nonce` | 60 s | 20 req | Prevents nonce flooding / enumeration |
| `POST /api/auth/login` | 60 s | 10 req | Brute-force login protection |
| `POST /api/heartbeat` | 60 s | 120 req | Allows 1 heartbeat per 2 s per session |

Exceeding limits returns `429 Too Many Requests`. The rate limiter uses Redis `INCR` + `EXPIRE` for atomicity. If Redis is unavailable the limiter fails open (availability over strict enforcement), but this scenario is logged.

**STRIDE coverage:** Denial of Service (request flooding), Spoofing (login brute-force).

---

## 6. CORS Policy

CORS is configured with an explicit allowlist:

```typescript
const ALLOWED_ORIGINS = new Set(
    (process.env.TRUST_DASHBOARD_ORIGIN || 'http://localhost:3005').split(',').map(o => o.trim())
);
```

- Requests with no `Origin` header (same-origin or non-browser) are allowed
- Localhost variants (`http(s)://localhost:<port>`) are allowed in development
- All other origins receive a CORS error — the browser will block the request

Socket.io CORS is restricted to the same origin set. Wildcard origin (`*`) is never used because `withCredentials: true` requires an explicit reflected origin.

---

## 7. Session Management

| Property | Value |
|---|---|
| Session storage | Redis `session:<uuid>` |
| TTL | 1 hour, renewed on each heartbeat |
| Heartbeat interval | 30 seconds (Desktop Agent) |
| Watchdog scan interval | 60 seconds (server-side) |
| Revocation | Immediate Redis DEL + Socket.io broadcast |

The `SessionService.startHeartbeatWatchdog()` scan forcibly revokes sessions whose `lastHeartbeat` timestamp has exceeded the threshold — this covers Desktop Agent crashes or network drops where the client cannot send a revoke signal.

Revoked sessions are deleted from Redis and immediately broadcast via `session_revoked` WebSocket so all Trust Dashboard instances reflect the change in real time without polling.

---

## 8. Audit Trail and Tamper Detection (NFR-13, NFR-14)

Every authentication event, access decision, and session revocation is written to MongoDB as an `AuditLog` document:

```
{
  action, timestamp,
  metadata: { userHash, resourceHash, riskScore, decision },
  anchored, merkleRoot
}
```

**Merkle anchoring cycle (60 seconds):**

1. All un-anchored logs are fetched from MongoDB
2. Each log is SHA-256 hashed (canonical JSON representation)
3. A `merkletreejs` Merkle tree is constructed from the leaf hashes
4. The root is submitted to `AuditLedger.sol` via `logEvent(bytes32 root)` — permanently recorded on-chain
5. All included logs are marked `anchored: true` with the root stored in the document
6. The root is immediately recomputed from the same logs and compared to the on-chain value
7. Any mismatch triggers a `tamper_alert` Socket.io event to the dashboard and emits a `TamperDetected` blockchain event

Any post-anchor modification to a log document produces a different Merkle root — the tamper is detected on the next cycle and surfaced to the Trust Dashboard in real time.

**STRIDE coverage:** Tampering (on-chain immutable record), Repudiation (every decision logged with userHash and anchored).

---

## 9. AI Model Integrity

The AI Risk Engine validates its own model file on startup:

```python
expected_hash = os.environ['MODEL_HASH']
actual_hash   = sha256(open('model.pkl', 'rb').read()).hexdigest()
assert actual_hash == expected_hash, 'Model integrity check failed'
```

The expected hash is provided via the `MODEL_HASH` environment variable at container launch. If the loaded model file has been replaced or corrupted, the service refuses to start — preventing supply-chain substitution of the anomaly detection model.

---

## 10. Encryption and Key Management

| Data | At Rest | In Transit |
|---|---|---|
| Desktop Agent private key | `electron.safeStorage` (OS AES via TPM/Keychain) | Never transmitted |
| Session tokens | Redis in-memory | TLS 1.3 (mTLS) |
| Audit logs | MongoDB (optional encryption-at-rest) | TLS 1.3 |
| AI request body | — | HMAC-signed over TLS |
| Blockchain state | Ethereum node storage | HTTPS RPC |

**Memory hygiene:** After ZKP generation, the private key buffer is explicitly zeroed with `Buffer.fill(0)` before the reference is released. This limits the window during which the key exists in memory.

**Key rotation:**

| Key / Secret | Storage | How to rotate |
|---|---|---|
| Desktop Agent private key | `electron.safeStorage` (per-device) | Re-enroll to rotate |
| mTLS certificates | Docker secrets / filesystem | Re-issue from CA; restart gateway |
| HMAC secret | `.env` → `HMAC_SECRET` | Update env and redeploy |
| Admin API key | `.env` → `ADMIN_API_KEY` | Update env and redeploy |
| Redis AUTH password | `.env` | Update env and restart Redis |
| MongoDB credentials | `.env` | Update env and restart MongoDB |

---

## 11. Injection Protection

- **NoSQL Injection** — All MongoDB interactions use Mongoose ODM with typed schemas. User-supplied values are never interpolated into raw query strings.
- **Redis** — All Redis operations use the official `ioredis` client with structured command calls; no Lua scripts with user input.
- **Blockchain** — Smart contract calls use ethers.js; all parameters are ABI-encoded, preventing injection into EVM calldata.
- **XSS** — React's virtual DOM escapes all output by default. No `dangerouslySetInnerHTML` is used anywhere in the Trust Dashboard or Desktop Agent renderer.
- **CSRF** — All state-changing admin API calls require the `X-Admin-Key` header; cookie-only auth is not used, so cross-site form submissions cannot trigger admin actions.

---

## 12. Error Handling and Information Disclosure

- All unhandled errors are caught by a central Express error handler that returns `{ error: 'Internal Server Error' }` — no stack traces, file paths, or service names are exposed to clients
- Detailed errors are written to the internal `winston` logger (structured JSON) and are never included in API responses
- Auth failures return `401` uniformly regardless of whether the session ID is malformed, expired, or non-existent — callers cannot distinguish between cases
- Admin route auth failures return `401` (not `403`) so callers cannot determine whether a route exists
- The MongoDB URI password is masked (`****`) in error log output

**STRIDE coverage:** Information Disclosure (no internal state exposed in error responses).

---

## 13. Defensive Programming Controls

### Fail-Closed Defaults

Every decision point defaults to denial when uncertain:
- AI Engine unreachable → access denied
- Blockchain query fails → access denied
- `ADMIN_API_KEY` not set → all admin requests rejected
- mTLS client cert absent → request rejected

### Least Privilege

- Each microservice runs in an isolated Docker container with only the ports it needs exposed
- The gateway's blockchain signer account holds only the minimum gas required for transactions; no ETH is held beyond operational needs
- The `LOGGER_ROLE` in `AuditLedger.sol` is granted only to the gateway's signer address

### Environment Isolation

Sensitive configuration (private keys, DB URIs, HMAC secrets) is managed via `.env` files and never hardcoded in source. In production these would be mapped to AWS Secrets Manager or Azure Key Vault.

---

## 14. STRIDE Threat Mitigations Summary

| Threat Category | Specific Threat | Mitigation |
|---|---|---|
| **Spoofing** | Identity impersonation | ZKP (proves identity without secrets) + mTLS client certificates |
| **Spoofing** | Session hijacking | Session IDs are UUIDs; all traffic over mTLS; sessions expire after 1 hour |
| **Tampering** | Audit log modification | Merkle-anchored logs; on-chain root comparison detects any change |
| **Tampering** | Request body modification | Zod validation + HMAC-signed AI requests |
| **Tampering** | AI model substitution | SHA-256 model integrity check at startup |
| **Repudiation** | Deny access decisions | Immutable blockchain audit trail with userHash on every decision |
| **Repudiation** | Deny session creation | On-chain `SessionCreated` event with timestamp |
| **Information Disclosure** | Key leakage | ZKP (key never leaves device); `electron.safeStorage`; memory zeroing |
| **Information Disclosure** | Internal error exposure | Generic error responses; no stack traces to clients |
| **Information Disclosure** | Admin route enumeration | 401 (not 403) on admin auth failure |
| **Denial of Service** | Login brute-force | Rate limiting (10 req/60 s on login) |
| **Denial of Service** | Payload amplification | 10 kb body size limit |
| **Denial of Service** | Session exhaustion | Heartbeat watchdog revokes stale sessions |
| **Elevation of Privilege** | Unauthorized policy change | 2-of-3 on-chain multi-sig enforced |
| **Elevation of Privilege** | Admin API abuse | `requireAdmin` with timing-safe comparison; fails closed |
| **Elevation of Privilege** | Risk score bypass | AI Engine fails closed; real-time anomaly detection |

---

## 15. Reporting a Vulnerability

This is an academic project. For issues found in this codebase, open a GitHub issue with the label `security`.
