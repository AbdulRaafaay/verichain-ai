# Security Policy — VeriChain AI

This document describes the complete security architecture, threat mitigations, and defensive programming controls implemented in VeriChain AI. All controls map directly to the STRIDE threat model and OWASP Top 10 analysis from Deliverable 2, and satisfy the Assignment 3 secure implementation requirements.

---

## 1. Authentication Model

VeriChain AI uses a **multi-factor, zero-knowledge authentication** model. No password, private key, or identity secret is ever transmitted over the network.

### Sequence 1 — Zero-Knowledge Proof Login

1. **Nonce Request** — The Desktop Agent calls `GET /api/auth/nonce?clientId=<id>`. The gateway generates a 16-byte cryptographically random nonce (`crypto.randomBytes(16).toString('hex')`), stores it in Redis with a 5-minute TTL keyed to `nonce:<clientId>:<nonce>`, and returns it. The TTL prevents stale nonce accumulation and any reuse of the same nonce returns 401.

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

2. The Python microservice runs **Isolation Forest** on six behavioral telemetry features:
   - `accessVelocity` — requests per minute (normal ~5)
   - `uniqueResources` — distinct resources per session (normal 1–10)
   - `downloadBytes` — bytes transferred (normal ~50,000)
   - `geoDistanceKm` — distance from baseline location (normal ~0)
   - `timeSinceLast` — seconds since previous request (normal ~300)
   - `deviceIdMatch` — 1 if device matches enrolled, 0 otherwise

   Scores are dynamically calibrated using `df_min`/`df_max` from the actual training distribution so the full 0–100 range is used. The scoring formula: `score = clip((1 − (raw − df_min) / (df_max − df_min)) × 100, 0, 100)`.

3. The engine returns a risk score (0–100). The gateway enforces:
   - Score > 75 → **REVOKE**: session deleted from Redis, on-chain `revokeSession` called, `session_revoked` WebSocket event broadcast
   - Score 50–75 → **STEP_UP**: access denied, step-up re-authentication required
   - Score < 50 → **PERMIT**: access granted

4. If the AI Engine is unreachable, the system **fails closed**: score defaults to 100 (REVOKE). No request is ever granted without an explicit risk assessment.

**STRIDE coverage:** Elevation of Privilege (anomaly detection blocks compromised sessions), Denial of Service (watchdog revokes stale sessions).

### 2.3 Blockchain Policy Check

After the risk check, the gateway queries `AccessPolicy.sol` via a gas-free `view` call:

```solidity
function isAccessAllowed(bytes32 userHash, bytes32 resourceHash)
    external view returns (bool)
{
    return accessRules[userHash][resourceHash];
}
```

The result is recorded in the audit log as `policyMatched: true|false`. A separate state-changing variant, `checkAccess`, is invoked through the serialised `sendTx` queue purely to emit an `AccessDecision` event for the on-chain audit trail. The two paths are decoupled: the read used for the per-request decision never blocks on a transaction or competes for the gateway's nonce.

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
| Session storage | Redis `session:<uuid>` (UUID v4) |
| TTL | 1 hour, refreshed on each heartbeat |
| Heartbeat interval | 10 seconds (Desktop Agent) |
| Watchdog scan interval | 5 seconds (server-side) |
| Watchdog timeout | 35 seconds without heartbeat → revoke |
| Revocation propagation | Redis DEL + on-chain `revokeSession` (via `sendTx` queue) + `session_revoked` Socket.io broadcast |
| TTL-expiry handling | Redis keyspace notifications subscribe to `__keyevent@0__:expired`; expired session keys trigger an on-chain `revokeSession("Redis TTL Expired")` automatically |

Three independent mechanisms can revoke a session, all converging on the same workflow:

1. **AI risk** — score > 75 in `resource.controller.ts` → off-chain DEL + on-chain revoke + `tamper_alert` socket event with the per-feature reasons that drove the score
2. **Heartbeat watchdog** — `lastHeartbeat` aged out → on-chain revoke with reason "Heartbeat Timeout"
3. **Redis TTL expiry** — keyspace notification → on-chain revoke with reason "Redis TTL Expired" (closes the desync window where a session that lapsed silently in Redis would otherwise remain `active: true` on-chain forever)

All three paths produce a `SessionRevoked` event on `AccessPolicy.sol`, so the on-chain history is the single source of truth for session lifecycle.

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

1. All un-anchored logs are fetched from MongoDB (`{ anchored: false }`)
2. Each log is SHA-256 hashed (canonical JSON representation of `metadata`)
3. A `merkletreejs` Merkle tree is constructed from the leaf hashes (`sortPairs: true`)
4. The root is submitted to `AuditLedger.sol` via `anchorMerkleRoot(bytes32 root, uint256 logCount)` — routed through the serialised `sendTx` queue so it cannot collide on the gateway's nonce
5. All included logs are marked `anchored: true` with the root and tx hash stored in the document
6. The root is recomputed from the same logs read back fresh from the database and compared to the on-chain value
7. Any mismatch flips the shared `IntegrityState` module to `COMPROMISED`, fires a `tamper_alert` Socket.io event with details, and calls `triggerAlert("MERKLE_MISMATCH", root)` on `AccessPolicy.sol` (also via `sendTx`)

The Trust Dashboard's top bar reflects `IntegrityState` live — green "Audit SECURE" → red "Audit COMPROMISED" the moment the gateway detects a mismatch. The state resets to SECURE on the next clean cycle.

Any post-anchor modification to a log document produces a different Merkle root — the tamper is detected on the next 60-second cycle and surfaced in real time. Because the on-chain root is immutable, an attacker cannot retroactively cover their tracks even with full database write access.

**STRIDE coverage:** Tampering (on-chain immutable record), Repudiation (every decision logged with userHash and anchored).

---

## 9. AI Model Integrity, Methodology, and Validation

### 9.1 Integrity verification (NFR-09)

On startup the AI Risk Engine SHA-256 hashes its `model.pkl` and compares against the
`registeredModelHash` value stored on-chain in `AccessPolicy.sol`. Behaviour is asymmetric:

- **Hash matches** → engine starts normally
- **Hash mismatch** → engine aborts with a `RuntimeError` and refuses to serve scoring requests
- **Model file missing** (first boot) → engine logs a warning and auto-trains a fresh baseline; the resulting hash should be registered on-chain by the admin so subsequent boots become integrity-checked

This protects against three substitution vectors:
1. Container image supply-chain compromise (an attacker swapping the bundled model)
2. Local file-system attack (replacing `model.pkl` after container start)
3. Backdoor model that scores attackers as PERMIT (a maliciously-trained model would have a different hash)

### 9.2 Training methodology (synthetic, justified)

The model is trained on 2,000 synthetic samples drawn from the realistic-behaviour distribution
described in the README. Synthetic data is the appropriate choice for this academic prototype
because:

- No publicly available behavioural-telemetry dataset matches the six features and the access-control context (CICIDS, CSE-CIC-IDS2018 are network/intrusion-oriented, not session behaviour)
- Real session telemetry would require GDPR-grade data handling beyond the scope of an SSD coursework
- The synthetic-data approach is documented practice in the academic insider-threat literature (e.g. CMU CERT Insider Threat dataset)

The model has known ML limitations (independent-feature sampling, Gaussian assumption, no temporal context) which are documented in the project's CLAUDE.md.

### 9.3 Validation against synthesised attacks

To produce a defensible security claim rather than relying on the unsupervised model alone, training generates an additional **held-out attack-pattern set** of 250 samples covering five realistic exfiltration / abuse scenarios:

| Pattern | Recall @ score ≥ 50 | Recall @ score > 75 |
|---|---|---|
| Mass enumeration (high velocity + many resources + rapid) | 100% | high |
| Bulk download (50 MB single transfer) | 100% | high |
| Rapid-fire (credential stuffing pattern) | 100% | high |
| Stolen device (`deviceIdMatch=0`) | 100% | high |
| Geographic anomaly (single feature) | 74% | varies |
| **Aggregate** | **94.8%** | **84.0%** |

False-positive rate on the 2,000 training normals: **10.6%** at the STEP_UP threshold, **2.1%** at the REVOKE threshold.

Metrics are logged at training time and persisted in `model.pkl` under the `validation_metrics` key, retrievable via `GET /health` from the AI engine.

### 9.4 Hybrid scoring (single-feature extreme handling)

Isolation Forest saturates on extreme single-axis outliers — a 9σ deviation in one feature
isolates to the same tree depth as a 4σ deviation. To prevent this from degrading single-feature
attack recall, a post-hoc z-score floor is applied:

| Per-feature z-score (anomaly direction) | Effect |
|---|---|
| `deviation > 4.0` | Score raised to at least **51** (forces STEP_UP) |
| `deviation > 7.0` | Score raised to at least **76** (forces REVOKE) |

The floor reason is recorded in the audit log as `scoreFloor: "strong_single_feature_outlier"` or
`"extreme_single_feature_outlier"`. The unsupervised IF still drives multi-feature scoring;
the floor is only an explainability-friendly safety net for the failure mode IF is known to have.

### 9.5 Per-decision explainability

Every score returns a `reasons` array — features whose `|z| > 1.5`, ordered by deviation magnitude,
each tagged `concerning: true` (anomaly direction) or `false` (safe-direction outlier).
Reason summaries are logged at the gateway, broadcast on `tamper_alert` socket events, and shown
inline in the Desktop Agent risk gauge and the Trust Dashboard's Threat Alerts panel. This means
every REVOKE / STEP_UP can be answered with "*because* feature X was Y σ from the training mean,"
not just "because the AI said so."

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

## 14. Cloud Security

The current deployment is **fully local** — every component runs on the developer's machine
(host-launched gateway / dashboard / Electron agent + four Docker containers for the stateful
services). This is the appropriate scope for a Semester-6 prototype demo, and it removes
several attack surfaces that a cloud deployment would introduce.

### 14.1 What's in place today (relevant even locally)

| Control | How it's implemented | Where |
|---|---|---|
| Secrets out of source code | All credentials read from `.env`; `.env` gitignored; `.env.example` ships only `CHANGE_ME_*` placeholders | repo root |
| Fail-fast on placeholder values | `start-all.ps1` aborts if any `CHANGE_ME_*` value remains in `.env` — prevents accidental deployment with default secrets | `start-all.ps1` |
| HMAC over internal RPC | Gateway → AI engine traffic is HMAC-SHA256 signed, even on a private Docker network | `aiClient.js` + `app.py` |
| Database access restriction | MongoDB requires AUTH (`MONGO_INITDB_ROOT_USERNAME` / `_PASSWORD`); Redis requires AUTH (`--requirepass`) | `docker-compose.yml` |
| Container isolation | Each backing service runs in its own Docker container on a private `internal_net` bridge network | `docker-compose.yml` |
| Least-privilege role mapping | Smart-contract `GATEWAY_ROLE` is granted only to the gateway's signer; `ADMIN_ROLE` to three distinct addresses (single-key demo limitation aside) | `deploy.js`, `AccessPolicy.sol` |

### 14.2 What changes for a real cloud deployment

If this project were promoted to a managed cloud environment (AWS / Azure / GCP), the following
additional controls would replace or augment the local equivalents:

| Concern | Cloud-native control |
|---|---|
| Secrets storage | AWS Secrets Manager / Azure Key Vault / GCP Secret Manager — replace `.env` files; rotate via console |
| TLS termination | ACM certificates + ALB / Application Gateway with auto-rotation; mTLS enforced at the load balancer with cert-pinning to the agent fleet |
| Identity & access | IAM roles for the gateway runtime; dashboard admin auth replaced by OAuth2 / SSO with short-lived JWTs (the current `ADMIN_API_KEY` is a known prototype shortcut) |
| Database access | Private subnet, security-group ingress restricted to the gateway subnet; encryption at rest enabled (MongoDB Atlas / Azure Cosmos / RDS Postgres) |
| Object storage (audit archive) | S3 / Blob bucket with **bucket policies denying public access**, server-side encryption, versioning + Object Lock for tamper-evidence |
| Network egress | VPC egress restricted to the AI engine endpoint and the blockchain RPC; everything else denied |
| Logging | CloudWatch / Azure Monitor with log retention policies; structured JSON logs already produced by `winston` make ingestion trivial |
| Blockchain RPC | Managed Ethereum endpoint (Infura / Alchemy) with API-key + HTTPS; gateway holds private key in HSM, not .env |
| Container scanning | ECR / ACR vulnerability scans on every push; image signing (cosign) before deployment |

### 14.3 Why this scope is acceptable for the deliverable

The assignment explicitly says "If deployed on cloud" — VeriChain is not. The choice to demo
locally is intentional: it removes cloud-provider variability, keeps the security boundaries
inspectable at every layer, and makes the threat model fully reproducible for the marker.
Every cloud-security control listed above has a local equivalent in the current codebase
(secrets in `.env` instead of Secrets Manager, mTLS instead of ALB-terminated TLS,
Docker network instead of VPC, etc.), so the design **is** cloud-ready — it just hasn't been
deployed there.

---

## 15. STRIDE Threat Mitigations Summary

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

## 16. Reporting a Vulnerability

This is an academic project. For issues found in this codebase, open a GitHub issue with the label `security`.
