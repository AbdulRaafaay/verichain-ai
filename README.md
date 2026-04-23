# VeriChain AI — Blockchain-Secured AI Anomaly Detection

VeriChain AI is a multi-layered security infrastructure designed to protect enterprise resources using Zero-Knowledge Proofs (ZKP), Behavioral AI, and Blockchain-anchored auditing.

## Architecture
1. **Desktop Agent**: Electron app for secure resource access via ZKP and mTLS.
2. **Security Gateway (PEP)**: Node.js orchestrator enforcing mTLS, ZKP, and session policies.
3. **AI Risk Engine**: Python microservice providing real-time behavioral anomaly detection.
4. **Blockchain Layer**: Solidity contracts for session management and immutable log anchoring.
5. **Trust Dashboard**: React interface for real-time security monitoring and tamper detection.

## Prerequisites
- Docker & Docker Compose
- Node.js (v18+)
- Python 3.11+

## Quick Start
1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Generate Security Certificates (mTLS)**:
   ```bash
   ./scripts/generate-certs.sh
   ```

3. **Deploy Smart Contracts**:
   ```bash
   cd packages/contracts
   npx hardhat node
   # (In another terminal)
   npx hardhat run scripts/deploy.js --network localhost
   ```

4. **Launch the Ecosystem**:
   ```bash
   docker-compose up --build
   ```

## Security Features
- **NFR-03: mTLS Enforcement**: All traffic requires mutual TLS with hardware-backed certs.
- **NFR-04: ZKP Authentication**: Authenticate without revealing private keys via Groth16.
- **NFR-07: Behavioral Anomaly Detection**: Isolation Forest model scores session risk.
- **NFR-13: Log Anchoring**: Audit logs are batched and anchored to Ethereum every 60s.
- **NFR-09: Model Integrity**: AI Engine verifies its own hash against the blockchain at boot.

## Demo Flow
Follow these steps to experience the full VeriChain AI security lifecycle:

1. **Enrollment**: Launch the Desktop Agent. Click "Login with Zero-Knowledge". Since it's the first run, the Agent will generate a new identity and store it in your OS Secure Storage (TPM/Keychain).
2. **Authentication**: The Agent generates a ZKP proof and authenticates via mTLS. You are redirected to the Dashboard.
3. **Session Monitoring**: Open the Trust Dashboard at `http://localhost:3001`. You will see your new session appear in real-time with an initial low risk score.
4. **Accessing Resources**: Use the Agent to access a protected "File Vault". An audit log will immediately appear in the Trust Dashboard and the Agent's Telemetry screen.
5. **Simulating Anomaly**: Rapidly access resources multiple times in the Agent. The AI Risk Engine will detect high access velocity, increasing your risk score on the Dashboard.
6. **Tamper Detection**: (Advanced) Manually modify an audit log entry in MongoDB. Within 60 seconds, the Merkle Anchoring service will detect the integrity mismatch and fire a `MERKLE_MISMATCH` critical alert on the Trust Dashboard.
7. **Replay Protection**: Attempt to reuse a previous ZKP proof. The Gateway will reject it as the nonce has already been consumed in Redis.

## Testing
To run the smart contract security suite:
```bash
cd packages/contracts
npx hardhat test
```
