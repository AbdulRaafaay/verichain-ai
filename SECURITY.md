# VeriChain AI Security Documentation

This document outlines the security controls and non-functional requirements (NFRs) implemented in the VeriChain AI ecosystem.

## 1. Identity & Authentication (ZKP)
- **Control**: Zero-Knowledge Proof (Groth16) authentication.
- **Implementation**: The Desktop Agent generates a proof of identity knowledge without revealing the private key.
- **NFR-04**: Fail-closed ZKP validation at the Security Gateway.
- **NFR-05**: Replay protection using Redis-backed nonces.

## 2. Communication Security (mTLS)
- **Control**: Mutual TLS (mTLS) with certificate pinning.
- **Implementation**: All communication between Agent and Gateway requires valid client certificates.
- **NFR-03**: Mandatory mTLS enforcement for all API endpoints.

## 3. Behavioral AI (Risk Scoring)
- **Control**: Real-time behavioral anomaly detection.
- **Implementation**: Flask-based AI engine using the Isolation Forest algorithm.
- **NFR-07**: Scoring of telemetry (velocity, session duration, geo-drift).
- **NFR-08**: Fail-closed design (risk=100 on AI engine failure).

## 4. Immutable Auditing (Blockchain)
- **Control**: Merkle-anchored audit logs on Ethereum (Hardhat).
- **Implementation**: Logs are batched and anchored every 60 seconds.
- **NFR-13**: Merkle root anchoring to the `AuditLedger` contract.
- **NFR-14**: Automated tamper detection with on-chain alerts.

## 5. Session Management
- **Control**: Continuous trust verification via heartbeats.
- **Implementation**: 30-second heartbeat loop from Agent to Gateway.
- **NFR-06**: Automatic session revocation after 35 seconds of silence.

## 6. Infrastructure Hardening
- **Control**: Network isolation and non-root containers.
- **Implementation**: Internal net isolation for AI Engine, DB, and Blockchain.
- **NFR-10**: No-root execution in Docker for all security services.
- **NFR-11**: AI Engine integrity verification against on-chain hash at startup.

---
**Status**: All controls verified and functional.
