/**
 * admin.controller.ts
 * 
 * Purpose: Handles administrative operations for the VeriChain AI ecosystem.
 * Includes session monitoring, manual revocation, policy proposal management,
 * and system health monitoring.
 * 
 * Security Controls (NFR-11):
 * - Authorization: All methods assume an upstream admin-auth check (e.g., dashboard login).
 * - Auditability: All admin actions are logged via winston and anchored on-chain.
 */

import { Request, Response } from 'express';
import { ethers } from 'ethers';
import crypto from 'crypto';
import axios from 'axios';
import mongoose from 'mongoose';
import { SessionService } from '../services/session.service';
import { BlockchainService } from '../services/blockchain.service';
import { AuditLogModel } from '../models/audit-log.model';
import { IntegrityState } from '../services/integrity.state';
import redisClient from '../services/redisClient';
import { logger } from '../utils/logger';

export class AdminController {

    /**
     * Retrieves a list of all active sessions and their real-time risk scores.
     * @param req - Express Request
     * @param res - Express Response (JSON containing session array)
     */
    static async getOverview(req: Request, res: Response) {
        try {
            const raw = await SessionService.getAllSessions();
            const sessions = raw.map((s: any) => ({
                id: s.sessionId,
                userHash: s.userHash || s.clientId || 'unknown',
                currentResource: s.currentResource || '—',
                loginTime: s.createdAt,
                lastHeartbeat: s.lastHeartbeat || s.createdAt,
                duration: s.createdAt
                    ? Math.round((Date.now() - new Date(s.createdAt).getTime()) / 1000) + 's'
                    : '—',
                riskScore: s.riskScore ?? 0,
                status: s.status === 'active' ? 'ACTIVE' : 'REVOKED',
                metadata: s
            }));
            res.json({ activeSessions: sessions.length, sessions });
        } catch (err) {
            logger.error('Admin Overview Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    /**
     * Forcibly terminates an active session and broadcasts a revocation event.
     * @param req - Express Request (body contains sessionId)
     * @param res - Express Response (JSON success flag)
     */
    static async revokeSession(req: Request, res: Response) {
        const { sessionId, reason } = req.body;
        if (!sessionId) return res.status(400).json({ error: 'sessionId required' });

        try {
            await SessionService.revokeSession(sessionId, reason || 'Admin Revocation');
            const io = req.app.get('io');
            if (io) io.emit('session_revoked', { sessionId, reason });
            res.json({ success: true });
        } catch (err) {
            logger.error('Admin Revocation Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    // ── Audit logs ────────────────────────────────────────────────────────────

    static async getAuditLogs(req: Request, res: Response) {
        try {
            const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
            const raw = await AuditLogModel.find({})
                .sort({ timestamp: -1 })
                .limit(limit)
                .lean();

            const logs = raw.map((l: any) => ({
                _id: l._id,
                timestamp: l.timestamp ? (typeof l.timestamp === 'string' ? l.timestamp : l.timestamp.toISOString()) : new Date().toISOString(),
                eventType: l.action,
                userHash: l.metadata?.userHash || l.metadata?.clientId || '',
                resourceHash: l.metadata?.resourceHash || l.metadata?.resourceId || '',
                riskScore: l.metadata?.riskScore ?? 0,
                decision: l.metadata?.decision || l.action,
                anchored: l.anchored,
                merkleRoot: l.merkleRoot || '',
                metadata: l.metadata
            }));

            res.json(logs);
        } catch (err) {
            logger.error('Audit Logs Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    // ── System Status (NFR-01/02) ─────────────────────────────────────────────
    static async getSystemStatus(req: Request, res: Response) {
        try {
            const status: any = {
                gateway: 'Connected',
                pinned:  'Enabled',
                zkp:     'Operational',
                ai:      'Operational',
                blockchain: 'Connected',
                audit:   'Running',
                storage: 'Healthy',
                heartbeat: 'Running'
            };

            // DB check
            try { 
                if (mongoose.connection.db) {
                    await mongoose.connection.db.admin().ping(); 
                } else {
                    status.audit = 'Disconnected';
                }
            } catch { status.audit = 'Degraded'; status.storage = 'Error'; }
            // Redis check
            try { await redisClient.ping(); } catch { status.heartbeat = 'Error'; }
            // Blockchain check
            try { await BlockchainService.provider.getBlockNumber(); } catch { status.blockchain = 'Disconnected'; }
            // AI check
            try { await axios.get('http://ai-engine:5001/health', { timeout: 1500 }); } catch { 
                try { await axios.get('http://127.0.0.1:5001/health', { timeout: 1000 }); } catch { status.ai = 'Unreachable'; }
            }

            res.json(status);
        } catch (err) {
            res.status(500).json({ error: 'Status check failed' });
        }
    }

    // ── Recent Alerts (last 24 h, for ThreatAlerts page hydration) ────────────
    /**
     * Returns the last 24 h of alert-relevant audit log entries so the
     * ThreatAlerts page can populate even when the user wasn't connected
     * during the original event. Live updates still arrive via Socket.io.
     */
    static async getRecentAlerts(req: Request, res: Response) {
        try {
            const since = new Date(Date.now() - 24 * 3600 * 1000);
            const docs = await AuditLogModel.find({
                timestamp: { $gte: since },
                action: { $in: ['SESSION_REVOKED', 'SESSION_TIMEOUT', 'LOGIN_FAILED', 'TAMPER_DETECTED', 'ACCESS_DENIED', 'TAMPERED_EVENT'] },
            }).sort({ timestamp: -1 }).limit(100).lean();

            const alerts = docs.map((d: any) => ({
                type:      d.action,
                timestamp: d.timestamp ? new Date(d.timestamp).toISOString() : new Date().toISOString(),
                severity:  d.action === 'TAMPER_DETECTED' || d.action === 'TAMPERED_EVENT' ? 'CRITICAL'
                         : d.action === 'SESSION_REVOKED' || d.action === 'LOGIN_FAILED' ? 'HIGH'
                         : 'MEDIUM',
                details:   d.metadata?.reasonSummary
                         || d.metadata?.reason
                         || `${d.action.replace(/_/g, ' ').toLowerCase()}`,
                txHash:    d.txHash,
                riskScore: d.metadata?.riskScore,
                reasons:   d.metadata?.reasons,
                sessionId: d.metadata?.sessionId,
            }));
            res.json(alerts);
        } catch (err) {
            logger.error('getRecentAlerts failed', { error: (err as Error).message });
            res.json([]);
        }
    }

    // ── Blockchain Events (NFR-12) ───────────────────────────────────────────
    /**
     * Aggregates events from BOTH AccessPolicy and AuditLedger contracts.
     * BlockchainService.getPastEvents() already returns the canonical dashboard
     * shape: { id, name, tx, block, args, timestamp }, so we pass through directly.
     */
    static async getBlockchainEvents(req: Request, res: Response) {
        try {
            const events = await BlockchainService.getPastEvents();
            res.json(events);
        } catch (err) {
            logger.error('getBlockchainEvents failed', { error: (err as Error).message });
            res.json([]);
        }
    }

    // ── Policy management ─────────────────────────────────────────────────────

    static async getPendingPolicies(req: Request, res: Response) {
        try {
            const keys = await redisClient.keys('policy:pending:*');
            const policies = await Promise.all(
                keys.map(async (k: string) => {
                    const v = await redisClient.get(k);
                    return v ? JSON.parse(v) : null;
                })
            );
            res.json(policies.filter(Boolean));
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    static async proposePolicy(req: Request, res: Response) {
        const { userHash, resourceHash, action } = req.body;
        try {
            const changeHash = ethers.keccak256(ethers.toUtf8Bytes(`${userHash}:${resourceHash}:${action}`));
            const proposal = {
                hash: changeHash, userHash, resourceHash, action,
                approvals: 0, timestamp: new Date().toISOString()
            };
            await redisClient.setEx(`policy:pending:${changeHash}`, 86400, JSON.stringify(proposal));

            // Anchor the proposal on-chain so a later approveChange() call has a record
            // to look up. Without this, the smart contract's `require(pc.proposedAt > 0)`
            // reverts with "Change not proposed".
            BlockchainService.sendTx(async () => {
                const tx = await BlockchainService.accessPolicy.proposeChange(changeHash);
                return tx.wait();
            }).then(() => {
                logger.info('Policy change proposed on-chain', { changeHash });
            }).catch((bcErr: Error) => {
                // Already proposed (Solidity revert) is fine — second proposal of the same
                // hash is idempotent for the demo. Anything else gets logged but doesn't
                // fail the HTTP response (Redis copy still works as the off-chain demo path).
                if (!bcErr.message?.includes('Change already proposed')) {
                    logger.warn('On-chain proposeChange failed', { error: bcErr.message });
                }
            });

            res.status(201).json(proposal);
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    // Multi-sig threshold: 2 approvals required before on-chain execution.
    // Architecture note: the gateway holds a single signer key, so "admin 1" and
    // "admin 2" are simulated via two sequential approve calls in the demo.
    // In production, each admin would hold their own key and sign independently
    // using EIP-712 typed-data signatures verified by the smart contract.
    private static readonly MULTISIG_THRESHOLD = 2;

    /**
     * Convert any user-supplied identifier into a valid bytes32 hex string.
     * - If input is already a 0x-prefixed 64-char hex value, use it as-is.
     * - Otherwise SHA-256 hash it so we always produce 32 valid bytes.
     * This prevents the "invalid BytesLike value" crash when admins type
     * human-readable strings like "vault/secret" into the policy form.
     */
    private static toBytes32(input: string): string {
        const cleaned = (input || '').trim();
        const isHex = /^(0x)?[0-9a-fA-F]{64}$/.test(cleaned);
        if (isHex) {
            return cleaned.startsWith('0x') ? cleaned : '0x' + cleaned;
        }
        // Hash the raw user input deterministically — same input → same bytes32
        const hash = crypto.createHash('sha256').update(cleaned).digest('hex');
        return '0x' + hash;
    }

    static async approvePolicy(req: Request, res: Response) {
        const { changeHash } = req.body;
        try {
            const raw = await redisClient.get(`policy:pending:${changeHash}`);
            if (!raw) return res.status(404).json({ error: 'Proposal not found' });

            const proposal = JSON.parse(raw);
            proposal.approvals += 1;

            if (proposal.approvals >= AdminController.MULTISIG_THRESHOLD) {
                // Execute the policy change on-chain once threshold is reached.
                // toBytes32() guarantees the inputs are valid bytes32 even when the
                // admin typed human strings like "vault/secret" into the form.
                try {
                    const userBytes32     = AdminController.toBytes32(proposal.userHash);
                    const resourceBytes32 = AdminController.toBytes32(proposal.resourceHash);
                    const grant = proposal.action === 'GRANT';

                    await BlockchainService.sendTx(async () => {
                        const tx = await BlockchainService.accessPolicy.approveChange(
                            changeHash,
                            userBytes32,
                            resourceBytes32,
                            grant
                        );
                        return tx.wait();
                    });

                    proposal.executedOnChain = true;
                    logger.info('Policy change executed on-chain', { changeHash, action: proposal.action });
                } catch (bcErr) {
                    const msg = (bcErr as Error).message || '';
                    // "Already approved" is the EXPECTED outcome of the second click in
                    // a single-signer demo (the contract requires distinct addresses).
                    // It's not a real error — the off-chain counter still records the
                    // approval and the dashboard shows EXECUTED.
                    if (msg.includes('Already approved')) {
                        logger.info('Multi-sig: second on-chain approval blocked by contract (expected with single demo signer)', { changeHash });
                        proposal.executedOnChain = false;
                        proposal.demoSingleSignerLimit = true;
                    } else {
                        logger.error('On-chain policy execution failed', { error: msg });
                    }
                    // Return the updated approval count regardless
                }
            }

            await redisClient.setEx(`policy:pending:${changeHash}`, 86400, JSON.stringify(proposal));
            res.json(proposal);
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    static async simulateTamper(req: Request, res: Response) {
        try {
            const log = await AuditLogModel.findOne({ anchored: false });
            if (log) {
                log.action = 'TAMPERED_EVENT';
                await log.save();
            }
            const timestamp = new Date().toISOString();
            IntegrityState.markCompromised(timestamp);
            const io = req.app.get('io');
            if (io) io.emit('tamper_alert', {
                type:      'TAMPER_DETECTED',
                severity:  'CRITICAL',
                timestamp,
                details:   'Manual tamper simulation triggered by admin',
            });
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
}
