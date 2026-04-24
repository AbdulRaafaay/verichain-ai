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
import axios from 'axios';
import mongoose from 'mongoose';
import { SessionService } from '../services/session.service';
import { BlockchainService } from '../services/blockchain.service';
import { AuditLogModel } from '../models/audit-log.model';
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

    // ── Blockchain Events (NFR-12) ───────────────────────────────────────────
    static async getBlockchainEvents(req: Request, res: Response) {
        try {
            const filter = {
                address: BlockchainService.accessPolicy.target,
                fromBlock: 0,
                toBlock: 'latest'
            };
            const logs = await BlockchainService.provider.getLogs(filter as any);
            const events = logs.map((l: any) => {
                const parsed = BlockchainService.accessPolicy.interface.parseLog(l);
                return {
                    id: l.transactionHash.substring(0, 12),
                    name: parsed?.name || 'Unknown',
                    args: parsed?.args ? Object.fromEntries(
                        Object.entries(parsed.args).filter(([k]) => isNaN(Number(k)))
                    ) : {},
                    block: l.blockNumber,
                    tx: l.transactionHash
                };
            }).reverse();
            res.json(events);
        } catch (err) {
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
            res.status(201).json(proposal);
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    static async approvePolicy(req: Request, res: Response) {
        const { changeHash } = req.body;
        try {
            const raw = await redisClient.get(`policy:pending:${changeHash}`);
            if (!raw) return res.status(404).json({ error: 'Proposal not found' });
            const proposal = JSON.parse(raw);
            proposal.approvals += 1;
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
            const io = req.app.get('io');
            if (io) io.emit('tamper_alert', {
                type: 'TAMPER_DETECTED',
                timestamp: new Date().toISOString()
            });
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
}
