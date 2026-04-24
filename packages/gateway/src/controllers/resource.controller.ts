import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { BlockchainService } from '../services/blockchain.service';
import { SessionService } from '../services/session.service';
import { AuditService } from '../services/audit.service';
import { getIO } from '../services/socket.service';
// @ts-ignore — JS module without types
import { getRiskScore, evaluateRiskScore } from '../services/aiClient';
import crypto from 'crypto';

/**
 * ResourceController — Sequence 2.
 * Validates the session, scores the request with the AI engine, checks the
 * on-chain access policy, and returns an allow/deny decision.
 * After each decision it broadcasts updated session data to the Trust Dashboard.
 */
export class ResourceController {

    /** Pushes updated session list to the Trust Dashboard via Socket.io. */
    private static async broadcastState(req: Request): Promise<void> {
        const broadcastFn = req.app.get('broadcastState');
        if (broadcastFn) {
            await broadcastFn().catch(() => {/* ignore if socket not ready */});
        }
    }

    static async requestAccess(req: Request, res: Response) {
        const { sessionId, resourceId, telemetry } = req.body;

        try {
            // 1. Validate the session
            const session = await SessionService.getSession(sessionId);
            if (!session) {
                await AuditService.log('ACCESS_DENIED', { sessionId, resourceId, reason: 'Invalid session' });
                return res.status(401).json({ error: 'Invalid or expired session' });
            }

            // 2. Score the request with the AI risk engine
            const riskScore: number = await getRiskScore({
                sessionId,
                resourceId,
                simulateAnomaly: telemetry?.simulateAnomaly ?? false,
                ...telemetry,
            });

            const decision = evaluateRiskScore(riskScore);

            // Persist the latest risk score on the session so the dashboard shows it
            await SessionService.updateRiskScore(sessionId, riskScore);

            if (decision === 'REVOKE') {
                await SessionService.revokeSession(sessionId, 'High AI Risk Score');
                await AuditService.log('SESSION_REVOKED', { sessionId, riskScore, reason: 'High Risk' });

                // Notify the Trust Dashboard in real-time
                try {
                    const io = getIO();
                    io.emit('session_revoked', { sessionId, reason: 'High Risk Score' });
                    io.emit('tamper_alert', {
                        type:      'ANOMALY_DETECTED',
                        severity:  'CRITICAL',
                        timestamp: new Date().toISOString(),
                        details:   `Session ${sessionId.substring(0, 8)}… revoked — AI risk score ${riskScore}/100`,
                    });
                } catch { /* socket not ready */ }

                await ResourceController.broadcastState(req);
                return res.status(403).json({
                    error:     'Access Denied: High Risk Detected. Session Revoked.',
                    riskScore,
                    decision,
                });
            }

            // 3. Check on-chain access policy
            const userHash          = session.userHash;
            const userHashBytes32   = `0x${userHash}`;
            const resourceHash      = crypto.createHash('sha256').update(resourceId).digest('hex');
            const resourceHashBytes32 = `0x${resourceHash}`;

            const isAllowed = await BlockchainService.accessPolicy.checkAccess(userHashBytes32, resourceHashBytes32);

            if (!isAllowed) {
                await AuditService.log('ACCESS_DENIED', { sessionId, userHash, resourceId, riskScore, reason: 'Policy restriction' });
                await ResourceController.broadcastState(req);
                return res.status(403).json({ error: 'Access Denied: Policy Violation', riskScore, decision });
            }

            // 4. Grant access — log with hashes for audit trail
            await AuditService.log('ACCESS_GRANTED', {
                sessionId, userHash, resourceId,
                resourceHash, riskScore, decision,
            });

            // Emit blockchain event for real-time Blockchain tab
            try {
                const io = getIO();
                io.emit('blockchain_event', {
                    id:          sessionId + Date.now(),
                    event:       'AccessDecision',
                    txHash:      '0x' + resourceHash,
                    blockNumber: 0,
                    timestamp:   new Date().toISOString(),
                    details:     { allowed: true, riskScore, decision },
                });
            } catch { /* socket not ready */ }

            await ResourceController.broadcastState(req);

            res.json({ success: true, riskScore, accessGranted: true, decision });
        } catch (err) {
            logger.error('Resource Access Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Access Denied: Security Service Unreachable' });
        }
    }
}
