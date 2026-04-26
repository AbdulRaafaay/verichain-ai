import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { BlockchainService } from '../services/blockchain.service';
import { SessionService } from '../services/session.service';
import { AuditService } from '../services/audit.service';
import { getIO } from '../services/socket.service';
// @ts-ignore — JS module without types
import { getRiskAssessment, evaluateRiskScore } from '../services/aiClient';
import crypto from 'crypto';

/**
 * ResourceController — Sequence 2.
 * Validates the session, scores the request with the AI engine, checks the on-chain
 * access policy via a `view` call, and returns an allow/deny decision with explainability.
 *
 * Every decision now includes a `reasons` array sourced from the AI engine's per-feature
 * z-score analysis, so logs and the desktop agent can show *why* the request was scored
 * the way it was instead of just a bare number.
 */
export class ResourceController {

    private static async broadcastState(req: Request): Promise<void> {
        const broadcastFn = req.app.get('broadcastState');
        if (broadcastFn) {
            await broadcastFn().catch(() => {/* ignore if socket not ready */});
        }
    }

    /** Format reasons array into a human-readable summary string for logs. */
    private static summariseReasons(reasons: any[]): string {
        if (!reasons || !reasons.length) return 'no anomalous features';
        return reasons.map(r => {
            // System faults (engine_unreachable, invalid_response) have no z-score —
            // print a clean label rather than "feature: undefined (expected ~?, z=undefined)"
            if (r.systemFault || typeof r.zScore !== 'number') {
                return r.label || r.feature || 'unknown system fault';
            }
            return `${r.label || r.feature}: ${r.value}${r.unit || ''} (expected ~${typeof r.expected === 'number' ? r.expected.toFixed(1) : '?'}, z=${r.zScore})`;
        }).join('; ');
    }

    static async requestAccess(req: Request, res: Response) {
        const { sessionId, resourceId, telemetry } = req.body;

        try {
            // 1. Validate the session
            const session = await SessionService.getSession(sessionId);
            if (!session) {
                await AuditService.log('ACCESS_DENIED', { sessionId, resourceId, reason: 'Invalid session' });
                return res.status(401).json({ error: 'Invalid or expired session', reason: 'Session does not exist or has expired' });
            }

            // 2. Score the request with the AI engine — returns score, top reasons,
            //    and any post-hoc score-floor tag explaining hybrid scoring decisions.
            const assessment = await getRiskAssessment({
                sessionId,
                resourceId,
                ...telemetry,
            });
            const riskScore: number = assessment.score;
            const reasons: any[]    = assessment.reasons || [];
            const scoreFloor: string | null = assessment.scoreFloor || null;
            const decision: 'PERMIT' | 'STEP_UP' | 'REVOKE' = evaluateRiskScore(riskScore);

            const reasonSummary = ResourceController.summariseReasons(reasons);
            const floorTag = scoreFloor ? ` | floor=${scoreFloor}` : '';

            await SessionService.updateRiskScore(sessionId, riskScore);

            if (decision === 'REVOKE') {
                logger.warn(`AI REVOKE | session=${sessionId.substring(0, 8)} score=${riskScore}${floorTag} | ${reasonSummary}`);
                await SessionService.revokeSession(sessionId, 'High AI Risk Score');
                await AuditService.log('SESSION_REVOKED', {
                    sessionId, riskScore, decision, reasons, scoreFloor,
                    reason: 'High Risk',
                    reasonSummary,
                });

                BlockchainService.revokeSession(sessionId, 'High AI Risk Score')
                    .catch((bcErr: Error) => logger.error('On-chain REVOKE failed', { error: bcErr.message }));

                try {
                    const io = getIO();
                    io.emit('session_revoked', { sessionId, reason: 'High Risk Score', riskScore, reasons, scoreFloor });
                    io.emit('tamper_alert', {
                        type:      'ANOMALY_DETECTED',
                        severity:  'CRITICAL',
                        timestamp: new Date().toISOString(),
                        details:   `Session ${sessionId.substring(0, 8)}… revoked — risk ${riskScore}/100. ${reasonSummary}`,
                        riskScore,
                        reasons,
                        scoreFloor,
                    });
                } catch { /* socket not ready */ }

                await ResourceController.broadcastState(req);
                return res.status(403).json({
                    error:     'Access Denied: High Risk Detected. Session Revoked.',
                    riskScore,
                    decision,
                    reasons,
                    reasonSummary,
                    scoreFloor,
                });
            }

            if (decision === 'STEP_UP') {
                logger.warn(`AI STEP_UP | session=${sessionId.substring(0, 8)} score=${riskScore}${floorTag} | ${reasonSummary}`);
            }

            // 3. On-chain access policy check (read-only view function)
            const userHash            = session.userHash;
            const userHashBytes32     = BlockchainService.toBytes32(userHash);
            const resourceHash        = crypto.createHash('sha256').update(resourceId).digest('hex');
            const resourceHashBytes32 = BlockchainService.toBytes32(resourceHash);

            const hasExplicitRule = await BlockchainService.isAccessAllowed(userHashBytes32, resourceHashBytes32);

            // Demo policy: AI is the gatekeeper. PERMIT/STEP_UP both pass when no explicit
            // on-chain rule exists. Production should switch this to deny-by-default.
            // hasExplicitRule is recorded in the audit log either way.

            await AuditService.log('ACCESS_GRANTED', {
                sessionId, userHash, resourceId,
                resourceHash, riskScore, decision,
                reasons, reasonSummary, scoreFloor,
                policyMatched: hasExplicitRule,
            });

            await SessionService.updateCurrentResource(sessionId, resourceId);

            // Fire-and-forget on-chain audit-trail emission via sendTx queue
            BlockchainService.sendTx(async () => {
                const tx = await BlockchainService.accessPolicy.checkAccess(userHashBytes32, resourceHashBytes32);
                return tx.wait();
            }).catch((bcErr: Error) => logger.warn('On-chain AccessDecision emit failed', { error: bcErr.message }));

            await ResourceController.broadcastState(req);

            res.json({
                success: true,
                riskScore,
                accessGranted: true,
                decision,
                resourceId,
                reasons,
                reasonSummary: decision === 'STEP_UP' ? reasonSummary : '',
                scoreFloor,
            });
        } catch (err) {
            logger.error('Resource Access Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Access Denied: Security Service Unreachable', reason: 'Backend error' });
        }
    }
}
