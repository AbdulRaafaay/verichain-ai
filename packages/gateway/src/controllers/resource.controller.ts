import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { BlockchainService } from '../services/blockchain.service';
import { SessionService } from '../services/session.service';
import { AuditService } from '../services/audit.service';
// @ts-ignore
import { getRiskScore, evaluateRiskScore } from '../services/aiClient';
import crypto from 'crypto';

/**
 * ResourceController manages access requests to protected resources.
 * Sequence 2 & 3 implementation.
 */
export class ResourceController {
    static async requestAccess(req: Request, res: Response) {
        const { sessionId, resourceId, telemetry } = req.body;
        
        try {
            // 1. Validate Session (Redis)
            const session = await SessionService.getSession(sessionId);
            if (!session) {
                await AuditService.log('ACCESS_DENIED', { sessionId, resourceId, reason: 'Invalid session' });
                return res.status(401).json({ error: 'Invalid or expired session' });
            }

            // 2. Call AI Risk Engine (HMAC)
            const riskScore = await getRiskScore({
                sessionId,
                resourceId,
                ...telemetry
            });

            const riskEvaluation = evaluateRiskScore(riskScore);
            
            if (riskEvaluation === 'REVOKE') {
                await SessionService.revokeSession(sessionId, 'High AI Risk Score');
                await AuditService.log('SESSION_REVOKED', { sessionId, riskScore, reason: 'High Risk' });
                return res.status(403).json({ error: 'Access Denied: High Risk Detected. Session Revoked.' });
            }

            // 3. Check AccessPolicy.sol (Blockchain)
            const userHash = session.userHash;
            // Use keccak256 as per requirement FR-10
            const userHashBytes32 = `0x${userHash}`;
            const resourceHash = crypto.createHash('sha256').update(resourceId).digest('hex');
            const resourceHashBytes32 = `0x${resourceHash}`;

            const isAllowed = await BlockchainService.accessPolicy.checkAccess(userHashBytes32, resourceHashBytes32);
            
            if (!isAllowed) {
                await AuditService.log('ACCESS_DENIED', { sessionId, userHash, resourceId, riskScore, reason: 'Policy restriction' });
                return res.status(403).json({ error: 'Access Denied: Policy Violation' });
            }

            // 4. Return Decision
            await AuditService.log('ACCESS_GRANTED', { sessionId, userHash, resourceId, riskScore });
            
            res.json({
                success: true,
                riskScore,
                accessGranted: true,
                evaluation: riskEvaluation
            });
        } catch (err) {
            logger.error('Resource Access Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Access Denied: Security Service Unreachable' });
        }
    }
}
