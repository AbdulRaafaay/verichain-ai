import { Request, Response } from 'express';
import { ZKPService } from '../services/zkp.service';
import { SessionService } from '../services/session.service';
import { NonceService } from '../services/nonce.service';
import { AuditService } from '../services/audit.service';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * AuthController handles the ZKP-based authentication flow (Sequence 1).
 */
export class AuthController {
    static async getNonce(req: Request, res: Response) {
        const { clientId } = req.query;
        if (!clientId) return res.status(400).json({ error: 'clientId required' });
        
        try {
            const nonce = await NonceService.generateNonce(clientId as string);
            res.json({ nonce });
        } catch (err) {
            res.status(500).json({ error: 'Failed to generate nonce' });
        }
    }

    static async login(req: Request, res: Response) {
        const { clientId, nonce, proof, publicSignals, userHash } = req.body;

        try {
            // 1. Verify and Burn Nonce
            const isNonceValid = await NonceService.verifyAndBurn(clientId, nonce);
            if (!isNonceValid) {
                await AuditService.log('LOGIN_FAILED', { clientId, reason: 'Invalid nonce' });
                return res.status(401).json({ error: 'Invalid or expired nonce' });
            }

            // 2. Verify ZKP Proof (Real Logic)
            const isProofValid = await ZKPService.verifyProof(proof, publicSignals);
            if (!isProofValid) {
                await AuditService.log('LOGIN_FAILED', { clientId, userHash, reason: 'ZKP verification failed' });
                return res.status(403).json({ error: 'ZKP Proof Verification Failed' });
            }

            // 3. Create Session in Redis
            const sessionId = crypto.randomUUID();
            await SessionService.createSession(sessionId, { userHash, clientId });

            logger.info(`User ${userHash} logged in with session ${sessionId}`);
            await AuditService.log('LOGIN_SUCCESS', { sessionId, userHash, clientId });

            res.json({
                status: 'success',
                sessionId,
                expiresIn: 3600
            });
        } catch (err) {
            logger.error('Login Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Authentication Error' });
        }
    }
}
