import { Request, Response } from 'express';
import { ZKPService } from '../services/zkp.service';
import { SessionService } from '../services/session.service';
import { NonceService } from '../services/nonce.service';
import { AuditService } from '../services/audit.service';
import { BlockchainService } from '../services/blockchain.service';
import { getIO } from '../services/socket.service';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * AuthController handles the ZKP-based authentication flow (Sequence 1).
 * After successful login it triggers the shared broadcastState helper so the
 * Trust Dashboard reflects the new session in real time without polling.
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
            // 1. Verify and burn the one-time nonce (replay protection)
            const isNonceValid = await NonceService.verifyAndBurn(clientId, nonce);
            if (!isNonceValid) {
                await AuditService.log('LOGIN_FAILED', { clientId, reason: 'Invalid nonce' });
                return res.status(401).json({ error: 'Invalid or expired nonce' });
            }

            // 2. Verify the Groth16 ZK proof
            const isProofValid = await ZKPService.verifyProof(proof, publicSignals);
            if (!isProofValid) {
                await AuditService.log('LOGIN_FAILED', { clientId, userHash, reason: 'ZKP verification failed' });
                return res.status(403).json({ error: 'ZKP Proof Verification Failed' });
            }

            // 3. Create authenticated session in Redis
            const sessionId = crypto.randomUUID();
            await SessionService.createSession(sessionId, { userHash, clientId, riskScore: 0 });

            logger.info(`User ${userHash} authenticated — session ${sessionId}`);
            await AuditService.log('LOGIN_SUCCESS', { sessionId, userHash, clientId });

            // 4. Anchor session on-chain (NFR-06) — non-blocking, serialised via sendTx queue.
            BlockchainService.createSession(sessionId, userHash)
                .then((receipt: any) => {
                    try {
                        const io = getIO();
                        // Canonical dashboard event shape — { id, name, tx, block, args, timestamp }
                        io.emit('blockchain_event', {
                            id:        receipt?.hash ? `${receipt.hash}:created` : `${sessionId}:created`,
                            name:      'SessionCreated',
                            tx:        receipt?.hash ?? '—',
                            block:     receipt?.blockNumber ?? 0,
                            args:      { sessionId, userHash: userHash.substring(0, 16) + '…' },
                            timestamp: new Date().toISOString(),
                        });
                    } catch { /* socket not ready */ }
                })
                .catch((err: Error) => logger.warn('On-chain session creation failed', { error: err.message }));

            // 5. Push live update to Trust Dashboard via shared broadcaster
            const broadcastFn = req.app.get('broadcastState');
            if (broadcastFn) broadcastFn().catch(() => {/* socket not ready */});

            res.json({ status: 'success', sessionId, expiresIn: 3600 });
        } catch (err) {
            logger.error('Login Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Authentication Error' });
        }
    }
}
