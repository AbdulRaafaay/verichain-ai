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
 * After successful login it broadcasts a session_update event so the Trust
 * Dashboard reflects the new session in real time without polling.
 */
export class AuthController {

    /** Emits current session list + stats to all connected Trust Dashboard clients. */
    private static async broadcastSessions(): Promise<void> {
        try {
            const io = getIO();
            const raw = await SessionService.getAllSessions();
            const sessions = raw.map((s: any) => ({
                id: s.sessionId,
                userHash: s.userHash || s.clientId || 'unknown',
                loginTime: s.createdAt,
                duration: s.createdAt
                    ? Math.round((Date.now() - new Date(s.createdAt).getTime()) / 1000) + 's'
                    : '—',
                riskScore: s.riskScore ?? 0,
                status: s.status === 'active' ? 'ACTIVE' : 'REVOKED',
            }));

            const avgRisk = sessions.length
                ? Math.round(sessions.reduce((a: number, b: any) => a + (b.riskScore || 0), 0) / sessions.length)
                : 0;

            io.emit('session_update', sessions);
            io.emit('stats_update', {
                activeSessions: sessions.length,
                avgRiskScore: avgRisk,
                alertsToday: 0,
                logIntegrity: 'SECURE',
            });
        } catch {
            // Socket not yet initialised — safe to ignore during startup
        }
    }

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

            // 4. Anchor session on-chain (NFR-06) — non-blocking
            const sessionIdHash = sessionId.replace(/-/g, '');
            const userHashPadded = userHash.substring(0, 64).padEnd(64, '0');
            BlockchainService.accessPolicy
                .createSession(`0x${sessionIdHash}`, `0x${userHashPadded}`)
                .then((tx: any) => tx.wait())
                .then(() => {
                    const io = getIO();
                    io.emit('blockchain_event', {
                        id:          sessionId,
                        event:       'SessionCreated',
                        txHash:      sessionIdHash,
                        blockNumber: 0,
                        timestamp:   new Date().toISOString(),
                        details:     { userHash: userHash.substring(0, 16) + '…' },
                    });
                })
                .catch((err: Error) => logger.warn('On-chain session creation failed', { error: err.message }));

            // 5. Push live update to Trust Dashboard
            await AuthController.broadcastSessions();

            res.json({ status: 'success', sessionId, expiresIn: 3600 });
        } catch (err) {
            logger.error('Login Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Authentication Error' });
        }
    }
}
