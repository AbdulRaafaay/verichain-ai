import { Request, Response } from 'express';
import { SessionService } from '../services/session.service';
import { logger } from '../utils/logger';

/**
 * AdminController handles high-privileged actions for the Trust Dashboard.
 * Maps to Phase 7 Gaps.
 */
export class AdminController {
    static async getOverview(req: Request, res: Response) {
        try {
            const sessions = await SessionService.getAllSessions();
            res.json({
                activeSessions: sessions.length,
                sessions: sessions
            });
        } catch (err) {
            logger.error('Admin Overview Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

    static async revokeSession(req: Request, res: Response) {
        const { sessionId, reason } = req.body;
        if (!sessionId) return res.status(400).json({ error: 'SessionId required' });

        try {
            await SessionService.revokeSession(sessionId, reason || 'Admin Revocation');
            
            // Broadcast via Socket.io if available
            const io = req.app.get('io');
            if (io) {
                io.emit('session_revoked', { sessionId, reason });
            }

            res.json({ success: true, message: `Session ${sessionId} revoked` });
        } catch (err) {
            logger.error('Admin Revocation Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
}
