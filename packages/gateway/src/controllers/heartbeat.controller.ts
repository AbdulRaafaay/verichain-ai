import { Request, Response } from 'express';
import { SessionService } from '../services/session.service';
import { logger } from '../utils/logger';

/**
 * HeartbeatController processes periodic agent pings (Sequence 3 Step 1).
 */
export class HeartbeatController {
    static async ping(req: Request, res: Response) {
        const { sessionId } = req.body;
        if (!sessionId) return res.status(400).json({ error: 'SessionId required' });

        try {
            const updated = await SessionService.updateHeartbeat(sessionId);
            if (!updated) {
                return res.status(401).json({ error: 'Session expired or invalid' });
            }

            res.json({ status: 'alive', timestamp: new Date().toISOString() });
        } catch (err) {
            logger.error('Heartbeat Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
}
