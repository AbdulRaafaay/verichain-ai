import { Request, Response } from 'express';
import { SessionService } from '../services/session.service';
import { logger } from '../utils/logger';

export class HeartbeatController {

    static async ping(req: Request, res: Response) {
        const { sessionId } = req.body;

        try {
            const updated = await SessionService.updateHeartbeat(sessionId);
            if (!updated) {
                return res.status(401).json({ error: 'Session expired or invalid' });
            }

            logger.info(`Heartbeat received: ${sessionId}`);

            // Broadcast updated session state to Trust Dashboard so lastHeartbeat refreshes
            const broadcastFn = req.app.get('broadcastState');
            if (broadcastFn) broadcastFn().catch(() => {});

            res.json({ status: 'alive', timestamp: new Date().toISOString() });
        } catch (err) {
            logger.error('Heartbeat Error', { error: (err as Error).message });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
}
