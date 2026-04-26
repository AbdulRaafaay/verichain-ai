import { Server } from 'socket.io';
import { logger } from '../utils/logger';
import { SessionService } from './session.service';
import crypto from 'crypto';

let io: Server;

const ADMIN_KEY = process.env.ADMIN_API_KEY;

/** Constant-time string compare so admin-key validation is timing-attack resistant. */
function timingSafeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export const initSocket = (server: any) => {
    const allowedOrigin = process.env.TRUST_DASHBOARD_ORIGIN || 'http://localhost:3005';
    logger.info(`Socket.io Initializing. Allowed Origin: ${allowedOrigin}`);

    io = new Server(server, {
        cors: {
            origin: allowedOrigin,
            methods: ['GET', 'POST'],
            credentials: true,
        }
    });

    // Authentication middleware — applied before any event handler.
    // Dashboard clients must present the admin key in socket.handshake.auth.token.
    // Desktop Agent clients authenticate with their session ID, which we validate
    // against Redis to ensure it actually exists.
    io.use(async (socket, next) => {
        const token     = socket.handshake.auth?.token as string | undefined;
        const sessionId = socket.handshake.query?.sessionId as string | undefined;

        if (token) {
            // Dashboard client path
            if (!ADMIN_KEY) return next(new Error('Server misconfigured: admin key not set'));
            if (!timingSafeEquals(token, ADMIN_KEY)) {
                logger.warn('WebSocket auth rejected: invalid admin token', { id: socket.id });
                return next(new Error('Unauthorized'));
            }
            return next();
        }

        if (sessionId) {
            // Desktop Agent path — verify session exists in Redis. Without this,
            // any client passing ?sessionId=anything would receive private events.
            try {
                const session = await SessionService.getSession(sessionId);
                if (!session) {
                    logger.warn('WebSocket auth rejected: unknown sessionId', { id: socket.id });
                    return next(new Error('Unauthorized'));
                }
                return next();
            } catch (err) {
                logger.warn('WebSocket auth rejected: session lookup failed', { error: (err as Error).message });
                return next(new Error('Unauthorized'));
            }
        }

        logger.warn('WebSocket connection rejected: no credentials', { id: socket.id });
        next(new Error('Unauthorized'));
    });

    io.on('connection', (socket) => {
        const isAgent = !!socket.handshake.query?.sessionId;
        logger.info(isAgent ? 'Desktop Agent connected via WebSocket' : 'Trust Dashboard connected via WebSocket', { socketId: socket.id });

        socket.on('disconnect', () => {
            logger.info('WebSocket client disconnected', { socketId: socket.id });
        });
    });

    return io;
};

export const getIO = () => {
    if (!io) throw new Error('Socket.io not initialized');
    return io;
};

export const broadcastSecurityAlert = (alert: any) => {
    if (io) {
        io.emit('security_alert', alert);
        logger.info('Security Alert Broadcasted', alert);
    }
};
