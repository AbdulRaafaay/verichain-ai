import { Server } from 'socket.io';
import { logger } from '../utils/logger';

let io: Server;

export const initSocket = (server: any) => {
    const allowedOrigin = process.env.TRUST_DASHBOARD_ORIGIN || 'http://localhost:3001';
    logger.info(`Socket.io Initializing. Allowed Origin: ${allowedOrigin}`);
    io = new Server(server, {
        cors: {
            origin: allowedOrigin,
            methods: ['GET', 'POST'],
            credentials: true,
        }
    });

    io.on('connection', (socket) => {
        logger.info('Trust Dashboard connected via WebSocket', { socketId: socket.id });
        
        socket.on('disconnect', () => {
            logger.info('Dashboard disconnected', { socketId: socket.id });
        });
    });

    return io;
};

export const getIO = () => {
    if (!io) {
        throw new Error('Socket.io not initialized');
    }
    return io;
};

export const broadcastSecurityAlert = (alert: any) => {
    if (io) {
        io.emit('security_alert', alert);
        logger.info('Security Alert Broadcasted', alert);
    }
};
