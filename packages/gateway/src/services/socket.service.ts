import { Server } from 'socket.io';
import { logger } from '../utils/logger';

let io: Server;

export const initSocket = (server: any) => {
    io = new Server(server, {
        cors: {
            origin: '*', // In production, restrict to TRUST_DASHBOARD_ORIGIN
            methods: ['GET', 'POST']
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
