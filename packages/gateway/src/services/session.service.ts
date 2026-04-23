import redisClient from './redisClient';
import { logger } from '../utils/logger';
import { BlockchainService } from './blockchain.service';
import { AuditService } from './audit.service';

/**
 * SessionService manages active authenticated sessions (Sequence 1/2/3).
 * Stored in Redis for high-speed lookup and automatic TTL expiry.
 */
export class SessionService {
    private static SESSION_TTL = 3600; // 1 hour
    private static HEARTBEAT_TIMEOUT = 35; // Seconds

    static startHeartbeatWatchdog() {
        setInterval(async () => {
            try {
                const sessions = await this.getAllSessions();
                const now = new Date();
                
                for (const session of sessions) {
                    const lastHeartbeat = new Date(session.lastHeartbeat);
                    const diffSeconds = (now.getTime() - lastHeartbeat.getTime()) / 1000;
                    
                    if (diffSeconds > this.HEARTBEAT_TIMEOUT) {
                        logger.warn(`Session ${session.sessionId} timed out. Revoking on-chain.`);
                        await this.revokeSession(session.sessionId, 'Heartbeat Timeout');
                        await AuditService.log('SESSION_TIMEOUT', { sessionId: session.sessionId, lastHeartbeat: session.lastHeartbeat });
                        
                        // Blockchain revocation (NFR-06)
                        try {
                            const tx = await BlockchainService.accessPolicy.revokeSession(
                                `0x${session.sessionId.replace(/-/g, '')}`, 
                                'Heartbeat Timeout'
                            );
                            await tx.wait();
                        } catch (bcErr) {
                            logger.error('Failed to revoke session on-chain', { error: (bcErr as Error).message });
                        }
                    }
                }
            } catch (err) {
                logger.error('Heartbeat Watchdog Error', { error: (err as Error).message });
            }
        }, 5000); // Check every 5 seconds (NFR-06)
    }

    static async createSession(sessionId: string, data: any): Promise<void> {
        await redisClient.setEx(
            `session:${sessionId}`,
            this.SESSION_TTL,
            JSON.stringify({
                ...data,
                sessionId,
                createdAt: new Date().toISOString(),
                lastHeartbeat: new Date().toISOString(),
                status: 'active'
            })
        );
        logger.info(`Session created: ${sessionId}`);
    }

    static async getSession(sessionId: string): Promise<any | null> {
        const data = await redisClient.get(`session:${sessionId}`);
        return data ? JSON.parse(data) : null;
    }

    static async updateHeartbeat(sessionId: string): Promise<boolean> {
        const session = await this.getSession(sessionId);
        if (!session) return false;

        session.lastHeartbeat = new Date().toISOString();
        await redisClient.setEx(
            `session:${sessionId}`,
            this.SESSION_TTL,
            JSON.stringify(session)
        );
        return true;
    }

    static async revokeSession(sessionId: string, reason: string): Promise<void> {
        await redisClient.del(`session:${sessionId}`);
        logger.warn(`Session revoked: ${sessionId} | Reason: ${reason}`);
    }

    static async getAllSessions(): Promise<any[]> {
        const keys = await redisClient.keys('session:*');
        const sessions = await Promise.all(keys.map(async (key) => {
            const data = await redisClient.get(key);
            return data ? JSON.parse(data) : null;
        }));
        return sessions.filter(s => s !== null);
    }
}
