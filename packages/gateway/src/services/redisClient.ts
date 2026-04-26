import { createClient } from 'redis';
import { logger } from '../utils/logger';
import EventEmitter from 'events';

const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';

const redisClient = createClient({ url: redisUrl });

redisClient.on('error', (err) => logger.error('Redis Client Error', { error: err.message }));
redisClient.on('connect', () => logger.info('Redis Client Connected'));

// Emits 'session:expired' when a session key's TTL fires so other services
// can perform coordinated cleanup (e.g. on-chain revocation) without circular deps.
export const sessionEvents = new EventEmitter();

export const initRedis = async () => {
    if (!redisClient.isOpen) {
        await redisClient.connect();
    }

    // Enable keyspace notifications for expired-key events (Redis config: "Ex")
    try {
        await redisClient.sendCommand(['CONFIG', 'SET', 'notify-keyspace-events', 'Ex']);

        // Subscriber must be a separate client — a subscribed client cannot issue commands
        const subscriber = redisClient.duplicate();
        await subscriber.connect();

        // __keyevent@0__:expired fires whenever a key expires in DB 0
        await subscriber.subscribe('__keyevent@0__:expired', (key: string) => {
            if (key.startsWith('session:')) {
                const sessionId = key.slice('session:'.length);
                logger.info(`Redis TTL expired for session: ${sessionId}`);
                sessionEvents.emit('session:expired', sessionId);
            }
        });

        logger.info('Redis keyspace notifications enabled (expired-key subscriber active)');
    } catch (err: any) {
        // Some managed Redis providers disable CONFIG SET — log and continue
        logger.warn('Could not enable Redis keyspace notifications', { error: err.message });
    }
};

export default redisClient;
