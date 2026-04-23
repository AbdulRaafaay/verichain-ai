import { createClient } from 'redis';
import { logger } from '../utils/logger';

const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';

const redisClient = createClient({
    url: redisUrl
});

redisClient.on('error', (err) => logger.error('Redis Client Error', { error: err.message }));
redisClient.on('connect', () => logger.info('Redis Client Connected'));

export const initRedis = async () => {
    if (!redisClient.isOpen) {
        await redisClient.connect();
    }
};

export default redisClient;
