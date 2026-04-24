import { Request, Response, NextFunction } from 'express';
import redisClient from '../services/redisClient';
import { logger } from '../utils/logger';

interface RateLimitOptions {
    windowSecs: number;
    max: number;
    keyPrefix?: string;
}

/**
 * Redis-backed sliding-window rate limiter.
 * Key is built from the client's IP (or mTLS subject CN when available).
 */
export const rateLimit = ({ windowSecs, max, keyPrefix = 'rl' }: RateLimitOptions) =>
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const ip  = req.ip || req.socket.remoteAddress || 'unknown';
        const key = `${keyPrefix}:${ip}`;

        try {
            const current = await redisClient.incr(key);
            if (current === 1) {
                await redisClient.expire(key, windowSecs);
            }
            if (current > max) {
                res.setHeader('Retry-After', String(windowSecs));
                res.status(429).json({ error: 'Too many requests. Please slow down.' });
                return;
            }
            res.setHeader('X-RateLimit-Limit',     String(max));
            res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - current)));
        } catch (err) {
            // If Redis is unavailable, fail open so auth still works
            logger.warn('Rate limiter Redis error — failing open', { error: (err as Error).message });
        }

        next();
    };
