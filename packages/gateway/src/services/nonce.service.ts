import redisClient from './redisClient';
import { logger } from '../utils/logger';

/**
 * NonceService handles one-time-use tokens to prevent replay attacks (Sequence 1).
 * High-performance Redis implementation.
 */
export class NonceService {
    private static TTL = 300; // 5 minutes

    static async generateNonce(clientId: string): Promise<string> {
        const nonce = Math.random().toString(36).substring(2, 15);
        await redisClient.setEx(`nonce:${clientId}:${nonce}`, this.TTL, '1');
        return nonce;
    }

    static async verifyAndBurn(clientId: string, nonce: string): Promise<boolean> {
        const key = `nonce:${clientId}:${nonce}`;
        const exists = await redisClient.del(key);
        return exists === 1;
    }
}
