import redisClient from './redisClient';
import crypto from 'crypto';

/**
 * NonceService handles one-time-use tokens to prevent replay attacks (Sequence 1).
 * High-performance Redis implementation.
 */
export class NonceService {
    private static TTL = 300; // 5 minutes

    static async generateNonce(clientId: string): Promise<string> {
        // 16 bytes of CSPRNG → 32-char hex string parseable by Desktop Agent
        const nonce = crypto.randomBytes(16).toString('hex');
        await redisClient.setEx(`nonce:${clientId}:${nonce}`, this.TTL, '1');
        return nonce;
    }

    static async verifyAndBurn(clientId: string, nonce: string): Promise<boolean> {
        const key = `nonce:${clientId}:${nonce}`;
        const exists = await redisClient.del(key);
        return exists === 1;
    }
}
