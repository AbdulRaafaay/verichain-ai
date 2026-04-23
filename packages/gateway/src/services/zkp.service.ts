// @ts-ignore
import * as snarkjs from 'snarkjs';
import path from 'path';
import fs from 'fs';
import { logger } from '../utils/logger';

/**
 * ZKPService verifies Zero-Knowledge Proofs (Sequence 1 Step 3).
 * NFR-04: Proof validation must be fail-closed.
 */
export class ZKPService {
    private static VK_PATH = path.resolve(__dirname, '../config/zkp/verification_key.json');

    static async verifyProof(proof: any, publicSignals: any): Promise<boolean> {
        try {
            if (!fs.existsSync(this.VK_PATH)) {
                logger.error('ZKP Verification Key missing', { path: this.VK_PATH });
                return false; // Fail-closed
            }

            const vKey = JSON.parse(fs.readFileSync(this.VK_PATH, 'utf-8'));
            const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
            
            if (res) {
                logger.info('ZKP Proof Verified successfully');
            } else {
                logger.warn('ZKP Proof Verification FAILED');
            }
            
            return res;
        } catch (err) {
            logger.error('ZKP Service Error', { error: (err as Error).message });
            return false; // Fail-closed
        }
    }
}
