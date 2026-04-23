import { MerkleTree } from 'merkletreejs';
import crypto from 'crypto';
import { AuditLogModel } from '../models/audit-log.model';
import { BlockchainService } from './blockchain.service';
import { logger } from '../utils/logger';
import { broadcastSecurityAlert } from './socket.service';

/**
 * MerkleService handles the batching of audit logs and anchoring roots to blockchain.
 * NFR-13/14: Immutable Merkle Root Anchoring & Tamper Detection.
 */
export class MerkleService {
    private static BATCH_INTERVAL = 60000; // 1 minute

    static startBatcher() {
        setInterval(async () => {
            try {
                await this.processBatch();
            } catch (err) {
                logger.error('Merkle Batching Error', { error: (err as Error).message });
            }
        }, this.BATCH_INTERVAL);
    }

    private static async processBatch() {
        // 1. Fetch unanchored logs
        const logs = await AuditLogModel.find({ anchored: false }).limit(100);
        if (logs.length === 0) return;

        logger.info(`Starting Merkle batch for ${logs.length} logs...`);

        // 2. Build Merkle Tree
        const leaves = logs.map(log => 
            crypto.createHash('sha256').update(JSON.stringify(log.metadata)).digest()
        );
        const tree = new MerkleTree(leaves, crypto.createHash('sha256').update.bind(crypto.createHash('sha256')), { sortPairs: true });
        const root = tree.getRoot().toString('hex');

        // 3. Anchor Root to Blockchain (NFR-13)
        try {
            const tx = await BlockchainService.auditLedger.anchorMerkleRoot(`0x${root}`, logs.length);
            const receipt = await tx.wait();

            // 4. Update Logs in Database
            await AuditLogModel.updateMany(
                { _id: { $in: logs.map(l => l._id) } },
                { $set: { anchored: true, merkleRoot: root, txHash: receipt.hash } }
            );

            logger.info(`Merkle Root anchored: 0x${root} | Tx: ${receipt.hash}`);

            // 5. Tamper Detection (NFR-14)
            // Recompute root from database and compare with what we just anchored
            const currentLogs = await AuditLogModel.find({
                merkleRoot: root,
                anchored: true
            }).sort({ timestamp: 1 });

            const recomputedLeaves = currentLogs.map(l => 
                crypto.createHash('sha256').update(JSON.stringify(l.metadata)).digest()
            );
            const recomputedTree = new MerkleTree(recomputedLeaves, crypto.createHash('sha256').update.bind(crypto.createHash('sha256')), { sortPairs: true });
            const recomputedRoot = recomputedTree.getRoot().toString('hex');

            if (recomputedRoot !== root) {
                logger.error('TAMPER DETECTED: Database logs modified after anchoring!');
                
                // Emit alert to Dashboard
                broadcastSecurityAlert({
                    type: 'TAMPER_ALERT',
                    message: 'Audit log integrity violation detected (Merkle Mismatch)',
                    timestamp: new Date()
                });

                // Trigger on-chain alert
                try {
                    await BlockchainService.accessPolicy.triggerAlert('MERKLE_MISMATCH', `0x${root}`);
                } catch (alertErr) {
                    logger.error('Failed to trigger on-chain alert', { error: (alertErr as Error).message });
                }
            } else {
                logger.info('Integrity verification PASSED: Database matches Blockchain root.');
            }
        } catch (err) {
            logger.error('Blockchain Anchoring Failed', { error: (err as Error).message });
            broadcastSecurityAlert({
                type: 'ANCHOR_FAILURE',
                message: 'Failed to anchor audit logs to blockchain',
                timestamp: new Date()
            });
        }
    }
}
