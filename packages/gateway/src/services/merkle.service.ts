import { MerkleTree } from 'merkletreejs';
import crypto from 'crypto';
import { AuditLogModel } from '../models/audit-log.model';
import { BlockchainService } from './blockchain.service';
import { logger } from '../utils/logger';
import { broadcastSecurityAlert, getIO } from './socket.service';

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
        // hashFn must return Buffer — crypto.createHash().update().digest() does this correctly.
        const hashFn = (data: Buffer) => crypto.createHash('sha256').update(data).digest();
        const leaves = logs.map(log =>
            crypto.createHash('sha256').update(JSON.stringify(log.metadata)).digest()
        );
        const tree = new MerkleTree(leaves, hashFn, { sortPairs: true });
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

            // 5. Notify Trust Dashboard — Merkle Chain tab & Blockchain tab
            try {
                const io = getIO();
                const anchorPayload = {
                    rootHash:    `0x${root}`,
                    blockNumber: receipt.blockNumber ?? 0,
                    logCount:    logs.length,
                    timestamp:   new Date().toISOString(),
                    status:      'CLEAN' as const,
                    txHash:      receipt.hash,
                };
                io.emit('merkle_anchor', anchorPayload);
                io.emit('blockchain_event', {
                    id:          receipt.hash,
                    event:       'MerkleRootAnchored',
                    txHash:      receipt.hash,
                    blockNumber: receipt.blockNumber ?? 0,
                    timestamp:   anchorPayload.timestamp,
                    details:     { logCount: logs.length, root: `0x${root}`.substring(0, 18) + '…' },
                });
            } catch { /* socket not ready */ }

            // 6. Tamper Detection (NFR-14) — recompute and compare
            const currentLogs = await AuditLogModel.find({
                merkleRoot: root,
                anchored: true
            }).sort({ timestamp: 1 });

            const recomputedLeaves = currentLogs.map(l =>
                crypto.createHash('sha256').update(JSON.stringify(l.metadata)).digest()
            );
            const recomputedTree = new MerkleTree(recomputedLeaves, hashFn, { sortPairs: true });
            const recomputedRoot = recomputedTree.getRoot().toString('hex');

            if (recomputedRoot !== root) {
                logger.error('TAMPER DETECTED: Database logs modified after anchoring!');

                const tamperPayload = {
                    type:      'TAMPER_ALERT',
                    severity:  'CRITICAL' as const,
                    timestamp: new Date().toISOString(),
                    details:   'Merkle mismatch: database logs were modified after blockchain anchoring',
                    txHash:    receipt.hash,
                };

                broadcastSecurityAlert(tamperPayload as any);

                try {
                    const io = getIO();
                    io.emit('tamper_alert', tamperPayload);
                } catch { /* socket not ready */ }

                try {
                    await BlockchainService.accessPolicy.triggerAlert(
                        'MERKLE_MISMATCH',
                        `0x${root}`
                    );
                } catch (alertErr) {
                    logger.error('Failed to trigger on-chain alert', { error: (alertErr as Error).message });
                }
            } else {
                logger.info('Integrity verification PASSED: Database matches Blockchain root.');
            }
        } catch (err) {
            logger.error('Blockchain Anchoring Failed', { error: (err as Error).message });
            broadcastSecurityAlert({
                type:      'ANCHOR_FAILURE',
                message:   'Failed to anchor audit logs to blockchain',
                timestamp: new Date(),
            } as any);
        }
    }
}
