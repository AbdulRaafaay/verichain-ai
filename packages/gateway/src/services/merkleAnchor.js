'use strict';

const crypto = require('crypto');
const { MerkleTree } = require('merkletreejs');
const winston = require('winston');
const AuditLogModel = require('../models/AuditLogModel');
const { getBlockchainClient } = require('./blockchainClient');

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

const ANCHOR_INTERVAL_MS = 60 * 1000;

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function buildMerkleTree(logs) {
    const leaves = logs.map(log => {
        const canonical = JSON.stringify({
            id: log._id.toString(),
            eventType: log.eventType,
            userHash: log.userHash,
            resourceHash: log.resourceHash || '',
            sessionId: log.sessionId || '',
            riskScore: log.riskScore || 0,
            decision: log.decision,
            timestamp: log.timestamp.toISOString(),
        });
        return sha256(canonical);
    });

    return new MerkleTree(leaves, sha256, { sortPairs: true });
}

async function runAnchorCycle(io) {
    const blockchain = getBlockchainClient();

    try {
        const unanchored = await AuditLogModel.find({ anchored: false })
            .sort({ timestamp: 1 })
            .limit(1000)
            .lean();

        if (unanchored.length === 0) {
            return;
        }

        const tree = buildMerkleTree(unanchored);
        const merkleRoot = '0x' + tree.getRoot().toString('hex');

        logger.info(`Anchoring ${unanchored.length} logs. Root: ${merkleRoot}`);
        const tx = await blockchain.auditLedger.anchorMerkleRoot(merkleRoot, unanchored.length);
        await tx.wait();

        const logIds = unanchored.map(l => l._id);
        await AuditLogModel.updateMany(
            { _id: { $in: logIds } },
            {
                $set: {
                    anchored: true,
                    merkleRoot: merkleRoot,
                    anchorTxHash: tx.hash,
                    anchoredAt: new Date(),
                }
            }
        );

        // Verification
        const currentLogs = await AuditLogModel.find({ merkleRoot: merkleRoot, anchored: true })
            .sort({ timestamp: 1 })
            .lean();
        const recomputedRoot = '0x' + buildMerkleTree(currentLogs).getRoot().toString('hex');

        if (recomputedRoot !== merkleRoot) {
            logger.error('TAMPER DETECTED: Merkle root mismatch!');
            await blockchain.accessPolicy.triggerAlert('MERKLE_MISMATCH', Buffer.from(merkleRoot.slice(2), 'hex'));
            if (io) io.to('admins').emit('tamper_alert', { type: 'MERKLE_MISMATCH', anchoredRoot: merkleRoot, recomputedRoot });
        } else {
            logger.info('Integrity check passed');
            if (io) io.to('admins').emit('merkle_status', { status: 'OK', root: merkleRoot, logCount: unanchored.length });
        }
    } catch (err) {
        logger.error('Anchor cycle error', { error: err.message });
    }
}

function startMerkleAnchorService(io) {
    logger.info('Starting Merkle anchor service');
    runAnchorCycle(io);
    setInterval(() => runAnchorCycle(io), ANCHOR_INTERVAL_MS);
}

module.exports = { startMerkleAnchorService, buildMerkleTree };
