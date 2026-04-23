'use strict';

const express = require('express');
const router = express.Router();
const validateZKP = require('../middleware/validateZKP');
const AuditLogger = require('../services/auditLogger');
const { getBlockchainClient } = require('../services/blockchainClient');
const crypto = require('crypto');

router.post('/login', validateZKP, async (req, res) => {
    const { userHash, deviceId } = req.verifiedUser;
    const blockchain = getBlockchainClient();

    try {
        const sessionId = crypto.randomUUID();
        const sessionIdHash = crypto.createHash('sha256').update(sessionId).digest('hex');
        
        // Record session on-chain
        const tx = await blockchain.accessPolicy.createSession('0x' + sessionIdHash, '0x' + userHash);
        await tx.wait();

        // Log successful login
        // await AuditLogger.log(...)

        res.status(200).json({
            status: 'success',
            sessionId: sessionId,
            expiresIn: 3600
        });
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message });
    }
});

module.exports = router;
