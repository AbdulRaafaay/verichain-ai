'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { Server: WebSocketServer } = require('socket.io');
const winston = require('winston');
const mongoose = require('mongoose');

const { loadEnv } = require('./config/env');
const { initBlockchainClient } = require('./services/blockchainClient');
const { startMerkleAnchorService } = require('./services/merkleAnchor');
const mtlsVerify = require('./middleware/mtlsVerify');
const authRoutes = require('./routes/auth.routes');

const env = loadEnv();

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.Console(),
    ]
});

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: [env.DESKTOP_AGENT_ORIGIN, env.TRUST_DASHBOARD_ORIGIN],
    credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// Mutual TLS (NFR-03) — Applied to all functional routes
app.use(mtlsVerify);

app.use('/auth', authRoutes);

// Health Check (no mTLS for health check if desired, but here we applied it globally)
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: Date.now() });
});

async function startServer() {
    // Database connection
    await mongoose.connect(env.MONGODB_URI);
    logger.info('Connected to MongoDB');

    // Blockchain client
    await initBlockchainClient({
        rpcUrl: env.BLOCKCHAIN_RPC,
        accessPolicyAddress: env.ACCESS_POLICY_ADDRESS,
        auditLedgerAddress: env.AUDIT_LEDGER_ADDRESS,
        gatewayPrivateKey: env.GATEWAY_PRIVATE_KEY,
    });

    // mTLS server options
    const tlsOptions = {
        key: fs.readFileSync(path.join(__dirname, '../../../../certs/gateway.key')),
        cert: fs.readFileSync(path.join(__dirname, '../../../../certs/gateway.crt')),
        ca: fs.readFileSync(path.join(__dirname, '../../../../certs/ca.crt')),
        requestCert: true,
        rejectUnauthorized: true,
    };

    const httpsServer = https.createServer(tlsOptions, app);

    const io = new WebSocketServer(httpsServer, {
        cors: {
            origin: env.TRUST_DASHBOARD_ORIGIN,
            credentials: true,
        },
    });

    app.set('io', io);

    // Start background services
    startMerkleAnchorService(io);

    httpsServer.listen(env.GATEWAY_PORT, () => {
        logger.info(`VeriChain Security Gateway running on port ${env.GATEWAY_PORT} (mTLS)`);
    });
}

if (require.main === module) {
    startServer().catch((err) => {
        logger.error('Fatal startup error', { error: err.message });
        process.exit(1);
    });
}

module.exports = { app };
