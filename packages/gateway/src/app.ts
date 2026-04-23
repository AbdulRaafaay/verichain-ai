import express, { Request, Response } from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import helmet from 'helmet';
import cors from 'cors';
import mongoose from 'mongoose';
import { initRedis } from './services/redisClient';
import { SessionService } from './services/session.service';
import { initSocket } from './services/socket.service';
import { BlockchainService } from './services/blockchain.service';
import { MerkleService } from './services/merkle.service';
import { logger } from './utils/logger';
import { mtlsVerify } from './middleware/mtlsVerify';
import routes from './routes';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

// Security Middleware (STRIDE mitigations)
app.use(helmet());
app.use(cors({
    origin: '*', // Restrict in production
    credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// Apply mTLS check to all routes (except health handled inside middleware)
app.use(mtlsVerify);

// Apply routes
app.use('/api', routes);

// Health Check
app.get('/health', (req: Request, res: Response) => res.json({ status: 'healthy', timestamp: Date.now() }));

const PORT = process.env.GATEWAY_PORT || 8443;

async function start() {
    try {
        // Blockchain client initialization
        await BlockchainService.init();
        logger.info('Blockchain Service initialized');

        // Connect Database
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://mongodb:27017/verichain');
        logger.info('MongoDB connected');

        // Connect Redis (Nonces/Sessions)
        await initRedis();

        // HTTPS Server Setup (mTLS - NFR-03)
        const tlsOptions = {
            key: fs.readFileSync(process.env.GATEWAY_KEY_PATH || './certs/gateway.key'),
            cert: fs.readFileSync(process.env.GATEWAY_CERT_PATH || './certs/gateway.crt'),
            ca: fs.readFileSync(process.env.CA_CERT_PATH || './certs/ca.crt'),
            requestCert: true,
            rejectUnauthorized: true,
        };

        const server = https.createServer(tlsOptions, app);

        // Initialize Real-Time WebSockets
        initSocket(server);

        // Start Background Merkle Batcher
        MerkleService.startBatcher();
        
        // Start Heartbeat Watchdog
        SessionService.startHeartbeatWatchdog();

        server.listen(PORT, () => {
            logger.info(`VeriChain Security Gateway (TypeScript) active on port ${PORT} (mTLS)`);
        });
    } catch (err: any) {
        logger.error('Gateway Startup Failed', { error: (err as Error).message });
        process.exit(1);
    }
}

if (require.main === module) {
    start();
}

export default app;
