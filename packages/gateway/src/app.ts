import express, { Request, Response, NextFunction } from 'express';
import https from 'https';
import fs from 'fs';
import helmet from 'helmet';
import cors from 'cors';
import mongoose from 'mongoose';
import { initRedis } from './services/redisClient';
import { SessionService } from './services/session.service';
import { initSocket, getIO } from './services/socket.service';
import { BlockchainService } from './services/blockchain.service';
import { MerkleService } from './services/merkle.service';
import { AuditLogModel } from './models/audit-log.model';
import { IntegrityState } from './services/integrity.state';
import { logger } from './utils/logger';
import { mtlsVerify } from './middleware/mtlsVerify';
import routes from './routes';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

// Trust the first hop reverse proxy so req.ip returns the real client IP
// (required for rate-limiter accuracy when deployed behind nginx)
app.set('trust proxy', 1);

// ── Security middleware (STRIDE mitigations) ──────────────────────────────────
app.use(helmet());

// CORS — restrict to the configured Trust Dashboard origin.
// In development the env var defaults to the dashboard dev server.
const ALLOWED_ORIGINS = new Set(
    (process.env.TRUST_DASHBOARD_ORIGIN || 'http://localhost:3005').split(',').map(o => o.trim())
);
app.use(cors({
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean | string) => void) => {
        // Allow requests with no Origin header (same-origin, mobile, etc.)
        if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, origin || true);
        // Allow localhost variants for development
        if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) return callback(null, origin);
        callback(new Error(`CORS: origin '${origin}' not allowed`));
    },
    credentials: true,
}));

app.use(express.json({ limit: '10kb' }));

// mTLS client-cert enforcement (health endpoint exempt inside middleware)
app.use(mtlsVerify);

// API routes (validation + rate limiting applied inside routes/index.ts)
app.use('/api', routes);

// Health probe — no auth required
app.get('/health', (_req: Request, res: Response) =>
    res.json({ status: 'healthy', timestamp: Date.now() })
);

// Central error handler (4-arg signature required by Express)
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', { error: err.message });
    res.status(500).json({ error: 'Internal Server Error' });
});

// ── Helpers shared between controllers via req.app ────────────────────────────

/** Normalises a raw Redis session into the shape Trust Dashboard expects. */
function normaliseSession(s: any) {
    return {
        id:            s.sessionId,
        userHash:      s.userHash || s.clientId || 'unknown',
        currentResource: s.currentResource || '—',
        loginTime:     s.createdAt,
        lastHeartbeat: s.lastHeartbeat || s.createdAt,
        duration:      s.createdAt
            ? Math.round((Date.now() - new Date(s.createdAt).getTime()) / 1000) + 's'
            : '—',
        riskScore: s.riskScore ?? 0,
        status:    s.status === 'active' ? 'ACTIVE' : 'REVOKED',
    };
}

/** Counts security-relevant events in the last 24 h. */
async function countAlertsToday(): Promise<number> {
    try {
        const since = new Date(Date.now() - 24 * 3600 * 1000);
        return await AuditLogModel.countDocuments({
            timestamp: { $gte: since },
            action: { $in: ['SESSION_REVOKED', 'SESSION_TIMEOUT', 'LOGIN_FAILED', 'TAMPER_DETECTED', 'ACCESS_DENIED'] },
        });
    } catch {
        return 0;
    }
}

/** Broadcasts the current session list + derived stats to all dashboard clients. */
async function broadcastState() {
    try {
        const io = getIO();
        const raw = await SessionService.getAllSessions();
        const sessions = raw.map(normaliseSession);
        const avgRisk = sessions.length
            ? Math.round(sessions.reduce((a: number, b: any) => a + (b.riskScore || 0), 0) / sessions.length)
            : 0;
        const alertsToday = await countAlertsToday();

        io.emit('session_update', sessions);
        io.emit('stats_update', {
            activeSessions: sessions.length,
            avgRiskScore:   avgRisk,
            alertsToday,
            logIntegrity:   IntegrityState.get(),
        });
    } catch {
        // Socket not yet initialised — ignore
    }
}


// Expose helpers so controllers can reach them without importing circular deps
app.set('broadcastState', broadcastState);
app.set('normaliseSession', normaliseSession);

const PORT = process.env.GATEWAY_PORT || 8443;

async function start() {
    try {
        await BlockchainService.init();
        logger.info('Blockchain Service initialised');

        try {
            await mongoose.connect(process.env.MONGODB_URI || 'mongodb://mongodb:27017/verichain');
            logger.info('MongoDB connected');
        } catch (e: any) {
            // Mask only the password part, not the whole prefix
            const maskedUri = process.env.MONGODB_URI?.replace(/(:)([^@/]+)(@)/, '$1****$3');
            logger.error('MongoDB connection failed', { error: e.message, uri: maskedUri });
            throw e;
        }

        try {
            await initRedis();
            logger.info('Redis connected');
        } catch (e: any) {
            const maskedUrl = process.env.REDIS_URL?.replace(/(:)([^@/]+)(@)/, '$1****$3');
            logger.error('Redis connection failed', { error: e.message, url: maskedUrl });
            throw e;
        }

        // mTLS HTTPS server (NFR-03)
        const tlsOptions = {
            key:  fs.readFileSync(process.env.GATEWAY_KEY_PATH  || './certs/gateway.key'),
            cert: fs.readFileSync(process.env.GATEWAY_CERT_PATH || './certs/gateway.crt'),
            ca:   fs.readFileSync(process.env.CA_CERT_PATH      || './certs/ca.crt'),
            requestCert:        true,
            // false lets TLS complete without a client cert; mtlsVerify enforces it per-route
            rejectUnauthorized: false,
        };

        const server = https.createServer(tlsOptions, app);
        const io = initSocket(server);

        // Store io on the app so controllers can reach it via req.app.get('io')
        app.set('io', io);

        // Push current state to any Trust Dashboard that connects after a session exists
        io.on('connection', async (socket: any) => {
            try {
                const raw = await SessionService.getAllSessions();
                const sessions = raw.map(normaliseSession);
                const avgRisk = sessions.length
                    ? Math.round(sessions.reduce((a: number, b: any) => a + (b.riskScore || 0), 0) / sessions.length)
                    : 0;
                const alertsToday = await countAlertsToday();
                socket.emit('session_update', sessions);
                socket.emit('stats_update', {
                    activeSessions: sessions.length,
                    avgRiskScore:   avgRisk,
                    alertsToday,
                    logIntegrity:   IntegrityState.get(),
                });
            } catch { /* Redis not ready yet */ }
        });

        // Periodic stats pulse every 10 s — keeps the Overview chart alive
        setInterval(broadcastState, 10_000);

        MerkleService.startBatcher();
        SessionService.startHeartbeatWatchdog();
        SessionService.listenForExpiredSessions();

        server.listen(PORT, () => {
            logger.info(`VeriChain Security Gateway active on :${PORT} (mTLS)`);
        });
    } catch (err) {
        logger.error('Gateway startup failed', { error: (err as Error).message });
        process.exit(1);
    }
}

if (require.main === module) start();

export default app;
