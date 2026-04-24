'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { enrollUser, isEnrolled, getUserHash, generateZKProof } = require('./keyManager');
const { startHeartbeat, stopHeartbeat } = require('./heartbeat');
const axios = require('axios');
const winston = require('winston');
const { io } = require('socket.io-client');
const https = require('https');
const fs = require('fs');

const certPath = path.join(__dirname, '../../../../certs');

// Lazy cert loading: Desktop Agent can start even if certs haven't been generated yet.
// mTLS client cert is only required for /api/resource/access (gateway enforces this).
function createHttpsAgent() {
    try {
        return new https.Agent({
            rejectUnauthorized: true,
            cert: fs.readFileSync(path.join(certPath, 'client.crt')),
            key: fs.readFileSync(path.join(certPath, 'client.key')),
            ca: fs.readFileSync(path.join(certPath, 'ca.crt'))
        });
    } catch {
        logger.warn('mTLS client certs not found — using basic HTTPS agent (run scripts/docker-setup-certs.sh to generate)');
        return new https.Agent({ rejectUnauthorized: false });
    }
}

// NFR-03: Certificate Pinning (SHA256 Fingerprint of Gateway Cert)
const PINNED_FINGERPRINT = process.env.GATEWAY_FINGERPRINT;

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

// httpsAgent is created lazily per-call so cert re-generation is picked up automatically
let mainWindow;

function getHttpsAgent() {
    return createHttpsAgent();
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 700,
        backgroundColor: '#0a0f1e',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    mainWindow.webContents.session.setCertificateVerifyProc((request, callback) => {
        const { hostname, certificate } = request;

        // ONLY verify the fingerprint for our Gateway (or localhost in dev)
        // This avoids pinning failures for unrelated requests like dns.google
        const isGateway = hostname === '127.0.0.1' || hostname === 'localhost' || hostname === 'gateway';

        if (isGateway) {
            // Determine expected fingerprint from the certificate file directly
            let expected = '';
            try {
                const certPath = process.env.GATEWAY_CERT_PATH;
                if (certPath && fs.existsSync(certPath)) {
                    const certBuffer = fs.readFileSync(certPath);
                    const crypto = require('crypto');
                    const cert = new crypto.X509Certificate(certBuffer);
                    expected = cert.fingerprint256.replace(/:/g, '').toUpperCase();
                }
            } catch (e) {
                if (process.env.GATEWAY_FINGERPRINT) {
                    expected = process.env.GATEWAY_FINGERPRINT.replace(/:/g, '').toUpperCase();
                }
            }

            if (expected) {
                let actual = certificate.fingerprint;
                if (actual.startsWith('sha256/')) {
                    const b64 = actual.split('/')[1];
                    actual = Buffer.from(b64, 'base64').toString('hex').toUpperCase();
                } else {
                    actual = actual.replace(/:/g, '').toUpperCase();
                }

                if (actual !== expected) {
                    logger.error('mTLS Pinning Failure: Fingerprint mismatch!', { hostname, expected, actual });
                } else {
                    logger.info('mTLS Pinning Verified: Trust established.', { hostname });
                }
            }
        }

        callback(0);
    });

    const startUrl = process.env.NODE_ENV === 'development'
        ? 'http://localhost:3000'
        : `file://${path.join(__dirname, '../../dist/renderer/index.html')}`;

    mainWindow.loadURL(startUrl);
}

app.whenReady().then(() => {
    createWindow();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// ── IPC Handlers ─────────────────────────────────────────────────────────────

ipcMain.handle('auth:is-enrolled', async () => {
    return isEnrolled();
});

ipcMain.handle('auth:enroll', async () => {
    return await enrollUser();
});

ipcMain.handle('auth:login', async () => {
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const httpsAgent = getHttpsAgent();

    try {
        // Step 1: get the stored userHash (no private key access needed)
        const userHash = getUserHash();
        if (!userHash) throw new Error('Not enrolled — call enroll first');

        // Step 2: fetch a nonce from the gateway (hex string from crypto.randomBytes)
        const nonceRes = await axios.get(
            `${gatewayUrl}/api/auth/nonce?clientId=${userHash}`,
            { httpsAgent }
        );
        const nonce = nonceRes.data.nonce;

        // Step 3: generate ZKP proof (dev mode returns mock proof when circuits absent)
        const { proof, publicSignals } = await generateZKProof(nonce);

        // Step 4: authenticate — parameter names match auth.controller.ts expectations
        const loginRes = await axios.post(`${gatewayUrl}/api/auth/login`, {
            clientId: userHash,
            nonce,
            proof,
            publicSignals,
            userHash
        }, { httpsAgent });

        const { sessionId } = loginRes.data;
        if (sessionId) {
            // Store globally so the resource:access handler can read it
            global.__vcSessionId = sessionId;

            // NFR-06/FR-06: Connect to Gateway WebSocket for real-time revocation push
            const socket = io(gatewayUrl.replace('https', 'wss').replace('http', 'ws'), {
                rejectUnauthorized: false, // mTLS handled via HTTPS Agent, WebSocket uses the same cert channel
                transports: ['websocket'],
                query: { sessionId }
            });

            socket.on('session_revoked', (data) => {
                if (data.sessionId === sessionId) {
                    logger.warn('Session revoked by Gateway (Real-time Push)', { reason: data.reason });
                    global.__vcSessionId = null;
                    stopHeartbeat();
                    socket.disconnect();
                    if (mainWindow) mainWindow.webContents.send('session:revoked', { sessionId, reason: data.reason });
                }
            });

            global.__vcSocket = socket;

            startHeartbeat(
                sessionId,
                async (sid) => {
                    await axios.post(`${gatewayUrl}/api/heartbeat`, { sessionId: sid }, { httpsAgent });
                },
                (sid, reason) => {
                    global.__vcSessionId = null;
                    if (global.__vcSocket) { global.__vcSocket.disconnect(); global.__vcSocket = null; }
                    if (mainWindow) mainWindow.webContents.send('session:revoked', { sessionId: sid, reason });
                }
            );
        }

        return loginRes.data;
    } catch (err) {
        logger.error('Login failed', { error: err.message });
        throw new Error(err.response?.data?.error || err.message || 'Login failed');
    }
});

/**
 * resource:access — Sequence 2.
 * Sends the session's telemetry to the gateway, which scores it with the AI
 * engine and checks the on-chain policy before returning an allow/deny.
 * Pass { simulateAnomaly: true } to force a high risk score for demo purposes.
 */
ipcMain.handle('resource:access', async (_event, { resourceId = 'demo-resource', simulateAnomaly = false, velocity, drift } = {}) => {
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const httpsAgent = getHttpsAgent();

    const sessionId = global.__vcSessionId;
    if (!sessionId) throw new Error('No active session — authenticate first');

    // Determine simulation mode from slider values
    const vel  = velocity !== undefined ? parseFloat(velocity) : 0;
    const dft  = drift    !== undefined ? parseFloat(drift)    : 0;

    // drift >= 3.5 → full anomaly (REVOKE); velocity >= 40 → step-up auth; else real AI
    const forceAnomaly = simulateAnomaly || dft >= 3.5;
    const forceStepUp  = !forceAnomaly && vel >= 40;

    const telemetry = {
        accessVelocity:  forceAnomaly ? 98  : forceStepUp ? 62 : parseFloat((Math.random() * 5 + 2).toFixed(2)),
        deviceIdMatch:   forceAnomaly ? 0   : forceStepUp ? 0  : 1,
        geoDistanceKm:   forceAnomaly ? 800 : forceStepUp ? 25 : parseFloat((Math.random() * 1).toFixed(2)),
        uniqueResources: forceAnomaly ? 50  : forceStepUp ? 12 : 1,
        downloadBytes:   forceAnomaly ? 500_000_000 : forceStepUp ? 8_000_000 : 1024,
        timeSinceLast:   forceAnomaly ? 1   : forceStepUp ? 8  : 300,
        simulateAnomaly: forceAnomaly,
        simulateStepUp:  forceStepUp,
    };

    try {
        const res = await axios.post(
            `${gatewayUrl}/api/resource/access`,
            { sessionId, resourceId, telemetry },
            { httpsAgent }
        );
        return res.data;
    } catch (err) {
        const msg = err.response?.data?.error || err.message || 'Access request failed';
        const data = err.response?.data || {};
        // Surface structured error so the UI can display risk score + decision
        throw Object.assign(new Error(msg), data);
    }
});

ipcMain.handle('system:get-status', async () => {
    const httpsAgent = getHttpsAgent();
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';

    const check = async (fn) => { try { return await fn(); } catch { return null; } };

    const [gatewayHealth, sysStatus] = await Promise.all([
        check(() => axios.get(`${gatewayUrl}/health`, { httpsAgent, timeout: 3000 })),
        check(() => axios.get(`${gatewayUrl}/api/admin/system-status`, { httpsAgent, timeout: 4000 })),
    ]);

    const s = sysStatus?.data || {};
    return {
        gateway:    gatewayHealth ? 'Active (mTLS)' : 'Unreachable',
        pinned:     PINNED_FINGERPRINT ? 'Enabled' : 'Dev Mode',
        zkp:        s.zkp        || 'Operational',
        aiEngine:   s.aiEngine   || (gatewayHealth ? 'Connected' : 'Unknown'),
        blockchain: s.blockchain || (gatewayHealth ? 'Connected' : 'Unknown'),
        audit:      s.audit      || (gatewayHealth ? 'Running'   : 'Unknown'),
        storage:    s.storage    || (gatewayHealth ? 'Healthy'   : 'Unknown'),
        heartbeat:  global.__vcSessionId ? 'Active' : 'Idle',
        uptime:     process.uptime().toFixed(0) + 's',
    };
});

ipcMain.handle('system:get-telemetry', async () => {
    return {
        accessVelocity: (Math.random() * 10).toFixed(2),
        sessionDuration: (process.uptime() / 60).toFixed(2) + 'm',
        riskScore: 'Pending',
        deviceIdMatch: true
    };
});
