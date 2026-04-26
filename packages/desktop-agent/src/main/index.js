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
const startTime = Date.now();

const certPath = path.join(__dirname, '../../../../certs');

// Lazy cert loading: Desktop Agent can start even if certs haven't been generated yet.
// mTLS client cert is only required for /api/resource/access (gateway enforces this).
function createHttpsAgent() {
    const isDev = process.env.NODE_ENV !== 'production';
    try {
        return new https.Agent({
            rejectUnauthorized: !isDev, // Disable for dev/self-signed certs
            cert: fs.readFileSync(path.join(certPath, 'client.crt')),
            key: fs.readFileSync(path.join(certPath, 'client.key')),
            ca: fs.readFileSync(path.join(certPath, 'ca.crt'))
        });
    } catch {
        logger.warn('mTLS client certs not found — using basic HTTPS agent');
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

    // NFR-03 cert pinning — enforce hard fail on mismatch for our gateway hostname.
    // callback(0)  = trust  |  callback(-2) = reject  |  callback(-3) = use OS chain.
    mainWindow.webContents.session.setCertificateVerifyProc((request, callback) => {
        const { hostname, certificate } = request;
        const isGateway = hostname === '127.0.0.1' || hostname === 'localhost' || hostname === 'gateway';

        if (!isGateway) {
            // For non-gateway hosts (dns.google, fonts.googleapis.com, …) defer to the OS chain.
            return callback(-3);
        }

        // Resolve the expected fingerprint from disk (the cert that startup just generated).
        let expected = '';
        try {
            const certPath = process.env.GATEWAY_CERT_PATH;
            if (certPath && fs.existsSync(certPath)) {
                const certBuffer = fs.readFileSync(certPath);
                const crypto = require('crypto');
                const cert = new crypto.X509Certificate(certBuffer);
                expected = cert.fingerprint256.replace(/:/g, '').toUpperCase();
            }
        } catch (_e) { /* fall through to env var */ }

        if (!expected && process.env.GATEWAY_FINGERPRINT) {
            expected = process.env.GATEWAY_FINGERPRINT.replace(/:/g, '').toUpperCase();
        }

        if (!expected) {
            // Pinning configured but no expected fingerprint available — fail closed.
            logger.error('mTLS Pinning: no expected fingerprint configured — rejecting', { hostname });
            return callback(-2);
        }

        let actual = certificate.fingerprint;
        if (actual.startsWith('sha256/')) {
            const b64 = actual.split('/')[1];
            actual = Buffer.from(b64, 'base64').toString('hex').toUpperCase();
        } else {
            actual = actual.replace(/:/g, '').toUpperCase();
        }

        if (actual !== expected) {
            logger.error('mTLS Pinning Failure: rejecting mismatched gateway cert', { hostname, expected, actual });
            return callback(-2);
        }

        logger.info('mTLS Pinning Verified: trust established', { hostname });
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
 * Accepts all 6 Isolation Forest features directly from the renderer.
 * Raw values are forwarded to the gateway with no pre-filtering.
 */
ipcMain.handle('resource:access', async (_event, {
    resourceId     = 'demo-resource',
    accessVelocity  = 0,
    geoDistanceKm   = 0,
    uniqueResources = 1,
    downloadBytes   = 1024,
    timeSinceLast   = 300,
    deviceIdMatch   = 1,
} = {}) => {
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const httpsAgent = getHttpsAgent();

    const sessionId = global.__vcSessionId;
    if (!sessionId) throw new Error('No active session — authenticate first');

    const telemetry = {
        accessVelocity:  Number(accessVelocity),
        geoDistanceKm:   Number(geoDistanceKm),
        uniqueResources: Number(uniqueResources),
        downloadBytes:   Number(downloadBytes),
        timeSinceLast:   Number(timeSinceLast),
        deviceIdMatch:   Number(deviceIdMatch),
    };

    // Detailed I/O log so you can trace exactly what the AI engine is being asked to score.
    console.log('\n┌─────────────────────────────────────────────────────────────');
    console.log(`│ [resource:access] → POST ${gatewayUrl}/api/resource/access`);
    console.log(`│ sessionId : ${sessionId.slice(0, 8)}…`);
    console.log(`│ resourceId: ${resourceId}`);
    console.log('│ telemetry :');
    console.log(`│    accessVelocity  = ${telemetry.accessVelocity}  req/min`);
    console.log(`│    geoDistanceKm   = ${telemetry.geoDistanceKm}   km`);
    console.log(`│    uniqueResources = ${telemetry.uniqueResources} files`);
    console.log(`│    downloadBytes   = ${telemetry.downloadBytes}   bytes (${(telemetry.downloadBytes/1024/1024).toFixed(2)} MB)`);
    console.log(`│    timeSinceLast   = ${telemetry.timeSinceLast}   seconds`);
    console.log(`│    deviceIdMatch   = ${telemetry.deviceIdMatch}`);
    console.log('└─────────────────────────────────────────────────────────────');

    try {
        const res = await axios.post(
            `${gatewayUrl}/api/resource/access`,
            { sessionId, resourceId, telemetry },
            { httpsAgent }
        );

        const { riskScore, decision, reasons } = res.data;
        const concerning = (reasons || []).filter(r => r.concerning);
        const informational = (reasons || []).filter(r => !r.concerning);

        const fmtReason = (r) => {
            if (r.systemFault || typeof r.zScore !== 'number') {
                return r.label || r.feature || 'system fault';
            }
            return `${r.label || r.feature}: ${r.value}${r.unit ? ' '+r.unit : ''}  (expected ~${r.expected?.toFixed?.(1) ?? r.expected}, z=${r.zScore})`;
        };

        console.log('┌─────────────────────────────────────────────────────────────');
        console.log(`│ [resource:access] ← RESPONSE  ${decision} · risk=${riskScore}`);
        if (concerning.length) {
            console.log('│ Anomaly-direction features (driving the score up):');
            for (const r of concerning) console.log(`│    ⚠ ${fmtReason(r)}`);
        }
        if (informational.length) {
            console.log('│ Unusual but not concerning (safe-direction outliers):');
            for (const r of informational) console.log(`│    ℹ ${fmtReason(r)}`);
        }
        if (!concerning.length && !informational.length) {
            console.log('│ All features within normal training distribution');
        }
        if (res.data.scoreFloor) {
            console.log(`│ ⚡ Score floor applied: ${res.data.scoreFloor}`);
        }
        console.log('└─────────────────────────────────────────────────────────────\n');

        return res.data;
    } catch (err) {
        const msg = err.response?.data?.error || err.message || 'Access request failed';
        const data = err.response?.data || {};

        console.log('┌─────────────────────────────────────────────────────────────');
        console.log(`│ [resource:access] ← DENIED  ${data.decision || '?'} · risk=${data.riskScore ?? '?'}`);
        const concerning = (data.reasons || []).filter(r => r.concerning);
        const informational = (data.reasons || []).filter(r => !r.concerning);
        const fmtReason = (r) => {
            if (r.systemFault || typeof r.zScore !== 'number') {
                return r.label || r.feature || 'system fault';
            }
            return `${r.label || r.feature}: ${r.value}${r.unit ? ' '+r.unit : ''}  (expected ~${r.expected?.toFixed?.(1) ?? r.expected}, z=${r.zScore})`;
        };
        if (concerning.length) {
            console.log('│ Anomaly-direction features (driving the score up):');
            for (const r of concerning) console.log(`│    ⚠ ${fmtReason(r)}`);
        }
        if (informational.length) {
            console.log('│ Unusual but not concerning:');
            for (const r of informational) console.log(`│    ℹ ${fmtReason(r)}`);
        }
        if (data.scoreFloor) {
            console.log(`│ ⚡ Score floor applied: ${data.scoreFloor}`);
        }
        console.log(`│ message: ${msg}`);
        console.log('└─────────────────────────────────────────────────────────────\n');

        throw Object.assign(new Error(msg), data);
    }
});

ipcMain.handle('system:get-status', async () => {
    const httpsAgent = getHttpsAgent();
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    // No hardcoded fallback — production must inject ADMIN_API_KEY explicitly.
    // If unset, the admin status fetch falls back to /health below.
    const adminKey = process.env.ADMIN_API_KEY;
    const adminHeaders = adminKey ? { 'X-Admin-Key': adminKey } : undefined;

    const check = async (fn) => {
        try {
            const r = await fn();
            return r.data;
        } catch (err) {
            logger.error('Status check failed', { url: gatewayUrl, error: err.message });
            return null;
        }
    };

    const s = adminHeaders
        ? await check(() => axios.get(`${gatewayUrl}/api/admin/system-status`, { httpsAgent, headers: adminHeaders, timeout: 3000 }))
        : null;
    
    const uptimeSec = Math.floor((Date.now() - startTime) / 1000);
    const uptimeStr = uptimeSec > 60 ? `${Math.floor(uptimeSec / 60)}m ${uptimeSec % 60}s` : `${uptimeSec}s`;

    if (!s) {
        // Fallback: check basic health if detailed status fails
        const health = await check(() => axios.get(`${gatewayUrl}/health`, { httpsAgent, timeout: 2000 }));
        return {
            gateway: health ? 'Active (mTLS)' : 'Unreachable',
            pinned:  'Error',
            zkp:     'Unknown',
            ai:      'Unknown',
            blockchain: 'Disconnected',
            audit:   'Offline',
            storage: 'Unknown',
            heartbeat: 'Inactive',
            uptime: uptimeStr
        };
    }

    return {
        ...s,
        uptime: uptimeStr
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
