'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { enrollUser, isEnrolled, generateZKProof } = require('./keyManager');
const { startHeartbeat, stopHeartbeat } = require('./heartbeat');
const axios = require('axios');
const winston = require('winston');
const https = require('https');
const fs = require('fs');

// Load mTLS certificates for local development
const certPath = path.join(__dirname, '../../../../certs');
const httpsAgent = new https.Agent({
    rejectUnauthorized: false, // Still allow self-signed for dev
    cert: fs.readFileSync(path.join(certPath, 'client.crt')),
    key: fs.readFileSync(path.join(certPath, 'client.key')),
    ca: fs.readFileSync(path.join(certPath, 'ca.crt'))
});

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

// Allow self-signed certificates for local development (mTLS Gateway)
app.commandLine.appendSwitch('ignore-certificate-errors');

let mainWindow;

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

    // In development, load from localhost:3000 (React dev server)
    // In production, load from build/index.html
    // Force trust for localhost during development
    mainWindow.webContents.session.setCertificateVerifyProc((request, callback) => {
        const { hostname } = request;
        if (hostname === 'localhost') {
            callback(0); // 0 = trust
        } else {
            callback(-2); // -2 = use default verification
        }
    });

    const startUrl = process.env.NODE_ENV === 'development' 
        ? 'http://localhost:3000' 
        : `file://${path.join(__dirname, '../renderer/index.html')}`;

    mainWindow.loadURL(startUrl);

    if (process.env.NODE_ENV === 'development') {
        mainWindow.webContents.openDevTools();
    }
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

// Powerful bypass for local development SSL errors
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
    if (url.startsWith('https://localhost:8443')) {
        event.preventDefault();
        callback(true);
    } else {
        callback(false);
    }
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// IPC Handlers for Phase 6
ipcMain.handle('auth:is-enrolled', async () => {
    return isEnrolled();
});

ipcMain.handle('auth:enroll', async () => {
    return await enrollUser();
});

ipcMain.handle('auth:login', async (event, { sessionNonce, userHash, deviceId }) => {
    try {
        const { proof, publicSignals } = await generateZKProof(sessionNonce);
        
        // Connect to Gateway (using mTLS certs if configured)
        const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
        
        const response = await axios.post(`${gatewayUrl}/auth/login`, {
            proof,
            publicSignals,
            sessionNonce,
            deviceId,
            userHash
        }, {
            httpsAgent
        });

        if (response.data.sessionId) {
            // Start heartbeats
            startHeartbeat(response.data.sessionId, async (sid) => {
                await axios.post(`${gatewayUrl}/auth/heartbeat`, { sessionId: sid }, { httpsAgent });
            });
        }

        return response.data;
    } catch (err) {
        logger.error('Login failed', { error: err.message });
        throw err;
    }
});

ipcMain.handle('system:get-status', async () => {
    return {
        gateway: 'Connected',
        mtls: 'Active',
        zkp: 'Operational',
        ai: 'Operational',
        blockchain: 'Connected',
        audit: 'Operational',
        uptime: '00:12:45'
    };
});

ipcMain.handle('system:get-telemetry', async () => {
    return {
        accessVelocity: 5.2,
        sessionDuration: '00:45:12',
        riskScore: 12,
        deviceIdMatch: true
    };
});
