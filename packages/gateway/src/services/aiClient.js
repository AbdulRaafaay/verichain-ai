'use strict';

const axios = require('axios');
const crypto = require('crypto');
const winston = require('winston');
const { loadEnv } = require('../config/env');

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

const env = loadEnv();

const AI_ENGINE_URL = env.AI_ENGINE_URL;
const AI_HMAC_SECRET = env.AI_HMAC_SECRET;
const AI_TIMEOUT_MS = 3000;

function computeHMAC(payload) {
    return crypto
        .createHmac('sha256', AI_HMAC_SECRET)
        .update(payload)
        .digest('hex');
}

function hashForAI(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

async function getRiskScore(sessionMeta) {
    const payload = {
        sessionHash: hashForAI(sessionMeta.sessionId),
        resourceHash: hashForAI(sessionMeta.resourceId || ''),
        deviceIdHash: hashForAI(sessionMeta.deviceId),
        accessVelocity: sessionMeta.accessVelocity || 0,
        geoHash: hashForAI(sessionMeta.geoDistanceKm || 0),
        uniqueResources: sessionMeta.uniqueResources || 0,
        downloadBytes: sessionMeta.downloadBytes || 0,
        timeSinceLast: sessionMeta.timeSinceLast || 0,
        deviceIdMatch: sessionMeta.deviceIdMatch ? 1 : 0,
    };

    const payloadStr = JSON.stringify(payload);
    const hmac = computeHMAC(payloadStr);

    try {
        const response = await axios.post(
            `${AI_ENGINE_URL}/score`,
            payload,
            {
                timeout: AI_TIMEOUT_MS,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Internal-Auth': hmac,
                },
                proxy: false,
            }
        );

        const score = response.data?.riskScore;
        if (typeof score !== 'number' || score < 0 || score > 100) {
            logger.warn('AI Engine returned invalid score format — fail-closed', { received: score });
            return 100;
        }

        return score;
    } catch (err) {
        logger.error('AI Engine unreachable — FAIL-CLOSED returning score 100', {
            error: err.message,
            code: err.code,
        });
        return 100;
    }
}

function evaluateRiskScore(score) {
    if (score > 75) return 'REVOKE';
    if (score >= 50) return 'STEP_UP';
    return 'PERMIT';
}

module.exports = { getRiskScore, evaluateRiskScore };
