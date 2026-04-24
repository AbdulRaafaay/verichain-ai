'use strict';

/**
 * aiClient.js — HMAC-authenticated client for the Python AI Risk Engine.
 *
 * Fail behaviour:
 *   - If the AI engine is unreachable the score defaults to 15 (PERMIT) so
 *     that authentication still works during demo / offline runs.
 *   - If telemetry contains { simulateAnomaly: true } a score of 92 (REVOKE)
 *     is returned immediately, letting the demo trigger a session revocation
 *     without needing the Python service running.
 */

const axios  = require('axios');
const crypto = require('crypto');

const AI_ENGINE_URL  = process.env.AI_ENGINE_URL  || 'http://localhost:5001';
const AI_HMAC_SECRET = process.env.AI_HMAC_SECRET  || 'dev-hmac-secret-change-in-production';
const AI_TIMEOUT_MS  = 3000;

// Default score returned when the AI engine is offline — low enough to PERMIT
const FALLBACK_SCORE_NORMAL  = 15;
// Score returned for simulated scenarios (bypasses AI engine for reliable demo)
const SIMULATED_ANOMALY_SCORE  = 92;   // Triggers REVOKE (>75)
const SIMULATED_STEP_UP_SCORE  = 65;   // Triggers STEP_UP (50-75)

function computeHMAC(payload) {
    return crypto
        .createHmac('sha256', AI_HMAC_SECRET)
        .update(payload)
        .digest('hex');
}

function hashForAI(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

/**
 * getRiskScore — calls the AI engine and returns a score 0-100.
 *
 * @param {object} sessionMeta - telemetry + session context
 * @param {boolean} [sessionMeta.simulateAnomaly] - if true, instantly return a
 *   high anomaly score without contacting the AI engine (demo helper)
 * @returns {Promise<number>} 0-100 risk score
 */
async function getRiskScore(sessionMeta) {
    if (sessionMeta.simulateAnomaly) return SIMULATED_ANOMALY_SCORE;
    if (sessionMeta.simulateStepUp)  return SIMULATED_STEP_UP_SCORE;

    const payload = {
        sessionHash:    hashForAI(sessionMeta.sessionId),
        resourceHash:   hashForAI(sessionMeta.resourceId || ''),
        deviceIdHash:   hashForAI(sessionMeta.deviceId || ''),
        accessVelocity: sessionMeta.accessVelocity   || 0,
        geoHash:        hashForAI(sessionMeta.geoDistanceKm || 0),
        uniqueResources: sessionMeta.uniqueResources || 0,
        downloadBytes:  sessionMeta.downloadBytes    || 0,
        timeSinceLast:  sessionMeta.timeSinceLast    || 0,
        deviceIdMatch:  sessionMeta.deviceIdMatch    ? 1 : 0,
    };

    const payloadStr = JSON.stringify(payload);
    const hmac = computeHMAC(payloadStr);

    try {
        const response = await axios.post(
            `${AI_ENGINE_URL}/score`,
            payloadStr,
            {
                timeout: AI_TIMEOUT_MS,
                headers: {
                    'Content-Type':   'application/json',
                    'X-Internal-Auth': hmac,
                },
                proxy: false,
            }
        );

        const score = response.data?.riskScore;
        if (typeof score !== 'number' || score < 0 || score > 100) {
            console.warn('[aiClient] AI engine returned invalid score — using fallback', { received: score });
            return FALLBACK_SCORE_NORMAL;
        }

        return score;
    } catch (err) {
        // Fail-open: return a low score so the demo works without the Python service
        console.warn('[aiClient] AI engine unreachable — using fallback score', {
            error: err.message,
            fallback: FALLBACK_SCORE_NORMAL,
        });
        return FALLBACK_SCORE_NORMAL;
    }
}

/**
 * evaluateRiskScore — maps a numeric score to an access decision.
 * @param {number} score
 * @returns {'PERMIT'|'STEP_UP'|'REVOKE'}
 */
function evaluateRiskScore(score) {
    if (score > 75) return 'REVOKE';
    if (score >= 50) return 'STEP_UP';
    return 'PERMIT';
}

module.exports = { getRiskScore, evaluateRiskScore };
