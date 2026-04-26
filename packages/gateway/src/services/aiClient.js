'use strict';

/**
 * aiClient.js — HMAC-authenticated client for the Python AI Risk Engine.
 *
 * Security:
 *   - Fails CLOSED: if the AI engine is unreachable, returns 100 (REVOKE) — no access
 *     is ever granted without a valid risk assessment.
 *   - Raw telemetry is forwarded directly to the engine; no simulation flags or
 *     threshold pre-filtering at this layer (gateway is a pure PEP).
 */

const axios  = require('axios');
const crypto = require('crypto');

const AI_ENGINE_URL  = process.env.AI_ENGINE_URL  || 'http://localhost:5001';
const AI_HMAC_SECRET = process.env.AI_HMAC_SECRET  || 'dev-hmac-secret-change-in-production';
const AI_TIMEOUT_MS  = 3000;

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
 * getRiskAssessment — forwards raw telemetry to the AI engine and returns a structured
 * decision object containing the risk score, the top contributing features ("reasons"),
 * and an optional `scoreFloor` tag set when post-hoc hybrid scoring lifted the IF score.
 *
 * @param {object} sessionMeta - raw session telemetry + identifiers
 * @returns {Promise<{score:number, reasons:Array<{feature?:string,label?:string,value?:number,expected?:number,zScore?:number,deviation?:number,direction?:string,concerning?:boolean,unit?:string,systemFault?:boolean}>, rawDecision:number, scoreFloor:string|null}>}
 */
async function getRiskAssessment(sessionMeta) {
    // For omitted fields use the training-distribution baseline so a missing
    // value doesn't look anomalous to the model (training means: ~50KB, ~300s, ~5).
    // Critical: never use `|| 0` — explicit 0 should be respected, only undefined/NaN should fall back.
    const n = (v, def) => {
        if (v === undefined || v === null) return def;
        const x = Number(v);
        return Number.isFinite(x) ? x : def;
    };
    const payload = {
        sessionHash:    hashForAI(sessionMeta.sessionId  || ''),
        resourceHash:   hashForAI(sessionMeta.resourceId || ''),
        deviceIdHash:   hashForAI(sessionMeta.deviceId   || ''),
        accessVelocity:  n(sessionMeta.accessVelocity,  5),
        geoDistanceKm:   n(sessionMeta.geoDistanceKm,   0),
        uniqueResources: n(sessionMeta.uniqueResources, 5),
        downloadBytes:   n(sessionMeta.downloadBytes,   50000),
        timeSinceLast:   n(sessionMeta.timeSinceLast,   300),
        deviceIdMatch:   n(sessionMeta.deviceIdMatch,   1),
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
                    'Content-Type':    'application/json',
                    'X-Internal-Auth': hmac,
                },
                proxy: false,
            }
        );

        const data = response.data || {};
        const score = data.riskScore;
        if (typeof score !== 'number' || score < 0 || score > 100) {
            console.warn('[aiClient] Invalid score from AI engine — fail-closed', { received: score });
            return {
                score: 100,
                reasons: [{
                    feature: 'invalid_response',
                    label: 'AI engine returned invalid score',
                    concerning: true,
                    systemFault: true,
                }],
                rawDecision: 0,
                scoreFloor: 'invalid_response',
            };
        }

        return {
            score,
            reasons: Array.isArray(data.reasons) ? data.reasons : [],
            rawDecision: typeof data.rawDecision === 'number' ? data.rawDecision : 0,
            scoreFloor: data.scoreFloor ?? null,
        };
    } catch (err) {
        // Fail-CLOSED: deny access whenever the AI engine is unreachable.
        // One transient retry guards against keep-alive sockets dying on first
        // request after a gateway restart (you see this once at 09:58:28 in the logs).
        const retryable = err.code === 'ECONNRESET' || err.code === 'EPIPE' ||
                          err.message?.includes('socket hang up');
        if (retryable && !sessionMeta._retried) {
            console.warn('[aiClient] transient socket error — retrying once', { error: err.message });
            return getRiskAssessment({ ...sessionMeta, _retried: true });
        }

        console.warn('[aiClient] AI engine unreachable — fail-closed (score=100)', { error: err.message });
        return {
            score: 100,
            reasons: [{
                feature: 'engine_unreachable',
                label: 'AI engine unreachable',
                concerning: true,
                systemFault: true,   // tells formatters not to print z-score gibberish
            }],
            rawDecision: 0,
            scoreFloor: 'engine_unreachable',
        };
    }
}

/**
 * evaluateRiskScore — maps a continuous score to an access decision.
 * @param {number} score
 * @returns {'PERMIT'|'STEP_UP'|'REVOKE'}
 */
function evaluateRiskScore(score) {
    if (score > 75) return 'REVOKE';
    if (score >= 50) return 'STEP_UP';
    return 'PERMIT';
}

/** Backwards-compatible thin wrapper — returns just the float score. */
async function getRiskScore(sessionMeta) {
    const { score } = await getRiskAssessment(sessionMeta);
    return score;
}

module.exports = { getRiskScore, getRiskAssessment, evaluateRiskScore };
