/**
 * VeriChain AI — Continuous mTLS Heartbeat Service
 * Sends a cryptographic heartbeat to the Gateway every 30 seconds.
 * Maps to: FR-06 / NFR-06
 */

'use strict';

const HEARTBEAT_INTERVAL_MS = 30 * 1000;

let heartbeatInterval = null;

function startHeartbeat(sessionId, sendFn, onRevoked) {
    stopHeartbeat();
    
    heartbeatInterval = setInterval(async () => {
        try {
            await sendFn(sessionId);
        } catch (err) {
            stopHeartbeat();
            if (onRevoked) onRevoked(sessionId, 'HEARTBEAT_FAILED');
        }
    }, HEARTBEAT_INTERVAL_MS);
}

function stopHeartbeat() {
    if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
    }
}

module.exports = { startHeartbeat, stopHeartbeat };
