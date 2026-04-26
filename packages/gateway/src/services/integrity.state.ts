/**
 * integrity.state.ts — Shared module for log-integrity state.
 *
 * Lives in its own file so the Merkle service (which detects tampering) and
 * the app's broadcast loop (which reports it) can both import it without a
 * circular dependency.
 */

export type LogIntegrityState = 'SECURE' | 'COMPROMISED';

let state: LogIntegrityState = 'SECURE';
let lastTamperAt: string | null = null;

export const IntegrityState = {
    get(): LogIntegrityState { return state; },
    getLastTamperAt(): string | null { return lastTamperAt; },
    markCompromised(timestamp: string = new Date().toISOString()): void {
        state = 'COMPROMISED';
        lastTamperAt = timestamp;
    },
    markSecure(): void { state = 'SECURE'; },
};
