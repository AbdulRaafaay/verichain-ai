/**
 * schemas.ts — Zod input validation schemas for all gateway API endpoints.
 *
 * Each schema is used by the validate / validateQuery middleware to reject
 * malformed requests before they reach controller logic, preventing injection
 * attacks and unexpected application state.
 *
 * Security controls applied here:
 *  - String length bounds prevent oversized payloads slipping past the 10 kb
 *    body-size limit in edge cases (deeply nested JSON).
 *  - UUID enforcement on sessionId fields prevents enumeration by guessing
 *    sequential IDs.
 *  - Enum enforcement on action prevents any value other than GRANT/REVOKE
 *    reaching the blockchain policy contract.
 */

import { z } from 'zod';

/** GET /api/auth/nonce */
export const NonceQuerySchema = z.object({
    clientId: z.string().min(1).max(128),
});

/** POST /api/auth/login */
export const LoginSchema = z.object({
    clientId:      z.string().min(1).max(128),
    nonce:         z.string().min(1).max(256),
    proof:         z.record(z.unknown()),
    publicSignals: z.array(z.string()),
    userHash:      z.string().min(1).max(128),
});

/** POST /api/heartbeat */
export const HeartbeatSchema = z.object({
    sessionId: z.string().uuid(),
});

/** POST /api/resource/access */
export const ResourceAccessSchema = z.object({
    sessionId:  z.string().uuid(),
    resourceId: z.string().min(1).max(256),
    telemetry:  z.record(z.unknown()).optional(),
});

/** POST /api/admin/revoke */
export const RevokeSessionSchema = z.object({
    sessionId: z.string().uuid(),
    reason:    z.string().max(256).optional(),
});

/** POST /api/admin/propose-policy */
export const ProposePolicySchema = z.object({
    userHash:     z.string().min(1).max(128),
    resourceHash: z.string().min(1).max(128),
    action:       z.enum(['GRANT', 'REVOKE']),
});

/** POST /api/admin/approve */
export const ApprovePolicySchema = z.object({
    changeHash: z.string().min(1).max(128),
});
