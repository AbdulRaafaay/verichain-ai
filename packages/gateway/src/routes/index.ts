import { Router } from 'express';
import { AuthController }      from '../controllers/auth.controller';
import { HeartbeatController } from '../controllers/heartbeat.controller';
import { ResourceController }  from '../controllers/resource.controller';
import { AdminController }     from '../controllers/admin.controller';
import { validate, validateQuery } from '../middleware/validate';
import { rateLimit }           from '../middleware/rateLimit';
import { requireAdmin }        from '../middleware/requireAdmin';
import {
    NonceQuerySchema,
    LoginSchema,
    HeartbeatSchema,
    ResourceAccessSchema,
    RevokeSessionSchema,
    ProposePolicySchema,
    ApprovePolicySchema,
} from '../types/schemas';

const router = Router();

// ── Auth (Sequence 1) ─────────────────────────────────────────────────────────
router.get(
    '/auth/nonce',
    rateLimit({ windowSecs: 60, max: 20, keyPrefix: 'rl:nonce' }),
    validateQuery(NonceQuerySchema),
    AuthController.getNonce,
);

router.post(
    '/auth/login',
    rateLimit({ windowSecs: 60, max: 10, keyPrefix: 'rl:login' }),
    validate(LoginSchema),
    AuthController.login,
);

// ── Resource access (Sequence 2) ──────────────────────────────────────────────
router.post(
    '/resource/access',
    validate(ResourceAccessSchema),
    ResourceController.requestAccess,
);

// ── Heartbeat (Sequence 3) ────────────────────────────────────────────────────
router.post(
    '/heartbeat',
    rateLimit({ windowSecs: 60, max: 120, keyPrefix: 'rl:hb' }),
    validate(HeartbeatSchema),
    HeartbeatController.ping,
);

// ── Admin — all routes require X-Admin-Key header ────────────────────────────
router.use('/admin', requireAdmin);

router.get('/admin/overview',            AdminController.getOverview);
router.post('/admin/revoke',             validate(RevokeSessionSchema), AdminController.revokeSession);
router.get('/admin/audit-logs',          AdminController.getAuditLogs);
router.get('/admin/pending-policies',    AdminController.getPendingPolicies);
router.post('/admin/propose-policy',     validate(ProposePolicySchema), AdminController.proposePolicy);
router.post('/admin/approve',            validate(ApprovePolicySchema), AdminController.approvePolicy);
router.post('/admin/simulate-tamper',    AdminController.simulateTamper);
router.get('/admin/system-status',       AdminController.getSystemStatus);
router.get('/admin/blockchain-events',   AdminController.getBlockchainEvents);
router.get('/admin/recent-alerts',       AdminController.getRecentAlerts);

export default router;
