import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { HeartbeatController } from '../controllers/heartbeat.controller';
import { ResourceController } from '../controllers/resource.controller';
import { AdminController } from '../controllers/admin.controller';

const router = Router();

// Sequence 1: Auth
router.get('/auth/nonce', AuthController.getNonce);
router.post('/auth/login', AuthController.login);

// Sequence 2: Resource Access
router.post('/resource/access', ResourceController.requestAccess);

// Sequence 3: Heartbeat
router.post('/heartbeat', HeartbeatController.ping);

// Admin / Dashboard Endpoints
router.get('/admin/overview', AdminController.getOverview);
router.post('/admin/revoke', AdminController.revokeSession);

export default router;
