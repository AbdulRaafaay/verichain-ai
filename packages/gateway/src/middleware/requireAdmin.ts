/**
 * requireAdmin.ts — Admin API authentication middleware.
 *
 * All /api/admin/* routes require the caller to present the shared admin key
 * via the X-Admin-Key request header.  The Trust Dashboard sends this key on
 * every admin API call.
 *
 * Security controls (STRIDE: Elevation of Privilege):
 *  - Shared secret checked with crypto.timingSafeEqual to prevent timing attacks
 *  - Returns 401 (not 403) so unauthenticated callers do not learn whether the
 *    route exists (avoids information disclosure)
 *  - If ADMIN_API_KEY is not set the middleware fails closed: every request is
 *    rejected rather than accidentally allowing unauthenticated access
 */

import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { logger } from '../utils/logger';

const ADMIN_KEY = process.env.ADMIN_API_KEY;

if (!ADMIN_KEY) {
    // Log loudly at startup — admin endpoints will reject all requests until the
    // variable is set.  We do NOT default to an empty string (would bypass the check).
    console.error('[SECURITY] ADMIN_API_KEY environment variable is not set — admin routes will return 401.');
}

export const requireAdmin = (req: Request, res: Response, next: NextFunction): void => {
    if (!ADMIN_KEY) {
        logger.warn('Admin request rejected: ADMIN_API_KEY not configured', { ip: req.ip, path: req.path });
        res.status(401).json({ error: 'Admin access not configured' });
        return;
    }

    const provided = req.headers['x-admin-key'];
    if (!provided || typeof provided !== 'string') {
        logger.warn('Admin request rejected: missing X-Admin-Key header', { ip: req.ip, path: req.path });
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    // Constant-time comparison prevents timing-based secret enumeration
    const providedBuf = Buffer.from(provided);
    const expectedBuf = Buffer.from(ADMIN_KEY);
    const match =
        providedBuf.length === expectedBuf.length &&
        crypto.timingSafeEqual(providedBuf, expectedBuf);

    if (!match) {
        logger.warn('Admin request rejected: invalid X-Admin-Key', { ip: req.ip, path: req.path });
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    next();
};
