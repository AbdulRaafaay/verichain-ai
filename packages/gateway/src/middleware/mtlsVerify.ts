/**
 * mtlsVerify.ts — Mutual TLS client-certificate enforcement middleware.
 *
 * Only the /api/resource/access endpoint requires a valid mTLS client cert
 * (Desktop Agent presents its cert; Trust Dashboard / browsers cannot).
 *
 * In development (NODE_ENV !== 'production') the cert check is skipped so
 * the demo works without a local PKI.  Set NODE_ENV=production to enforce.
 *
 * Security controls (NFR-03):
 *  - Verifies a client cert was presented (getPeerCertificate)
 *  - Verifies the cert was signed by the trusted CA (socket.authorized)
 *  - Logs subject CN and fingerprint on success for audit trail
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

const MTLS_REQUIRED_PATHS = ['/api/resource/access'];

export const mtlsVerify = (req: Request, res: Response, next: NextFunction) => {
    const requiresMtls = MTLS_REQUIRED_PATHS.some(p => req.path.startsWith(p));
    if (!requiresMtls) return next();

    // Skip hard enforcement outside production so devs can run without a local PKI
    if (process.env.NODE_ENV !== 'production') {
        logger.warn('mTLS check skipped (NODE_ENV !== production)', { path: req.path });
        return next();
    }

    const cert = (req.socket as any).getPeerCertificate?.();

    if (!cert || Object.keys(cert).length === 0) {
        logger.warn('mTLS rejected: no client certificate', { ip: req.ip, path: req.path });
        return res.status(400).json({ error: 'Client certificate required' });
    }

    if (!(req.socket as any).authorized) {
        logger.warn('mTLS rejected: untrusted client certificate', { ip: req.ip, path: req.path });
        return res.status(401).json({ error: 'Unauthorized client certificate' });
    }

    logger.info('mTLS handshake verified', {
        subject:     cert.subject?.CN,
        fingerprint: cert.fingerprint,
    });

    next();
};
