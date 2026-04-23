import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

/**
 * mtlsVerify middleware ensures that a client certificate was presented and verified.
 * NFR-03: Mutual TLS Authentication.
 */
export const mtlsVerify = (req: Request, res: Response, next: NextFunction) => {
    // Exclude health check from mTLS requirement for Docker healthchecks
    if (req.path === '/health' || req.path === '/api/health') {
        return next();
    }

    const cert = (req.socket as any).getPeerCertificate();

    if (!cert || Object.keys(cert).length === 0) {
        logger.warn('mTLS Verification Failed: No client certificate presented', { ip: req.ip });
        return res.status(400).json({ error: 'Client certificate required' });
    }

    if (!(req.socket as any).authorized) {
        logger.warn('mTLS Verification Failed: Client certificate unauthorized', { ip: req.ip });
        return res.status(401).json({ error: 'Unauthorized client certificate' });
    }

    // Optional: Log fingerprints or specific cert details for auditing
    logger.info('mTLS Handshake Successful', { 
        subject: cert.subject.CN, 
        fingerprint: cert.fingerprint 
    });

    next();
};
