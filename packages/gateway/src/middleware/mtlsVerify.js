'use strict';

const winston = require('winston');

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

/**
 * mTLS Verification Middleware
 * Validates that a client certificate was provided and is authorized by our Root CA.
 * Maps to: NFR-03
 */
function mtlsVerify(req, res, next) {
    const cert = req.socket.getPeerCertificate();

    if (!req.client.authorized) {
        logger.warn('Unauthorized mTLS connection attempt', {
            ip: req.ip,
            reason: req.socket.authorizationError
        });
        return res.status(403).json({
            error: 'Mutual TLS authentication required',
            reason: req.socket.authorizationError
        });
    }

    if (!cert || !cert.subject) {
        logger.warn('mTLS connection missing certificate subject', { ip: req.ip });
        return res.status(403).json({ error: 'Client certificate required' });
    }

    // Attach cert info to request
    req.clientCert = {
        subject: cert.subject.CN,
        fingerprint: cert.fingerprint
    };

    next();
}

module.exports = mtlsVerify;
