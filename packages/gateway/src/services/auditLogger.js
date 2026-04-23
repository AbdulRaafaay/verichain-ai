'use strict';

const AuditLog = require('../models/AuditLogModel');
const winston = require('winston');

const logger = winston.createLogger({
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

class AuditLogger {
    static async log({ eventType, userHash, resourceHash, sessionId, riskScore, decision, ip, details }) {
        try {
            const entry = new AuditLog({
                eventType,
                userHash,
                resourceHash,
                sessionId,
                riskScore,
                decision,
                ip,
                details
            });
            await entry.save();
            logger.info('Audit log saved', { eventType, userHash: userHash.substring(0, 8) });
        } catch (err) {
            logger.error('Failed to save audit log', { error: err.message });
        }
    }
}

module.exports = AuditLogger;
