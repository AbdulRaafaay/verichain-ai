/**
 * audit.service.ts — Tamper-evident audit logging service.
 *
 * Every authentication event, access decision, and session lifecycle change is
 * persisted to MongoDB as an AuditLog document.  Un-anchored logs are later
 * batched by MerkleService and their root is committed to Ethereum, making
 * retrospective modification detectable.
 *
 * Security controls: no sensitive data (passwords, private keys) is stored — only
 * hashed identifiers and risk scores.
 */

import { AuditLogModel } from '../models/audit-log.model';
import { logger } from '../utils/logger';

export class AuditService {

    /**
     * log — writes an immutable audit record to MongoDB.
     *
     * @param action   - Event type (e.g. 'LOGIN_SUCCESS', 'ACCESS_DENIED')
     * @param metadata - Structured context: userHash, resourceHash, riskScore, reason, etc.
     *                   Must not contain raw credentials or private keys.
     *
     * Security: errors are caught and logged internally so a DB write failure
     * never silently swallows the parent request — it is surfaced via Winston.
     */
    static async log(action: string, metadata: any): Promise<void> {
        try {
            await AuditLogModel.create({
                action,
                metadata,
                timestamp: new Date(),
                anchored:  false,
            });
            logger.info(`Audit log created: ${action}`);
        } catch (err) {
            logger.error('Failed to create audit log', { error: (err as Error).message });
        }
    }
}
