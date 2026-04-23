import { AuditLogModel } from '../models/audit-log.model';
import { logger } from '../utils/logger';

export class AuditService {
    static async log(action: string, metadata: any) {
        try {
            await AuditLogModel.create({
                action,
                metadata,
                timestamp: new Date(),
                anchored: false
            });
            logger.info(`Audit log created: ${action}`);
        } catch (err) {
            logger.error('Failed to create audit log', { error: (err as Error).message });
        }
    }
}
