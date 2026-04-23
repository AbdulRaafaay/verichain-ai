import mongoose, { Schema, Document } from 'mongoose';

export interface IAuditLog extends Document {
    action: string;
    metadata: any;
    timestamp: Date;
    merkleRoot?: string;
    txHash?: string;
    anchored: boolean;
}

const AuditLogSchema: Schema = new Schema({
    action: { type: String, required: true },
    metadata: { type: Schema.Types.Mixed },
    timestamp: { type: Date, default: Date.now },
    merkleRoot: { type: String },
    txHash: { type: String },
    anchored: { type: Boolean, default: false }
});

export const AuditLogModel = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
