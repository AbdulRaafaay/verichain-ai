'use strict';

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    eventType: { type: String, required: true, index: true },
    userHash: { type: String, required: true, index: true },
    resourceHash: { type: String, index: true },
    sessionId: { type: String, index: true },
    riskScore: { type: Number, min: 0, max: 100 },
    decision: { type: String, enum: ['PERMIT', 'DENY', 'STEP_UP', 'REVOKE'], required: true },
    ip: { type: String },
    details: { type: mongoose.Schema.Types.Mixed },
    anchored: { type: Boolean, default: false, index: true },
    merkleRoot: { type: String, index: true },
    anchorTxHash: { type: String },
    anchoredAt: { type: Date },
    timestamp: { type: Date, default: Date.now, index: true }
});

// Compound index for anchoring service
auditLogSchema.index({ anchored: 1, timestamp: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
