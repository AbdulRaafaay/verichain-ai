import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

interface Alert {
    type: string;
    timestamp: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    details: string;
    txHash?: string;
}

const SEVERITY_CLASS: Record<string, string> = {
    CRITICAL: 'critical',
    HIGH:     'high',
    MEDIUM:   'medium',
};

const SEVERITY_BADGE: Record<string, string> = {
    CRITICAL: 'badge-red',
    HIGH:     'badge-yellow',
    MEDIUM:   'badge-blue',
};

const ThreatAlerts: React.FC = () => {
    const [alerts, setAlerts] = useState<Alert[]>([]);

    useEffect(() => {
        const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
        const socket = io(gatewayUrl, { withCredentials: true });

        // tamper_alert: from MerkleService (real tamper) or AdminController (simulate)
        socket.on('tamper_alert', (alert: any) => {
            setAlerts(prev => [{
                type:      alert?.type || 'TAMPER_ALERT',
                timestamp: alert?.timestamp || new Date().toISOString(),
                severity:  alert?.severity || 'CRITICAL',
                details:   alert?.details || 'Audit log integrity violation detected (Merkle mismatch)',
                txHash:    alert?.txHash,
            }, ...prev]);
        });

        // session anomaly revocations also surface as threat alerts
        socket.on('session_revoked', (data: any) => {
            if (data?.reason === 'High Risk Score' || data?.reason?.includes('Risk')) {
                setAlerts(prev => [{
                    type:      'ANOMALY_DETECTED',
                    timestamp: new Date().toISOString(),
                    severity:  'HIGH',
                    details:   `Session ${(data.sessionId || '').substring(0, 8)}… revoked — AI anomaly detected`,
                }, ...prev]);
            }
        });

        return () => { socket.disconnect(); };
    }, []);

    const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
    const high     = alerts.filter(a => a.severity === 'HIGH').length;
    const medium   = alerts.filter(a => a.severity === 'MEDIUM').length;

    return (
        <div className="page threat-alerts">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Threat &amp; Tamper Alerts</h1>
                    <p className="page-sub">Real-time tamper detection events pushed from the Security Gateway</p>
                </div>
                {alerts.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.6rem' }}>
                        {critical > 0 && <span className="badge badge-red">🔴 {critical} Critical</span>}
                        {high     > 0 && <span className="badge badge-yellow">⚠ {high} High</span>}
                        {medium   > 0 && <span className="badge badge-blue">{medium} Medium</span>}
                    </div>
                )}
            </div>

            {alerts.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-icon">✅</div>
                    <div className="empty-msg" style={{ fontSize: '1rem', fontWeight: 500, color: 'var(--success)' }}>
                        All systems normal
                    </div>
                    <div className="empty-msg" style={{ marginTop: '0.35rem' }}>
                        No active threats or tamper events. Real-time alerts will appear here.
                    </div>
                </div>
            ) : (
                <div className="alert-feed">
                    {alerts.map((a, i) => (
                        <div key={i} className={`alert-card ${SEVERITY_CLASS[a.severity] || 'medium'}`}>
                            <div className="alert-meta">
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                                    <span className={`badge ${SEVERITY_BADGE[a.severity] || 'badge-blue'}`}>
                                        {a.severity}
                                    </span>
                                    <span className="alert-type">{a.type}</span>
                                </div>
                                <span className="alert-time">{new Date(a.timestamp).toLocaleString()}</span>
                            </div>
                            <p className="alert-detail">{a.details || 'Integrity mismatch detected on-chain.'}</p>
                            {a.txHash && (
                                <p className="alert-tx">
                                    Tx: {a.txHash}
                                </p>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ThreatAlerts;
