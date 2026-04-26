import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import api, { GATEWAY_URL, ADMIN_KEY } from '../api';

interface Reason {
    feature?:    string;
    label?:      string;
    value?:      number;
    expected?:   number;
    zScore?:     number;
    deviation?:  number;
    direction?:  string;
    concerning?: boolean;
    unit?:       string;
}

interface Alert {
    type:       string;
    timestamp:  string;
    severity:   'CRITICAL' | 'HIGH' | 'MEDIUM';
    details:    string;
    txHash?:    string;
    riskScore?: number;
    reasons?:   Reason[];
    sessionId?: string;
    /** Stable de-dup key: tx-hash + timestamp+ session id*/
    _key?:      string;
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

const STORAGE_KEY = 'verichain_threat_alerts';

const keyOf = (a: Alert) =>
    a._key || `${a.type}|${a.timestamp}|${a.sessionId || a.txHash || ''}`;

const ThreatAlerts: React.FC = () => {
    const [alerts, setAlerts] = useState<Alert[]>(() => {
        try {
            const saved = sessionStorage.getItem(STORAGE_KEY);
            return saved ? JSON.parse(saved) : [];
        } catch { return []; }
    });

    useEffect(() => {
        try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(alerts)); } catch { /* storage full */ }
    }, [alerts]);

    /** Merge new alerts into state, deduplicating by stable key. */
    const merge = (incoming: Alert[]) => {
        setAlerts(prev => {
            const seen = new Set(prev.map(keyOf));
            const additions = incoming
                .map(a => ({ ...a, _key: keyOf(a) }))
                .filter(a => !seen.has(a._key!));
            return [...additions, ...prev].slice(0, 200);
        });
    };

    useEffect(() => {
        // Hydrate from server on mount — covers events that fired before this tab opened.
        api.get<Alert[]>('/api/admin/recent-alerts')
            .then(r => merge(r.data || []))
            .catch(() => { /* gateway not ready */ });

        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);

        // Live: tamper_alert from MerkleService (real tamper) or AdminController (simulate)
        socket.on('tamper_alert', (alert: any) => {
            merge([{
                type:      alert?.type || 'TAMPER_ALERT',
                timestamp: alert?.timestamp || new Date().toISOString(),
                severity:  alert?.severity || 'CRITICAL',
                details:   alert?.details || 'Audit log integrity violation detected (Merkle mismatch)',
                txHash:    alert?.txHash,
                riskScore: alert?.riskScore,
                reasons:   alert?.reasons,
                sessionId: alert?.sessionId,
            }]);
        });

        // Live: session anomaly revocations
        socket.on('session_revoked', (data: any) => {
            if (data?.reason === 'High Risk Score' || data?.reason?.includes('Risk')) {
                const sessionId = data.sessionId || '';
                merge([{
                    type:      'SESSION_REVOKED',
                    timestamp: new Date().toISOString(),
                    severity:  'HIGH',
                    details:   `Session ${sessionId.substring(0, 8)}… revoked — AI risk score ${data.riskScore ?? '?'}/100`,
                    riskScore: data.riskScore,
                    reasons:   data.reasons,
                    sessionId,
                }]);
            }
        });

        return () => { socket.disconnect(); };
    }, []);

    const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
    const high     = alerts.filter(a => a.severity === 'HIGH').length;
    const medium   = alerts.filter(a => a.severity === 'MEDIUM').length;

    const formatVal = (v: any, unit?: string) => {
        if (typeof v !== 'number') return String(v ?? '?');
        if (unit === 'bytes' && v >= 1000) {
            if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)} MB`;
            return `${(v / 1024).toFixed(0)} KB`;
        }
        return `${v.toFixed(v < 10 ? 2 : 0)}${unit ? ' ' + unit : ''}`;
    };

    return (
        <div className="page threat-alerts">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>⚡</span> Threat &amp; Tamper Alerts</h1>
                    <p className="page-sub">Live anomaly detections, Merkle integrity violations, and revocation events · with explainability</p>
                </div>
                {alerts.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        {critical > 0 && <span className="badge badge-red">🔴 {critical} Critical</span>}
                        {high     > 0 && <span className="badge badge-yellow">⚠ {high} High</span>}
                        {medium   > 0 && <span className="badge badge-blue">{medium} Medium</span>}
                        <button
                            className="btn-ghost btn-sm"
                            onClick={() => {
                                setAlerts([]);
                                try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* noop */ }
                            }}
                        >
                            Clear All
                        </button>
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
                        No active threats or tamper events. The page hydrates from the last 24 h on load and live-updates via Socket.io.
                    </div>
                </div>
            ) : (
                <div className="alert-feed">
                    {alerts.map((a, i) => (
                        <div key={a._key || i} className={`alert-card ${SEVERITY_CLASS[a.severity] || 'medium'}`}>
                            <div className="alert-meta">
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                                    <span className={`badge ${SEVERITY_BADGE[a.severity] || 'badge-blue'}`}>
                                        {a.severity}
                                    </span>
                                    <span className="alert-type">{a.type.replace(/_/g, ' ')}</span>
                                    {typeof a.riskScore === 'number' && (
                                        <span className={`badge ${a.riskScore > 75 ? 'badge-red' : a.riskScore >= 50 ? 'badge-yellow' : 'badge-green'}`}>
                                            risk {a.riskScore.toFixed(0)}
                                        </span>
                                    )}
                                </div>
                                <span className="alert-time">{new Date(a.timestamp).toLocaleString()}</span>
                            </div>
                            <p className="alert-detail">{a.details || 'Integrity mismatch detected on-chain.'}</p>

                            {/* Per-feature explanations from the Isolation Forest */}
                            {a.reasons && a.reasons.length > 0 && (
                                <div style={{ marginTop: '0.6rem', padding: '0.6rem 0.75rem', background: 'rgba(28, 42, 74, 0.3)', borderRadius: 6, fontSize: '0.78rem' }}>
                                    <div style={{ fontSize: '0.66rem', color: 'var(--danger)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginBottom: '0.3rem' }}>
                                        Anomaly direction · why this fired
                                    </div>
                                    {a.reasons.filter(r => r.concerning !== false).map((r, idx) => (
                                        <div key={'c'+idx} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                                            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                                                ⚠ {r.label || r.feature}:
                                            </span>
                                            <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--danger)' }}>
                                                {formatVal(r.value, r.unit)} (expected ~{formatVal(r.expected, r.unit)}, z={r.zScore})
                                            </span>
                                        </div>
                                    ))}
                                    {a.reasons.some(r => r.concerning === false) && (
                                        <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginTop: '0.5rem', marginBottom: '0.3rem' }}>
                                            Unusual but not concerning
                                        </div>
                                    )}
                                    {a.reasons.filter(r => r.concerning === false).map((r, idx) => (
                                        <div key={'i'+idx} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                                            <span style={{ color: 'var(--text-muted)' }}>
                                                ℹ {r.label || r.feature}:
                                            </span>
                                            <span className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                                                {formatVal(r.value, r.unit)} (expected ~{formatVal(r.expected, r.unit)}, z={r.zScore})
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}

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
