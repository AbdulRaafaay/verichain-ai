import React, { useEffect, useState } from 'react';
import axios from 'axios';
import DetailModal from '../components/DetailModal';

interface AuditLog {
    _id: string;
    timestamp: string;
    eventType: string;
    userHash: string;
    resourceHash: string;
    riskScore: number;
    decision: string;
    anchored: boolean;
    merkleRoot: string;
    metadata?: any;
}

const AuditLogs: React.FC = () => {
    const [logs, setLogs]       = useState<AuditLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter]   = useState('');
    const [selected, setSelected] = useState<AuditLog | null>(null);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';

    useEffect(() => {
        axios.get<AuditLog[]>(`${gatewayUrl}/api/admin/audit-logs`, { withCredentials: true })
            .then(r => setLogs(r.data))
            .catch(err => console.error('Failed to fetch audit logs', err))
            .finally(() => setLoading(false));
    }, [gatewayUrl]);

    const filtered = filter
        ? logs.filter(l =>
            l.eventType?.toLowerCase().includes(filter.toLowerCase()) ||
            l.userHash?.toLowerCase().includes(filter.toLowerCase()) ||
            l.decision?.toLowerCase().includes(filter.toLowerCase())
          )
        : logs;

    const anchoredCount = logs.filter(l => l.anchored).length;

    return (
        <div className="page audit-logs">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Audit Logs</h1>
                    <p className="page-sub">Tamper-evident event log anchored to Ethereum via Merkle tree</p>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <span className="badge badge-green">⛓ {anchoredCount} anchored</span>
                    <span className="badge badge-gray">{logs.length} total</span>
                </div>
            </div>

            <div style={{ marginBottom: '1.25rem', maxWidth: 340 }}>
                <input
                    placeholder="Filter by event, user, or decision…"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                />
            </div>

            {loading ? (
                <div className="loading-state">
                    <div className="spinner" />
                    <span>Loading audit logs…</span>
                </div>
            ) : filtered.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-icon">≡</div>
                    <div className="empty-msg">{filter ? 'No logs match your filter.' : 'No audit events recorded yet.'}</div>
                </div>
            ) : (
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Event</th>
                                <th>User Hash</th>
                                <th>Risk</th>
                                <th>Decision</th>
                                <th>Integrity</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map(log => (
                                <tr key={log._id} onClick={() => setSelected(log)} style={{ cursor: 'pointer' }}>
                                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                                        {new Date(log.timestamp).toLocaleString()}
                                    </td>
                                    <td>
                                        <span className={`badge ${log.eventType?.includes('FAIL') ? 'badge-red' : log.eventType?.includes('WARN') ? 'badge-yellow' : 'badge-blue'}`}>
                                            {log.eventType || '—'}
                                        </span>
                                    </td>
                                    <td>
                                        <span className="mono">
                                            {log.userHash ? log.userHash.substring(0, 10) + '…' : '—'}
                                        </span>
                                    </td>
                                    <td>
                                        <span className={`badge ${(log.riskScore ?? 0) > 75 ? 'badge-red' : (log.riskScore ?? 0) > 49 ? 'badge-yellow' : 'badge-green'}`}>
                                            {Math.round(log.riskScore ?? 0)}
                                        </span>
                                    </td>
                                    <td style={{ fontWeight: 500 }}>{log.decision || '—'}</td>
                                    <td>
                                        {log.anchored ? (
                                            <span className="badge badge-green" title={log.merkleRoot}>⛓ Anchored</span>
                                        ) : (
                                            <span className="badge badge-gray">Pending</span>
                                        )}
                                    </td>
                                    <td>
                                        <button className="btn-ghost" style={{ fontSize: '0.75rem' }}>View Details</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {selected && (
                <DetailModal
                    isOpen={!!selected}
                    onClose={() => setSelected(null)}
                    title="Audit Log Detail"
                    data={{
                        'Event ID': selected._id,
                        'Timestamp': selected.timestamp,
                        'Action': selected.eventType,
                        'User Hash': selected.userHash,
                        'Resource Hash': selected.resourceHash,
                        'Risk Score': selected.riskScore,
                        'Decision': selected.decision,
                        'Anchored': selected.anchored ? 'YES' : 'NO',
                        'Merkle Root': selected.merkleRoot || 'Not yet anchored',
                        ...selected.metadata
                    }}
                />
            )}
        </div>
    );
};

export default AuditLogs;
