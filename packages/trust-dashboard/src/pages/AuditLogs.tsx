import React, { useEffect, useState } from 'react';
import api from '../api';
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
    const [logs, setLogs]         = useState<AuditLog[]>([]);
    const [loading, setLoading]   = useState(true);
    const [filter, setFilter]     = useState('');
    const [selected, setSelected] = useState<AuditLog | null>(null);
    const [page, setPage]         = useState(0);
    const PAGE_SIZE = 10;

    useEffect(() => {
        api.get<AuditLog[]>('/api/admin/audit-logs')
            .then(r => setLogs(r.data))
            .catch(err => console.error('Failed to fetch audit logs', err))
            .finally(() => setLoading(false));
    }, []);

    const filtered = filter
        ? logs.filter(l =>
            l.eventType?.toLowerCase().includes(filter.toLowerCase()) ||
            l.userHash?.toLowerCase().includes(filter.toLowerCase()) ||
            l.decision?.toLowerCase().includes(filter.toLowerCase())
          )
        : logs;

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    const paginated  = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    const anchoredCount = logs.filter(l => l.anchored).length;

    const QUICK_FILTERS = [
        { label: 'All',     value: '' },
        { label: 'Login',   value: 'LOGIN' },
        { label: 'Access',  value: 'ACCESS' },
        { label: 'Revoked', value: 'REVOK' },
        { label: 'Denied',  value: 'DENIED' },
        { label: 'Failed',  value: 'FAIL' },
    ];

    return (
        <div className="page audit-logs">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>≡</span> Audit Log</h1>
                    <p className="page-sub">Every security-relevant event · MongoDB durability + Merkle on-chain proof</p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <span className="badge badge-green">⛓ {anchoredCount} anchored</span>
                    <span className="badge badge-gray">{logs.length} total</span>
                </div>
            </div>

            <div className="filter-chips">
                {QUICK_FILTERS.map(f => (
                    <span
                        key={f.label}
                        className={`chip ${filter.toUpperCase() === f.value ? 'active' : ''}`}
                        onClick={() => { setFilter(f.value); setPage(0); }}
                    >
                        {f.label}
                    </span>
                ))}
            </div>

            <div style={{ marginBottom: '1.25rem', maxWidth: 340 }}>
                <input
                    placeholder="Search by event, user hash, or decision…"
                    value={filter}
                    onChange={e => { setFilter(e.target.value); setPage(0); }}
                />
            </div>

            {loading ? (
                <div className="table-wrap">
                    <table>
                        <thead><tr><th>Timestamp</th><th>Event</th><th>User Hash</th><th>Risk</th><th>Decision</th><th>Integrity</th><th>Actions</th></tr></thead>
                        <tbody>
                            {Array.from({ length: 5 }).map((_, i) => (
                                <tr key={i} className="skeleton-row">
                                    <td><div className="skeleton-cell" style={{ width: '9rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '7rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '6rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '2.5rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '5rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '5rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '5rem' }} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : filtered.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-icon">≡</div>
                    <div className="empty-msg">{filter ? 'No logs match your filter.' : 'No audit events recorded yet.'}</div>
                </div>
            ) : (
                <>
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
                            {paginated.map(log => (
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
                {totalPages > 1 && (
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.75rem', padding: '0.875rem 1rem', borderTop: '1px solid var(--border)', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        <span>Page {page + 1} of {totalPages}</span>
                        <button className="btn-ghost" style={{ fontSize: '0.8rem' }} disabled={page === 0} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <button className="btn-ghost" style={{ fontSize: '0.8rem' }} disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
                </>
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
