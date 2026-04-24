import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface Proposal {
    hash: string;
    userHash: string;
    resourceHash: string;
    action: 'GRANT' | 'REVOKE';
    approvals: number;
    timestamp: string;
}

const THRESHOLD = 2;

const PolicyManager: React.FC = () => {
    const [userHash, setUserHash]         = useState('');
    const [resourceHash, setResourceHash] = useState('');
    const [action, setAction]             = useState<'GRANT' | 'REVOKE'>('GRANT');
    const [pendingChanges, setPendingChanges] = useState<Proposal[]>([]);
    const [submitting, setSubmitting]     = useState(false);
    const [approving, setApproving]       = useState<string | null>(null);
    const [error, setError]               = useState('');
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';

    useEffect(() => {
        axios.get<Proposal[]>(`${gatewayUrl}/api/admin/pending-policies`, { withCredentials: true })
            .then(r => setPendingChanges(r.data))
            .catch(() => setError('Failed to fetch pending policies.'));
    }, [gatewayUrl]);

    const proposeChange = async () => {
        if (!userHash.trim() || !resourceHash.trim()) return;
        setSubmitting(true);
        setError('');
        try {
            const res = await axios.post<Proposal>(
                `${gatewayUrl}/api/admin/propose-policy`,
                { userHash: userHash.trim(), resourceHash: resourceHash.trim(), action },
                { withCredentials: true }
            );
            setPendingChanges(prev => [res.data, ...prev]);
            setUserHash('');
            setResourceHash('');
        } catch {
            setError('Failed to propose policy change.');
        } finally {
            setSubmitting(false);
        }
    };

    const approveChange = async (proposal: Proposal) => {
        setApproving(proposal.hash);
        try {
            const res = await axios.post<Proposal>(
                `${gatewayUrl}/api/admin/approve`,
                { changeHash: proposal.hash },
                { withCredentials: true }
            );
            setPendingChanges(prev => prev.map(p => p.hash === proposal.hash ? res.data : p));
        } catch {
            setError('Approval failed.');
        } finally {
            setApproving(null);
        }
    };

    const pending  = pendingChanges.filter(p => p.approvals < THRESHOLD).length;
    const executed = pendingChanges.filter(p => p.approvals >= THRESHOLD).length;

    return (
        <div className="page policy-manager">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Policy Manager</h1>
                    <p className="page-sub">Multi-signature access control — requires 2-of-3 admin approvals (NFR-11)</p>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem' }}>
                    {pending  > 0 && <span className="badge badge-yellow">{pending} pending</span>}
                    {executed > 0 && <span className="badge badge-green">{executed} executed</span>}
                </div>
            </div>

            {error && (
                <div style={{ marginBottom: '1.25rem', padding: '0.75rem 1rem', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, color: 'var(--danger)', fontSize: '0.875rem' }}>
                    ⚠ {error}
                </div>
            )}

            {/* Propose Form */}
            <div className="card" style={{ maxWidth: 520, marginBottom: '2rem' }}>
                <div className="card-header">
                    <div className="card-title">⊕ Propose Policy Change</div>
                </div>
                <div className="form-group">
                    <label>User Hash</label>
                    <input
                        placeholder="0x… or identifier"
                        value={userHash}
                        onChange={e => setUserHash(e.target.value)}
                    />
                </div>
                <div className="form-group">
                    <label>Resource Hash</label>
                    <input
                        placeholder="0x… or resource identifier"
                        value={resourceHash}
                        onChange={e => setResourceHash(e.target.value)}
                    />
                </div>
                <div className="form-group">
                    <label>Action</label>
                    <select value={action} onChange={e => setAction(e.target.value as 'GRANT' | 'REVOKE')}>
                        <option value="GRANT">Grant Access</option>
                        <option value="REVOKE">Revoke Access</option>
                    </select>
                </div>
                <button
                    className="btn-primary"
                    onClick={proposeChange}
                    disabled={submitting || !userHash.trim() || !resourceHash.trim()}
                >
                    {submitting ? '⏳ Proposing…' : '⊕ Submit Proposal'}
                </button>
            </div>

            {/* Pending Table */}
            <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                    Pending Proposals — threshold {THRESHOLD}/{3}
                </div>
                {pendingChanges.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">⊕</div>
                        <div className="empty-msg">No pending policy changes.</div>
                    </div>
                ) : (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Resource</th>
                                    <th>Action</th>
                                    <th>Approvals</th>
                                    <th>Proposed</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {pendingChanges.map(p => (
                                    <tr key={p.hash}>
                                        <td><span className="mono">{p.userHash.substring(0, 14)}…</span></td>
                                        <td><span className="mono">{p.resourceHash.substring(0, 14)}…</span></td>
                                        <td>
                                            <span className={`badge ${p.action === 'GRANT' ? 'badge-green' : 'badge-red'}`}>
                                                {p.action}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                                <span className={`badge ${p.approvals >= THRESHOLD ? 'badge-green' : 'badge-yellow'}`}>
                                                    {p.approvals}/3 signatures
                                                </span>
                                                <div style={{ display: 'flex', gap: 3 }}>
                                                    {[...Array(3)].map((_, i) => (
                                                        <div key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: i < p.approvals ? (p.approvals >= THRESHOLD ? 'var(--success)' : 'var(--warning)') : 'var(--border)' }} />
                                                    ))}
                                                </div>
                                            </div>
                                        </td>
                                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                            {new Date(p.timestamp).toLocaleString()}
                                        </td>
                                        <td>
                                            {p.approvals >= THRESHOLD ? (
                                                <span className="badge badge-green">✓ EXECUTED</span>
                                            ) : (
                                                <button
                                                    className="btn-ghost"
                                                    style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
                                                    disabled={approving === p.hash}
                                                    onClick={() => approveChange(p)}
                                                >
                                                    {approving === p.hash ? '⏳' : (p.approvals === 0 ? '✍ Sign as Admin 1' : '✍ Sign as Admin 2')}
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PolicyManager;
