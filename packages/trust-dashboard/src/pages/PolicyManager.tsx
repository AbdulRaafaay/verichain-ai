import React, { useState, useEffect } from 'react';
import api from '../api';

interface Proposal {
    hash:         string;
    userHash:     string;
    resourceHash: string;
    action:       'GRANT' | 'REVOKE';
    approvals:    number;
    timestamp:    string;
    executedOnChain?: boolean;
}

const THRESHOLD = 2;

const PolicyManager: React.FC = () => {
    const [userHash, setUserHash]             = useState('');
    const [resourceHash, setResourceHash]     = useState('');
    const [action, setAction]                 = useState<'GRANT' | 'REVOKE'>('GRANT');
    const [pendingChanges, setPendingChanges] = useState<Proposal[]>([]);
    const [submitting, setSubmitting]         = useState(false);
    const [approving, setApproving]           = useState<string | null>(null);
    const [error, setError]                   = useState('');
    const [success, setSuccess]               = useState('');

    const fetchProposals = () => {
        api.get<Proposal[]>('/api/admin/pending-policies')
            .then(r => setPendingChanges(r.data))
            .catch(() => setError('Failed to fetch pending policies.'));
    };

    useEffect(() => {
        fetchProposals();
        const iv = setInterval(fetchProposals, 5000);
        return () => clearInterval(iv);
    }, []);

    const proposeChange = async () => {
        if (!userHash.trim() || !resourceHash.trim()) return;
        setSubmitting(true);
        setError(''); setSuccess('');
        try {
            const res = await api.post<Proposal>(
                '/api/admin/propose-policy',
                { userHash: userHash.trim(), resourceHash: resourceHash.trim(), action }
            );
            setPendingChanges(prev => [res.data, ...prev]);
            setSuccess(`Proposal ${res.data.hash.substring(0, 10)}… created — needs ${THRESHOLD} approvals to execute on-chain.`);
            setUserHash(''); setResourceHash('');
        } catch {
            setError('Failed to propose policy change.');
        } finally {
            setSubmitting(false);
        }
    };

    const approveChange = async (proposal: Proposal) => {
        setApproving(proposal.hash);
        setError(''); setSuccess('');
        try {
            const res = await api.post<Proposal>('/api/admin/approve', { changeHash: proposal.hash });
            setPendingChanges(prev => prev.map(p => p.hash === proposal.hash ? res.data : p));
            if (res.data.approvals >= THRESHOLD) {
                setSuccess(`Threshold reached — change executed on-chain (tx queued).`);
            } else {
                setSuccess(`Approval ${res.data.approvals} / ${THRESHOLD} recorded.`);
            }
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
                    <h1 className="page-title"><span>⊕</span> Policy Engine</h1>
                    <p className="page-sub">Multi-signature governance — 2-of-3 admin approvals required (NFR-11)</p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {pending  > 0 && <span className="badge badge-yellow">{pending} pending</span>}
                    {executed > 0 && <span className="badge badge-green">{executed} executed</span>}
                </div>
            </div>

            {error && (
                <div className="alert-banner danger" style={{ marginBottom: '1rem' }}>
                    <span style={{ fontSize: '1.2rem' }}>⚠</span>
                    <div className="alert-body"><p>{error}</p></div>
                </div>
            )}
            {success && (
                <div className="alert-banner" style={{ background: 'rgba(52, 211, 153, 0.07)', border: '1px solid rgba(52, 211, 153, 0.3)', color: 'var(--success)', marginBottom: '1rem' }}>
                    <span style={{ fontSize: '1.2rem' }}>✓</span>
                    <div className="alert-body"><p>{success}</p></div>
                </div>
            )}

            {/* Workflow explainer */}
            <div className="card" style={{ marginBottom: '1.25rem' }}>
                <div className="card-header">
                    <div>
                        <div className="card-title">🔁 Multi-Sig Workflow</div>
                        <div className="card-subtitle">Each step is enforced by <code style={{ color: 'var(--accent)' }}>AccessPolicy.sol</code></div>
                    </div>
                </div>
                <div className="workflow">
                    <div className="workflow-step done">
                        <div className="step-num">1</div>
                        <div className="step-text">Propose Change</div>
                    </div>
                    <div className="workflow-step active">
                        <div className="step-num">2</div>
                        <div className="step-text">Sign · 2-of-3</div>
                    </div>
                    <div className="workflow-step">
                        <div className="step-num">3</div>
                        <div className="step-text">On-chain Execute</div>
                    </div>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', lineHeight: 1.6 }}>
                    Solidity prevents the same address from approving twice. In this demo both clicks come from the same Hardhat key,
                    so the second on-chain approval will revert; the off-chain counter still tracks the workflow.
                </div>
            </div>

            <div className="grid-2">
                {/* Proposal Form */}
                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">⊕ Propose Policy Change</div>
                            <div className="card-subtitle">Step 1 — submit hash for multi-sig review</div>
                        </div>
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
                        style={{ width: '100%' }}
                    >
                        {submitting ? 'Proposing…' : '⊕ Submit Proposal'}
                    </button>
                </div>

                {/* Pending Proposals */}
                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">⏳ Pending Proposals</div>
                            <div className="card-subtitle">Threshold {THRESHOLD} of 3 admins</div>
                        </div>
                    </div>

                    {pendingChanges.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-icon">⊕</div>
                            <div className="empty-msg">No pending policy changes</div>
                        </div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            {pendingChanges.map(p => (
                                <div key={p.hash} style={{
                                    background: 'var(--bg-surface)',
                                    border: '1px solid var(--border)',
                                    borderRadius: 'var(--radius-sm)',
                                    padding: '0.85rem 1rem',
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.55rem' }}>
                                        <span className={`badge ${p.action === 'GRANT' ? 'badge-green' : 'badge-red'}`}>{p.action}</span>
                                        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                            {new Date(p.timestamp).toLocaleTimeString()}
                                        </span>
                                    </div>
                                    <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                                        user: {p.userHash.substring(0, 18)}…<br />
                                        resource: {p.resourceHash.substring(0, 18)}…
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                            <span className={`badge ${p.approvals >= THRESHOLD ? 'badge-green' : 'badge-yellow'}`}>
                                                {p.approvals} / {THRESHOLD}
                                            </span>
                                            <div style={{ display: 'flex', gap: 3 }}>
                                                {[...Array(3)].map((_, i) => (
                                                    <div key={i} style={{
                                                        width: 8, height: 8, borderRadius: '50%',
                                                        background: i < p.approvals
                                                            ? (p.approvals >= THRESHOLD ? 'var(--success)' : 'var(--warning)')
                                                            : 'var(--border)',
                                                    }} />
                                                ))}
                                            </div>
                                        </div>
                                        {p.approvals >= THRESHOLD ? (
                                            <span className="badge badge-green">✓ EXECUTED</span>
                                        ) : (
                                            <button
                                                className="btn-ghost btn-sm"
                                                disabled={approving === p.hash}
                                                onClick={() => approveChange(p)}
                                            >
                                                {approving === p.hash ? '…' : (p.approvals === 0 ? 'Sign · Admin 1' : 'Sign · Admin 2')}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PolicyManager;
