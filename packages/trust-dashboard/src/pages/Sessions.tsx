import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import DetailModal from '../components/DetailModal';

interface Session {
    id: string;
    userHash: string;
    currentResource: string;
    loginTime: string;
    lastHeartbeat: string;
    duration: string;
    riskScore: number;
    status: 'ACTIVE' | 'REVOKED';
    metadata?: any;
}

const Sessions: React.FC = () => {
    const [sessions, setSessions] = useState<Session[]>([]);
    const [loading, setLoading]   = useState(true);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [selected, setSelected] = useState<Session | null>(null);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';

    useEffect(() => {
        const socket = io(gatewayUrl, { withCredentials: true } as any);

        const fetchSessions = async () => {
            try {
                const res = await axios.get(`${gatewayUrl}/api/admin/overview`, { withCredentials: true });
                setSessions(res.data.sessions || []);
            } catch (err) {
                console.error('Failed to fetch sessions', err);
            } finally {
                setLoading(false);
            }
        };

        fetchSessions();

        // Real-time: socket events from gateway
        socket.on('session_update', (updated: Session[]) => {
            setSessions(updated);
            setLoading(false);
        });
        socket.on('session_revoked', ({ sessionId }: { sessionId: string }) =>
            setSessions(prev => prev.map(s => (s.id === sessionId ? { ...s, status: 'REVOKED' } : s)))
        );

        const poll = setInterval(fetchSessions, 5000);
        const tick = setInterval(() => setSessions(s => [...s]), 1000);

        return () => { socket.disconnect(); clearInterval(poll); clearInterval(tick); };
    }, [gatewayUrl]);

    const revokeSession = async (e: React.MouseEvent, id: string) => {
        e.stopPropagation();
        setRevoking(id);
        try {
            await axios.post(`${gatewayUrl}/api/admin/revoke`, { sessionId: id }, { withCredentials: true });
        } catch (err) {
            console.error('Failed to revoke session', err);
        } finally {
            setRevoking(null);
        }
    };

    const riskBadge = (score: number) => {
        if (score > 75) return <span className="badge badge-red">{Math.round(score)}</span>;
        if (score > 50) return <span className="badge badge-yellow">{Math.round(score)}</span>;
        return <span className="badge badge-green">{Math.round(score)}</span>;
    };

    const active  = sessions.filter(s => s.status === 'ACTIVE').length;
    const revoked = sessions.filter(s => s.status === 'REVOKED').length;

    return (
        <div className="page sessions">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Active Sessions</h1>
                    <p className="page-sub">All authenticated sessions and their real-time risk posture</p>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <span className="badge badge-green">● {active} Active</span>
                    {revoked > 0 && <span className="badge badge-gray">{revoked} Revoked</span>}
                </div>
            </div>

            {loading ? (
                <div className="loading-state">
                    <div className="spinner" />
                    <span>Loading sessions…</span>
                </div>
            ) : sessions.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-icon">◎</div>
                    <div className="empty-msg">No sessions yet. Authenticate via the Desktop Agent to see them here.</div>
                </div>
            ) : (
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Session ID</th>
                                <th>User Hash</th>
                                <th>Current Resource</th>
                                <th>Login Time</th>
                                <th>Duration</th>
                                <th>Last Heartbeat</th>
                                <th>Risk Score</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sessions.map(s => {
                                const sid = s.id || (s as any).sessionId || '';
                                const hbAge = s.lastHeartbeat
                                    ? Math.floor((Date.now() - new Date(s.lastHeartbeat).getTime()) / 1000)
                                    : null;
                                const hbColor = hbAge !== null && hbAge < 35 ? 'var(--success)' : 'var(--warning)';
                                return (
                                    <tr key={sid} onClick={() => setSelected(s)} style={{ cursor: 'pointer' }}>
                                        <td><span className="mono" title={sid}>{sid.substring(0, 8)}…</span></td>
                                        <td><span className="mono" title={s.userHash}>{(s.userHash || '').substring(0, 10)}…</span></td>
                                        <td><code style={{ fontSize: '0.75rem' }}>{s.currentResource || 'None'}</code></td>
                                        <td style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                                            {s.loginTime ? new Date(s.loginTime).toLocaleTimeString() : '—'}
                                        </td>
                                        <td>{s.duration || '—'}</td>
                                        <td style={{ fontWeight: 600, color: hbColor }}>
                                            {hbAge !== null ? `${hbAge}s ago` : '—'}
                                        </td>
                                        <td>
                                            {riskBadge(s.riskScore ?? 0)}
                                        </td>
                                        <td>
                                            <span className={`badge ${s.status === 'ACTIVE' ? 'badge-green' : 'badge-gray'}`}>
                                                {s.status === 'ACTIVE' ? '● ' : ''}{s.status}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '0.5rem' }}>
                                                <button className="btn-ghost" style={{ fontSize: '0.75rem' }}>Inspect</button>
                                                {s.status === 'ACTIVE' && (
                                                    <button
                                                        className="btn-danger"
                                                        disabled={revoking === sid}
                                                        onClick={(e) => revokeSession(e, sid)}
                                                        style={{ fontSize: '0.78rem', padding: '0.3rem 0.7rem' }}
                                                    >
                                                        {revoking === sid ? '…' : 'Revoke'}
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}

            {selected && (
                <DetailModal
                    isOpen={!!selected}
                    onClose={() => setSelected(null)}
                    title="Session Details"
                    data={{
                        'Session ID': selected.id,
                        'User Hash': selected.userHash,
                        'Current Resource': selected.currentResource,
                        'Login Time': selected.loginTime,
                        'Duration': selected.duration,
                        'Risk Score': selected.riskScore,
                        'Status': selected.status,
                        ...selected.metadata
                    }}
                />
            )}
        </div>
    );
};

export default Sessions;
