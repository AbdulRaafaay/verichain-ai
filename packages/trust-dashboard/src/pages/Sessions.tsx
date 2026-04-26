/**
 * Sessions.tsx — Real-time session monitor.
 *
 * Displays all authenticated sessions, their live AI risk scores, and last
 * heartbeat timestamps. Receives instant updates via Socket.io (session_update /
 * session_revoked) and falls back to 5-second HTTP polling when the socket is
 * not yet connected.
 *
 * Security: all admin API calls are authenticated via the X-Admin-Key header
 * attached by the shared `api` axios instance (src/api.ts).
 */

import React, { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import api, { GATEWAY_URL, ADMIN_KEY } from '../api';
import DetailModal from '../components/DetailModal';

interface Session {
    id: string;
    userHash: string;
    loginTime: string;
    lastHeartbeat: string;
    duration: string;
    riskScore: number;
    status: 'ACTIVE' | 'REVOKED';
}

const Sessions: React.FC = () => {
    const [sessions, setSessions] = useState<Session[]>([]);
    const [loading, setLoading]   = useState(true);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [selected, setSelected] = useState<Session | null>(null);

    const latestSessions = useRef<Session[]>([]);
    latestSessions.current = sessions;

    useEffect(() => {
        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);

        const fetchSessions = async () => {
            try {
                const res = await api.get('/api/admin/overview');
                setSessions(res.data.sessions || []);
            } catch { /* gateway not ready */ }
            finally { setLoading(false); }
        };

        fetchSessions();

        socket.on('session_update', (updated: Session[]) => {
            setSessions(updated);
            setLoading(false);
        });
        socket.on('session_revoked', ({ sessionId }: { sessionId: string }) =>
            setSessions(prev => prev.map(s => s.id === sessionId ? { ...s, status: 'REVOKED' } : s))
        );

        const poll = setInterval(fetchSessions, 5000);
        const tick = setInterval(() => setSessions(s => [...s]), 1000);

        return () => { socket.disconnect(); clearInterval(poll); clearInterval(tick); };
    }, []);

    const revokeSession = async (e: React.MouseEvent, id: string) => {
        e.stopPropagation();
        setRevoking(id);
        try {
            await api.post('/api/admin/revoke', { sessionId: id });
        } catch { /* noop */ }
        finally { setRevoking(null); }
    };

    const riskBadge = (score: number) => {
        if (score > 75) return <span className="badge badge-red">{score}</span>;
        if (score > 50) return <span className="badge badge-yellow">{score}</span>;
        return <span className="badge badge-green">{score}</span>;
    };

    const active  = sessions.filter(s => s.status === 'ACTIVE').length;
    const revoked = sessions.filter(s => s.status === 'REVOKED').length;

    return (
        <div className="page sessions">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>◎</span> Active Sessions</h1>
                    <p className="page-sub">Live ZKP-authenticated sessions with continuous risk scoring</p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <span className="badge badge-green">● {active} Active</span>
                    {revoked > 0 && <span className="badge badge-gray">{revoked} Revoked</span>}
                </div>
            </div>

            {loading ? (
                <div className="table-wrap">
                    <table>
                        <thead><tr><th>Session ID</th><th>User Hash</th><th>Login Time</th><th>Duration</th><th>Last Heartbeat</th><th>Risk Score</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>
                            {Array.from({ length: 4 }).map((_, i) => (
                                <tr key={i} className="skeleton-row">
                                    <td><div className="skeleton-cell" style={{ width: '7rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '9rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '5rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '4rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '4rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '3rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '4.5rem' }} /></td>
                                    <td><div className="skeleton-cell" style={{ width: '4rem' }} /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
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
                                    <tr key={sid} style={{ cursor: 'pointer' }} onClick={() => setSelected(s)}>
                                        <td><span className="mono" title={sid}>{sid.substring(0, 10)}…</span></td>
                                        <td><span className="mono" title={s.userHash}>{(s.userHash || '').substring(0, 16)}…</span></td>
                                        <td style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                                            {s.loginTime ? new Date(s.loginTime).toLocaleTimeString() : '—'}
                                        </td>
                                        <td>{s.duration || '—'}</td>
                                        <td style={{ fontWeight: 600, color: hbColor }}>
                                            {hbAge !== null ? `${hbAge}s ago` : '—'}
                                        </td>
                                        <td>
                                            {riskBadge(s.riskScore ?? 0)}
                                            <div className="risk-bar-wrap" style={{ width: 60 }}>
                                                <div className="risk-bar" style={{
                                                    width: `${s.riskScore ?? 0}%`,
                                                    background: (s.riskScore ?? 0) > 75 ? 'var(--danger)' : (s.riskScore ?? 0) > 50 ? 'var(--warning)' : 'var(--success)',
                                                }} />
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`badge ${s.status === 'ACTIVE' ? 'badge-green' : 'badge-gray'}`}>
                                                {s.status === 'ACTIVE' ? '● ' : ''}{s.status}
                                            </span>
                                        </td>
                                        <td>
                                            {s.status === 'ACTIVE' && (
                                                <button
                                                    className="btn-danger"
                                                    disabled={revoking === sid}
                                                    onClick={e => revokeSession(e, sid)}
                                                    style={{ fontSize: '0.78rem', padding: '0.3rem 0.7rem' }}
                                                >
                                                    {revoking === sid ? '…' : 'Revoke'}
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}

            {selected && (() => {
                const sid = (selected as any).id || (selected as any).sessionId || '';
                const meta = (selected as any).metadata || {};
                return (
                    <DetailModal
                        isOpen={!!selected}
                        onClose={() => setSelected(null)}
                        title="Session Details"
                        data={{
                            'Session ID':       sid,
                            'User Hash':        selected.userHash || '—',
                            'Status':           selected.status,
                            'Risk Score':       selected.riskScore ?? 0,
                            'Login Time':       selected.loginTime ? new Date(selected.loginTime).toLocaleString() : '—',
                            'Last Heartbeat':   selected.lastHeartbeat ? new Date(selected.lastHeartbeat).toLocaleString() : '—',
                            'Duration':         selected.duration || '—',
                            'Current Resource': meta.currentResource || (selected as any).currentResource || '—',
                            'Device ID':        meta.deviceId || '—',
                            'IP Address':       meta.ipAddress || meta.ip || '—',
                            'Geo Distance (km)': meta.geoDistanceKm ?? '—',
                            'Access Velocity':  meta.accessVelocity ?? '—',
                            'Download Bytes':   meta.downloadBytes ?? '—',
                        }}
                    />
                );
            })()}
        </div>
    );
};

export default Sessions;
