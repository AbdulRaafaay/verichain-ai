import React, { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Stats {
    activeSessions: number;
    avgRiskScore: number;
    alertsToday: number;
    logIntegrity: string;
}

interface RiskPoint { time: string; score: number; }
interface Alert     { type: string; timestamp: string; }
interface BlockchainStatus { root: string; logCount: number; timestamp: string; }

const Overview: React.FC = () => {
    const [stats, setStats] = useState<Stats>({
        activeSessions: 0,
        avgRiskScore: 0,
        alertsToday: 0,
        logIntegrity: 'SECURE',
    });
    const [recentAlerts, setRecentAlerts]     = useState<Alert[]>([]);
    const [blockchainStatus, setBlockchainStatus] = useState<BlockchainStatus | null>(null);
    const [riskData, setRiskData]             = useState<RiskPoint[]>([]);

    // Ref so the polling interval can read the latest count without a stale closure
    const recentAlertsRef = useRef<Alert[]>([]);
    recentAlertsRef.current = recentAlerts;

    useEffect(() => {
        const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
        const socket = io(gatewayUrl, { withCredentials: true });

        const updateStats = (newStats: Stats) => {
            setStats(newStats);
            setRiskData(prev =>
                [...prev, { time: new Date().toLocaleTimeString(), score: newStats.avgRiskScore }].slice(-20)
            );
        };

        socket.on('stats_update', updateStats);
        socket.on('tamper_alert',  (alert: Alert)        => setRecentAlerts(prev => [alert, ...prev].slice(0, 5)));
        socket.on('merkle_status', (s: BlockchainStatus) => setBlockchainStatus(s));

        // Polling fallback — derive stats from the session overview every 5 s
        const poll = setInterval(async () => {
            try {
                const res = await axios.get(`${gatewayUrl}/api/admin/overview`, { withCredentials: true });
                const sessions: any[] = res.data.sessions || [];
                const avg = sessions.length
                    ? Math.round(sessions.reduce((a: number, s: any) => a + (s.riskScore || 0), 0) / sessions.length)
                    : 0;
                updateStats({
                    activeSessions: sessions.length,
                    avgRiskScore:   avg,
                    alertsToday:    recentAlertsRef.current.length,
                    logIntegrity:   'SECURE',
                });
            } catch { /* gateway not ready */ }
        }, 5000);

        return () => { socket.disconnect(); clearInterval(poll); };
    }, []);

    const integrityColor = stats.logIntegrity === 'SECURE' ? 'sv-green' : 'sv-red';

    return (
        <div className="page overview">
            <div className="page-header">
                <div>
                    <h1 className="page-title">System Overview</h1>
                    <p className="page-sub">Live security posture and event summary</p>
                </div>
            </div>

            {/* KPI Row */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-label">◎ Active Sessions</div>
                    <div className={`stat-value sv-blue`}>{stats.activeSessions}</div>
                    <div className="stat-foot">authenticated users</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⌁ Avg Risk Score</div>
                    <div className={`stat-value ${stats.avgRiskScore > 75 ? 'sv-red' : stats.avgRiskScore > 50 ? 'sv-yellow' : 'sv-green'}`}>
                        {stats.avgRiskScore}
                    </div>
                    <div className="stat-foot">out of 100</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⚡ Alerts Today</div>
                    <div className={`stat-value ${stats.alertsToday > 0 ? 'sv-yellow' : 'sv-green'}`}>
                        {stats.alertsToday}
                    </div>
                    <div className="stat-foot">tamper events</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⛓ Log Integrity</div>
                    <div className={`stat-value ${integrityColor}`}>{stats.logIntegrity}</div>
                    <div className="stat-foot">merkle-anchored</div>
                </div>
            </div>

            {/* Charts / Panels */}
            <div className="grid-3" style={{ marginBottom: '1.5rem' }}>
                <div className="card">
                    <div className="card-header">
                        <div className="card-title">Risk Score Trend</div>
                        <span className="badge badge-blue">{riskData.length} pts</span>
                    </div>
                    <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={riskData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e3060" />
                            <XAxis dataKey="time" stroke="#4a6080" fontSize={11} tick={{ fill: '#8fa3c8' }} />
                            <YAxis stroke="#4a6080" fontSize={11} domain={[0, 100]} tick={{ fill: '#8fa3c8' }} />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#111d35', border: '1px solid #1e3060', borderRadius: '8px' }}
                                labelStyle={{ color: '#8fa3c8', fontSize: '11px' }}
                            />
                            <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={false} activeDot={{ r: 4, fill: '#3b82f6' }} />
                        </LineChart>
                    </ResponsiveContainer>
                    {riskData.length === 0 && (
                        <div className="empty-state" style={{ paddingTop: '1rem' }}>
                            <div className="empty-msg">Waiting for live data…</div>
                        </div>
                    )}
                </div>

                <div className="card">
                    <div className="card-header">
                        <div className="card-title">⛓ Blockchain</div>
                    </div>
                    {blockchainStatus ? (
                        <div>
                            <div style={{ marginBottom: '0.75rem' }}>
                                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>LAST MERKLE ROOT</div>
                                <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                                    {blockchainStatus.root}
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: '0.75rem' }}>
                                <div>
                                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>LOGS ANCHORED</div>
                                    <div style={{ fontWeight: 700, color: 'var(--success)' }}>{blockchainStatus.logCount}</div>
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>ANCHORED AT</div>
                                    <div style={{ fontSize: '0.78rem' }}>{new Date(blockchainStatus.timestamp).toLocaleTimeString()}</div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <div className="empty-icon">⛓</div>
                            <div className="empty-msg">Waiting for anchoring cycle…</div>
                        </div>
                    )}
                </div>
            </div>

            {/* Recent Alerts */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">⚡ Recent Alerts</div>
                    <span className="badge badge-gray">{recentAlerts.length}</span>
                </div>
                {recentAlerts.length === 0 ? (
                    <div className="empty-state" style={{ padding: '1.5rem' }}>
                        <div className="empty-icon">✅</div>
                        <div className="empty-msg">All systems normal. No active threats.</div>
                    </div>
                ) : (
                    <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {recentAlerts.map((a, i) => (
                            <li key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 0', borderBottom: i < recentAlerts.length - 1 ? '1px solid var(--border)' : 'none' }}>
                                <span className="badge badge-red">ALERT</span>
                                <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{a.type}</span>
                                <span style={{ marginLeft: 'auto', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                                    {new Date(a.timestamp).toLocaleTimeString()}
                                </span>
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </div>
    );
};

export default Overview;
