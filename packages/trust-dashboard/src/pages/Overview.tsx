import React, { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import api, { GATEWAY_URL, ADMIN_KEY } from '../api';

interface Stats {
    activeSessions: number;
    avgRiskScore:   number;
    alertsToday:    number;
    logIntegrity:   string;
}

interface RiskPoint   { time: string; score: number; sessions: number; }
interface BlockchainStatus { root: string; logCount: number; timestamp: string; }
interface SystemStatus { gateway: string; ai: string; blockchain: string; storage: string; heartbeat: string; }

/** Live system architecture diagram — nodes pulse when traffic is detected. */
const ArchitectureMap: React.FC<{ stats: Stats; sysStatus: SystemStatus | null; lastEventName: string | null }> = ({ stats, sysStatus, lastEventName }) => {
    const isHealthy = (s?: string) => !!s && (s === 'Connected' || s === 'Operational' || s === 'Running' || s === 'Healthy');

    const nodes = [
        { id: 'agent',      label: 'Desktop Agent', sub: 'Electron + ZKP', x: 8,  y: 50, active: stats.activeSessions > 0 },
        { id: 'gateway',    label: 'Gateway (PEP)', sub: 'mTLS + Express', x: 38, y: 50, active: isHealthy(sysStatus?.gateway) },
        { id: 'ai',         label: 'AI Engine',     sub: 'IsoForest',      x: 68, y: 12, active: isHealthy(sysStatus?.ai) },
        { id: 'redis',      label: 'Redis',         sub: 'Sessions',       x: 68, y: 50, active: isHealthy(sysStatus?.heartbeat) },
        { id: 'mongo',      label: 'MongoDB',       sub: 'Audit Logs',     x: 68, y: 88, active: isHealthy(sysStatus?.storage) },
        { id: 'blockchain', label: 'Blockchain',    sub: 'Hardhat / EVM',  x: 92, y: 50, active: isHealthy(sysStatus?.blockchain) },
    ];

    return (
        <div className="arch-map">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
                <defs>
                    <marker id="arrowhead" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                        <polygon points="0 0, 6 3, 0 6" fill="rgba(96, 165, 250, 0.5)" />
                    </marker>
                </defs>
                {/* Connection lines */}
                <line x1="20" y1="50" x2="35" y2="50" stroke="rgba(96, 165, 250, 0.4)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
                <line x1="50" y1="50" x2="62" y2="14" stroke="rgba(96, 165, 250, 0.3)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
                <line x1="50" y1="50" x2="62" y2="50" stroke="rgba(96, 165, 250, 0.3)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
                <line x1="50" y1="50" x2="62" y2="86" stroke="rgba(96, 165, 250, 0.3)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
                <line x1="80" y1="50" x2="89" y2="50" stroke="rgba(168, 85, 247, 0.4)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
                <line x1="80" y1="86" x2="89" y2="55" stroke="rgba(168, 85, 247, 0.4)" strokeWidth="0.4" markerEnd="url(#arrowhead)" />
            </svg>

            {nodes.map(n => (
                <div
                    key={n.id}
                    className={`arch-node ${n.active ? 'active' : ''}`}
                    style={{
                        left:  `${n.x}%`,
                        top:   `${n.y}%`,
                        transform: 'translate(-50%, -50%)',
                    }}
                >
                    <div style={{ fontWeight: 700 }}>{n.label}</div>
                    <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)' }}>{n.sub}</div>
                </div>
            ))}

            <div style={{ position: 'absolute', bottom: '0.75rem', left: '1rem', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                Last event: <span style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{lastEventName || '—'}</span>
            </div>
        </div>
    );
};

const Overview: React.FC = () => {
    const [stats, setStats] = useState<Stats>({
        activeSessions: 0, avgRiskScore: 0, alertsToday: 0, logIntegrity: 'SECURE',
    });
    const [riskData, setRiskData] = useState<RiskPoint[]>([]);
    const [blockchainStatus, setBlockchainStatus] = useState<BlockchainStatus | null>(null);
    const [lastEventName, setLastEventName]       = useState<string | null>(null);
    const [sysStatus, setSysStatus]               = useState<SystemStatus | null>(null);

    const recentAlertsRef = useRef<number>(0);

    useEffect(() => {
        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);

        const onStats = (newStats: Stats) => {
            setStats(newStats);
            setRiskData(prev =>
                [...prev, {
                    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                    score: newStats.avgRiskScore,
                    sessions: newStats.activeSessions,
                }].slice(-30)
            );
            recentAlertsRef.current = newStats.alertsToday;
        };

        socket.on('stats_update', onStats);
        socket.on('merkle_status', (s: BlockchainStatus) => setBlockchainStatus(s));
        socket.on('blockchain_event', (e: any) => setLastEventName(e?.name || null));

        // System health for the architecture diagram
        const fetchHealth = () => api.get<SystemStatus>('/api/admin/system-status').then(r => setSysStatus(r.data)).catch(() => {});
        fetchHealth();
        const healthInterval = setInterval(fetchHealth, 10_000);

        return () => { socket.disconnect(); clearInterval(healthInterval); };
    }, []);

    const integrityColor = stats.logIntegrity === 'SECURE' ? 'sv-green' : 'sv-red';

    return (
        <div className="page">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>⬡</span> System Overview</h1>
                    <p className="page-sub">Real-time security posture across the entire VeriChain stack</p>
                </div>
            </div>

            {/* KPI Strip */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-label">◎ Active Sessions</div>
                    <div className="stat-value sv-blue">{stats.activeSessions}</div>
                    <div className="stat-foot">authenticated users · live</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⌁ Avg Risk Score</div>
                    <div className={`stat-value ${stats.avgRiskScore > 75 ? 'sv-red' : stats.avgRiskScore > 50 ? 'sv-yellow' : 'sv-green'}`}>
                        {stats.avgRiskScore}
                    </div>
                    <div className="stat-foot">isolation forest · 0–100</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⚡ Security Events</div>
                    <div className={`stat-value ${stats.alertsToday > 0 ? 'sv-yellow' : 'sv-green'}`}>
                        {stats.alertsToday}
                    </div>
                    <div className="stat-foot">last 24h · revocations + alerts</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⛓ Audit Integrity</div>
                    <div className={`stat-value ${integrityColor}`} style={{ fontSize: '1.2rem', paddingTop: '0.55rem' }}>
                        {stats.logIntegrity}
                    </div>
                    <div className="stat-foot">merkle-anchored · NFR-13/14</div>
                </div>
            </div>

            {/* Architecture map full-width */}
            <div className="card" style={{ marginBottom: '1.25rem', padding: '1.25rem' }}>
                <div className="card-header">
                    <div>
                        <div className="card-title">⊞ Live Architecture</div>
                        <div className="card-subtitle">Components illuminate when traffic flows through them</div>
                    </div>
                </div>
                <div style={{ height: 280, position: 'relative' }}>
                    <ArchitectureMap stats={stats} sysStatus={sysStatus} lastEventName={lastEventName} />
                </div>
            </div>

            {/* Charts row */}
            <div className="grid-3" style={{ marginBottom: '1.25rem' }}>
                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">⌁ Risk Score Stream</div>
                            <div className="card-subtitle">Average risk across all active sessions</div>
                        </div>
                        <span className="badge badge-blue">{riskData.length} pts</span>
                    </div>
                    <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={riskData}>
                            <defs>
                                <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%"   stopColor="#60a5fa" stopOpacity={0.4} />
                                    <stop offset="100%" stopColor="#60a5fa" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1c2a4a" vertical={false} />
                            <XAxis dataKey="time" stroke="#5b6b8a" fontSize={11} tick={{ fill: '#94a3b8' }} />
                            <YAxis stroke="#5b6b8a" fontSize={11} domain={[0, 100]} tick={{ fill: '#94a3b8' }} />
                            <Tooltip />
                            <Area type="monotone" dataKey="score" stroke="#60a5fa" strokeWidth={2} fill="url(#riskGradient)" />
                        </AreaChart>
                    </ResponsiveContainer>
                    {riskData.length === 0 && (
                        <div className="empty-state" style={{ padding: '1rem' }}>
                            <div className="empty-msg">Waiting for live telemetry…</div>
                        </div>
                    )}
                </div>

                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">⛓ Latest Anchor</div>
                            <div className="card-subtitle">On-chain Merkle root</div>
                        </div>
                    </div>
                    {blockchainStatus ? (
                        <div>
                            <div style={{ marginBottom: '1rem' }}>
                                <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginBottom: '0.25rem', letterSpacing: '0.1em', fontWeight: 700, textTransform: 'uppercase' }}>Merkle Root</div>
                                <div className="mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)', wordBreak: 'break-all', lineHeight: 1.5 }}>
                                    {blockchainStatus.root}
                                </div>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                                <div>
                                    <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>Logs</div>
                                    <div style={{ fontWeight: 700, color: 'var(--success)', fontSize: '1.4rem', marginTop: '0.2rem' }}>{blockchainStatus.logCount}</div>
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>Anchored</div>
                                    <div style={{ fontSize: '0.85rem', marginTop: '0.45rem', fontFamily: 'JetBrains Mono, monospace' }}>{new Date(blockchainStatus.timestamp).toLocaleTimeString()}</div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="empty-state" style={{ padding: '1.25rem 0' }}>
                            <div className="empty-icon">⛓</div>
                            <div className="empty-msg">First anchor cycle pending… (every 60s)</div>
                        </div>
                    )}
                </div>
            </div>

            {/* Live pipeline */}
            <div className="card">
                <div className="card-header">
                    <div>
                        <div className="card-title">⚡ Request Pipeline</div>
                        <div className="card-subtitle">Every resource access flows through these zero-trust gates</div>
                    </div>
                </div>
                <div className="pipeline-flow">
                    <div className="pipeline-step">
                        <div className="pipeline-step-icon">🔐</div>
                        <div className="pipeline-step-label">ZKP + mTLS</div>
                        <div className="pipeline-step-meta">FR-02/03/04</div>
                    </div>
                    <span className="pipeline-arrow">→</span>
                    <div className="pipeline-step">
                        <div className="pipeline-step-icon">⌁</div>
                        <div className="pipeline-step-label">AI Risk Score</div>
                        <div className="pipeline-step-meta">FR-07 · IsoForest</div>
                    </div>
                    <span className="pipeline-arrow">→</span>
                    <div className="pipeline-step">
                        <div className="pipeline-step-icon">⊕</div>
                        <div className="pipeline-step-label">Policy Check</div>
                        <div className="pipeline-step-meta">FR-10 · on-chain view</div>
                    </div>
                    <span className="pipeline-arrow">→</span>
                    <div className="pipeline-step">
                        <div className="pipeline-step-icon">⛓</div>
                        <div className="pipeline-step-label">Audit + Anchor</div>
                        <div className="pipeline-step-meta">FR-13/14 · Merkle</div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Overview;
