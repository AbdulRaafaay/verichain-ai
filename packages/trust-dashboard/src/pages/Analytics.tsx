import React, { useEffect, useState } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import api from '../api';

interface AuditLog {
    timestamp: string;
    riskScore: number;
    eventType: string;
    anchored: boolean;
}

interface DataPoint { name: string; risk: number; auths: number; }

function buildChartData(logs: AuditLog[]): DataPoint[] {
    const buckets: Record<string, { risk: number[]; auths: number }> = {};
    logs.forEach(log => {
        const hour = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (!buckets[hour]) buckets[hour] = { risk: [], auths: 0 };
        if (log.riskScore > 0) buckets[hour].risk.push(log.riskScore);
        if (log.eventType?.includes('LOGIN')) buckets[hour].auths += 1;
    });
    return Object.entries(buckets)
        .slice(-12)
        .map(([name, { risk, auths }]) => ({
            name,
            risk: risk.length ? Math.round(risk.reduce((a, b) => a + b, 0) / risk.length) : 0,
            auths,
        }));
}

const Analytics: React.FC = () => {
    const [data, setData]         = useState<DataPoint[]>([]);
    const [anchored, setAnchored] = useState(0);
    const [total, setTotal]       = useState(0);
    const [avgRisk, setAvgRisk]   = useState(0);
    const [loading, setLoading]   = useState(true);

    useEffect(() => {
        api.get<AuditLog[]>('/api/admin/audit-logs')
            .then(r => {
                const logs = r.data;
                setTotal(logs.length);
                setAnchored(logs.filter(l => l.anchored).length);
                const scores = logs.map(l => l.riskScore).filter(Boolean);
                setAvgRisk(scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0);
                setData(buildChartData(logs));
            })
            .catch(() => {})
            .finally(() => setLoading(false));
    }, []);

    const tooltipStyle = { backgroundColor: '#111d35', border: '1px solid #1e3060', borderRadius: '8px' };

    return (
        <div className="page analytics">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Security Analytics</h1>
                    <p className="page-sub">Aggregated metrics from audit logs and authentication events</p>
                </div>
            </div>

            {/* KPI strip */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
                <div className="stat-card">
                    <div className="stat-label">Total Events</div>
                    <div className="stat-value sv-blue">{total || '—'}</div>
                    <div className="stat-foot">audit log entries</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">Avg Risk Score</div>
                    <div className={`stat-value ${avgRisk > 75 ? 'sv-red' : avgRisk > 50 ? 'sv-yellow' : 'sv-green'}`}>{avgRisk || '—'}</div>
                    <div className="stat-foot">across all sessions</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⛓ Anchored</div>
                    <div className="stat-value sv-green">{total ? `${Math.round((anchored / total) * 100)}%` : '—'}</div>
                    <div className="stat-foot">{anchored} of {total} logs</div>
                </div>
            </div>

            {loading ? (
                <div className="loading-state"><div className="spinner" /><span>Loading analytics…</span></div>
            ) : data.length === 0 ? (
                <div className="empty-state" style={{ gridColumn: '1 / -1', padding: '4rem 2rem' }}>
                    <div className="empty-icon">⌁</div>
                    <div className="empty-msg">Awaiting Session Data…</div>
                    <p style={{ fontSize: '0.8rem', marginTop: '0.5rem', color: 'var(--text-dim)' }}>
                        Charts will populate automatically once authentication events are recorded.
                    </p>
                </div>
            ) : (
                <div className="grid-2">
                    <div className="card">
                        <div className="card-header">
                            <div className="card-title">⌁ Avg Risk Score (hourly)</div>
                        </div>
                        <ResponsiveContainer width="100%" height={260}>
                            <LineChart data={data}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e3060" />
                                <XAxis dataKey="name" stroke="#4a6080" tick={{ fill: '#8fa3c8', fontSize: 11 }} />
                                <YAxis stroke="#4a6080" tick={{ fill: '#8fa3c8', fontSize: 11 }} domain={[0, 100]} />
                                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: '#8fa3c8', fontSize: 11 }} />
                                <Line type="monotone" dataKey="risk" name="Risk Score" stroke="#3b82f6" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="card">
                        <div className="card-header">
                            <div className="card-title">◎ Authentication Volume</div>
                        </div>
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={data}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e3060" />
                                <XAxis dataKey="name" stroke="#4a6080" tick={{ fill: '#8fa3c8', fontSize: 11 }} />
                                <YAxis stroke="#4a6080" tick={{ fill: '#8fa3c8', fontSize: 11 }} />
                                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: '#8fa3c8', fontSize: 11 }} />
                                <Bar dataKey="auths" name="Logins" fill="#10b981" radius={[4, 4, 0, 0]} maxBarSize={32} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Analytics;
