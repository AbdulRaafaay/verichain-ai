import React, { useEffect, useState } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import axios from 'axios';

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

const PLACEHOLDER: DataPoint[] = [
    { name: '09:00', risk: 12, auths: 3 },
    { name: '10:00', risk: 18, auths: 6 },
    { name: '11:00', risk: 35, auths: 9 },
    { name: '12:00', risk: 22, auths: 11 },
    { name: '13:00', risk: 48, auths: 7 },
    { name: '14:00', risk: 31, auths: 10 },
];

const Analytics: React.FC = () => {
    const [data, setData] = useState<DataPoint[]>(PLACEHOLDER);
    const [anchored, setAnchored] = useState(0);
    const [total, setTotal]       = useState(0);
    const [avgRisk, setAvgRisk]   = useState(0);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';

    useEffect(() => {
        axios.get<AuditLog[]>(`${gatewayUrl}/api/admin/audit-logs`, { withCredentials: true })
            .then(r => {
                const logs = r.data;
                if (logs.length > 0) {
                    setData(buildChartData(logs));
                    setTotal(logs.length);
                    setAnchored(logs.filter(l => l.anchored).length);
                    const scores = logs.map(l => l.riskScore).filter(Boolean);
                    setAvgRisk(scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0);
                }
            })
            .catch(() => {/* use placeholder */});
    }, [gatewayUrl]);

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
        </div>
    );
};

export default Analytics;
