import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

interface Stats {
    activeSessions: number;
    avgRiskScore: number;
    alertsToday: number;
    logIntegrity: string;
}

const Overview: React.FC = () => {
    const [stats, setStats] = useState<Stats>({
        activeSessions: 0,
        avgRiskScore: 0,
        alertsToday: 0,
        logIntegrity: 'SECURE'
    });
    const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
    const [blockchainStatus, setBlockchainStatus] = useState<any>(null);

    useEffect(() => {
        const socket = io(process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443', {
            withCredentials: true
        });

        socket.on('stats_update', (newStats) => setStats(newStats));
        socket.on('tamper_alert', (alert: any) => setRecentAlerts((prev: any[]) => [alert, ...prev].slice(0, 5)));
        socket.on('merkle_status', (status) => setBlockchainStatus(status));

        return () => { socket.disconnect(); };
    }, []);

    return (
        <div className="page overview">
            <h1>System Overview</h1>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
                <div className="stat-card">
                    <h3>Active Sessions</h3>
                    <p>{stats.activeSessions}</p>
                </div>
                <div className="stat-card">
                    <h3>Avg Risk Score</h3>
                    <p>{stats.avgRiskScore}/100</p>
                </div>
                <div className="stat-card">
                    <h3>Alerts Today</h3>
                    <p>{stats.alertsToday}</p>
                </div>
                <div className="stat-card">
                    <h3>Log Integrity</h3>
                    <p style={{ color: stats.logIntegrity === 'SECURE' ? '#10b981' : '#ef4444' }}>{stats.logIntegrity}</p>
                </div>
            </div>

            <section style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem' }}>
                <div className="blockchain-status">
                    <h2>Blockchain Status</h2>
                    {blockchainStatus ? (
                        <div className="card">
                            <p>Last Anchored Root: {blockchainStatus.root}</p>
                            <p>Logs Anchored: {blockchainStatus.logCount}</p>
                            <p>Timestamp: {new Date(blockchainStatus.timestamp).toLocaleString()}</p>
                        </div>
                    ) : <p>Waiting for anchoring cycle...</p>}
                </div>

                <div className="recent-alerts">
                    <h2>Recent Alerts</h2>
                    {recentAlerts.length === 0 ? <p>No recent alerts.</p> : (
                        <ul>
                            {recentAlerts.map((a: any, i: number) => (
                                <li key={i} style={{ color: '#ef4444' }}>
                                    <strong>{a.type}</strong> - {new Date(a.timestamp).toLocaleTimeString()}
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </section>
        </div>
    );
};

export default Overview;
