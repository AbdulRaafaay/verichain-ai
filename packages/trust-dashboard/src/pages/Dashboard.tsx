import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

const Dashboard: React.FC = () => {
    const [logs, setLogs] = useState<any[]>([]);
    const [merkleStatus, setMerkleStatus] = useState<any>(null);
    const [alerts, setAlerts] = useState<any[]>([]);

    useEffect(() => {
        const socket = io(process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443', {
            withCredentials: true
        });

        socket.on('merkle_status', (status) => setMerkleStatus(status));
        socket.on('tamper_alert', (alert) => setAlerts(prev => [alert, ...prev]));
        socket.on('audit_log', (log) => setLogs(prev => [log, ...prev].slice(0, 50)));

        return () => { socket.disconnect(); };
    }, []);

    return (
        <div style={{ backgroundColor: '#0a0f1e', color: '#e8edf5', minHeight: '100vh', padding: '2rem' }}>
            <header>
                <h1>VeriChain AI Trust Dashboard</h1>
                <p>Real-time Blockchain-Anchored Audit Trail</p>
            </header>

            <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                <div style={{ background: '#111d35', padding: '1rem', borderRadius: '8px' }}>
                    <h2>Merkle Anchoring Status</h2>
                    {merkleStatus ? (
                        <div>
                            <p>Status: <span style={{ color: '#10b981' }}>{merkleStatus.status}</span></p>
                            <p>Last Root: {merkleStatus.root.substring(0, 20)}...</p>
                            <p>Logs Anchored: {merkleStatus.logCount}</p>
                        </div>
                    ) : <p>Waiting for anchoring cycle (60s)...</p>}
                </div>

                <div style={{ background: '#111d35', padding: '1rem', borderRadius: '8px', border: alerts.length ? '1fr solid #ef4444' : 'none' }}>
                    <h2>Security Alerts</h2>
                    {alerts.length === 0 ? <p>No tamper alerts detected.</p> : (
                        <ul>
                            {alerts.map((a, i) => <li key={i} style={{ color: '#ef4444' }}>[{a.type}] {a.timestamp}</li>)}
                        </ul>
                    )}
                </div>
            </section>

            <section style={{ marginTop: '2rem', background: '#111d35', padding: '1rem', borderRadius: '8px' }}>
                <h2>Live Audit Logs</h2>
                <div style={{ maxHeight: '400px', overflowY: 'auto', fontFamily: 'monospace' }}>
                    {logs.map((log, i) => (
                        <div key={i} style={{ padding: '0.5rem', borderBottom: '1px solid #1e3060' }}>
                            [{new Date(log.timestamp).toLocaleTimeString()}] {log.eventType} - {log.userHash.substring(0, 8)} - {log.decision}
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
};

export default Dashboard;
