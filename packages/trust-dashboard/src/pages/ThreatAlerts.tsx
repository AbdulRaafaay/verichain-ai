import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

interface Alert {
    type: string;
    timestamp: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    details: string;
    txHash?: string;
}

const ThreatAlerts: React.FC = () => {
    const [alerts, setAlerts] = useState<Alert[]>([]);

    useEffect(() => {
        const socket = io(process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443', {
            withCredentials: true
        });

        socket.on('tamper_alert', (alert) => setAlerts(prev => [alert, ...prev]));

        return () => { socket.disconnect(); };
    }, []);

    return (
        <div className="page threat-alerts">
            <h1>Threat & Tamper Alerts</h1>
            <div className="alert-feed">
                {alerts.length === 0 ? <p>All systems normal. No active threats.</p> : (
                    alerts.map((a, i) => (
                        <div key={i} className={`alert-card ${a.severity.toLowerCase()}`} style={{
                            border: '1px solid #ef4444',
                            background: '#152243',
                            padding: '1rem',
                            marginBottom: '1rem',
                            borderRadius: '8px'
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <strong style={{ color: '#ef4444' }}>{a.type}</strong>
                                <span>{new Date(a.timestamp).toLocaleString()}</span>
                            </div>
                            <p>{a.details || 'Integrity mismatch detected on-chain.'}</p>
                            {a.txHash && <p>Transaction: <small>{a.txHash}</small></p>}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default ThreatAlerts;
