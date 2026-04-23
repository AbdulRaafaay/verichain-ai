import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface AuditLog {
    _id: string;
    timestamp: string;
    eventType: string;
    userHash: string;
    resourceHash: string;
    riskScore: number;
    decision: string;
    anchored: boolean;
    merkleRoot: string;
}

const AuditLogs: React.FC = () => {
    const [logs, setLogs] = useState<AuditLog[]>([]);

    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
                const response = await axios.get(`${gatewayUrl}/admin/audit-logs`, { withCredentials: true });
                setLogs(response.data);
            } catch (err) {
                console.error('Failed to fetch audit logs', err);
            }
        };

        fetchLogs();
    }, []);

    return (
        <div className="page audit-logs">
            <h1>Audit Logs</h1>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event</th>
                        <th>User</th>
                        <th>Risk</th>
                        <th>Decision</th>
                        <th>Integrity</th>
                    </tr>
                </thead>
                <tbody>
                    {logs.map(log => (
                        <tr key={log._id}>
                            <td>{new Date(log.timestamp).toLocaleString()}</td>
                            <td>{log.eventType}</td>
                            <td>{log.userHash.substring(0, 8)}...</td>
                            <td>{log.riskScore}</td>
                            <td>{log.decision}</td>
                            <td>
                                {log.anchored ? (
                                    <span style={{ color: '#10b981' }}>✓ Anchored</span>
                                ) : (
                                    <span style={{ color: '#8fa3c8' }}>Pending</span>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default AuditLogs;
