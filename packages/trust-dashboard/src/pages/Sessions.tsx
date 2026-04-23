import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Session {
    id: string;
    userHash: string;
    loginTime: string;
    duration: string;
    riskScore: number;
    status: 'ACTIVE' | 'REVOKED';
}

const Sessions: React.FC = () => {
    const [sessions, setSessions] = useState<Session[]>([]);

    useEffect(() => {
        const fetchSessions = async () => {
            try {
                const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
                const response = await axios.get(`${gatewayUrl}/admin/sessions`, { withCredentials: true });
                setSessions(response.data);
            } catch (err) {
                console.error('Failed to fetch sessions', err);
            }
        };

        fetchSessions();
        const interval = setInterval(fetchSessions, 10000); // Polling for session updates
        return () => clearInterval(interval);
    }, []);

    const revokeSession = async (id: string) => {
        try {
            const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
            await axios.post(`${gatewayUrl}/admin/revoke-session`, { sessionId: id }, { withCredentials: true });
            setSessions((prev: Session[]) => prev.map((s: Session) => s.id === id ? { ...s, status: 'REVOKED' } : s));
        } catch (err) {
            console.error('Failed to revoke session', err);
        }
    };

    return (
        <div className="page sessions">
            <h1>Active Sessions</h1>
            <table>
                <thead>
                    <tr>
                        <th>Session ID</th>
                        <th>User Hash</th>
                        <th>Risk Score</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {sessions.map((s: Session) => (
                        <tr key={s.id}>
                            <td>{s.id.substring(0, 8)}...</td>
                            <td>{s.userHash.substring(0, 8)}...</td>
                            <td style={{ color: s.riskScore > 75 ? '#ef4444' : s.riskScore > 50 ? '#f59e0b' : '#10b981' }}>
                                {s.riskScore}/100
                            </td>
                            <td>{s.status}</td>
                            <td>
                                {s.status === 'ACTIVE' && (
                                    <button onClick={() => revokeSession(s.id)} style={{ color: '#ef4444' }}>Revoke</button>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default Sessions;
