import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';

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
        const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
        const socket = io(gatewayUrl, { withCredentials: true });

        const fetchSessions = async () => {
            try {
                const response = await axios.get(`${gatewayUrl}/api/admin/overview`, { withCredentials: true });
                setSessions(response.data.sessions || []);
            } catch (err) {
                console.error('Failed to fetch sessions', err);
            }
        };

        fetchSessions();

        socket.on('session_update', (updatedSessions: Session[]) => {
            setSessions(updatedSessions);
        });

        socket.on('session_revoked', ({ sessionId }: { sessionId: string }) => {
            setSessions((prev: any[]) => prev.map((s: any) => s.id === sessionId ? { ...s, status: 'REVOKED' } : s));
        });

        return () => { socket.disconnect(); };
    }, []);

    const revokeSession = async (id: string) => {
        try {
            const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
            await axios.post(`${gatewayUrl}/api/admin/revoke`, { sessionId: id }, { withCredentials: true });
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
                    {sessions.map((s: any) => (
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
