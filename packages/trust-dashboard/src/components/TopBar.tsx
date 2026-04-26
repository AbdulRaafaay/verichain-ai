import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { GATEWAY_URL, ADMIN_KEY } from '../api';

interface Stats {
    activeSessions: number;
    avgRiskScore:   number;
    alertsToday:    number;
    logIntegrity:   string;
}

/**
 * Persistent top bar visible on every page.
 * Shows live system health, session count, integrity state, and the wall clock.
 */
const TopBar: React.FC = () => {
    const [stats, setStats] = useState<Stats>({
        activeSessions: 0, avgRiskScore: 0, alertsToday: 0, logIntegrity: 'SECURE',
    });
    const [now, setNow] = useState(() => new Date());
    const [socketConnected, setSocketConnected] = useState(false);

    useEffect(() => {
        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);
        socket.on('connect',    () => setSocketConnected(true));
        socket.on('disconnect', () => setSocketConnected(false));
        socket.on('stats_update', (s: Stats) => setStats(s));

        const tick = setInterval(() => setNow(new Date()), 1000);
        return () => { socket.disconnect(); clearInterval(tick); };
    }, []);

    const integrityClass = stats.logIntegrity === 'SECURE' ? 'live' : 'alert';
    const liveClass = socketConnected ? 'live' : 'warn';

    return (
        <header className="topbar">
            <div className="topbar-left">
                <span className="tb-pill" style={{ color: 'var(--text-strong)' }}>
                    <span style={{ fontSize: '0.95rem' }}>🛡</span>
                    Continuous Zero-Trust Monitoring
                </span>
            </div>
            <div className="topbar-right">
                <span className={`tb-pill ${liveClass}`}>
                    <span className="dot" /> {socketConnected ? 'Live Stream' : 'Reconnecting…'}
                </span>
                <span className="tb-pill">
                    ◎ {stats.activeSessions} active
                </span>
                <span className={`tb-pill ${stats.alertsToday > 0 ? 'warn' : ''}`}>
                    ⚡ {stats.alertsToday} alerts / 24h
                </span>
                <span className={`tb-pill ${integrityClass}`}>
                    <span className="dot" /> Audit {stats.logIntegrity}
                </span>
                <span className="tb-time">{now.toLocaleTimeString([], { hour12: false })}</span>
            </div>
        </header>
    );
};

export default TopBar;
