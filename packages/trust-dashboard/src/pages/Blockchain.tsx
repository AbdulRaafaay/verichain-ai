import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';

interface BlockchainEvent {
    id: string;
    event: string;
    txHash: string;
    blockNumber: number;
    timestamp: string;
    details: any;
}

const EVENT_COLOR: Record<string, string> = {
    SessionCreated:     'badge-green',
    SessionRevoked:     'badge-red',
    AccessDecision:     'badge-blue',
    MerkleRootAnchored: 'badge-blue',
    AlertTriggered:     'badge-red',
    TamperDetected:     'badge-red',
    AuditLedgerDeployed:'badge-gray',
    AccessPolicyDeployed:'badge-gray',
};

const Blockchain: React.FC = () => {
    const [events, setEvents] = useState<BlockchainEvent[]>([]);
    const [loading, setLoading] = useState(true);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const addedIds = useRef(new Set<string>());

    const addEvent = (ev: BlockchainEvent) => {
        const key = ev.id || ev.txHash;
        if (addedIds.current.has(key)) return;
        addedIds.current.add(key);
        setEvents(prev => [ev, ...prev].slice(0, 50));
    };

    useEffect(() => {
        // Fetch historical events on mount
        axios.get(`${gatewayUrl}/api/admin/blockchain-events`, { withCredentials: true })
            .then(res => {
                const evs: BlockchainEvent[] = res.data || [];
                evs.forEach(e => addEvent(e));
            })
            .catch(() => {/* gateway may not be ready */})
            .finally(() => setLoading(false));

        const socket = io(gatewayUrl, { withCredentials: true });
        socket.on('blockchain_event', (ev: BlockchainEvent) => {
            setLoading(false);
            addEvent(ev);
        });

        return () => { socket.disconnect(); };
    }, []);

    return (
        <div className="page">
            <div className="page-header">
                <div>
                    <h1 className="page-title">On-Chain Ledger</h1>
                    <p className="page-sub">NFR-15: Permanent security event record on Hardhat/Ethereum</p>
                </div>
                <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
                    <span className="badge badge-blue">Chain ID: 1337</span>
                    <span className="badge badge-gray">{events.length} events</span>
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="card-title">Immutable Event Log</div>
                </div>

                {loading ? (
                    <div className="loading-state">
                        <div className="spinner" />
                        <span>Loading on-chain events…</span>
                    </div>
                ) : events.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">⛓</div>
                        <div className="empty-msg">No events yet. Authenticate via the Desktop Agent to generate on-chain records.</div>
                    </div>
                ) : (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Block</th>
                                    <th>Event</th>
                                    <th>Transaction Hash</th>
                                    <th>Details</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                {events.map((e, i) => (
                                    <tr key={i}>
                                        <td className="mono">
                                            {e.blockNumber > 0 ? `#${e.blockNumber}` : '—'}
                                        </td>
                                        <td>
                                            <span className={`badge ${EVENT_COLOR[e.event] || 'badge-blue'}`}>
                                                {e.event}
                                            </span>
                                        </td>
                                        <td className="mono" title={e.txHash}>
                                            {e.txHash ? e.txHash.substring(0, 20) + '…' : '—'}
                                        </td>
                                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {Object.entries(e.details || {})
                                                .filter(([, v]) => v !== undefined && v !== null)
                                                .map(([k, v]) => `${k}: ${v}`)
                                                .join(' · ') || '—'}
                                        </td>
                                        <td style={{ color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                                            {new Date(e.timestamp).toLocaleTimeString()}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div style={{ marginTop: '1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                Network: Hardhat Localhost · Chain ID: 1337 · {events.length} transactions tracked
            </div>
        </div>
    );
};

export default Blockchain;
