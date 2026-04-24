import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import DetailModal from '../components/DetailModal';

interface BlockchainEvent {
    id: string;
    name: string;
    tx: string;
    block: number;
    args: any;
    timestamp?: string;
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
    const [selected, setSelected] = useState<BlockchainEvent | null>(null);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const addedIds = useRef(new Set<string>());

    const addEvent = (ev: BlockchainEvent) => {
        const key = ev.tx || ev.id;
        if (addedIds.current.has(key)) return;
        addedIds.current.add(key);
        setEvents(prev => [ev, ...prev].slice(0, 50));
    };

    useEffect(() => {
        axios.get(`${gatewayUrl}/api/admin/blockchain-events`, { withCredentials: true })
            .then(res => {
                const evs: BlockchainEvent[] = res.data || [];
                evs.forEach(e => addEvent(e));
            })
            .catch(() => {})
            .finally(() => setLoading(false));

        const socket = io(gatewayUrl, { withCredentials: true });
        socket.on('blockchain_event', (ev: BlockchainEvent) => {
            setLoading(false);
            addEvent(ev);
        });

        return () => { socket.disconnect(); };
    }, [gatewayUrl]);

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
                                    <th>Arguments</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {events.map((e, i) => (
                                    <tr key={i} onClick={() => setSelected(e)} style={{ cursor: 'pointer' }}>
                                        <td className="mono">
                                            {e.block > 0 ? `#${e.block}` : '—'}
                                        </td>
                                        <td>
                                            <span className={`badge ${EVENT_COLOR[e.name] || 'badge-blue'}`}>
                                                {e.name}
                                            </span>
                                        </td>
                                        <td className="mono" title={e.tx}>
                                            {e.tx ? e.tx.substring(0, 20) + '…' : '—'}
                                        </td>
                                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {Object.entries(e.args || {})
                                                .map(([k, v]) => `${k}: ${String(v).substring(0, 12)}…`)
                                                .join(' · ') || '—'}
                                        </td>
                                        <td>
                                            <button className="btn-ghost" style={{ fontSize: '0.75rem' }}>View Details</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {selected && (
                <DetailModal
                    isOpen={!!selected}
                    onClose={() => setSelected(null)}
                    title="Blockchain Event Details"
                    data={{
                        'Transaction Hash': selected.tx,
                        'Block Number': selected.block,
                        'Event Name': selected.name,
                        'Arguments': selected.args,
                        ...selected.args
                    }}
                />
            )}
        </div>
    );
};

export default Blockchain;
