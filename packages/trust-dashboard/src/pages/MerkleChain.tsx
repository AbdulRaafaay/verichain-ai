import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';

interface MerkleBatch {
    rootHash: string;
    blockNumber: number;
    logCount: number;
    timestamp: string;
    status: 'CLEAN' | 'TAMPER';
    txHash?: string;
}

const MerkleChain: React.FC = () => {
    const [batches, setBatches]           = useState<MerkleBatch[]>([]);
    const [countdown, setCountdown]       = useState(60);
    const [tamperDetected, setTamperDetected] = useState(false);
    const [tamperMsg, setTamperMsg]       = useState('');
    const [simulating, setSimulating]     = useState(false);
    const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
    const addedRoots = useRef(new Set<string>());

    useEffect(() => {
        // Fetch historical anchors from blockchain events on mount
        axios.get(`${gatewayUrl}/api/admin/blockchain-events`, { withCredentials: true })
            .then(res => {
                const anchors = (res.data || [])
                    .filter((e: any) => e.event === 'MerkleRootAnchored')
                    .map((e: any) => ({
                        rootHash:    e.details?.root || e.txHash,
                        blockNumber: e.blockNumber,
                        logCount:    e.details?.logCount || 0,
                        timestamp:   e.timestamp,
                        status:      'CLEAN' as const,
                        txHash:      e.txHash,
                    }));
                anchors.forEach((b: MerkleBatch) => {
                    if (addedRoots.current.has(b.rootHash)) return;
                    addedRoots.current.add(b.rootHash);
                    setBatches(prev => [b, ...prev].slice(0, 10));
                });
            })
            .catch(() => {});

        const socket = io(gatewayUrl, { withCredentials: true });

        socket.on('merkle_anchor', (batch: MerkleBatch) => {
            if (addedRoots.current.has(batch.rootHash)) return;
            addedRoots.current.add(batch.rootHash);
            setBatches(prev => [{ ...batch, status: 'CLEAN' as const }, ...prev].slice(0, 10));
            setCountdown(60);
        });

        socket.on('tamper_alert', (alert: any) => {
            setTamperDetected(true);
            setTamperMsg(alert?.details || 'Merkle mismatch detected');
            setBatches(prev => prev.map((b, i) => i === 0 ? { ...b, status: 'TAMPER' as const } : b));
        });

        const timer = setInterval(() => setCountdown(prev => prev > 0 ? prev - 1 : 0), 1000);

        return () => { socket.disconnect(); clearInterval(timer); };
    }, []);

    const simulateTamper = async () => {
        setSimulating(true);
        try {
            await axios.post(
                `${gatewayUrl}/api/admin/simulate-tamper`,
                {},
                { withCredentials: true }
            );
        } catch (err) {
            console.error('Tamper simulation failed', err);
        } finally {
            setSimulating(false);
        }
    };

    return (
        <div className="page">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Merkle Audit Chain</h1>
                    <p className="page-sub">NFR-13 &amp; NFR-14: Immutable audit anchoring to Ethereum</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>NEXT ANCHOR</div>
                        <div style={{ fontSize: '1.4rem', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: countdown < 10 ? 'var(--warning)' : 'var(--accent)' }}>
                            {String(countdown).padStart(2, '0')}s
                        </div>
                    </div>
                </div>
            </div>

            {tamperDetected && (
                <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
                    padding: '1rem 1.25rem', borderRadius: '10px', marginBottom: '1.5rem',
                    background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.4)',
                }}>
                    <span style={{ fontSize: '1.3rem' }}>🛑</span>
                    <div>
                        <strong style={{ color: 'var(--danger)', display: 'block' }}>NFR-14 TAMPER ALERT</strong>
                        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{tamperMsg}</span>
                    </div>
                    <button
                        onClick={() => setTamperDetected(false)}
                        style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '1rem' }}
                    >✕</button>
                </div>
            )}

            <div className="card" style={{ marginBottom: '1.5rem' }}>
                <div className="card-header">
                    <div className="card-title">On-Chain Anchors</div>
                    <button
                        className="btn btn-danger"
                        onClick={simulateTamper}
                        disabled={simulating}
                        style={{ fontSize: '0.82rem', padding: '0.4rem 0.85rem' }}
                    >
                        {simulating ? '⏳ Triggering…' : '🛑 Simulate Tamper'}
                    </button>
                </div>

                {batches.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">⛓</div>
                        <div className="empty-msg">Waiting for first anchoring cycle (every 60s)…</div>
                    </div>
                ) : (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Merkle Root Hash</th>
                                    <th>Block #</th>
                                    <th>Log Count</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {batches.map((b, i) => (
                                    <tr key={i} style={b.status === 'TAMPER' ? { background: 'rgba(239,68,68,0.07)' } : {}}>
                                        <td style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                                            {new Date(b.timestamp).toLocaleTimeString()}
                                        </td>
                                        <td className="mono" title={b.rootHash} style={{ fontSize: '0.78rem' }}>
                                            {b.rootHash.substring(0, 26)}…
                                        </td>
                                        <td>{b.blockNumber > 0 ? `#${b.blockNumber}` : '—'}</td>
                                        <td>{b.logCount} logs</td>
                                        <td>
                                            <span className={`badge ${b.status === 'CLEAN' ? 'badge-green' : 'badge-red'}`}>
                                                {b.status === 'CLEAN' ? '✓ CLEAN' : '🛑 TAMPERED'}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="card">
                    <div className="card-title">How It Works</div>
                    <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: '1.6', marginTop: '0.5rem' }}>
                        Every 60 seconds, all new audit logs are hashed into a Merkle tree.
                        The root is anchored to the <code>AuditLedger</code> smart contract,
                        providing <strong>Non-Repudiation (NFR-13)</strong>.
                    </p>
                </div>
                <div className="card">
                    <div className="card-title">Tamper Detection</div>
                    <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: '1.6', marginTop: '0.5rem' }}>
                        After each anchor, the system recomputes the root from MongoDB and
                        compares it to the on-chain value. Any mismatch triggers an immediate
                        <strong> TamperDetected</strong> event and a critical dashboard alert.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default MerkleChain;
