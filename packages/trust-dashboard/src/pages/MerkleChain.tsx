import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import api, { GATEWAY_URL, ADMIN_KEY } from '../api';

interface MerkleBatch {
    rootHash:    string;
    blockNumber: number;
    logCount:    number;
    timestamp:   string;
    status:      'CLEAN' | 'TAMPER';
    txHash?:     string;
}

/** Visualises a small binary Merkle tree from `count` leaves. */
const MiniMerkleTree: React.FC<{ count: number; rootHash?: string }> = ({ count, rootHash }) => {
    const leafCount = Math.min(Math.max(count, 2), 8);
    const leaves = Array.from({ length: leafCount });

    return (
        <div style={{ padding: '1rem 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.6rem' }}>
            {/* Root */}
            <div style={{
                padding: '0.5rem 0.95rem',
                background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.15), rgba(96, 165, 250, 0.1))',
                border: '1px solid rgba(168, 85, 247, 0.4)',
                borderRadius: 8,
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '0.74rem',
                color: '#c084fc',
                fontWeight: 700,
            }}>
                ROOT · {(rootHash || '').slice(0, 18)}…
            </div>

            {/* Branch 1 */}
            <div style={{ width: '60%', height: 1, background: 'rgba(168, 85, 247, 0.4)' }} />

            {/* Mid layer */}
            <div style={{ display: 'flex', justifyContent: 'space-around', width: '100%' }}>
                {[0, 1].map(i => (
                    <div key={i} style={{
                        padding: '0.35rem 0.65rem',
                        background: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        borderRadius: 6,
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.7rem',
                        color: 'var(--text-muted)',
                    }}>H{i + 1}</div>
                ))}
            </div>

            {/* Branch 2 */}
            <div style={{ width: '90%', height: 1, background: 'var(--border-soft)' }} />

            {/* Leaves */}
            <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'center', flexWrap: 'wrap', maxWidth: '100%' }}>
                {leaves.map((_, i) => (
                    <div key={i} style={{
                        padding: '0.25rem 0.55rem',
                        background: 'var(--bg-surface)',
                        border: '1px solid var(--border-soft)',
                        borderRadius: 4,
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.66rem',
                        color: 'var(--text-dim)',
                    }}>L{i + 1}</div>
                ))}
                {count > leafCount && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', alignSelf: 'center' }}>+{count - leafCount} more</span>
                )}
            </div>
        </div>
    );
};

const MerkleChain: React.FC = () => {
    const [batches, setBatches]               = useState<MerkleBatch[]>([]);
    const [countdown, setCountdown]           = useState(60);
    const [tamperDetected, setTamperDetected] = useState(false);
    const [tamperMsg, setTamperMsg]           = useState('');
    const [simulating, setSimulating]         = useState(false);
    const [selectedBatch, setSelectedBatch]   = useState<MerkleBatch | null>(null);
    const addedRoots = useRef(new Set<string>());

    useEffect(() => {
        api.get('/api/admin/blockchain-events')
            .then(res => {
                const anchors = (res.data || [])
                    .filter((e: any) => e.name === 'MerkleRootAnchored')
                    .map((e: any) => ({
                        rootHash:    e.args?.root || e.tx,
                        blockNumber: e.block,
                        logCount:    Number(e.args?.logCount) || 0,
                        timestamp:   e.timestamp,
                        status:      'CLEAN' as const,
                        txHash:      e.tx,
                    }));
                anchors.forEach((b: MerkleBatch) => {
                    if (addedRoots.current.has(b.rootHash)) return;
                    addedRoots.current.add(b.rootHash);
                    setBatches(prev => [b, ...prev].slice(0, 12));
                });
            })
            .catch(() => {});

        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);

        socket.on('merkle_anchor', (batch: MerkleBatch) => {
            if (addedRoots.current.has(batch.rootHash)) return;
            addedRoots.current.add(batch.rootHash);
            setBatches(prev => [{ ...batch, status: 'CLEAN' as const }, ...prev].slice(0, 12));
        });

        socket.on('merkle_tick', ({ remaining }: { remaining: number }) => setCountdown(remaining));

        socket.on('tamper_alert', (alert: any) => {
            setTamperDetected(true);
            setTamperMsg(alert?.details || 'Merkle mismatch detected — DB logs altered after anchoring');
            setBatches(prev => prev.map((b, i) => i === 0 ? { ...b, status: 'TAMPER' as const } : b));
        });

        return () => { socket.disconnect(); };
    }, []);

    const simulateTamper = async () => {
        setSimulating(true);
        try { await api.post('/api/admin/simulate-tamper', {}); }
        catch (err) { console.error('Tamper simulation failed', err); }
        finally { setSimulating(false); }
    };

    const latestBatch = selectedBatch || batches[0];
    const totalLogsAnchored = batches.reduce((sum, b) => sum + b.logCount, 0);

    return (
        <div className="page">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>🌳</span> Merkle Audit Chain</h1>
                    <p className="page-sub">Tamper-proof anchoring · NFR-13 (immutable) · NFR-14 (detection)</p>
                </div>
                <div className="countdown-timer">
                    <div className="timer-label">Next Anchor</div>
                    <div className="timer-value" style={{ color: countdown < 10 ? 'var(--warning)' : 'var(--accent)' }}>
                        {String(countdown).padStart(2, '0')}s
                    </div>
                </div>
            </div>

            {tamperDetected && (
                <div className="alert-banner danger">
                    <span style={{ fontSize: '1.4rem' }}>🛑</span>
                    <div className="alert-body">
                        <strong>NFR-14 TAMPER ALERT</strong>
                        <p>{tamperMsg}</p>
                    </div>
                    <button className="btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setTamperDetected(false)}>Dismiss</button>
                </div>
            )}

            {/* Stat overview */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
                <div className="stat-card">
                    <div className="stat-label">⛓ Anchors</div>
                    <div className="stat-value sv-blue">{batches.length}</div>
                    <div className="stat-foot">total batches sealed</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">≡ Logs Anchored</div>
                    <div className="stat-value sv-green">{totalLogsAnchored}</div>
                    <div className="stat-foot">audit entries protected</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">⌁ Cycle</div>
                    <div className="stat-value sv-blue" style={{ fontSize: '1.2rem', paddingTop: '0.55rem' }}>60s</div>
                    <div className="stat-foot">batch interval</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">✓ Integrity</div>
                    <div className={`stat-value ${tamperDetected ? 'sv-red' : 'sv-green'}`} style={{ fontSize: '1.2rem', paddingTop: '0.55rem' }}>
                        {tamperDetected ? 'TAMPERED' : 'VERIFIED'}
                    </div>
                    <div className="stat-foot">last verification cycle</div>
                </div>
            </div>

            <div className="grid-3" style={{ marginTop: '1.25rem' }}>
                {/* Anchor history (left) */}
                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">⛓ Anchor History</div>
                            <div className="card-subtitle">Click a batch to inspect its tree structure</div>
                        </div>
                        <button
                            className="btn-danger btn-sm"
                            onClick={simulateTamper}
                            disabled={simulating}
                        >
                            {simulating ? 'Triggering…' : '🛑 Simulate Tamper'}
                        </button>
                    </div>

                    {batches.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-icon">⛓</div>
                            <div className="empty-msg">Awaiting first anchor cycle (every 60s)…</div>
                            <p style={{ fontSize: '0.78rem', marginTop: '0.5rem' }}>The Merkle service only runs when there are unanchored audit logs — authenticate first to generate logs.</p>
                        </div>
                    ) : (
                        <div className="table-wrap" style={{ border: 'none', background: 'transparent' }}>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Block</th>
                                        <th>Logs</th>
                                        <th>Root</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {batches.map((b, i) => (
                                        <tr
                                            key={i}
                                            style={{
                                                cursor: 'pointer',
                                                background: selectedBatch?.rootHash === b.rootHash ? 'var(--accent-dim)' : (b.status === 'TAMPER' ? 'rgba(248, 113, 113, 0.05)' : undefined),
                                            }}
                                            onClick={() => setSelectedBatch(b)}
                                        >
                                            <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                                {new Date(b.timestamp).toLocaleTimeString()}
                                            </td>
                                            <td className="mono">{b.blockNumber > 0 ? `#${b.blockNumber}` : '—'}</td>
                                            <td>{b.logCount}</td>
                                            <td className="mono" style={{ fontSize: '0.74rem' }}>{b.rootHash.substring(0, 22)}…</td>
                                            <td>
                                                <span className={`badge ${b.status === 'CLEAN' ? 'badge-green' : 'badge-red'}`}>
                                                    {b.status === 'CLEAN' ? '✓ CLEAN' : '🛑 TAMPER'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>

                {/* Tree visualization (right) */}
                <div className="card">
                    <div className="card-header">
                        <div>
                            <div className="card-title">🌳 Tree Inspector</div>
                            <div className="card-subtitle">{latestBatch ? `Batch from ${new Date(latestBatch.timestamp).toLocaleTimeString()}` : 'No batch selected'}</div>
                        </div>
                    </div>
                    {latestBatch ? (
                        <>
                            <MiniMerkleTree count={latestBatch.logCount} rootHash={latestBatch.rootHash} />
                            <div style={{ borderTop: '1px solid var(--border-soft)', marginTop: '0.75rem', paddingTop: '0.75rem' }}>
                                <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginBottom: '0.4rem' }}>Tx Hash</div>
                                <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>{latestBatch.txHash || '—'}</div>
                            </div>
                        </>
                    ) : (
                        <div className="empty-state" style={{ padding: '2rem' }}>
                            <div className="empty-msg">Select a batch from history to view its Merkle tree</div>
                        </div>
                    )}
                </div>
            </div>

            <div className="grid-2" style={{ marginTop: '1.25rem' }}>
                <div className="card">
                    <div className="card-title">🔬 How It Works</div>
                    <ol style={{ marginTop: '0.75rem', paddingLeft: '1.25rem', fontSize: '0.84rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                        <li>Every 60 seconds, the Merkle service queries unanchored audit logs from MongoDB</li>
                        <li>Each log's metadata is SHA-256 hashed → leaf nodes</li>
                        <li>Leaves are paired and re-hashed up the tree until a single root remains</li>
                        <li>That root is sealed permanently in <code style={{ color: 'var(--accent)' }}>AuditLedger.sol</code> on-chain</li>
                        <li>The root is then re-computed from the live DB and compared — any mismatch triggers <strong style={{ color: 'var(--danger)' }}>tamper_alert</strong></li>
                    </ol>
                </div>
                <div className="card">
                    <div className="card-title">🛡 Why It's Tamper-Evident</div>
                    <p style={{ marginTop: '0.75rem', fontSize: '0.84rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                        Once the root is on-chain it cannot be deleted or rewritten. If an attacker modifies even a single
                        character of any anchored log entry, the recomputed Merkle root will differ from the immutable
                        on-chain value, and the dashboard fires a <strong>CRITICAL alert</strong> the next 60-second cycle.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default MerkleChain;
