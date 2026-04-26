import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import api, { GATEWAY_URL, ADMIN_KEY } from '../api';
import DetailModal from '../components/DetailModal';

interface BlockchainEvent {
    id:        string;
    name:      string;
    tx:        string;
    block:     number;
    args:      any;
    timestamp?: string;
}

const EVENT_DESCRIPTIONS: Record<string, string> = {
    SessionCreated:        'New ZKP-authenticated session anchored on-chain',
    SessionRevoked:        'Session terminated — heartbeat timeout, AI risk, or admin',
    AccessDecision:        'Resource access permission evaluated by smart contract',
    MerkleRootAnchored:    'Audit log batch fingerprint sealed on-chain (NFR-13)',
    SystemAlert:           'Tamper detection or anomaly alert (NFR-14)',
    PolicyChangeProposed:  'Multi-sig policy change submitted for approval',
    PolicyChangeExecuted:  'Policy change reached threshold and executed',
};

const ALL_FILTERS = ['ALL', 'SessionCreated', 'SessionRevoked', 'AccessDecision', 'MerkleRootAnchored', 'SystemAlert'];

const Blockchain: React.FC = () => {
    const [events, setEvents]       = useState<BlockchainEvent[]>([]);
    const [loading, setLoading]     = useState(true);
    const [selected, setSelected]   = useState<BlockchainEvent | null>(null);
    const [filter, setFilter]       = useState('ALL');
    const addedIds = useRef(new Set<string>());

    const addEvent = (ev: BlockchainEvent) => {
        const key = ev.id || (ev.tx + ':' + ev.block);
        if (addedIds.current.has(key)) return;
        addedIds.current.add(key);
        setEvents(prev => [ev, ...prev].slice(0, 100));
    };

    useEffect(() => {
        api.get('/api/admin/blockchain-events')
            .then(res => {
                const evs: BlockchainEvent[] = res.data || [];
                evs.forEach(e => addEvent(e));
            })
            .catch(() => {})
            .finally(() => setLoading(false));

        const socket = io(GATEWAY_URL, { withCredentials: true, auth: { token: ADMIN_KEY } } as any);
        socket.on('blockchain_event', (ev: BlockchainEvent) => {
            setLoading(false);
            addEvent(ev);
        });

        return () => { socket.disconnect(); };
    }, []);

    const filtered = filter === 'ALL' ? events : events.filter(e => e.name === filter);

    const counts = events.reduce((acc, e) => {
        acc[e.name] = (acc[e.name] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div className="page">
            <div className="page-header">
                <div>
                    <h1 className="page-title"><span>⛓</span> On-Chain Event Ledger</h1>
                    <p className="page-sub">Immutable record of every security event from <code style={{ color: 'var(--accent)' }}>AccessPolicy.sol</code> and <code style={{ color: 'var(--accent)' }}>AuditLedger.sol</code></p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <span className="badge badge-blue">Chain ID 1337</span>
                    <span className="badge badge-gray">{events.length} events</span>
                </div>
            </div>

            {/* Event-type stats */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: '1.25rem' }}>
                {[
                    { name: 'SessionCreated',     icon: '◎', color: 'sv-green' },
                    { name: 'SessionRevoked',     icon: '⊗', color: 'sv-red' },
                    { name: 'AccessDecision',     icon: '⊕', color: 'sv-blue' },
                    { name: 'MerkleRootAnchored', icon: '🌳', color: 'sv-blue' },
                    { name: 'SystemAlert',        icon: '⚡', color: 'sv-yellow' },
                ].map(t => (
                    <div className="stat-card" key={t.name}>
                        <div className="stat-label">{t.icon} {t.name}</div>
                        <div className={`stat-value ${t.color}`} style={{ fontSize: '1.5rem' }}>{counts[t.name] || 0}</div>
                        <div className="stat-foot">events recorded</div>
                    </div>
                ))}
            </div>

            <div className="card">
                <div className="card-header">
                    <div>
                        <div className="card-title">Event Stream</div>
                        <div className="card-subtitle">Click any block to see decoded arguments</div>
                    </div>
                    <div className="filter-chips" style={{ marginBottom: 0 }}>
                        {ALL_FILTERS.map(f => (
                            <span key={f} className={`chip ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                                {f === 'ALL' ? `All · ${events.length}` : `${f} · ${counts[f] || 0}`}
                            </span>
                        ))}
                    </div>
                </div>

                {loading ? (
                    <div className="loading-state"><div className="spinner" /><span>Loading on-chain events…</span></div>
                ) : filtered.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">⛓</div>
                        <div className="empty-msg">
                            {events.length === 0
                                ? 'No on-chain events yet — authenticate via the Desktop Agent to generate them.'
                                : 'No events match this filter.'}
                        </div>
                    </div>
                ) : (
                    <div>
                        {filtered.map((e, i) => (
                            <div
                                key={e.id || i}
                                className={`block-card ${e.name}`}
                                onClick={() => setSelected(e)}
                            >
                                <div>
                                    <div className="block-meta">{e.block > 0 ? `Block #${e.block}` : 'pending'}</div>
                                    <div className="block-meta" style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginTop: '2px' }}>
                                        {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—'}
                                    </div>
                                </div>
                                <div>
                                    <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-strong)', marginBottom: '0.2rem' }}>{e.name}</div>
                                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                        {EVENT_DESCRIPTIONS[e.name] || 'Event from on-chain contract'}
                                    </div>
                                </div>
                                <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textAlign: 'right' }}>
                                    {e.tx ? e.tx.substring(0, 14) + '…' : '—'}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {selected && (
                <DetailModal
                    isOpen={!!selected}
                    onClose={() => setSelected(null)}
                    title={`${selected.name} · Block ${selected.block || 'pending'}`}
                    data={{
                        'Event Type':     selected.name,
                        'Description':    EVENT_DESCRIPTIONS[selected.name] || '—',
                        'Transaction Hash': selected.tx,
                        'Block Number':   selected.block,
                        'Timestamp':      selected.timestamp ? new Date(selected.timestamp).toLocaleString() : '—',
                        'Decoded Args':   selected.args,
                    }}
                />
            )}
        </div>
    );
};

export default Blockchain;
