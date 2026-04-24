import React, { useState, useEffect } from 'react';
import './agent.css';

type Screen = 'WELCOME' | 'AUTHENTICATION' | 'DASHBOARD' | 'STATUS' | 'TELEMETRY' | 'SECURITY' | 'SETTINGS' | 'ABOUT';
type AuthStep = 'idle' | 'proving' | 'verifying' | 'establishing' | 'success' | 'error';

interface AccessResult {
    success?: boolean;
    riskScore?: number;
    decision?: string;
    error?: string;
    anomaly?: boolean;
}

const STEPS: AuthStep[] = ['proving', 'verifying', 'establishing', 'success'];

const STEP_LABELS: Record<string, string> = {
    proving:      'Generating Groth16 proof via snarkjs…',
    verifying:    'Establishing mTLS channel… Certificate pinning verified ✓',
    establishing: 'Verify at Gateway… groth16.verify() running…',
};

const NAV_ITEMS: { screen: Screen; icon: string; label: string }[] = [
    { screen: 'DASHBOARD',  icon: '⬡', label: 'Dashboard'    },
    { screen: 'STATUS',     icon: '◎', label: 'System Status' },
    { screen: 'TELEMETRY',  icon: '⌁', label: 'Telemetry'    },
    { screen: 'SECURITY',   icon: '⊕', label: 'Security'     },
    { screen: 'SETTINGS',   icon: '⚙', label: 'Settings'     },
    { screen: 'ABOUT',      icon: 'ℹ', label: 'About'        },
];

function stepState(step: AuthStep, current: AuthStep): 'done' | 'active' | 'pending' {
    const ci = STEPS.indexOf(current);
    const si = STEPS.indexOf(step);
    if (si < ci) return 'done';
    if (si === ci) return 'active';
    return 'pending';
}

const App: React.FC = () => {
    const [currentScreen, setCurrentScreen] = useState<Screen>('WELCOME');
    const [isEnrolled, setIsEnrolled]       = useState(false);
    const [status, setStatus]               = useState<any>(null);
    const [telemetry, setTelemetry]         = useState<any>(null);
    const [authStep, setAuthStep]           = useState<AuthStep>('idle');
    const [authError, setAuthError]         = useState('');
    const [sessionId, setSessionId]         = useState('');
    const [resourceId, setResourceId]       = useState('demo-resource-001');
    const [accessResult, setAccessResult]   = useState<AccessResult | null>(null);
    const [accessLoading, setAccessLoading] = useState(false);
    const [velocity, setVelocity]           = useState(3.45);
    const [drift, setDrift]                 = useState(0.02);

    useEffect(() => {
        const el = (window as any).electron;
        if (el?.auth) {
            el.auth.isEnrolled().then(setIsEnrolled);
        }
        if (el?.system) {
            el.system.getStatus().then(setStatus);
            el.system.getTelemetry().then(setTelemetry);
        }

        el?.onSessionRevoked?.(() => {
            setSessionId('');
            setAuthStep('idle');
            setCurrentScreen('WELCOME');
        });
    }, []);

    const handleEnroll = async () => {
        setAuthStep('proving');
        setAuthError('');
        try {
            const el = (window as any).electron;
            if (!el?.auth) throw new Error('Electron Auth API not available (Browser mode)');
            await el.auth.enroll();
            setIsEnrolled(true);
            setAuthStep('idle');
        } catch (err: any) {
            setAuthStep('error');
            setAuthError(err.message || 'Enrollment failed');
        }
    };

    const handleLogin = async () => {
        setAuthError('');
        setAuthStep('proving');
        try {
            const el = (window as any).electron;
            if (!el?.auth) throw new Error('Electron Auth API not available (Browser mode)');
            await new Promise(r => setTimeout(r, 350));
            setAuthStep('verifying');
            const result = await el.auth.login();
            setAuthStep('establishing');
            await new Promise(r => setTimeout(r, 400));
            setSessionId(result.sessionId || '');
            setAuthStep('success');
        } catch (err: any) {
            setAuthStep('error');
            setAuthError(err.message || 'Authentication failed');
        }
    };

    const navigate = (screen: Screen) => setCurrentScreen(screen);
    const logout   = () => { setAuthStep('idle'); setSessionId(''); setAccessResult(null); setCurrentScreen('WELCOME'); };

    const requestAccess = async (simulateAnomaly = false, fromDashboard = false) => {
        setAccessLoading(true);
        setAccessResult(null);
        try {
            const el = (window as any).electron;
            if (!el?.resource) throw new Error('Electron Resource API not available');

            const result = await el.resource.access({
                resourceId,
                simulateAnomaly,
                // Only pass slider values from the Telemetry tab; Dashboard gets normal telemetry
                velocity: fromDashboard ? 0 : velocity,
                drift:    fromDashboard ? 0 : drift,
            });
            setAccessResult({ ...result, anomaly: simulateAnomaly });
        } catch (err: any) {
            setAccessResult({
                error:    err.message || 'Request failed',
                riskScore: err.riskScore,
                decision:  err.decision,
                anomaly:   simulateAnomaly,
            });
            // If session was revoked, go back to welcome
            if (err.message?.includes('Session Revoked') || err.message?.includes('revoked')) {
                setTimeout(() => { setSessionId(''); setAuthStep('idle'); setCurrentScreen('WELCOME'); }, 2500);
            }
        } finally {
            setAccessLoading(false);
        }
    };

    /* ── Screens ───────────────────────────────────────── */

    const renderWelcome = () => (
        <div className="fullscreen">
            <div className="welcome-logo">🔐</div>
            <h1 className="welcome-title">VeriChain AI</h1>
            <p className="welcome-subtitle">
                Zero-Knowledge Proof authentication with mTLS and blockchain-anchored audit trails.
            </p>
            <div className="welcome-features">
                <div className="feature-chip"><span>🔑</span> ZKP Groth16</div>
                <div className="feature-chip"><span>🔒</span> mTLS</div>
                <div className="feature-chip"><span>⛓</span> On-Chain</div>
            </div>
            <div className="welcome-actions">
                <button className="btn btn-primary" onClick={() => { setAuthStep('idle'); navigate('AUTHENTICATION'); }}>
                    🔐 Authenticate
                </button>
                <button className="btn btn-ghost" onClick={() => navigate('STATUS')}>
                    System Status
                </button>
            </div>
        </div>
    );

    const renderAuth = () => (
        <div className="fullscreen">
            <div className="auth-card">
                <div className="auth-card-title">
                    {isEnrolled ? 'Zero-Knowledge Login' : 'Enroll Identity'}
                </div>
                <p className="auth-card-sub">
                    {isEnrolled
                        ? 'Your private key never leaves this device.'
                        : 'Generate your cryptographic key pair to begin.'}
                </p>

                {authStep === 'idle' && !isEnrolled && (
                    <>
                        <button className="btn btn-primary btn-full" onClick={handleEnroll}>
                            🔑 Enroll New Identity
                        </button>
                        <button className="btn btn-ghost btn-full" style={{ marginTop: '0.6rem' }} onClick={() => navigate('WELCOME')}>
                            ← Back
                        </button>
                    </>
                )}

                {authStep === 'idle' && isEnrolled && (
                    <>
                        <div className="badge badge-green" style={{ marginBottom: '1.25rem' }}>
                            ● Identity enrolled
                        </div>
                        <button className="btn btn-primary btn-full" onClick={handleLogin}>
                            🚀 Authenticate with ZKP
                        </button>
                        <button className="btn btn-ghost btn-full" style={{ marginTop: '0.6rem' }} onClick={() => navigate('WELCOME')}>
                            ← Back
                        </button>
                    </>
                )}

                {(authStep === 'proving' || authStep === 'verifying' || authStep === 'establishing') && (
                    <div className="progress-steps">
                        {(['proving', 'verifying', 'establishing'] as AuthStep[]).map(s => {
                            const state = stepState(s, authStep);
                            return (
                                <div className="step-row" key={s}>
                                    <div className={`step-circle ${state}`}>
                                        {state === 'done' ? '✓' : STEPS.indexOf(s) + 1}
                                    </div>
                                    <span className={`step-label ${state}`}>{STEP_LABELS[s]}</span>
                                    {state === 'active' && <div className="step-spinner" />}
                                </div>
                            );
                        })}
                    </div>
                )}

                {authStep === 'success' && (
                    <>
                        <div className="progress-steps" style={{ marginBottom: '1.25rem' }}>
                            {(['proving', 'verifying', 'establishing'] as AuthStep[]).map(s => (
                                <div className="step-row" key={s}>
                                    <div className="step-circle done">✓</div>
                                    <span className="step-label done">{STEP_LABELS[s]}</span>
                                </div>
                            ))}
                        </div>
                        <div className="badge badge-green" style={{ marginBottom: '1rem' }}>
                            ● Authentication successful — {sessionId.substring(0, 8)}...
                        </div>
                        <button className="btn btn-success btn-full" onClick={() => navigate('DASHBOARD')}>
                            Enter Dashboard →
                        </button>
                    </>
                )}

                {authStep === 'error' && (
                    <>
                        <div className="alert-box error" style={{ marginBottom: '1.25rem' }}>
                            <span className="alert-icon">⚠</span>
                            <span>{authError}</span>
                        </div>
                        <button className="btn btn-ghost btn-full" onClick={() => setAuthStep('idle')}>
                            ← Retry
                        </button>
                    </>
                )}
            </div>
        </div>
    );

    const renderDashboard = () => {
        const latestRisk = accessResult?.riskScore ?? null;
        const riskColor  = latestRisk === null ? 'blue' : latestRisk > 75 ? 'red' : latestRisk > 50 ? 'yellow' : 'green';

        return (
            <div className="page">
                <div className="page-header">
                    <h1 className="page-title">Dashboard</h1>
                    <p className="page-subtitle">Real-time security posture and session metrics</p>
                </div>

                {/* KPI row */}
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-label">Risk Score</div>
                        <div className={`stat-value ${riskColor}`}>{latestRisk ?? '—'}</div>
                        <div className="stat-meta">from last access request</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Session</div>
                        <div className="stat-value green">ACTIVE</div>
                        <div className="stat-meta">{sessionId ? sessionId.substring(0, 10) + '…' : '—'}</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Access Velocity</div>
                        <div className="stat-value blue">{telemetry?.accessVelocity ?? '—'}</div>
                        <div className="stat-meta">req / sec</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Uptime</div>
                        <div className="stat-value blue">{telemetry?.sessionDuration ?? '—'}</div>
                        <div className="stat-meta">session duration</div>
                    </div>
                </div>

                {/* Resource Access Panel */}
                <div className="card" style={{ marginBottom: '1rem' }}>
                    <div className="card-title">🔑 Request Protected Resource</div>

                    <div style={{ display: 'flex', gap: '0.6rem', marginBottom: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
                        <input
                            value={resourceId}
                            onChange={e => setResourceId(e.target.value)}
                            placeholder="Resource ID (e.g. demo-resource-001)"
                            style={{
                                flex: 1, minWidth: 200,
                                background: 'var(--bg-surface)', border: '1px solid var(--border)',
                                color: 'var(--text-primary)', padding: '0.5rem 0.75rem',
                                borderRadius: '6px', fontSize: '0.875rem',
                                fontFamily: 'JetBrains Mono, monospace',
                            }}
                        />
                        <button
                            className="btn btn-primary"
                            disabled={accessLoading}
                            onClick={() => requestAccess(false, true)}
                        >
                            {accessLoading ? '⏳ Checking…' : '🔑 Request Access'}
                        </button>
                        <button
                            className="btn btn-danger"
                            disabled={accessLoading}
                            onClick={() => requestAccess(true, true)}
                            title="Sends anomalous telemetry — AI returns score 92 → session revoked"
                        >
                            ⚡ Simulate Anomaly
                        </button>
                    </div>

                    {/* Access Result */}
                    {accessResult && (
                        <div style={{
                            padding: '0.85rem 1rem',
                            borderRadius: '8px',
                            background: accessResult.success ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                            border: `1px solid ${accessResult.success ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '1.1rem' }}>{accessResult.success ? '✅' : '🚫'}</span>
                                <strong style={{ color: accessResult.success ? 'var(--success)' : 'var(--danger)' }}>
                                    {accessResult.success ? 'ACCESS GRANTED' : 'ACCESS DENIED'}
                                </strong>
                                {accessResult.riskScore !== undefined && (
                                    <span className={`badge ${(accessResult.riskScore ?? 0) > 75 ? 'badge-red' : (accessResult.riskScore ?? 0) > 50 ? 'badge-yellow' : 'badge-green'}`}>
                                        Risk: {accessResult.riskScore}/100
                                    </span>
                                )}
                                {accessResult.decision && (
                                    <span className="badge badge-blue">Decision: {accessResult.decision}</span>
                                )}
                                {accessResult.anomaly && (
                                    <span className="badge badge-red">⚡ Anomaly Simulated</span>
                                )}
                            </div>
                            {accessResult.error && (
                                <div style={{ fontSize: '0.82rem', color: 'var(--danger)', marginTop: '0.4rem' }}>
                                    {accessResult.error}
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* File Vault Panel */}
                <div className="card" style={{ marginBottom: '1rem' }}>
                    <div className="card-title">📂 Protected File Vault</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '1rem' }}>
                        {[
                            { name: 'q1_audit.pdf',   path: '/vault/reports/q1.pdf' },
                            { name: 'q2_audit.pdf',   path: '/vault/reports/q2.pdf' },
                            { name: 'system_keys.pem', path: '/vault/keys/master.pem' },
                            { name: 'user_data.db',    path: '/vault/db/users.db' },
                        ].map(f => (
                            <div
                                key={f.path}
                                className="file-item"
                                onClick={() => { setResourceId(f.path); requestAccess(false, true); }}
                                style={{
                                    padding: '1rem', background: 'var(--bg-surface)', border: '1px solid var(--border)',
                                    borderRadius: '8px', textAlign: 'center', cursor: 'pointer', transition: 'all 0.2s'
                                }}
                            >
                                <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>📄</div>
                                <div style={{ fontSize: '0.75rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.name}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Quick Nav */}
                <div className="card">
                    <div className="card-title">Quick Actions</div>
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <button className="btn btn-ghost" onClick={() => navigate('SECURITY')}>⊕ Security Center</button>
                        <button className="btn btn-ghost" onClick={() => navigate('TELEMETRY')}>⌁ Telemetry</button>
                        <button className="btn btn-danger" onClick={logout}>⏻ End Session</button>
                    </div>
                </div>
            </div>
        );
    };

    const renderStatus = () => {
        const items = [
            { key: 'Security Gateway',       val: status?.gateway    ?? '…', ok: status?.gateway?.includes('Active') },
            { key: 'mTLS Cert Pinning',      val: status?.pinned     ?? '…', ok: status?.pinned !== 'Unreachable' },
            { key: 'Zero-Knowledge Service', val: status?.zkp        ?? '…', ok: !!status?.zkp },
            { key: 'AI Risk Engine',         val: status?.aiEngine   ?? '…', ok: status?.aiEngine === 'Operational' },
            { key: 'Blockchain Network',     val: status?.blockchain ?? '…', ok: status?.blockchain?.includes('Block') || status?.blockchain === 'Connected' },
            { key: 'Audit Service',          val: status?.audit      ?? '…', ok: status?.audit?.includes('Running') || status?.audit?.includes('logs') },
            { key: 'Secure Storage',         val: status?.storage    ?? '…', ok: status?.storage === 'Connected' },
            { key: 'Heartbeat Service',      val: status?.heartbeat  ?? '…', ok: status?.heartbeat === 'Active' },
        ];
        const allGreen = items.filter(i => i.ok).length;

        return (
            <div className="page">
                <div className="page-header">
                    <h1 className="page-title">System Status</h1>
                    <p className="page-subtitle">Service connectivity and component health</p>
                    <button className="btn btn-ghost" style={{ fontSize: '0.8rem', padding: '0.3rem 0.7rem' }}
                        onClick={() => (window as any).electron?.system?.getStatus().then(setStatus)}>
                        ↻ Refresh
                    </button>
                </div>

                <div className="stats-grid" style={{ marginBottom: '1rem' }}>
                    <div className="stat-card">
                        <div className="stat-label">Services Online</div>
                        <div className={`stat-value ${allGreen === 8 ? 'green' : allGreen >= 5 ? 'yellow' : 'red'}`}>
                            {status ? `${allGreen}/8` : '…'}
                        </div>
                        <div className="stat-meta">components healthy</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Session State</div>
                        <div className={`stat-value ${sessionId ? 'green' : 'blue'}`}>
                            {sessionId ? 'AUTH' : 'GUEST'}
                        </div>
                        <div className="stat-meta">{sessionId ? sessionId.substring(0, 8) + '…' : 'read-only mode'}</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Process Uptime</div>
                        <div className="stat-value blue">{status?.uptime ?? '…'}</div>
                        <div className="stat-meta">since agent start</div>
                    </div>
                </div>

                <div className="card">
                    <div className="card-title">Service Infrastructure</div>
                    <div className="info-list">
                        {items.map(({ key, val, ok }) => (
                            <div className="info-row" key={key}>
                                <span className="info-key">{key}</span>
                                <span className={`badge ${!status ? 'badge-gray' : ok ? 'badge-green' : 'badge-red'}`}>
                                    {!status ? '…' : (ok ? '● ' : '✗ ') + val}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        );
    };

    const renderTelemetry = () => {
        const expectedDecision = drift >= 3.5 ? 'REVOKE' : velocity >= 40 ? 'STEP_UP' : 'PERMIT';
        const decisionColor    = expectedDecision === 'REVOKE' ? 'red' : expectedDecision === 'STEP_UP' ? 'yellow' : 'green';

        return (
            <div className="page">
                <div className="page-header">
                    <h1 className="page-title">Telemetry</h1>
                    <p className="page-subtitle">Live behavioral signals used by the AI Risk Engine for continuous scoring</p>
                </div>

                <div className="stats-grid" style={{ marginBottom: '1rem' }}>
                    <div className="stat-card">
                        <div className="stat-label">Access Velocity</div>
                        <div className={`stat-value ${velocity >= 40 ? 'red' : 'blue'}`}>{velocity}</div>
                        <div className="stat-meta">signals / window</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Geo Drift</div>
                        <div className={`stat-value ${drift >= 3.5 ? 'red' : drift >= 2 ? 'yellow' : 'green'}`}>{drift.toFixed(1)}°</div>
                        <div className="stat-meta">location deviation</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Session Uptime</div>
                        <div className="stat-value blue">{telemetry?.sessionDuration ?? '—'}</div>
                        <div className="stat-meta">active duration</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Expected Decision</div>
                        <div className={`stat-value ${decisionColor}`}>{expectedDecision}</div>
                        <div className="stat-meta">from current signals</div>
                    </div>
                </div>

                <div className="card" style={{ marginBottom: '1rem' }}>
                    <div className="card-title">🚨 Anomaly Simulator</div>
                    <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginBottom: '1rem' }}>
                        Scenario A — velocity ≥ 40 → <strong style={{ color: 'var(--warning)' }}>Step-Up Auth</strong>&nbsp;&nbsp;
                        Scenario B — geo drift ≥ 3.5 → <strong style={{ color: 'var(--danger)' }}>Session Revoke</strong>
                    </p>

                    <div style={{ marginBottom: '1.25rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem', fontSize: '0.85rem' }}>
                            <span>Access Velocity (signals/window)</span>
                            <strong style={{ color: velocity >= 40 ? 'var(--danger)' : 'var(--text-primary)' }}>{velocity}</strong>
                        </div>
                        <input type="range" min="0" max="100" step="1" value={velocity}
                            onChange={e => setVelocity(parseFloat(e.target.value))}
                            style={{ width: '100%', accentColor: velocity >= 40 ? 'var(--danger)' : 'var(--accent)' }} />
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                            <span>0 (normal)</span><span style={{ color: 'var(--warning)' }}>40+ (step-up)</span>
                        </div>
                    </div>

                    <div style={{ marginBottom: '1.5rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem', fontSize: '0.85rem' }}>
                            <span>Geo Drift (location deviation °)</span>
                            <strong style={{ color: drift >= 3.5 ? 'var(--danger)' : 'var(--text-primary)' }}>{drift.toFixed(1)}</strong>
                        </div>
                        <input type="range" min="0" max="5" step="0.1" value={drift}
                            onChange={e => setDrift(parseFloat(e.target.value))}
                            style={{ width: '100%', accentColor: drift >= 3.5 ? 'var(--danger)' : 'var(--accent)' }} />
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
                            <span>0.0 (normal)</span><span style={{ color: 'var(--danger)' }}>3.5+ (revoke)</span>
                        </div>
                    </div>

                    <button
                        className={`btn btn-full ${expectedDecision === 'REVOKE' ? 'btn-danger' : expectedDecision === 'STEP_UP' ? 'btn-warning' : 'btn-primary'}`}
                        onClick={() => requestAccess(false)}
                        disabled={accessLoading || !sessionId}
                        title={!sessionId ? 'Authenticate first' : ''}
                    >
                        {accessLoading ? '⏳ Scoring…' : `Apply Signals → ${expectedDecision}`}
                    </button>
                    {!sessionId && (
                        <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '0.5rem', textAlign: 'center' }}>
                            Authenticate first to send signals
                        </p>
                    )}
                </div>

                {/* Result from last Apply Signals */}
                {accessResult && (
                    <div className="card">
                        <div className="card-title">Last Signal Result</div>
                        <div style={{
                            padding: '0.85rem 1rem', borderRadius: '8px', marginTop: '0.5rem',
                            background: accessResult.success ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                            border: `1px solid ${accessResult.success ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '1.1rem' }}>{accessResult.success ? '✅' : '🚫'}</span>
                                <strong style={{ color: accessResult.success ? 'var(--success)' : 'var(--danger)' }}>
                                    {accessResult.decision || (accessResult.success ? 'PERMIT' : 'DENIED')}
                                </strong>
                                {accessResult.riskScore !== undefined && (
                                    <span className={`badge ${(accessResult.riskScore ?? 0) > 75 ? 'badge-red' : (accessResult.riskScore ?? 0) > 50 ? 'badge-yellow' : 'badge-green'}`}>
                                        Risk: {accessResult.riskScore}/100
                                    </span>
                                )}
                            </div>
                            {accessResult.error && (
                                <div style={{ fontSize: '0.82rem', color: 'var(--danger)', marginTop: '0.4rem' }}>{accessResult.error}</div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    };

    const renderSecurity = () => (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">Security Center</h1>
                <p className="page-subtitle">Cryptographic controls and identity protection status</p>
            </div>
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div className="card-title">Identity &amp; Keys</div>
                <div className="info-list">
                    <div className="info-row">
                        <span className="info-key">Private Key Storage</span>
                        <span className="badge badge-green">OS safeStorage</span>
                    </div>
                    <div className="info-row">
                        <span className="info-key">Identity Enrolled</span>
                        <span className={`badge ${isEnrolled ? 'badge-green' : 'badge-red'}`}>
                            {isEnrolled ? '✓ Yes' : '✗ No'}
                        </span>
                    </div>
                </div>
            </div>
            <div className="card">
                <div className="card-title">Transport &amp; ZKP</div>
                <div className="info-list">
                    <div className="info-row">
                        <span className="info-key">mTLS Cert Pinning</span>
                        <span className={`badge ${status?.pinned === 'Enabled' ? 'badge-green' : 'badge-yellow'}`}>
                            {status?.pinned ?? '—'}
                        </span>
                    </div>
                    <div className="info-row">
                        <span className="info-key">ZKP Circuit</span>
                        <span className="badge badge-blue">Groth16 / BN128</span>
                    </div>
                    <div className="info-row">
                        <span className="info-key">ZKP Engine</span>
                        <span className="badge badge-green">{status?.zkp ?? '—'}</span>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderSettings = () => (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">Settings</h1>
                <p className="page-subtitle">Desktop agent configuration</p>
            </div>
            <div className="settings-form">
                <div className="form-field">
                    <div className="form-label">Gateway URL</div>
                    <div className="form-value">
                        {process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443'}
                    </div>
                </div>
                <div className="form-field">
                    <div className="form-label">Theme</div>
                    <div className="form-value">Dark Navy</div>
                </div>
                <div className="form-field">
                    <div className="form-label">Key Storage</div>
                    <div className="form-value">Electron safeStorage (OS-level encryption)</div>
                </div>
                <div className="form-field">
                    <div className="form-label">ZKP Circuit</div>
                    <div className="form-value">Groth16 — BN128 (snarkjs)</div>
                </div>
            </div>
        </div>
    );

    const renderAbout = () => (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">About VeriChain AI</h1>
                <p className="page-subtitle">Zero-Trust Secure Software Design project</p>
            </div>
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div className="card-title">Version Info</div>
                <div className="info-list">
                    <div className="info-row"><span className="info-key">Version</span><span className="badge badge-blue">1.0.0</span></div>
                    <div className="info-row"><span className="info-key">Runtime</span><span className="info-value">Electron 28 + Vite</span></div>
                    <div className="info-row"><span className="info-key">Framework</span><span className="info-value">React 18 + TypeScript</span></div>
                </div>
            </div>
            <div className="card">
                <div className="card-title">Security Stack</div>
                <div className="info-list">
                    <div className="info-row"><span className="info-key">Auth Model</span><span className="badge badge-green">ZKP + mTLS</span></div>
                    <div className="info-row"><span className="info-key">ZKP Circuit</span><span className="info-value">Groth16 (BN128)</span></div>
                    <div className="info-row"><span className="info-key">Smart Contracts</span><span className="info-value">Solidity 0.8.20 (Hardhat)</span></div>
                    <div className="info-row"><span className="info-key">Risk Scoring</span><span className="info-value">AI — Isolation Forest</span></div>
                    <div className="info-row"><span className="info-key">Audit Trail</span><span className="info-value">Merkle + On-Chain Anchoring</span></div>
                </div>
            </div>
        </div>
    );

    const renderScreen = () => {
        switch (currentScreen) {
            case 'WELCOME':        return renderWelcome();
            case 'AUTHENTICATION': return renderAuth();
            case 'DASHBOARD':      return renderDashboard();
            case 'STATUS':         return renderStatus();
            case 'TELEMETRY':      return renderTelemetry();
            case 'SECURITY':       return renderSecurity();
            case 'SETTINGS':       return renderSettings();
            case 'ABOUT':          return renderAbout();
            default:               return null;
        }
    };

    const showSidebar = currentScreen !== 'WELCOME' && currentScreen !== 'AUTHENTICATION';

    return (
        <div className="app-shell">
            {showSidebar && (
                <nav className="sidebar">
                    <div className="sidebar-brand">
                        <div className="brand-logo">
                            <div className="brand-icon">🔐</div>
                            <div>
                                <div className="brand-text">VeriChain AI</div>
                                <div className="brand-sub">Desktop Agent</div>
                            </div>
                        </div>
                    </div>

                    {sessionId && (
                        <div className="session-badge">
                            <div className="session-dot" />
                            <span className="session-label">ACTIVE</span>
                            <span className="session-id">{sessionId.substring(0, 6)}…</span>
                        </div>
                    )}

                    <div className="sidebar-nav">
                        <div className="nav-section-label">Navigation</div>
                        {NAV_ITEMS.map(({ screen, icon, label }) => {
                            const isLocked = !sessionId && screen !== 'STATUS' && screen !== 'ABOUT' && screen !== 'SETTINGS';
                            return (
                                <div
                                    key={screen}
                                    className={`nav-item${currentScreen === screen ? ' active' : ''}${isLocked ? ' disabled' : ''}`}
                                    onClick={() => !isLocked && navigate(screen)}
                                    title={isLocked ? 'Authentication Required' : ''}
                                >
                                    <span className="nav-icon">{isLocked ? '🔒' : icon}</span>
                                    {label}
                                </div>
                            );
                        })}
                    </div>

                    <div className="sidebar-footer">
                        <button className="logout-btn" onClick={logout}>
                            <span>⏻</span> Logout
                        </button>
                    </div>
                </nav>
            )}
            <main className="main-content">
                {renderScreen()}

                {/* Step-Up Modal */}
                {accessResult?.decision === 'STEP_UP' && (
                    <div className="modal-overlay">
                        <div className="modal-card">
                            <div className="modal-icon warning">⚠</div>
                            <h2 className="modal-title">Step-Up Required</h2>
                            <p className="modal-text">AI Risk Engine detected elevated risk. Re-authenticate to continue.</p>
                            <button className="btn btn-warning btn-full" onClick={() => { setAccessResult(null); navigate('AUTHENTICATION'); }}>
                                Re-Authenticate
                            </button>
                        </div>
                    </div>
                )}

                {/* Revocation Modal */}
                {accessResult?.decision === 'REVOKE' && (
                    <div className="modal-overlay">
                        <div className="modal-card">
                            <div className="modal-icon danger">🛑</div>
                            <h2 className="modal-title">Session Revoked</h2>
                            <p className="modal-text">Critical anomaly detected. Access has been terminated.</p>
                            <button className="btn btn-danger btn-full" onClick={logout}>
                                OK
                            </button>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
};

export default App;
