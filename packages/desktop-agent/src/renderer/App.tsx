import React, { useState, useEffect, useCallback } from 'react';
import './agent.css';

type Screen    = 'WELCOME' | 'AUTHENTICATION' | 'DASHBOARD' | 'STATUS' | 'TELEMETRY' | 'SECURITY' | 'SETTINGS' | 'ABOUT';
type AuthStep  = 'idle' | 'proving' | 'verifying' | 'establishing' | 'success' | 'error';
type ToastType = 'success' | 'error' | 'warning' | 'info';

interface AiReason {
    feature?:    string;
    label?:      string;
    value?:      number;
    expected?:   number;
    zScore?:     number;
    deviation?:  number;
    direction?:  string;
    concerning?: boolean;
    unit?:       string;
}

interface AccessResult {
    success?:       boolean;
    riskScore?:     number;
    decision?:      string;
    error?:         string;
    reasons?:       AiReason[];
    reasonSummary?: string;
}

interface Toast {
    id: number;
    type: ToastType;
    message: string;
}

const STEPS: AuthStep[] = ['proving', 'verifying', 'establishing', 'success'];

const STEP_LABELS: Record<string, string> = {
    proving:      'Generating Groth16 proof via snarkjs…',
    verifying:    'Establishing mTLS channel… Certificate pinning verified ✓',
    establishing: 'Verifying at Gateway… groth16.verify() running…',
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

// ── Reasons panel ─────────────────────────────────────────────────────────────
const formatFeatureVal = (v: any, unit?: string): string => {
    if (typeof v !== 'number') return String(v ?? '?');
    if (unit === 'bytes' && v >= 1000) {
        if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)} MB`;
        return `${(v / 1024).toFixed(0)} KB`;
    }
    return `${v.toFixed(v < 10 ? 2 : 0)}${unit ? ' ' + unit : ''}`;
};

const ReasonsPanel: React.FC<{ reasons?: AiReason[]; decision?: string }> = ({ reasons, decision }) => {
    if (!reasons || reasons.length === 0) {
        if (decision === 'PERMIT') {
            return (
                <div style={{ marginTop: '0.6rem', padding: '0.55rem 0.75rem', background: 'rgba(52, 211, 153, 0.08)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--success)' }}>
                    ✓ All telemetry features within the normal training distribution
                </div>
            );
        }
        return null;
    }
    const concerning   = reasons.filter(r => r.concerning);
    const informational = reasons.filter(r => !r.concerning);

    const Row: React.FC<{ r: AiReason; concerning: boolean }> = ({ r, concerning: c }) => (
        <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '4px 0',
            borderBottom: '1px solid var(--border-soft)',
        }}>
            <span style={{ fontSize: '0.78rem', color: c ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: c ? 600 : 400 }}>
                {c ? '⚠ ' : 'ℹ '}{r.label || r.feature}
            </span>
            <span className="mono" style={{ fontSize: '0.74rem', color: c ? 'var(--danger)' : 'var(--text-dim)' }}>
                {formatFeatureVal(r.value, r.unit)} <span style={{ color: 'var(--text-dim)' }}>vs ~{formatFeatureVal(r.expected, r.unit)}</span>
                <span style={{ marginLeft: '0.5rem', color: c ? 'var(--warning)' : 'var(--text-dim)' }}>z={r.zScore}</span>
            </span>
        </div>
    );

    return (
        <div style={{ marginTop: '0.7rem', padding: '0.7rem 0.85rem', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6 }}>
            {concerning.length > 0 && (
                <>
                    <div style={{ fontSize: '0.66rem', color: 'var(--danger)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginBottom: '0.3rem' }}>
                        Anomaly direction · driving the score up
                    </div>
                    {concerning.map((r, i) => <Row key={'c'+i} r={r} concerning />)}
                </>
            )}
            {informational.length > 0 && (
                <>
                    <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginTop: concerning.length ? '0.6rem' : 0, marginBottom: '0.3rem' }}>
                        Unusual but not concerning
                    </div>
                    {informational.map((r, i) => <Row key={'i'+i} r={r} concerning={false} />)}
                </>
            )}
        </div>
    );
};

// ── Risk Gauge ────────────────────────────────────────────────────────────────
const RiskGauge: React.FC<{ score: number; decision: string; reasons?: AiReason[] }> = ({ score, decision, reasons }) => {
    const color =
        score > 75 ? 'var(--danger)' :
        score > 50 ? 'var(--warning)' :
                     'var(--success)';
    const label =
        decision === 'REVOKE'  ? 'SESSION REVOKED' :
        decision === 'STEP_UP' ? 'STEP-UP REQUIRED' :
                                 'ACCESS PERMITTED';
    const decisionBg =
        score > 75 ? 'rgba(248, 113, 113, 0.12)' :
        score > 50 ? 'rgba(251, 191, 36, 0.12)' :
                     'rgba(52, 211, 153, 0.12)';

    return (
        <div className="risk-gauge">
            <div className="risk-gauge-head">
                <span className="risk-gauge-label">Isolation Forest Score</span>
                <span className="risk-gauge-value" style={{ color }}>
                    {score.toFixed(2)}<span className="max">/100</span>
                </span>
            </div>
            <div className="risk-gauge-track">
                <div className="risk-gauge-zone" style={{ left: '50%' }} />
                <div className="risk-gauge-zone" style={{ left: '75%' }} />
                <div className="risk-gauge-fill" style={{
                    width: `${Math.min(score, 100)}%`,
                    background: `linear-gradient(90deg, var(--success), ${color})`,
                }} />
            </div>
            <div className="risk-gauge-scale">
                <span>0 · PERMIT</span>
                <span style={{ color: 'var(--warning)' }}>50 · STEP_UP</span>
                <span style={{ color: 'var(--danger)' }}>75 · REVOKE</span>
                <span>100</span>
            </div>
            <div className="risk-gauge-decision" style={{ background: decisionBg, border: `1px solid ${color}`, color }}>
                {score > 75 ? '🛑' : score > 50 ? '⚠' : '✓'} {label}
            </div>
            <ReasonsPanel reasons={reasons} decision={decision} />
        </div>
    );
};

// ── Telemetry row ─────────────────────────────────────────────────────────────
const TelRow: React.FC<{
    label: string; unit: string; value: number; min: number; max: number; step: number;
    onChange: (v: number) => void; warn?: number; danger?: number; invert?: boolean;
    fmt?: (v: number) => string;
}> = ({ label, unit, value, min, max, step, onChange, warn, danger, invert, fmt }) => {
    const bad = invert
        ? (danger != null && value <= danger) || (warn != null && value <= warn)
        : (danger != null && value >= danger) || (warn != null && value >= warn);
    const critical = invert
        ? danger != null && value <= danger
        : danger != null && value >= danger;
    const color = critical ? 'var(--danger)' : bad ? 'var(--warning)' : 'var(--success)';
    const display = fmt ? fmt(value) : value.toString();

    return (
        <div className="tel-row">
            <div className="tel-row-head">
                <span className="tel-row-label">{label}</span>
                <strong className="tel-row-value" style={{ color }}>
                    {display}<span className="unit">{unit}</span>
                </strong>
            </div>
            <input
                type="range" min={min} max={max} step={step} value={value}
                onChange={e => onChange(parseFloat(e.target.value))}
                style={{ accentColor: color }}
            />
        </div>
    );
};

let toastCounter = 0;

const App: React.FC = () => {
    const [currentScreen, setCurrentScreen] = useState<Screen>('WELCOME');
    const [isEnrolled, setIsEnrolled]       = useState(false);
    const [status, setStatus]               = useState<any>(null);
    const [authStep, setAuthStep]           = useState<AuthStep>('idle');
    const [authError, setAuthError]         = useState('');
    const [sessionId, setSessionId]         = useState('');
    const [resourceId, setResourceId]       = useState('demo-resource-001');
    const [accessResult, setAccessResult]   = useState<AccessResult | null>(null);
    const [accessLoading, setAccessLoading] = useState(false);
    const [toasts, setToasts]               = useState<Toast[]>([]);

    // ── All 6 Isolation Forest features ──────────────────────────────────────
    const [accessVelocity,  setAccessVelocity]  = useState(5);
    const [geoDistanceKm,   setGeoDistanceKm]   = useState(0);
    const [uniqueResources, setUniqueResources] = useState(2);
    const [downloadBytes,   setDownloadBytes]   = useState(50000);
    const [timeSinceLast,   setTimeSinceLast]   = useState(300);
    const [deviceIdMatch,   setDeviceIdMatch]   = useState(true);

    const addToast = useCallback((type: ToastType, message: string) => {
        const id = ++toastCounter;
        setToasts(prev => [...prev, { id, type, message }]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
    }, []);

    useEffect(() => {
        const el = (window as any).electron;
        if (el?.auth) el.auth.isEnrolled().then(setIsEnrolled);

        const poll = () => {
            if (el?.system) el.system.getStatus().then(setStatus).catch(() => {});
        };
        poll();
        const iv = setInterval(poll, 3000);

        el?.onSessionRevoked?.(() => {
            setSessionId('');
            setAuthStep('idle');
            setCurrentScreen('WELCOME');
            addToast('error', 'Session revoked by Gateway — re-authenticate to continue');
        });

        return () => clearInterval(iv);
    }, [addToast]);

    // ── Auth handlers ─────────────────────────────────────────────────────────
    const handleEnroll = async () => {
        setAuthStep('proving');
        setAuthError('');
        try {
            await (window as any).electron?.auth?.enroll();
            setIsEnrolled(true);
            setAuthStep('idle');
            addToast('success', 'Identity enrolled — key stored in OS safeStorage');
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
            await new Promise(r => setTimeout(r, 350));
            setAuthStep('verifying');
            const result = await el.auth.login();
            setAuthStep('establishing');
            await new Promise(r => setTimeout(r, 400));
            setSessionId(result.sessionId || '');
            setAuthStep('success');
            addToast('success', `Session ${(result.sessionId || '').substring(0, 8)}… established`);
        } catch (err: any) {
            setAuthStep('error');
            setAuthError(err.message || 'Authentication failed');
        }
    };

    // ── Resource access ───────────────────────────────────────────────────────
    const requestAccess = async () => {
        setAccessLoading(true);
        setAccessResult(null);
        try {
            const el = (window as any).electron;
            if (!el?.resource) throw new Error('Electron Resource API not available');

            const result = await el.resource.access({
                resourceId,
                accessVelocity,
                geoDistanceKm,
                uniqueResources,
                downloadBytes,
                timeSinceLast,
                deviceIdMatch: deviceIdMatch ? 1 : 0,
            });

            setAccessResult({ ...result, success: true });
            const summary = result.decision === 'STEP_UP' && result.reasonSummary
                ? ` · ${result.reasonSummary.slice(0, 80)}…`
                : '';
            addToast(
                result.decision === 'STEP_UP' ? 'warning' : 'success',
                `${result.decision} · risk ${(result.riskScore ?? 0).toFixed(2)}${summary}`
            );
        } catch (err: any) {
            const r: AccessResult = {
                error:         err.message || 'Request failed',
                riskScore:     err.riskScore,
                decision:      err.decision || 'REVOKE',
                reasons:       err.reasons,
                reasonSummary: err.reasonSummary,
            };
            setAccessResult(r);

            if (r.decision === 'REVOKE') {
                const reasonText = r.reasons?.[0]?.label
                    ? ` — ${r.reasons[0].label} anomaly`
                    : '';
                addToast('error', `REVOKED · risk ${(r.riskScore ?? 0).toFixed(2)}/100${reasonText}`);
                setTimeout(() => { setSessionId(''); setAuthStep('idle'); setCurrentScreen('WELCOME'); }, 3000);
            } else if (r.decision === 'STEP_UP') {
                addToast('warning', `STEP_UP required · risk ${(r.riskScore ?? 0).toFixed(2)}/100`);
            }
        } finally {
            setAccessLoading(false);
        }
    };

    const loadAnomaly = () => {
        // Pre-load extreme values — panel sees exactly what the AI receives
        setAccessVelocity(80);
        setGeoDistanceKm(450);
        setUniqueResources(40);
        setDownloadBytes(50_000_000);
        setTimeSinceLast(2);
        setDeviceIdMatch(false);
        setCurrentScreen('TELEMETRY');
        addToast('warning', 'Anomaly scenario loaded — click "Score with AI" to send');
    };

    const resetTelemetry = () => {
        setAccessVelocity(5);
        setGeoDistanceKm(0);
        setUniqueResources(2);
        setDownloadBytes(50000);
        setTimeSinceLast(300);
        setDeviceIdMatch(true);
    };

    const navigate = (screen: Screen) => setCurrentScreen(screen);
    const logout   = () => {
        setAuthStep('idle');
        setSessionId('');
        setAccessResult(null);
        setCurrentScreen('WELCOME');
    };

    /* ─── Screens ──────────────────────────────────────────────────────────── */

    const renderWelcome = () => (
        <div className="fullscreen">
            <div className="welcome-logo">🔐</div>
            <h1 className="welcome-title">VeriChain AI</h1>
            <p className="welcome-subtitle">
                Continuous zero-trust authentication with cryptographic proofs and on-chain audit anchoring.
            </p>

            <div className="welcome-pillars">
                <div className="welcome-pillar">
                    <div className="welcome-pillar-icon">🔑</div>
                    <div>
                        <strong>ZKP Login</strong>
                        Groth16 · key never transmitted
                    </div>
                </div>
                <div className="welcome-pillar">
                    <div className="welcome-pillar-icon">🔒</div>
                    <div>
                        <strong>Mutual TLS</strong>
                        Cert-pinned channel
                    </div>
                </div>
                <div className="welcome-pillar">
                    <div className="welcome-pillar-icon">🤖</div>
                    <div>
                        <strong>AI Risk Engine</strong>
                        Isolation Forest scoring
                    </div>
                </div>
                <div className="welcome-pillar">
                    <div className="welcome-pillar-icon">⛓</div>
                    <div>
                        <strong>Blockchain Audit</strong>
                        Merkle-anchored ledger
                    </div>
                </div>
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
                        <div className="badge badge-green" style={{ marginBottom: '1.25rem' }}>● Identity enrolled</div>
                        <button className="btn btn-primary btn-full" onClick={handleLogin}>
                            🚀 Authenticate with ZKP
                        </button>
                        <button className="btn btn-ghost btn-full" style={{ marginTop: '0.6rem' }} onClick={() => navigate('WELCOME')}>
                            ← Back
                        </button>
                    </>
                )}

                {(['proving', 'verifying', 'establishing'] as AuthStep[]).includes(authStep) && (
                    <div className="progress-steps">
                        {(['proving', 'verifying', 'establishing'] as AuthStep[]).map(s => {
                            const state = stepState(s as AuthStep, authStep);
                            return (
                                <div className="step-row" key={s}>
                                    <div className={`step-circle ${state}`}>
                                        {state === 'done' ? '✓' : STEPS.indexOf(s as AuthStep) + 1}
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
                        <button className="btn btn-ghost btn-full" onClick={() => setAuthStep('idle')}>← Retry</button>
                    </>
                )}
            </div>
        </div>
    );

    const renderDashboard = () => {
        const r = accessResult;
        const score = r?.riskScore ?? null;

        return (
            <div className="page">
                <div className="page-header">
                    <h1 className="page-title">Dashboard</h1>
                    <p className="page-subtitle">Real-time security posture and resource access</p>
                </div>

                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-label">Last Risk Score</div>
                        <div className={`stat-value ${score === null ? 'blue' : score > 75 ? 'red' : score > 50 ? 'yellow' : 'green'}`}>
                            {score !== null ? score.toFixed(2) : '—'}
                        </div>
                        <div className="stat-meta">from last AI evaluation</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Session</div>
                        <div className="stat-value green">ACTIVE</div>
                        <div className="stat-meta">{sessionId ? sessionId.substring(0, 10) + '…' : '—'}</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Velocity</div>
                        <div className={`stat-value ${accessVelocity >= 40 ? 'red' : 'blue'}`}>{accessVelocity}</div>
                        <div className="stat-meta">req / min</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Geo Distance</div>
                        <div className={`stat-value ${geoDistanceKm >= 300 ? 'red' : geoDistanceKm >= 100 ? 'yellow' : 'green'}`}>
                            {geoDistanceKm} km
                        </div>
                        <div className="stat-meta">from baseline</div>
                    </div>
                </div>

                {/* Access Panel */}
                <div className="card" style={{ marginBottom: '1rem' }}>
                    <div className="card-title">🔑 Request Protected Resource</div>

                    <div className="resource-bar">
                        <input
                            value={resourceId}
                            onChange={e => setResourceId(e.target.value)}
                            placeholder="Resource ID or path"
                        />
                        <button className="btn btn-primary" disabled={accessLoading} onClick={requestAccess}>
                            {accessLoading ? '⏳ Scoring…' : '🔑 Request Access'}
                        </button>
                        <button
                            className="btn btn-danger"
                            onClick={loadAnomaly}
                            title="Loads extreme telemetry values into the Telemetry Lab"
                        >
                            ⚡ Anomaly Preset
                        </button>
                    </div>

                    {/* AI Result */}
                    {r && r.riskScore !== undefined && (
                        <RiskGauge score={r.riskScore} decision={r.decision || 'REVOKE'} reasons={r.reasons} />
                    )}
                    {r && !r.riskScore && r.error && (
                        <div className="alert-box error" style={{ marginTop: '0.5rem' }}>
                            <span className="alert-icon">⚠</span><span>{r.error}</span>
                        </div>
                    )}
                </div>

                {/* File Vault */}
                <div className="card" style={{ marginBottom: '1rem' }}>
                    <div className="card-title">📂 Protected File Vault</div>
                    <div className="vault-grid">
                        {[
                            { name: 'q1_audit.pdf',    path: '/vault/reports/q1.pdf',     kind: 'PDF' },
                            { name: 'q2_audit.pdf',    path: '/vault/reports/q2.pdf',     kind: 'PDF' },
                            { name: 'system_keys.pem', path: '/vault/keys/master.pem',    kind: 'KEY' },
                            { name: 'user_data.db',    path: '/vault/db/users.db',        kind: 'DB' },
                            { name: 'audit_2026.xlsx', path: '/vault/reports/audit.xlsx', kind: 'XLS' },
                            { name: 'config.yml',      path: '/vault/config.yml',         kind: 'CFG' },
                        ].map(f => (
                            <div
                                key={f.path}
                                onClick={() => setResourceId(f.path)}
                                className={`vault-file ${resourceId === f.path ? 'selected' : ''}`}
                            >
                                <div className="vault-file-icon">📄</div>
                                <div className="vault-file-name" title={f.path}>{f.name}</div>
                                <div className="vault-file-meta">{f.kind}</div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card">
                    <div className="card-title">Quick Actions</div>
                    <div className="quick-actions">
                        <button className="btn btn-ghost" onClick={() => navigate('TELEMETRY')}>⌁ Telemetry Lab</button>
                        <button className="btn btn-ghost" onClick={() => navigate('SECURITY')}>⊕ Security Center</button>
                        <button className="btn btn-danger" onClick={logout}>⏻ End Session</button>
                    </div>
                </div>
            </div>
        );
    };

    const renderStatus = () => {
        const items = [
            { key: 'Security Gateway',       val: status?.gateway    ?? 'Connecting…',   ok: !!(status?.gateway === 'Connected' || status?.gateway?.includes('Active')) },
            { key: 'mTLS Cert Pinning',      val: status?.pinned     ?? 'Checking…',     ok: status?.pinned === 'Enabled' },
            { key: 'Zero-Knowledge Service', val: status?.zkp        ?? 'Initialising…', ok: !!(status?.zkp?.includes('Operational')) },
            { key: 'AI Risk Engine',         val: status?.ai         ?? 'Warming up…',   ok: status?.ai === 'Operational' },
            { key: 'Blockchain Network',     val: status?.blockchain ?? 'Syncing…',      ok: !!(status?.blockchain === 'Connected' || status?.blockchain?.includes('Block')) },
            { key: 'Audit Service',          val: status?.audit      ?? 'Starting…',     ok: !!(status?.audit === 'Running' || status?.audit?.includes('logs')) },
            { key: 'Secure Storage',         val: status?.storage    ?? 'Verifying…',    ok: !!(status?.storage === 'Healthy' || status?.storage === 'Connected') },
            { key: 'Heartbeat Service',      val: status?.heartbeat  ?? 'Idle',          ok: !!(status?.heartbeat === 'Running' || status?.heartbeat === 'Active') },
        ];
        const online = items.filter(i => i.ok).length;

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
                        <div className={`stat-value ${online === 8 ? 'green' : online >= 5 ? 'yellow' : 'red'}`}>
                            {status ? `${online}/8` : '…'}
                        </div>
                        <div className="stat-meta">components healthy</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Session</div>
                        <div className={`stat-value ${sessionId ? 'green' : 'blue'}`}>{sessionId ? 'AUTH' : 'GUEST'}</div>
                        <div className="stat-meta">{sessionId ? sessionId.substring(0, 8) + '…' : 'read-only'}</div>
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
        // Norm scales calibrated to the training distribution so the bars correspond
        // to what the Isolation Forest model actually treats as anomalous.
        // Training means/std: velocity 5±2, geo 0±5, resources 5±3, bytes 50k±20k,
        // timeSinceLast 300±100. ~2σ from mean is the "warning" threshold.
        const normVelocity  = Math.min(1, Math.max(0, (accessVelocity  - 1)  / 25));
        const normGeo       = Math.min(1, Math.max(0,  geoDistanceKm        / 100));
        const normResources = Math.min(1, Math.max(0, (uniqueResources - 1) / 20));
        const normBytes     = Math.min(1, Math.max(0,  downloadBytes        / 1_000_000));
        // Time since last — anomalous when LOW (rapid-fire). 1s = 1.0, 300s = 0.0
        const normTime      = Math.min(1, Math.max(0, 1 - timeSinceLast / 120));
        const normDevice    = deviceIdMatch ? 0 : 1;

        const features = [
            { label: 'Access Velocity',   value: accessVelocity,  unit: 'req/min',  norm: normVelocity  },
            { label: 'Geo Distance',      value: geoDistanceKm,   unit: 'km',       norm: normGeo       },
            { label: 'Unique Resources',  value: uniqueResources, unit: 'files',    norm: normResources },
            { label: 'Download Volume',   value: (downloadBytes / 1_000_000).toFixed(2) + ' MB', unit: '', norm: normBytes },
            { label: 'Time Since Last',   value: timeSinceLast,   unit: 's',        norm: normTime      },
            { label: 'Device Match',      value: deviceIdMatch ? 'YES' : 'NO', unit: '', norm: normDevice },
        ];

        return (
            <div className="page">
                <div className="page-header">
                    <h1 className="page-title">Telemetry Lab</h1>
                    <p className="page-subtitle">Control all 6 Isolation Forest features — the AI receives these exact values</p>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    {/* Sliders */}
                    <div className="card">
                        <div className="card-title">⌁ Feature Controls</div>

                        <TelRow label="Access Velocity" unit="req/min" value={accessVelocity} min={0} max={100} step={1}
                            onChange={setAccessVelocity} warn={15} danger={40} />
                        <TelRow label="Geo Distance" unit="km" value={geoDistanceKm} min={0} max={500} step={5}
                            onChange={setGeoDistanceKm} warn={100} danger={300} />
                        <TelRow label="Unique Resources" unit="files" value={uniqueResources} min={1} max={50} step={1}
                            onChange={setUniqueResources} warn={10} danger={25} />
                        <TelRow label="Download Volume" unit="bytes" value={downloadBytes} min={1024} max={100_000_000} step={100000}
                            onChange={setDownloadBytes} warn={5_000_000} danger={30_000_000}
                            fmt={v => v >= 1_000_000 ? `${(v / 1_000_000).toFixed(1)} MB` : `${(v / 1024).toFixed(0)} KB`} />
                        <TelRow label="Time Since Last" unit="s" value={timeSinceLast} min={1} max={600} step={1}
                            onChange={setTimeSinceLast} warn={30} danger={5} invert />

                        {/* Device Match toggle */}
                        <div className="device-toggle">
                            <span style={{ fontSize: '0.83rem', color: 'var(--text-muted)', fontWeight: 500 }}>Device ID Match</span>
                            <button
                                onClick={() => setDeviceIdMatch(p => !p)}
                                className={`device-toggle-btn ${deviceIdMatch ? 'match' : 'mismatch'}`}
                            >
                                {deviceIdMatch ? '● MATCH' : '✗ MISMATCH'}
                            </button>
                        </div>

                        <div className="tool-bar">
                            <button
                                className={`btn ${!sessionId ? 'btn-ghost' : 'btn-primary'}`}
                                onClick={requestAccess}
                                disabled={accessLoading || !sessionId}
                            >
                                {accessLoading ? '⏳ Scoring…' : '🤖 Score with AI'}
                            </button>
                            <button className="btn btn-ghost btn-secondary" onClick={resetTelemetry} title="Reset to baseline">
                                ↺ Reset
                            </button>
                        </div>
                        {!sessionId && (
                            <p style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '0.5rem', textAlign: 'center' }}>
                                Authenticate first to enable scoring
                            </p>
                        )}
                    </div>

                    {/* Live pipeline preview */}
                    <div className="card">
                        <div className="card-title">📡 Live Feature Vector</div>
                        <p style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginBottom: '0.85rem' }}>
                            Exact values the Isolation Forest will receive
                        </p>
                        {features.map(({ label, value, unit, norm }) => {
                            const tier = norm > 0.75 ? 'hi' : norm > 0.4 ? 'mi' : 'lo';
                            return (
                                <div key={label} className="fv-row">
                                    <div className="fv-head">
                                        <span>{label}</span>
                                        <span className={`fv-value ${tier}`}>{value} {unit}</span>
                                    </div>
                                    <div className="fv-track">
                                        <div className={`fv-fill ${tier}`} style={{ width: `${Math.min(norm * 100, 100)}%` }} />
                                    </div>
                                </div>
                            );
                        })}

                        {accessResult && accessResult.riskScore !== undefined ? (
                            <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border)', paddingTop: '1rem' }}>
                                <RiskGauge score={accessResult.riskScore} decision={accessResult.decision || 'PERMIT'} reasons={accessResult.reasons} />
                            </div>
                        ) : (
                            <div style={{ marginTop: '1.25rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                                Score will appear here after AI evaluation
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    const renderSecurity = () => (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">Security Center</h1>
                <p className="page-subtitle">Cryptographic controls and identity protection</p>
            </div>
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div className="card-title">Identity &amp; Keys</div>
                <div className="info-list">
                    <div className="info-row">
                        <span className="info-key">Private Key Storage</span>
                        <span className="badge badge-green">OS safeStorage (DPAPI/Keychain)</span>
                    </div>
                    <div className="info-row">
                        <span className="info-key">Key Size</span>
                        <span className="badge badge-blue">248-bit (BN128 safe)</span>
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
                    <div className="info-row">
                        <span className="info-key">AI HMAC Auth</span>
                        <span className="badge badge-green">HMAC-SHA256</span>
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
                    <div className="form-value">{process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443'}</div>
                </div>
                <div className="form-field">
                    <div className="form-label">Key Storage</div>
                    <div className="form-value">Electron safeStorage (OS-level encryption)</div>
                </div>
                <div className="form-field">
                    <div className="form-label">ZKP Circuit</div>
                    <div className="form-value">Groth16 — BN128 (snarkjs)</div>
                </div>
                <div className="form-field">
                    <div className="form-label">AI Model</div>
                    <div className="form-value">Isolation Forest (200 estimators, contamination=0.05)</div>
                </div>
            </div>
        </div>
    );

    const renderAbout = () => (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">About VeriChain AI</h1>
                <p className="page-subtitle">Zero-Trust Secure Software Design — Semester 6</p>
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
                    <div className="info-row"><span className="info-key">Auth</span><span className="badge badge-green">ZKP Groth16 + mTLS</span></div>
                    <div className="info-row"><span className="info-key">Risk Engine</span><span className="info-value">Isolation Forest (6 features)</span></div>
                    <div className="info-row"><span className="info-key">Contracts</span><span className="info-value">Solidity 0.8.20 / Hardhat</span></div>
                    <div className="info-row"><span className="info-key">Audit</span><span className="info-value">SHA-256 Merkle + On-Chain Anchor</span></div>
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
            {/* Toast Notifications */}
            <div className="toast-stack">
                {toasts.map(t => (
                    <div key={t.id} className={`toast ${t.type}`}>
                        {t.type === 'success' ? '✓' : t.type === 'error' ? '🛑' : t.type === 'warning' ? '⚠' : 'ℹ'} {t.message}
                    </div>
                ))}
            </div>

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
                            const locked = !sessionId && screen !== 'STATUS' && screen !== 'ABOUT' && screen !== 'SETTINGS';
                            return (
                                <div
                                    key={screen}
                                    className={`nav-item${currentScreen === screen ? ' active' : ''}${locked ? ' disabled' : ''}`}
                                    onClick={() => !locked && navigate(screen)}
                                    title={locked ? 'Authenticate first' : ''}
                                >
                                    <span className="nav-icon">{locked ? '🔒' : icon}</span>
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

                {accessResult?.decision === 'STEP_UP' && (
                    <div className="modal-overlay">
                        <div className="modal-card">
                            <div className="modal-icon warning">⚠</div>
                            <h2 className="modal-title">Step-Up Required</h2>
                            {accessResult.riskScore !== undefined && (
                                <div style={{ marginBottom: '0.75rem' }}>
                                    <RiskGauge score={accessResult.riskScore} decision="STEP_UP" reasons={accessResult.reasons} />
                                </div>
                            )}
                            <p className="modal-text">
                                {accessResult.reasonSummary
                                    ? <>The AI Risk Engine flagged <strong>{accessResult.reasons?.[0]?.label || 'behavioural anomaly'}</strong>. Re-authenticate to continue.</>
                                    : 'The AI Risk Engine detected elevated behavioural anomaly. Re-authenticate to continue.'}
                            </p>
                            <button className="btn btn-warning btn-full" onClick={() => { setAccessResult(null); navigate('AUTHENTICATION'); }}>
                                Re-Authenticate
                            </button>
                        </div>
                    </div>
                )}

                {accessResult?.decision === 'REVOKE' && (
                    <div className="modal-overlay">
                        <div className="modal-card">
                            <div className="modal-icon danger">🛑</div>
                            <h2 className="modal-title">Session Revoked</h2>
                            {accessResult.riskScore !== undefined && (
                                <div style={{ marginBottom: '0.75rem' }}>
                                    <RiskGauge score={accessResult.riskScore} decision="REVOKE" reasons={accessResult.reasons} />
                                </div>
                            )}
                            <p className="modal-text">
                                Critical anomaly detected by Isolation Forest{accessResult.reasons?.[0]?.label ? <> — primary cause: <strong>{accessResult.reasons[0].label}</strong></> : ''}.
                                Session has been revoked on-chain.
                            </p>
                            <button className="btn btn-danger btn-full" onClick={logout}>OK</button>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
};

export default App;
