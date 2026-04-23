import React, { useState, useEffect } from 'react';

// Define the 8 screens
type Screen = 'WELCOME' | 'AUTHENTICATION' | 'DASHBOARD' | 'STATUS' | 'TELEMETRY' | 'SECURITY' | 'SETTINGS' | 'ABOUT';

const App: React.FC = () => {
    const [currentScreen, setCurrentScreen] = useState<Screen>('WELCOME');
    const [isEnrolled, setIsEnrolled] = useState(false);
    const [status, setStatus] = useState<any>(null);
    const [telemetry, setTelemetry] = useState<any>(null);

    useEffect(() => {
        // Fetch initial state from Electron
        (window as any).electron?.auth.isEnrolled().then(setIsEnrolled);
        (window as any).electron?.system.getStatus().then(setStatus);
        (window as any).electron?.system.getTelemetry().then(setTelemetry);
    }, []);

    const renderScreen = () => {
        switch (currentScreen) {
            case 'WELCOME':
                return (
                    <div className="screen welcome">
                        <h1>Welcome to VeriChain AI</h1>
                        <p>Zero-Knowledge Authentication. Your privacy. Our priority.</p>
                        <button onClick={() => setCurrentScreen('AUTHENTICATION')} className="btn-primary">
                            Login with Zero-Knowledge
                        </button>
                        <button onClick={() => setCurrentScreen('STATUS')} className="btn-secondary">
                            View System Status
                        </button>
                    </div>
                );
            case 'AUTHENTICATION':
                return (
                    <div className="screen authentication">
                        <h2>Zero-Knowledge Login</h2>
                        <div className="progress">
                            <p>1. Create Proof — [In Progress]</p>
                            <p>2. Verify Proof — [Pending]</p>
                            <p>3. Establish Session — [Pending]</p>
                        </div>
                        <button onClick={() => setCurrentScreen('DASHBOARD')}>Skip to Dashboard (Dev)</button>
                    </div>
                );
            case 'DASHBOARD':
                return (
                    <div className="screen dashboard">
                        <h2>Dashboard</h2>
                        <div className="card">
                            <h3>Risk Score: {telemetry?.riskScore || 0}/100</h3>
                            <p>Status: ACTIVE</p>
                        </div>
                        <div className="metrics">
                            <p>Velocity: {telemetry?.accessVelocity} files/min</p>
                            <p>Duration: {telemetry?.sessionDuration}</p>
                        </div>
                    </div>
                );
            case 'STATUS':
                return (
                    <div className="screen status">
                        <h2>System Status</h2>
                        <ul>
                            <li>Gateway: {status?.gateway}</li>
                            <li>mTLS: {status?.mtls}</li>
                            <li>ZKP: {status?.zkp}</li>
                        </ul>
                    </div>
                );
            case 'TELEMETRY':
                return (
                    <div className="screen telemetry">
                        <h2>Telemetry</h2>
                        <p>Access Velocity: {telemetry?.accessVelocity}</p>
                        <p>Device Match: {telemetry?.deviceIdMatch ? 'YES' : 'NO'}</p>
                    </div>
                );
            case 'SECURITY':
                return (
                    <div className="screen security">
                        <h2>Security Center</h2>
                        <p>Private Key Storage: Secure (Encrypted)</p>
                    </div>
                );
            case 'SETTINGS':
                return (
                    <div className="screen settings">
                        <h2>Settings</h2>
                        <p>Theme: Dark (Navy)</p>
                    </div>
                );
            case 'ABOUT':
                return (
                    <div className="screen about">
                        <h2>About VeriChain AI</h2>
                        <p>Version 1.0.0</p>
                    </div>
                );
            default:
                return null;
        }
    };

    return (
        <div className="app-container" style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#0a0f1e', color: '#e8edf5' }}>
            {currentScreen !== 'WELCOME' && currentScreen !== 'AUTHENTICATION' && (
                <nav className="sidebar" style={{ width: '220px', borderRight: '1px solid #1e3060', padding: '1rem' }}>
                    <div onClick={() => setCurrentScreen('DASHBOARD')}>Dashboard</div>
                    <div onClick={() => setCurrentScreen('STATUS')}>Status</div>
                    <div onClick={() => setCurrentScreen('TELEMETRY')}>Telemetry</div>
                    <div onClick={() => setCurrentScreen('SECURITY')}>Security</div>
                    <div onClick={() => setCurrentScreen('SETTINGS')}>Settings</div>
                    <div onClick={() => setCurrentScreen('ABOUT')}>About</div>
                    <div onClick={() => setCurrentScreen('WELCOME')} style={{ marginTop: '2rem' }}>Logout</div>
                </nav>
            )}
            <main style={{ flex: 1, padding: '2rem' }}>
                {renderScreen()}
            </main>
        </div>
    );
};

export default App;
