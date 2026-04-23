import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Overview from './pages/Overview';
import Sessions from './pages/Sessions';
import AuditLogs from './pages/AuditLogs';
import PolicyManager from './pages/PolicyManager';
import ThreatAlerts from './pages/ThreatAlerts';
import Analytics from './pages/Analytics';

import './App.css';

const App: React.FC = () => {
    return (
        <Router>
            <div className="dashboard-container" style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#0a0f1e', color: '#e8edf5' }}>
                <nav className="sidebar" style={{ width: '240px', borderRight: '1px solid #1e3060', padding: '1.5rem' }}>
                    <div className="brand" style={{ marginBottom: '2.5rem', fontWeight: 700, fontSize: '1.2rem', color: '#3b82f6' }}>
                        VeriChain AI
                    </div>
                    <ul style={{ listStyle: 'none', padding: 0 }}>
                        <li style={{ marginBottom: '1rem' }}><Link to="/" className="nav-link">Overview</Link></li>
                        <li style={{ marginBottom: '1rem' }}><Link to="/sessions" className="nav-link">Sessions</Link></li>
                        <li style={{ marginBottom: '1rem' }}><Link to="/logs" className="nav-link">Audit Logs</Link></li>
                        <li style={{ marginBottom: '1rem' }}><Link to="/policies" className="nav-link">Policy Manager</Link></li>
                        <li style={{ marginBottom: '1rem' }}><Link to="/alerts" className="nav-link">Threat Alerts</Link></li>
                        <li style={{ marginBottom: '1rem' }}><Link to="/analytics" className="nav-link">Analytics</Link></li>
                    </ul>
                </nav>

                <main style={{ flex: 1, padding: '2rem', overflowY: 'auto' }}>
                    <Routes>
                        <Route path="/" element={<Overview />} />
                        <Route path="/sessions" element={<Sessions />} />
                        <Route path="/logs" element={<AuditLogs />} />
                        <Route path="/policies" element={<PolicyManager />} />
                        <Route path="/alerts" element={<ThreatAlerts />} />
                        <Route path="/analytics" element={<Analytics />} />
                    </Routes>
                </main>
            </div>
        </Router>
    );
};

export default App;
