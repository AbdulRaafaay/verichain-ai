import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import Overview      from './pages/Overview';
import Sessions      from './pages/Sessions';
import AuditLogs     from './pages/AuditLogs';
import MerkleChain   from './pages/MerkleChain';
import PolicyManager from './pages/PolicyManager';
import Blockchain    from './pages/Blockchain';
import ThreatAlerts  from './pages/ThreatAlerts';
import Analytics     from './pages/Analytics';
import TopBar        from './components/TopBar';
import './App.css';

const NAV_PRIMARY = [
    { to: '/',          icon: '⬡', label: 'Overview'      },
    { to: '/sessions',  icon: '◎', label: 'Sessions'      },
    { to: '/logs',      icon: '≡', label: 'Audit Logs'    },
    { to: '/analytics', icon: '⌁', label: 'Analytics'     },
];

const NAV_CHAIN = [
    { to: '/blockchain', icon: '⛓', label: 'Blockchain'    },
    { to: '/merkle',     icon: '🌳', label: 'Merkle Chain' },
    { to: '/policies',   icon: '⊕', label: 'Policy Engine'},
];

const NAV_SECURITY = [
    { to: '/alerts',  icon: '⚡', label: 'Threat Alerts' },
];

const NavSection: React.FC<{ title: string; items: typeof NAV_PRIMARY }> = ({ title, items }) => (
    <>
        <div className="nav-section">{title}</div>
        {items.map(({ to, icon, label }) => (
            <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
                <span className="nav-icon">{icon}</span>
                {label}
            </NavLink>
        ))}
    </>
);

const App: React.FC = () => (
    <Router>
        <div className="dashboard-container">
            <nav className="sidebar">
                <div className="brand">
                    <div className="brand-inner">
                        <div className="brand-icon">🔐</div>
                        <div>
                            <div className="brand-name">VeriChain AI</div>
                            <div className="brand-tag">Trust Console</div>
                        </div>
                    </div>
                </div>

                <div className="sidebar-nav-area">
                    <NavSection title="Monitoring"   items={NAV_PRIMARY}  />
                    <NavSection title="Chain & Policy" items={NAV_CHAIN}  />
                    <NavSection title="Security"     items={NAV_SECURITY} />
                </div>

                <div className="sidebar-status">
                    <div className="status-pill">
                        <div className="pulse-dot" />
                        <span>Gateway Online</span>
                    </div>
                </div>
            </nav>

            <main>
                <TopBar />
                <Routes>
                    <Route path="/"           element={<Overview />}      />
                    <Route path="/sessions"   element={<Sessions />}      />
                    <Route path="/logs"       element={<AuditLogs />}     />
                    <Route path="/analytics"  element={<Analytics />}     />
                    <Route path="/merkle"     element={<MerkleChain />}   />
                    <Route path="/policies"   element={<PolicyManager />} />
                    <Route path="/blockchain" element={<Blockchain />}    />
                    <Route path="/alerts"     element={<ThreatAlerts />}  />
                </Routes>
            </main>
        </div>
    </Router>
);

export default App;
