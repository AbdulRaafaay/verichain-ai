import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import Overview      from './pages/Overview';
import Sessions      from './pages/Sessions';
import AuditLogs     from './pages/AuditLogs';
import MerkleChain   from './pages/MerkleChain';
import PolicyManager from './pages/PolicyManager';
import Blockchain    from './pages/Blockchain';
import ThreatAlerts  from './pages/ThreatAlerts';
import './App.css';

const NAV = [
    { to: '/',          icon: '⬡', label: 'Overview'        },
    { to: '/sessions',  icon: '◎', label: 'Sessions'        },
    { to: '/logs',      icon: '≡', label: 'Audit Logs'      },
    { to: '/merkle',    icon: '🌳', label: 'Merkle Chain'    },
    { to: '/policies',  icon: '⊕', label: 'Policy Manager'  },
    { to: '/blockchain', icon: '⛓', label: 'Blockchain'      },
    { to: '/alerts',    icon: '⚡', label: 'Threat Alerts'   },
];

const App: React.FC = () => (
    <Router>
        <div className="dashboard-container">
            <nav className="sidebar">
                <div className="brand">
                    <div className="brand-inner">
                        <div className="brand-icon">🔐</div>
                        <div>
                            <div className="brand-name">VeriChain AI</div>
                            <div className="brand-tag">Trust Dashboard</div>
                        </div>
                    </div>
                </div>

                <div className="sidebar-nav-area">
                    <div className="nav-section">Monitor</div>
                    {NAV.map(({ to, icon, label }) => (
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
                </div>

                <div className="sidebar-status">
                    <div className="status-pill">
                        <div className="pulse-dot" />
                        <span>Gateway Connected</span>
                    </div>
                </div>
            </nav>

            <main>
                <Routes>
                    <Route path="/"           element={<Overview />}      />
                    <Route path="/sessions"   element={<Sessions />}      />
                    <Route path="/logs"       element={<AuditLogs />}     />
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
