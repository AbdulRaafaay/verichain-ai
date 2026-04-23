import React, { useState } from 'react';
import axios from 'axios';

const PolicyManager: React.FC = () => {
    const [userHash, setUserHash] = useState('');
    const [resourceHash, setResourceHash] = useState('');
    const [action, setAction] = useState('GRANT');
    const [pendingChanges, setPendingChanges] = useState<any[]>([]);

    const proposeChange = async () => {
        try {
            const gatewayUrl = process.env.REACT_APP_GATEWAY_URL || 'https://localhost:8443';
            const response = await axios.post(`${gatewayUrl}/admin/propose-policy`, {
                userHash,
                resourceHash,
                action
            }, { withCredentials: true });
            
            setPendingChanges(prev => [...prev, response.data]);
            alert('Policy change proposed successfully!');
        } catch (err) {
            console.error('Failed to propose policy change', err);
        }
    };

    return (
        <div className="page policy-manager">
            <h1>Policy Manager (Multi-Sig)</h1>
            
            <section className="propose-form">
                <h2>Propose New Policy</h2>
                <input 
                    placeholder="User Hash (0x...)" 
                    value={userHash} 
                    onChange={e => setUserHash(e.target.value)} 
                />
                <input 
                    placeholder="Resource Hash (0x...)" 
                    value={resourceHash} 
                    onChange={e => setResourceHash(e.target.value)} 
                />
                <select value={action} onChange={e => setAction(e.target.value)}>
                    <option value="GRANT">Grant Access</option>
                    <option value="REVOKE">Revoke Access</option>
                </select>
                <button onClick={proposeChange}>Propose Change</button>
            </section>

            <section className="pending-changes" style={{ marginTop: '2rem' }}>
                <h2>Pending Approvals (Threshold: 2/3)</h2>
                {pendingChanges.length === 0 ? <p>No pending policy changes.</p> : (
                    <ul>
                        {pendingChanges.map((change, i) => (
                            <li key={i}>
                                Propose: {change.action} for {change.userHash.substring(0, 8)}... 
                                | Approvals: {change.approvals}/3
                                <button style={{ marginLeft: '1rem' }}>Sign & Approve</button>
                            </li>
                        ))}
                    </ul>
                )}
            </section>
        </div>
    );
};

export default PolicyManager;
