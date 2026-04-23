import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const data = [
    { name: '10:00', risk: 10, auths: 5 },
    { name: '11:00', risk: 15, auths: 8 },
    { name: '12:00', risk: 45, auths: 12 },
    { name: '13:00', risk: 20, auths: 7 },
    { name: '14:00', risk: 30, auths: 9 },
];

const Analytics: React.FC = () => {
    return (
        <div className="page analytics">
            <h1>Security Analytics</h1>
            
            <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginTop: '2rem' }}>
                <div style={{ background: '#111d35', padding: '1.5rem', borderRadius: '12px' }}>
                    <h3>Avg Risk Score Trend (24h)</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <LineChart data={data}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e3060" />
                            <XAxis dataKey="name" stroke="#8fa3c8" />
                            <YAxis stroke="#8fa3c8" />
                            <Tooltip contentStyle={{ backgroundColor: '#111d35', border: '1px solid #1e3060' }} />
                            <Line type="monotone" dataKey="risk" stroke="#3b82f6" strokeWidth={2} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                <div style={{ background: '#111d35', padding: '1.5rem', borderRadius: '12px' }}>
                    <h3>Authentication Volume</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={data}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e3060" />
                            <XAxis dataKey="name" stroke="#8fa3c8" />
                            <YAxis stroke="#8fa3c8" />
                            <Tooltip contentStyle={{ backgroundColor: '#111d35', border: '1px solid #1e3060' }} />
                            <Bar dataKey="auths" fill="#10b981" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </section>
        </div>
    );
};

export default Analytics;
