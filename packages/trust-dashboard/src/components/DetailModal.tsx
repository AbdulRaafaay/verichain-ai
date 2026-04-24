import React from 'react';

interface DetailModalProps {
    isOpen: boolean;
    onClose: () => void;
    title: string;
    data: any;
}

const DetailModal: React.FC<DetailModalProps> = ({ isOpen, onClose, title, data }) => {
    if (!isOpen) return null;

    const renderValue = (val: any) => {
        if (typeof val === 'object' && val !== null) {
            return <pre style={{ fontSize: '0.8rem', margin: 0 }}>{JSON.stringify(val, null, 2)}</pre>;
        }
        return <span className="mono" style={{ wordBreak: 'break-all' }}>{String(val)}</span>;
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-card detail-modal" onClick={e => e.stopPropagation()} style={{ maxWidth: '600px', width: '90%' }}>
                <div className="modal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h2 className="modal-title" style={{ margin: 0 }}>{title}</h2>
                    <button className="btn-ghost" onClick={onClose} style={{ fontSize: '1.5rem', padding: '0 0.5rem' }}>&times;</button>
                </div>
                <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
                    <table className="detail-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <tbody>
                            {Object.entries(data).map(([key, value]) => (
                                <tr key={key} style={{ borderBottom: '1px solid var(--border)' }}>
                                    <td style={{ padding: '0.75rem 0', fontWeight: 600, width: '30%', verticalAlign: 'top' }}>{key}</td>
                                    <td style={{ padding: '0.75rem 0' }}>{renderValue(value)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <div className="modal-footer" style={{ marginTop: '1.5rem', textAlign: 'right' }}>
                    <button className="btn btn-primary" onClick={onClose}>Close</button>
                </div>
            </div>
        </div>
    );
};

export default DetailModal;
