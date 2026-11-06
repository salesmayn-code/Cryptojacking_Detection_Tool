import React from 'react';
import './Dashboard.css';

const SystemCard = ({ system, onClick }) => {
    const status = system.status?.toLowerCase() || 'unknown';

    const getStatusBadge = (s) => {
        switch (s) {
            case 'online':
            case 'normal':
                return 'success';
            case 'suspicious':
                return 'warning';
            case 'alert':
            case 'offline':
                return 'danger';
            default:
                return 'warning';
        }
    };

    return (
        <div
            className="system-card"
            role="button"
            tabIndex={0}
            onClick={() => onClick(system)}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onClick(system)}
        >
            <div className="system-card-header">
                <div>
                    <h3 className="system-name">{system.system_name}</h3>
                    <code className="system-id">{system.system_id}</code>
                </div>
                <span className={`badge badge-${getStatusBadge(status)}`}>
                    <span className={`status-dot ${status === 'online' ? 'online' : 'offline'}`} style={{ width: 6, height: 6 }} />
                    {status}
                </span>
            </div>

            {system.system_description && (
                <p className="system-description">{system.system_description}</p>
            )}

            <div className="system-footer">
                <div className="system-meta">
                    <span className="meta-label">Owner</span>
                    <span className="meta-value">{system.owner_email}</span>
                </div>
                {system.last_seen && (
                    <div className="system-meta">
                        <span className="meta-label">Last Seen</span>
                        <span className="meta-value tabular-nums">
                            {new Date(system.last_seen).toLocaleString()}
                        </span>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SystemCard;
