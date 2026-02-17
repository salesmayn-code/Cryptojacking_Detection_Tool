import React from 'react';
import './Dashboard.css';

const SystemCard = ({ system, onClick }) => {
    const getStatusColor = (status) => {
        switch (status?.toLowerCase()) {
            case 'online':
            case 'normal':
                return 'status-normal';
            case 'suspicious':
                return 'status-suspicious';
            case 'alert':
            case 'offline':
                return 'status-alert';
            default:
                return 'status-muted';
        }
    };

    const getStatusIcon = (status) => {
        switch (status?.toLowerCase()) {
            case 'online':
            case 'normal':
                return '🟢';
            case 'suspicious':
                return '🟡';
            case 'alert':
                return '🔴';
            case 'offline':
                return '⚫';
            default:
                return '⚪';
        }
    };

    return (
        <div className="system-card" onClick={() => onClick(system)}>
            <div className="system-card-header">
                <div>
                    <h3 className="system-name">{system.system_name}</h3>
                    <p className="system-id">{system.system_id}</p>
                </div>
                <div className={`system-status ${getStatusColor(system.status)}`}>
                    <span className="status-icon">{getStatusIcon(system.status)}</span>
                    <span className="status-text">{system.status || 'Unknown'}</span>
                </div>
            </div>

            {system.system_description && (
                <p className="system-description">{system.system_description}</p>
            )}

            <div className="system-footer">
                <div className="system-meta">
                    <span className="meta-label">Owner:</span>
                    <span className="meta-value">{system.owner_email}</span>
                </div>
                {system.last_seen && (
                    <div className="system-meta">
                        <span className="meta-label">Last Seen:</span>
                        <span className="meta-value">
                            {new Date(system.last_seen).toLocaleString()}
                        </span>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SystemCard;
