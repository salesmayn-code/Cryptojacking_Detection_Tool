import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { systemsAPI, alertsAPI, metricsAPI } from '../../services/api';
import './Dashboard.css';

const UserDashboard = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [system, setSystem] = useState(null);
    const [alerts, setAlerts] = useState([]);
    const [latestMetrics, setLatestMetrics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [lastUpdated, setLastUpdated] = useState(null);

    const fetchData = useCallback(async () => {
        try {
            setError('');
            const systemsRes = await systemsAPI.getAll(user?.email);
            const userSystem = systemsRes.data.systems?.[0];
            setSystem(userSystem);

            if (userSystem) {
                const alertsRes = await alertsAPI.getBySystem(userSystem.system_id, 5);
                setAlerts(alertsRes.data.alerts || []);

                try {
                    const metricsRes = await metricsAPI.getLatest(userSystem.system_id);
                    setLatestMetrics(metricsRes.data);
                } catch {
                    setLatestMetrics(null);
                }
            }

            setLastUpdated(new Date());
            setLoading(false);
        } catch (error) {
            console.error('Error fetching data:', error);
            setError('Could not refresh dashboard data. Please try again.');
            setLoading(false);
        }
    }, [user?.email]);

    useEffect(() => {
        if (!user?.email) return;
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [user?.email, fetchData]);

    if (loading) {
        return (
            <div className="dashboard-container">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
                </div>
            </div>
        );
    }

    const activeAlerts = alerts.filter(a => a.status === 'unread').length;
    const systemStatus = system?.status || 'offline';

    return (
        <div className="dashboard-container fade-in">
            {/* System Status Hero */}
            <div className="hero-section">
                <div className="hero-content">
                    <h1 className="hero-title">Your System Status</h1>
                    {system ? (
                        <>
                            <div className="system-name-large">{system.system_name}</div>
                            <code className="system-id-large">{system.system_id}</code>
                            <div className={`status-indicator status-${systemStatus}`}>
                                <span className={`status-dot ${systemStatus}`}></span>
                                <span className="status-text">{systemStatus.toUpperCase()}</span>
                            </div>
                        </>
                    ) : (
                        <div className="no-system-message">
                            <p>No system registered</p>
                            <p className="text-muted">Please contact your administrator</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Stats Overview */}
            <div className="dashboard-stats">
                <div className="stat-card clickable" onClick={() => navigate('/alerts')}>
                    <div className="stat-icon stat-icon-danger">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                            <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className={`stat-value ${activeAlerts > 0 ? 'danger' : ''}`}>
                            {activeAlerts}
                        </div>
                        <div className="stat-label">Active Alerts</div>
                    </div>
                    {activeAlerts > 0 && <div className="stat-pulse"></div>}
                </div>

                <div className="stat-card clickable" onClick={() => system && navigate(`/system/${system.system_id}`)}>
                    <div className="stat-icon stat-icon-blue">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
                            <rect x="9" y="9" width="6" height="6" />
                            <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
                            <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
                            <line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" />
                            <line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">
                            {latestMetrics ? `${latestMetrics.cpu?.cpu_percent?.toFixed(1)}%` : '--'}
                        </div>
                        <div className="stat-label">CPU Usage</div>
                    </div>
                </div>

                <div className="stat-card clickable" onClick={() => system && navigate(`/system/${system.system_id}`)}>
                    <div className="stat-icon stat-icon-green">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="22" y1="12" x2="2" y2="12" />
                            <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
                            <line x1="6" y1="16" x2="6.01" y2="16" />
                            <line x1="10" y1="16" x2="10.01" y2="16" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">
                            {latestMetrics ? `${latestMetrics.memory?.memory_percent?.toFixed(1)}%` : '--'}
                        </div>
                        <div className="stat-label">Memory Usage</div>
                    </div>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="dashboard-actions">
                <button
                    onClick={() => system && navigate(`/system/${system.system_id}`)}
                    className="btn btn-primary"
                    disabled={!system}
                >
                    View Live Metrics
                </button>
                <button onClick={() => navigate('/alerts')} className="btn btn-secondary">
                    View Alerts
                </button>
                <button onClick={() => navigate('/reports')} className="btn btn-secondary">
                    Reports
                </button>
                <button onClick={fetchData} className="btn btn-secondary">
                    Refresh
                </button>
            </div>

            {error && <div className="alert alert-danger">{error}</div>}
            {lastUpdated && <p className="text-muted">Last updated: {lastUpdated.toLocaleTimeString()}</p>}

            {/* Recent Alerts */}
            <div className="dashboard-section">
                <div className="section-header">
                    <h2 className="section-title">Recent Alerts</h2>
                    <button onClick={() => navigate('/alerts')} className="btn btn-secondary btn-sm">
                        View All
                    </button>
                </div>
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">OK</div>
                        <p className="empty-title">All Clear</p>
                        <p className="empty-subtitle">No cryptojacking activity detected. Your system is being monitored continuously.</p>
                    </div>
                ) : (
                    <div className="alerts-list">
                        {alerts.map((alert) => (
                            <div
                                key={alert.alert_id}
                                className={`alert-item ${alert.status === 'unread' ? 'unread' : ''}`}
                                onClick={() => navigate('/alerts')}
                            >
                                <div className="alert-icon">
                                    {alert.alert_type === 'cryptojacking_detected' ? 'CRIT' : 'INFO'}
                                </div>
                                <div className="alert-content">
                                    <div className="alert-title">
                                        Cryptojacking Detected
                                    </div>
                                    <div className="alert-meta">
                                        {new Date(alert.timestamp).toLocaleString()} |
                                        Confidence: {(alert.confidence * 100).toFixed(1)}%
                                    </div>
                                    {alert.suspicious_processes && alert.suspicious_processes.length > 0 && (
                                        <div className="alert-processes">
                                            {alert.suspicious_processes.slice(0, 3).map((proc, i) => (
                                                <code key={i} className="process-tag">{proc}</code>
                                            ))}
                                        </div>
                                    )}
                                </div>
                                <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                    {alert.status}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* System Info */}
            {system && (
                <div className="dashboard-section">
                    <h2 className="section-title">System Information</h2>
                    <div className="info-card">
                        <div className="info-row">
                            <span className="info-label">System Name:</span>
                            <span className="info-value">{system.system_name}</span>
                        </div>
                        <div className="info-row">
                            <span className="info-label">System ID:</span>
                            <code className="info-value">{system.system_id}</code>
                        </div>
                        {system.system_description && (
                            <div className="info-row">
                                <span className="info-label">Description:</span>
                                <span className="info-value">{system.system_description}</span>
                            </div>
                        )}
                        <div className="info-row">
                            <span className="info-label">Status:</span>
                            <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>{systemStatus}</span>
                        </div>
                        {system.last_seen && (
                            <div className="info-row">
                                <span className="info-label">Last Seen:</span>
                                <span className="info-value">{new Date(system.last_seen).toLocaleString()}</span>
                            </div>
                        )}
                        {system.device_info && (
                            <>
                                <div className="info-row">
                                    <span className="info-label">Operating System:</span>
                                    <span className="info-value">{system.device_info.system}</span>
                                </div>
                                <div className="info-row">
                                    <span className="info-label">Device Name:</span>
                                    <span className="info-value">{system.device_info.node}</span>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default UserDashboard;
