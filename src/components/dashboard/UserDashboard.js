import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { systemsAPI, alertsAPI, metricsAPI } from '../../services/api';
import './Dashboard.css';

const UserDashboard = () => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const [system, setSystem] = useState(null);
    const [alerts, setAlerts] = useState([]);
    const [latestMetrics, setLatestMetrics] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchData();
        // Auto-refresh every 10 seconds
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            setLoading(true);

            // Fetch user's system
            const systemsRes = await systemsAPI.getAll(user?.email);
            const userSystem = systemsRes.data.systems?.[0];
            setSystem(userSystem);

            if (userSystem) {
                // Fetch alerts for this system
                const alertsRes = await alertsAPI.getBySystem(userSystem.system_id, 5);
                setAlerts(alertsRes.data.alerts || []);

                // Try to get latest metrics
                try {
                    const metricsRes = await metricsAPI.getLatest(userSystem.system_id);
                    setLatestMetrics(metricsRes.data);
                } catch (error) {
                    // No metrics yet, that's okay
                    setLatestMetrics(null);
                }
            }

            setLoading(false);
        } catch (error) {
            console.error('Error fetching data:', error);
            setLoading(false);
        }
    };

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
        <div className="dashboard-container">
            {/* Navigation */}
            <nav className="dashboard-nav">
                <div className="nav-brand">
                    <div className="brand-logo">🛡️</div>
                    <div>
                        <h2 className="brand-title">CRYPTOJACKING DETECTOR</h2>
                        <p className="brand-subtitle">Personal Monitoring System</p>
                    </div>
                </div>
                <div className="nav-user">
                    <span className="user-name">{user?.full_name}</span>
                    <span className="badge badge-success">User</span>
                    <button onClick={logout} className="btn btn-secondary btn-sm">
                        Logout
                    </button>
                </div>
            </nav>

            {/* System Status Hero */}
            <div className="hero-section">
                <div className="hero-content">
                    <h1 className="hero-title">Your System Status</h1>
                    {system ? (
                        <>
                            <div className="system-name-large">{system.system_name}</div>
                            <code className="system-id-large">{system.system_id}</code>
                            <div className={`status-indicator status-${systemStatus}`}>
                                <span className="status-dot"></span>
                                <span className="status-text">{systemStatus.toUpperCase()}</span>
                            </div>
                        </>
                    ) : (
                        <div className="no-system-message">
                            <p>⚠️ No system registered</p>
                            <p className="text-muted">Please contact your administrator</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Stats Overview */}
            <div className="dashboard-stats">
                <div className="stat-card clickable" onClick={() => navigate('/alerts')}>
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-content">
                        <div className={`stat-value ${activeAlerts > 0 ? 'danger' : ''}`}>
                            {activeAlerts}
                        </div>
                        <div className="stat-label">Active Alerts</div>
                    </div>
                    {activeAlerts > 0 && <div className="stat-pulse"></div>}
                </div>

                <div className="stat-card clickable" onClick={() => system && navigate(`/system/${system.system_id}`)}>
                    <div className="stat-icon">📊</div>
                    <div className="stat-content">
                        <div className="stat-value">
                            {latestMetrics ? `${latestMetrics.cpu?.cpu_percent?.toFixed(1)}%` : '--'}
                        </div>
                        <div className="stat-label">CPU Usage</div>
                    </div>
                </div>

                <div className="stat-card clickable" onClick={() => system && navigate(`/system/${system.system_id}`)}>
                    <div className="stat-icon">🧠</div>
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
                    📈 View Live Monitoring
                </button>
                <button
                    onClick={() => navigate('/alerts')}
                    className="btn btn-secondary"
                >
                    🚨 View All Alerts
                </button>
                <button
                    onClick={() => navigate('/reports')}
                    className="btn btn-secondary"
                >
                    📊 Generate Report
                </button>
            </div>

            {/* Recent Alerts */}
            <div className="dashboard-section">
                <div className="section-header">
                    <h2 className="section-title">Recent Alerts</h2>
                    <button onClick={() => navigate('/alerts')} className="btn btn-secondary btn-sm">
                        View All →
                    </button>
                </div>
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">✓</div>
                        <p className="empty-title">All Clear!</p>
                        <p className="empty-subtitle">No cryptojacking activity detected. Your system is being monitored 24/7.</p>
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
                                    {alert.alert_type === 'cryptojacking_detected' ? '🚨' : 'ℹ️'}
                                </div>
                                <div className="alert-content">
                                    <div className="alert-title">
                                        Cryptojacking Detected
                                    </div>
                                    <div className="alert-meta">
                                        {new Date(alert.timestamp).toLocaleString()} •
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
                            <span className={`status-badge status-${systemStatus}`}>{systemStatus}</span>
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
