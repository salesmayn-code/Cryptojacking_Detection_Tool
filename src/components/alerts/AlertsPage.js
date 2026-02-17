import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { alertsAPI } from '../../services/api';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import './Alerts.css';

const AlertsPage = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();
    const [alerts, setAlerts] = useState([]);
    const [filteredAlerts, setFilteredAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('all'); // all, unread, acknowledged
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchAlerts();
        // Auto-refresh every 10 seconds
        const interval = setInterval(fetchAlerts, 10000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        applyFilters();
    }, [alerts, filter, searchTerm]);

    const fetchAlerts = async () => {
        try {
            const [alertsRes, statsRes] = await Promise.all([
                alertsAPI.getAll({ limit: 100 }),
                alertsAPI.getStats()
            ]);

            setAlerts(alertsRes.data.alerts || []);
            setStats(statsRes.data);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching alerts:', error);
            setLoading(false);
        }
    };

    const applyFilters = () => {
        let filtered = [...alerts];

        // Apply status filter
        if (filter !== 'all') {
            filtered = filtered.filter(alert => alert.status === filter);
        }

        // Apply search filter
        if (searchTerm) {
            filtered = filtered.filter(alert =>
                alert.system_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                alert.alert_type.toLowerCase().includes(searchTerm.toLowerCase())
            );
        }

        setFilteredAlerts(filtered);
    };

    const handleUpdateStatus = async (alertId, newStatus) => {
        try {
            await alertsAPI.update(alertId, { status: newStatus });
            fetchAlerts();
        } catch (error) {
            console.error('Error updating alert:', error);
        }
    };

    const getAlertIcon = (alertType) => {
        switch (alertType) {
            case 'cryptojacking_detected':
                return '🚨';
            case 'suspicious_activity':
                return '⚠️';
            default:
                return 'ℹ️';
        }
    };

    const getConfidenceColor = (confidence) => {
        if (confidence >= 0.8) return 'high';
        if (confidence >= 0.5) return 'medium';
        return 'low';
    };

    if (loading) {
        return (
            <div className="alerts-page">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
                </div>
            </div>
        );
    }

    // Prepare chart data
    const pieData = [
        { name: 'Unread', value: stats?.unread_alerts || 0, color: '#ef4444' },
        { name: 'Acknowledged', value: stats?.acknowledged_alerts || 0, color: '#10b981' },
    ];

    return (
        <div className="alerts-page">
            {/* Navigation */}
            <nav className="dashboard-nav">
                <div className="nav-brand">
                    <button onClick={() => navigate('/dashboard')} className="btn btn-secondary btn-sm">
                        ← Dashboard
                    </button>
                    <h2>🚨 Alert Management</h2>
                </div>
                <div className="nav-user">
                    <span className="user-name">{user?.full_name}</span>
                    <span className={`badge badge-${user?.role === 'admin' ? 'success' : 'warning'}`}>
                        {user?.role}
                    </span>
                    <button onClick={logout} className="btn btn-secondary btn-sm">
                        Logout
                    </button>
                </div>
            </nav>

            {/* Stats Overview */}
            <div className="alerts-stats">
                <div className="stat-card alert-stat">
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats?.total_alerts || 0}</div>
                        <div className="stat-label">Total Alerts</div>
                    </div>
                </div>

                <div className="stat-card alert-stat">
                    <div className="stat-icon">🔔</div>
                    <div className="stat-content">
                        <div className="stat-value danger">{stats?.unread_alerts || 0}</div>
                        <div className="stat-label">Unread</div>
                    </div>
                </div>

                <div className="stat-card alert-stat">
                    <div className="stat-icon">✅</div>
                    <div className="stat-content">
                        <div className="stat-value success">{stats?.acknowledged_alerts || 0}</div>
                        <div className="stat-label">Acknowledged</div>
                    </div>
                </div>

                {/* Alert Distribution Chart */}
                <div className="stat-card chart-stat">
                    <h3 className="chart-title">Alert Distribution</h3>
                    {pieData.some(d => d.value > 0) ? (
                        <ResponsiveContainer width="100%" height={150}>
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={40}
                                    outerRadius={60}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip />
                                <Legend />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="no-data">No alerts yet</div>
                    )}
                </div>
            </div>

            {/* Filters and Search */}
            <div className="alerts-controls">
                <div className="filter-buttons">
                    <button
                        className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >
                        All ({alerts.length})
                    </button>
                    <button
                        className={`filter-btn ${filter === 'unread' ? 'active' : ''}`}
                        onClick={() => setFilter('unread')}
                    >
                        Unread ({alerts.filter(a => a.status === 'unread').length})
                    </button>
                    <button
                        className={`filter-btn ${filter === 'acknowledged' ? 'active' : ''}`}
                        onClick={() => setFilter('acknowledged')}
                    >
                        Acknowledged ({alerts.filter(a => a.status === 'acknowledged').length})
                    </button>
                </div>

                <div className="search-box">
                    <input
                        type="text"
                        placeholder="Search by system ID or alert type..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="form-input search-input"
                    />
                    <span className="search-icon">🔍</span>
                </div>
            </div>

            {/* Alerts Table */}
            <div className="alerts-section">
                {filteredAlerts.length === 0 ? (
                    <div className="empty-state">
                        <p>
                            {searchTerm
                                ? 'No alerts matching your search criteria.'
                                : filter === 'all'
                                    ? 'No alerts yet. System is monitoring for cryptojacking activity.'
                                    : `No ${filter} alerts.`}
                        </p>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="table alerts-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>System</th>
                                    <th>Timestamp</th>
                                    <th>Confidence</th>
                                    <th>Suspicious Processes</th>
                                    <th>Metrics</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredAlerts.map((alert) => (
                                    <tr key={alert.alert_id} className={`alert-row ${alert.status}`}>
                                        <td>
                                            <div className="alert-type-cell">
                                                <span className="alert-type-icon">{getAlertIcon(alert.alert_type)}</span>
                                                <span>{alert.alert_type}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <code className="system-id-code">{alert.system_id}</code>
                                        </td>
                                        <td className="timestamp-cell">
                                            {new Date(alert.timestamp).toLocaleString()}
                                        </td>
                                        <td>
                                            <div className={`confidence-badge ${getConfidenceColor(alert.confidence)}`}>
                                                {(alert.confidence * 100).toFixed(1)}%
                                            </div>
                                        </td>
                                        <td className="processes-cell">
                                            {alert.suspicious_processes && alert.suspicious_processes.length > 0 ? (
                                                <div className="processes-list">
                                                    {alert.suspicious_processes.slice(0, 2).map((proc, i) => (
                                                        <code key={i} className="process-badge">{proc}</code>
                                                    ))}
                                                    {alert.suspicious_processes.length > 2 && (
                                                        <span className="more-badge">
                                                            +{alert.suspicious_processes.length - 2} more
                                                        </span>
                                                    )}
                                                </div>
                                            ) : (
                                                <span className="text-muted">—</span>
                                            )}
                                        </td>
                                        <td className="metrics-cell">
                                            {alert.metrics ? (
                                                <div className="metrics-preview">
                                                    <span>CPU: {alert.metrics.cpu_usage?.toFixed(1)}%</span>
                                                    <span>MEM: {alert.metrics.memory_usage?.toFixed(1)}%</span>
                                                </div>
                                            ) : (
                                                <span className="text-muted">—</span>
                                            )}
                                        </td>
                                        <td>
                                            <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td>
                                            <div className="alert-actions">
                                                {alert.status === 'unread' && (
                                                    <button
                                                        onClick={() => handleUpdateStatus(alert.alert_id, 'acknowledged')}
                                                        className="btn btn-sm btn-success"
                                                        title="Acknowledge"
                                                    >
                                                        ✓
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => navigate(`/system/${alert.system_id}`)}
                                                    className="btn btn-sm btn-primary"
                                                    title="View System"
                                                >
                                                    👁️
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AlertsPage;
