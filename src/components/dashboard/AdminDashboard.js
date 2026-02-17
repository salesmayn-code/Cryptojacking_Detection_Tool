import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { systemsAPI, alertsAPI } from '../../services/api';
import SystemCard from './SystemCard';
import './Dashboard.css';

const AdminDashboard = () => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const [systems, setSystems] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showAddSystem, setShowAddSystem] = useState(false);
    const [newSystem, setNewSystem] = useState({
        system_name: '',
        system_description: '',
        owner_email: user?.email || '',
    });

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        try {
            setLoading(true);

            // Fetch all systems (admin can see all)
            const systemsRes = await systemsAPI.getAll();
            setSystems(systemsRes.data.systems || []);

            // Fetch alert statistics
            const statsRes = await alertsAPI.getStats();
            setStats(statsRes.data);

            // Fetch recent alerts
            const alertsRes = await alertsAPI.getAll({ limit: 10 });
            setAlerts(alertsRes.data.alerts || []);
        } catch (error) {
            console.error('Error fetching data:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleAddSystem = async (e) => {
        e.preventDefault();
        try {
            await systemsAPI.create(newSystem);
            setShowAddSystem(false);
            setNewSystem({
                system_name: '',
                system_description: '',
                owner_email: user?.email || '',
            });
            fetchData();
        } catch (error) {
            console.error('Error adding system:', error);
            alert('Failed to add system');
        }
    };

    const handleSystemClick = (system) => {
        navigate(`/system/${system.system_id}`);
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

    return (
        <div className="dashboard-container">
            {/* Navigation */}
            <nav className="dashboard-nav">
                <div className="nav-brand">
                    <h2>🔒 Cryptojacking Detector</h2>
                </div>
                <div className="nav-user">
                    <span className="user-name">{user?.full_name}</span>
                    <span className="badge badge-success">Admin</span>
                    <button onClick={logout} className="btn btn-secondary btn-sm">
                        Logout
                    </button>
                </div>
            </nav>

            {/* Stats Overview */}
            <div className="dashboard-stats">
                <div className="stat-card">
                    <div className="stat-icon">🖥️</div>
                    <div className="stat-content">
                        <div className="stat-value">{systems.length}</div>
                        <div className="stat-label">Total Systems</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats?.total_alerts || 0}</div>
                        <div className="stat-label">Total Alerts</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon">🔔</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats?.unread_alerts || 0}</div>
                        <div className="stat-label">Unread Alerts</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats?.acknowledged_alerts || 0}</div>
                        <div className="stat-label">Acknowledged</div>
                    </div>
                </div>
            </div>

            {/* Action Buttons */}
            <div className="dashboard-actions">
                <button
                    onClick={() => setShowAddSystem(true)}
                    className="btn btn-primary"
                >
                    ➕ Add New System
                </button>
                <button
                    onClick={() => navigate('/alerts')}
                    className="btn btn-secondary"
                >
                    📋 View All Alerts
                </button>
                <button
                    onClick={() => navigate('/reports')}
                    className="btn btn-secondary"
                >
                    📊 Generate Report
                </button>
            </div>

            {/* Add System Modal */}
            {showAddSystem && (
                <div className="modal-overlay" onClick={() => setShowAddSystem(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>Add New System</h2>
                            <button
                                onClick={() => setShowAddSystem(false)}
                                className="modal-close"
                            >
                                ✕
                            </button>
                        </div>
                        <form onSubmit={handleAddSystem}>
                            <div className="form-group">
                                <label className="form-label">System Name</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={newSystem.system_name}
                                    onChange={(e) => setNewSystem({ ...newSystem, system_name: e.target.value })}
                                    required
                                    placeholder="Lab Computer 01"
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Description</label>
                                <textarea
                                    className="form-input"
                                    value={newSystem.system_description}
                                    onChange={(e) => setNewSystem({ ...newSystem, system_description: e.target.value })}
                                    placeholder="Optional description"
                                    rows="3"
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Owner Email</label>
                                <input
                                    type="email"
                                    className="form-input"
                                    value={newSystem.owner_email}
                                    onChange={(e) => setNewSystem({ ...newSystem, owner_email: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="modal-actions">
                                <button type="button" onClick={() => setShowAddSystem(false)} className="btn btn-secondary">
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary">
                                    Add System
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Systems Grid */}
            <div className="dashboard-section">
                <h2 className="section-title">Monitored Systems</h2>
                {systems.length === 0 ? (
                    <div className="empty-state">
                        <p>No systems registered yet. Add your first system to start monitoring.</p>
                    </div>
                ) : (
                    <div className="systems-grid">
                        {systems.map((system) => (
                            <SystemCard
                                key={system.system_id}
                                system={system}
                                onClick={handleSystemClick}
                            />
                        ))}
                    </div>
                )}
            </div>

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
                        <p>No alerts yet. System is monitoring for cryptojacking activity.</p>
                    </div>
                ) : (
                    <div className="alerts-list">
                        {alerts.slice(0, 5).map((alert) => (
                            <div key={alert.alert_id} className="alert-item">
                                <div className="alert-icon">
                                    {alert.alert_type === 'cryptojacking_detected' ? '🚨' : 'ℹ️'}
                                </div>
                                <div className="alert-content">
                                    <div className="alert-title">
                                        Cryptojacking Detected - {alert.system_id}
                                    </div>
                                    <div className="alert-meta">
                                        {new Date(alert.timestamp).toLocaleString()} •
                                        Confidence: {(alert.confidence * 100).toFixed(1)}%
                                    </div>
                                </div>
                                <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                    {alert.status}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminDashboard;
