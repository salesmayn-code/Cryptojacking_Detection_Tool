import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { systemsAPI, alertsAPI } from '../../services/api';
import SystemCard from './SystemCard';
import './Dashboard.css';

const AdminDashboard = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [systems, setSystems] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [initialLoading, setInitialLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState('');
    const [lastUpdated, setLastUpdated] = useState(null);
    const [showAddSystem, setShowAddSystem] = useState(false);
    const [newSystem, setNewSystem] = useState({
        system_name: '',
        system_description: '',
        owner_email: user?.email || '',
    });

    const fetchData = useCallback(async ({ manual = false } = {}) => {
        if (manual) setRefreshing(true);
        try {
            setError('');
            const [systemsRes, statsRes, alertsRes] = await Promise.all([
                systemsAPI.getAll(),
                alertsAPI.getStats(),
                alertsAPI.getAll({ limit: 10 }),
            ]);

            setSystems(systemsRes.data.systems || []);
            setStats(statsRes.data);
            setAlerts(alertsRes.data.alerts || []);
            setLastUpdated(new Date());
        } catch (err) {
            console.error('Error fetching data:', err);
            setError('Could not refresh admin dashboard data.');
        } finally {
            setInitialLoading(false);
            setRefreshing(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        const interval = setInterval(() => fetchData(), 10000);
        return () => clearInterval(interval);
    }, [fetchData]);

    useEffect(() => {
        if (!showAddSystem) return undefined;
        const onKeyDown = (e) => {
            if (e.key === 'Escape' && !submitting) setShowAddSystem(false);
        };
        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, [showAddSystem, submitting]);

    const handleAddSystem = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        try {
            await systemsAPI.create(newSystem);
            setShowAddSystem(false);
            setNewSystem({
                system_name: '',
                system_description: '',
                owner_email: user?.email || '',
            });
            await fetchData();
        } catch (err) {
            console.error('Error adding system:', err);
            setError(err.response?.data?.detail || 'Failed to register endpoint.');
        } finally {
            setSubmitting(false);
        }
    };

    const handleSystemClick = (system) => {
        navigate(`/system/${system.system_id}`);
    };

    if (initialLoading) {
        return (
            <div className="dashboard-container" aria-busy="true" aria-label="Loading fleet operations">
                <div className="skeleton-card" style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', width: '240px' }}>
                        <div className="skeleton skeleton-line tall" />
                        <div className="skeleton skeleton-line short" />
                    </div>
                    <div className="skeleton" style={{ width: '260px', height: '36px', borderRadius: '8px' }} />
                </div>
                <div className="dashboard-stats">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line short" />
                            <div className="skeleton skeleton-line tall" />
                        </div>
                    ))}
                </div>
            </div>
        );
    }

    return (
        <div className="dashboard-container fade-in">
            <section className="command-bar">
                <div className="command-bar-identity">
                    <div className="command-bar-title-row">
                        <h1 className="command-bar-title">Fleet Security Operations</h1>
                        <span className="badge badge-success">{systems.length} Endpoints</span>
                    </div>
                    {lastUpdated && (
                        <div className="command-bar-meta">
                            <span className="command-bar-meta-item">Last synced {lastUpdated.toLocaleTimeString()}</span>
                        </div>
                    )}
                </div>

                <div className="command-bar-actions">
                    <button type="button" onClick={() => setShowAddSystem(true)} className="btn btn-primary">
                        Register Endpoint
                    </button>
                    <button type="button" onClick={() => navigate('/alerts')} className="btn btn-secondary">
                        Security Alerts
                    </button>
                    <button type="button" onClick={() => navigate('/reports')} className="btn btn-secondary">
                        Reports
                    </button>
                    <button type="button" onClick={() => navigate('/admin/audit-logs')} className="btn btn-secondary">
                        Audit Trail
                    </button>
                    <button
                        type="button"
                        onClick={() => fetchData({ manual: true })}
                        className="btn btn-secondary"
                        disabled={refreshing}
                    >
                        <svg
                            width="14"
                            height="14"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            className={refreshing ? 'spin-inline' : ''}
                            aria-hidden="true"
                        >
                            <polyline points="23 4 23 10 17 10" />
                            <polyline points="1 20 1 14 7 14" />
                            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                        </svg>
                        <span>Refresh</span>
                    </button>
                </div>
            </section>

            {error && <div className="alert alert-danger" role="alert">{error}</div>}

            <section className="dashboard-stats stagger-enter">
                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-blue" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Registered Endpoints</div>
                            <div className="stat-value tabular-nums">{systems.length}</div>
                        </div>
                    </div>
                </div>

                <div className="stat-card clickable" role="button" tabIndex={0} onClick={() => navigate('/alerts')} onKeyDown={(e) => e.key === 'Enter' && navigate('/alerts')}>
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-cyan" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Total Incidents</div>
                            <div className="stat-value tabular-nums">{stats?.total_alerts || 0}</div>
                        </div>
                    </div>
                </div>

                <div className="stat-card clickable" role="button" tabIndex={0} onClick={() => navigate('/alerts')} onKeyDown={(e) => e.key === 'Enter' && navigate('/alerts')}>
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-danger" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Unread Alerts</div>
                            <div className="stat-value danger tabular-nums">{stats?.unread_alerts || 0}</div>
                        </div>
                    </div>
                </div>

                <div className="stat-card clickable" role="button" tabIndex={0} onClick={() => navigate('/alerts')} onKeyDown={(e) => e.key === 'Enter' && navigate('/alerts')}>
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-green" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Acknowledged</div>
                            <div className="stat-value success tabular-nums">{stats?.acknowledged_alerts || 0}</div>
                        </div>
                    </div>
                </div>
            </section>

            {showAddSystem && (
                <div className="modal-overlay" onClick={() => !submitting && setShowAddSystem(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="add-system-title">
                        <div className="modal-header">
                            <h2 id="add-system-title">Register Monitored Endpoint</h2>
                            <button type="button" onClick={() => setShowAddSystem(false)} className="modal-close" disabled={submitting} aria-label="Close modal">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <line x1="18" y1="6" x2="6" y2="18" />
                                    <line x1="6" y1="6" x2="18" y2="18" />
                                </svg>
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
                                    placeholder="Lab Workstation 01"
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Description</label>
                                <textarea
                                    className="form-input"
                                    value={newSystem.system_description}
                                    onChange={(e) => setNewSystem({ ...newSystem, system_description: e.target.value })}
                                    placeholder="Department or hardware notes"
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
                                <button type="button" onClick={() => setShowAddSystem(false)} className="btn btn-secondary" disabled={submitting}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary" disabled={submitting}>
                                    {submitting ? 'Registering...' : 'Register System'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <div className="dashboard-section">
                <h2 className="section-title">Monitored Endpoints ({systems.length})</h2>
                {systems.length === 0 ? (
                    <div className="empty-state">
                        <p>No systems registered yet. Click &ldquo;Register Endpoint&rdquo; to add one.</p>
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

            <div className="dashboard-section">
                <div className="section-header">
                    <h2 className="section-title">Recent Fleet Alerts</h2>
                    <button type="button" onClick={() => navigate('/alerts')} className="btn btn-secondary btn-sm">
                        View All
                    </button>
                </div>
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <p>No alerts across monitored endpoints.</p>
                    </div>
                ) : (
                    <div className="alerts-list">
                        {alerts.map((alert) => (
                            <div
                                key={alert.alert_id}
                                className={`alert-item ${alert.status === 'unread' ? 'unread' : ''}`}
                                onClick={() => navigate('/alerts')}
                                role="button"
                                tabIndex={0}
                                onKeyDown={(e) => e.key === 'Enter' && navigate('/alerts')}
                            >
                                <div className="alert-icon" aria-hidden="true">
                                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                                        <line x1="12" y1="9" x2="12" y2="13" />
                                        <line x1="12" y1="17" x2="12.01" y2="17" />
                                    </svg>
                                </div>
                                <div className="alert-content">
                                    <div className="alert-title">
                                        {alert.alert_type.replace(/_/g, ' ')} — <code>{alert.system_id}</code>
                                    </div>
                                    <div className="alert-meta tabular-nums">
                                        {new Date(alert.timestamp).toLocaleString()} · Confidence {(alert.confidence * 100).toFixed(1)}%
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
