import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
    LineChart,
    Line,
    AreaChart,
    Area,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';
import { metricsAPI, systemsAPI, alertsAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Monitoring.css';

const SystemMonitoring = () => {
    const { systemId } = useParams();
    const navigate = useNavigate();
    const { logout } = useAuth();
    const [system, setSystem] = useState(null);
    const [metrics, setMetrics] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [refreshInterval, setRefreshInterval] = useState(null);

    useEffect(() => {
        fetchData();

        // Auto-refresh every 5 seconds
        const interval = setInterval(fetchData, 5000);
        setRefreshInterval(interval);

        return () => {
            if (refreshInterval) clearInterval(refreshInterval);
        };
    }, [systemId]);

    const fetchData = async () => {
        try {
            // Fetch system details
            const systemRes = await systemsAPI.getById(systemId);
            setSystem(systemRes.data);

            // Fetch metrics
            const metricsRes = await metricsAPI.getBySystem(systemId, 50);
            const metricsData = metricsRes.data.metrics || [];

            // Transform metrics for charts
            const transformedMetrics = metricsData.map((m, index) => ({
                time: new Date(m.timestamp).toLocaleTimeString(),
                cpu: m.cpu?.cpu_percent || 0,
                memory: m.memory?.memory_percent || 0,
                networkSent: (m.network?.bytes_sent || 0) / 1024, // KB
                networkRecv: (m.network?.bytes_recv || 0) / 1024, // KB
            })).reverse();

            setMetrics(transformedMetrics);

            // Fetch alerts
            const alertsRes = await alertsAPI.getBySystem(systemId, 10);
            setAlerts(alertsRes.data.alerts || []);

            setLoading(false);
        } catch (error) {
            console.error('Error fetching monitoring data:', error);
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="monitoring-container">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
                </div>
            </div>
        );
    }

    const latestMetric = metrics[metrics.length - 1] || {};

    return (
        <div className="monitoring-container">
            {/* Header */}
            <div className="monitoring-header">
                <button onClick={() => navigate('/dashboard')} className="btn btn-secondary">
                    ← Back to Dashboard
                </button>
                <h1>{system?.system_name || systemId}</h1>
                <button onClick={logout} className="btn btn-secondary">
                    Logout
                </button>
            </div>

            {/* Current Status */}
            <div className="status-cards">
                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">CPU Usage</span>
                        <span className="status-card-icon">💻</span>
                    </div>
                    <div className="status-card-value">{latestMetric.cpu?.toFixed(1)}%</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill cpu"
                            style={{ width: `${latestMetric.cpu}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">Memory Usage</span>
                        <span className="status-card-icon">🧠</span>
                    </div>
                    <div className="status-card-value">{latestMetric.memory?.toFixed(1)}%</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill memory"
                            style={{ width: `${latestMetric.memory}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">Network (KB)</span>
                        <span className="status-card-icon">🌐</span>
                    </div>
                    <div className="status-card-value">
                        ↑ {latestMetric.networkSent?.toFixed(0)} / ↓ {latestMetric.networkRecv?.toFixed(0)}
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">System Status</span>
                        <span className="status-card-icon">
                            {system?.status === 'normal' || system?.status === 'online' ? '🟢' : '🔴'}
                        </span>
                    </div>
                    <div className="status-card-value">{system?.status || 'Unknown'}</div>
                </div>
            </div>

            {/* Charts */}
            <div className="charts-grid">
                {/* CPU Chart */}
                <div className="chart-card">
                    <h3 className="chart-title">CPU Usage Over Time</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <AreaChart data={metrics}>
                            <defs>
                                <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
                            <YAxis stroke="#94a3b8" fontSize={12} />
                            <Tooltip
                                contentStyle={{
                                    background: '#1e293b',
                                    border: '1px solid #334155',
                                    borderRadius: '8px',
                                    color: '#f1f5f9'
                                }}
                            />
                            <Area type="monotone" dataKey="cpu" stroke="#3b82f6" fillOpacity={1} fill="url(#colorCpu)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* Memory Chart */}
                <div className="chart-card">
                    <h3 className="chart-title">Memory Usage Over Time</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <AreaChart data={metrics}>
                            <defs>
                                <linearGradient id="colorMemory" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
                            <YAxis stroke="#94a3b8" fontSize={12} />
                            <Tooltip
                                contentStyle={{
                                    background: '#1e293b',
                                    border: '1px solid #334155',
                                    borderRadius: '8px',
                                    color: '#f1f5f9'
                                }}
                            />
                            <Area type="monotone" dataKey="memory" stroke="#10b981" fillOpacity={1} fill="url(#colorMemory)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* Network Chart */}
                <div className="chart-card chart-card-full">
                    <h3 className="chart-title">Network Traffic (KB)</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <LineChart data={metrics}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
                            <YAxis stroke="#94a3b8" fontSize={12} />
                            <Tooltip
                                contentStyle={{
                                    background: '#1e293b',
                                    border: '1px solid #334155',
                                    borderRadius: '8px',
                                    color: '#f1f5f9'
                                }}
                            />
                            <Legend />
                            <Line type="monotone" dataKey="networkSent" stroke="#f59e0b" name="Sent" />
                            <Line type="monotone" dataKey="networkRecv" stroke="#8b5cf6" name="Received" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Alerts Section */}
            <div className="monitoring-section">
                <h2 className="section-title">Recent Alerts for this System</h2>
                {alerts.length === 0 ? (
                    <div className="empty-state">
                        <p>No alerts for this system. Monitoring is active.</p>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Alert Type</th>
                                    <th>Confidence</th>
                                    <th>Status</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map((alert) => (
                                    <tr key={alert.alert_id}>
                                        <td>{new Date(alert.timestamp).toLocaleString()}</td>
                                        <td>{alert.alert_type}</td>
                                        <td>{(alert.confidence * 100).toFixed(1)}%</td>
                                        <td>
                                            <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td>
                                            {alert.suspicious_processes && alert.suspicious_processes.length > 0
                                                ? alert.suspicious_processes.join(', ')
                                                : 'N/A'}
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

export default SystemMonitoring;
