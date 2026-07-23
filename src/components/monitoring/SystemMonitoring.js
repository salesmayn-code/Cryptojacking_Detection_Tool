import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
    AreaChart,
    Area,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';
import { metricsAPI, systemsAPI, alertsAPI } from '../../services/api';
import './Monitoring.css';

const SystemMonitoring = () => {
    const { systemId } = useParams();
    const [system, setSystem] = useState(null);
    const [metrics, setMetrics] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [systemId]);

    const fetchData = async () => {
        try {
            const systemRes = await systemsAPI.getById(systemId);
            setSystem(systemRes.data);

            const metricsRes = await metricsAPI.getBySystem(systemId, 50);
            const metricsData = metricsRes.data.metrics || [];
            const latestRaw = metricsData[metricsData.length - 1] || null;

            const transformedMetrics = metricsData.map((m, index) => {
                const prev = index > 0 ? metricsData[index - 1] : null;
                const sent = m.network?.bytes_sent || 0;
                const recv = m.network?.bytes_recv || 0;
                const prevSent = prev?.network?.bytes_sent ?? sent;
                const prevRecv = prev?.network?.bytes_recv ?? recv;
                const gpuBlock = m.gpu || {};
                const gpuUtil = Number.isFinite(gpuBlock.utilization_percent)
                    ? gpuBlock.utilization_percent
                    : (Number.isFinite(gpuBlock.engine_utilization_percent) ? gpuBlock.engine_utilization_percent : null);
                const gpuMemPct = Number.isFinite(gpuBlock.memory_used_percent)
                    ? gpuBlock.memory_used_percent
                    : (
                        Number.isFinite(gpuBlock.memory_used_mb) && Number.isFinite(gpuBlock.memory_total_mb) && gpuBlock.memory_total_mb > 0
                            ? (gpuBlock.memory_used_mb / gpuBlock.memory_total_mb) * 100
                            : null
                    );
                const gpuAvailable = gpuBlock?.available === false ? false : (gpuUtil !== null || gpuMemPct !== null);

                return {
                    time: new Date(m.timestamp).toLocaleTimeString(),
                    cpu: m.cpu?.cpu_percent || 0,
                    memory: m.memory?.memory_percent || 0,
                    networkSent: Math.max(0, (sent - prevSent) / 1024),
                    networkRecv: Math.max(0, (recv - prevRecv) / 1024),
                    gpuUtil: gpuUtil ?? 0,
                    gpuMem: gpuMemPct ?? 0,
                    gpuMemUsed: Number.isFinite(gpuBlock.memory_used_mb) ? gpuBlock.memory_used_mb : null,
                    gpuMemTotal: Number.isFinite(gpuBlock.memory_total_mb) ? gpuBlock.memory_total_mb : null,
                    gpuAvailable,
                };
            });

            setMetrics(transformedMetrics);

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
    const systemStatus = system?.status || 'offline';
    const lastGpuMetric = [...metrics].reverse().find((m) => m.gpuAvailable) || latestMetric;
    const gpuAvailable = !!lastGpuMetric.gpuAvailable;
    const gpuUtilLabel = gpuAvailable ? `${lastGpuMetric.gpuUtil?.toFixed(1)}%` : 'N/A';
    const gpuMemLabel = gpuAvailable && lastGpuMetric.gpuMemTotal
        ? `${lastGpuMetric.gpuMemUsed?.toFixed(0) || 0} / ${lastGpuMetric.gpuMemTotal?.toFixed(0)} MB`
        : 'N/A';
    const gpuMemPercent = gpuAvailable ? Math.min(100, lastGpuMetric.gpuMem || 0) : 0;
    const hasGpuData = metrics.some((m) => m.gpuAvailable);

    const tooltipStyle = {
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        borderRadius: '10px',
        color: 'var(--text-primary)',
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
        fontSize: '0.8125rem',
    };

    return (
        <div className="monitoring-container fade-in">
            {/* Header */}
            <div className="monitoring-header">
                <div>
                    <h1>{system?.system_name || systemId}</h1>
                    <div className="monitoring-header-meta">
                        <code>{systemId}</code>
                        <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>
                            {systemStatus}
                        </span>
                    </div>
                </div>
            </div>

            {/* Current Status */}
            <div className="status-cards">
                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">CPU Usage</span>
                        <span className="status-card-icon status-card-icon-blue">CPU</span>
                    </div>
                    <div className="status-card-value">{latestMetric.cpu?.toFixed(1)}%</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill cpu"
                            style={{ width: `${Math.min(100, latestMetric.cpu || 0)}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">Memory Usage</span>
                        <span className="status-card-icon status-card-icon-green">MEM</span>
                    </div>
                    <div className="status-card-value">{latestMetric.memory?.toFixed(1)}%</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill memory"
                            style={{ width: `${Math.min(100, latestMetric.memory || 0)}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">GPU Usage</span>
                        <span className="status-card-icon status-card-icon-purple">GPU</span>
                    </div>
                    <div className="status-card-value">{gpuUtilLabel}</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill gpu"
                            style={{ width: `${Math.min(100, lastGpuMetric.gpuUtil || 0)}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">GPU Memory</span>
                        <span className="status-card-icon status-card-icon-purple">VRAM</span>
                    </div>
                    <div className="status-card-value status-card-value-sm">{gpuMemLabel}</div>
                    <div className="status-card-bar">
                        <div
                            className="status-card-bar-fill gpu-memory"
                            style={{ width: `${gpuMemPercent}%` }}
                        ></div>
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">System Status</span>
                        <span className={`status-card-icon ${systemStatus === 'online' ? 'status-card-icon-green' : 'status-card-icon-muted'}`}>
                            {systemStatus === 'online' ? 'ON' : 'OFF'}
                        </span>
                    </div>
                    <div className="status-card-value">{systemStatus}</div>
                    <div className={`status-dot-large ${systemStatus}`}></div>
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
                                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Area type="monotone" dataKey="cpu" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#colorCpu)" />
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
                                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Area type="monotone" dataKey="memory" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorMemory)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* GPU Usage Chart */}
                <div className="chart-card">
                    <h3 className="chart-title">GPU Usage Over Time</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <AreaChart data={metrics}>
                            <defs>
                                <linearGradient id="colorGpu" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Area type="monotone" dataKey="gpuUtil" stroke="#a855f7" strokeWidth={2} fillOpacity={1} fill="url(#colorGpu)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* Network Chart */}
                <div className="chart-card chart-card-full">
                    <h3 className="chart-title">Network Traffic (KB per Interval)</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <LineChart data={metrics}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} />
                            <YAxis stroke="var(--text-muted)" fontSize={11} />
                            <Tooltip contentStyle={tooltipStyle} />
                            <Legend />
                            <Line type="monotone" dataKey="networkSent" stroke="#f59e0b" strokeWidth={2} dot={false} name="Sent" />
                            <Line type="monotone" dataKey="networkRecv" stroke="#8b5cf6" strokeWidth={2} dot={false} name="Received" />
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
