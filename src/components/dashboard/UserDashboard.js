import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ReferenceLine,
    ResponsiveContainer,
} from 'recharts';
import { useAuth } from '../../context/AuthContext';
import { systemsAPI, alertsAPI, metricsAPI } from '../../services/api';
import TelemetryTooltip from '../common/TelemetryTooltip';
import './Dashboard.css';

const UserDashboard = () => {
    const { user } = useAuth();
    const navigate = useNavigate();
    const [system, setSystem] = useState(null);
    const [alerts, setAlerts] = useState([]);
    const [recentSeries, setRecentSeries] = useState([]);
    const [latestMetrics, setLatestMetrics] = useState(null);
    const [initialLoading, setInitialLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState('');
    const [lastUpdated, setLastUpdated] = useState(null);
    const [copiedId, setCopiedId] = useState(false);

    const hasAnimatedChartRef = useRef(false);

    const fetchData = useCallback(async ({ manual = false } = {}) => {
        if (manual) setRefreshing(true);
        try {
            setError('');
            const knownId = user?.system_id;

            let userSystem = null;
            let alertsList = [];
            let metricsRows = [];

            if (knownId) {
                const [systemsRes, alertsRes, metricsRes] = await Promise.all([
                    systemsAPI.getAll(user?.email),
                    alertsAPI.getBySystem(knownId, 5).catch(() => ({ data: { alerts: [] } })),
                    metricsAPI.getBySystem(knownId, 24).catch(() => ({ data: { metrics: [] } })),
                ]);
                userSystem =
                    systemsRes.data.systems?.find((s) => s.system_id === knownId) ||
                    systemsRes.data.systems?.[0] ||
                    null;
                alertsList = alertsRes.data.alerts || [];
                metricsRows = metricsRes.data.metrics || [];
            } else {
                const systemsRes = await systemsAPI.getAll(user?.email);
                userSystem = systemsRes.data.systems?.[0] || null;
                if (userSystem) {
                    const [alertsRes, metricsRes] = await Promise.all([
                        alertsAPI.getBySystem(userSystem.system_id, 5).catch(() => ({ data: { alerts: [] } })),
                        metricsAPI.getBySystem(userSystem.system_id, 24).catch(() => ({ data: { metrics: [] } })),
                    ]);
                    alertsList = alertsRes.data.alerts || [];
                    metricsRows = metricsRes.data.metrics || [];
                }
            }

            setSystem(userSystem);
            setAlerts(alertsList);

            if (metricsRows.length > 0) {
                setLatestMetrics(metricsRows[metricsRows.length - 1]);
                const mapped = metricsRows.map((m) => ({
                    time: new Date(m.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                    }),
                    cpu: Number((m.cpu?.cpu_percent || 0).toFixed(1)),
                    memory: Number((m.memory?.memory_percent || 0).toFixed(1)),
                }));
                setRecentSeries(mapped);
                if (!hasAnimatedChartRef.current) {
                    setTimeout(() => {
                        hasAnimatedChartRef.current = true;
                    }, 300);
                }
            } else {
                setLatestMetrics(null);
                setRecentSeries([]);
            }

            setLastUpdated(new Date());
        } catch (err) {
            console.error('Error fetching data:', err);
            setError('Could not refresh dashboard data. Please try again.');
        } finally {
            setInitialLoading(false);
            setRefreshing(false);
        }
    }, [user?.email, user?.system_id]);

    useEffect(() => {
        if (!user?.email) return undefined;
        fetchData();
        const interval = setInterval(() => fetchData(), 5000);
        return () => clearInterval(interval);
    }, [user?.email, fetchData]);

    const handleCopySystemId = async (sysId) => {
        if (!sysId) return;
        try {
            await navigator.clipboard.writeText(sysId);
            setCopiedId(true);
            setTimeout(() => setCopiedId(false), 1600);
        } catch {
            // Clipboard unavailable
        }
    };

    if (initialLoading) {
        return (
            <div className="dashboard-container" aria-busy="true" aria-label="Loading operations dashboard">
                <div className="skeleton-card" style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', width: '260px' }}>
                        <div className="skeleton skeleton-line tall" />
                        <div className="skeleton skeleton-line medium" />
                    </div>
                    <div className="skeleton" style={{ width: '280px', height: '36px', borderRadius: '8px' }} />
                </div>

                <div className="dashboard-stats">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line short" />
                            <div className="skeleton skeleton-line tall" />
                            <div className="skeleton" style={{ height: '5px', width: '100%' }} />
                        </div>
                    ))}
                </div>

                <div className="dashboard-main-grid">
                    <div className="skeleton-card">
                        <div className="skeleton skeleton-line medium" />
                        <div className="skeleton skeleton-chart" />
                    </div>
                    <div className="skeleton-card">
                        <div className="skeleton skeleton-line short" />
                        <div className="skeleton" style={{ height: '200px', width: '100%', borderRadius: '8px' }} />
                    </div>
                </div>
            </div>
        );
    }

    const activeAlerts = alerts.filter((a) => a.status === 'unread').length;
    const systemStatus = system?.status || 'offline';
    const cpuPct = latestMetrics?.cpu?.cpu_percent;
    const memPct = latestMetrics?.memory?.memory_percent;
    const gpuPct = latestMetrics?.gpu?.utilization_percent ?? latestMetrics?.gpu?.engine_utilization_percent;

    return (
        <div className="dashboard-container fade-in">
            {/* Endpoint Command Bar */}
            <section className="command-bar">
                <div className="command-bar-identity">
                    {system ? (
                        <>
                            <div className="command-bar-title-row">
                                <h1 className="command-bar-title">{system.system_name}</h1>
                                <span className={`status-indicator status-${systemStatus}`}>
                                    <span className={`status-dot ${systemStatus}`}></span>
                                    <span>{systemStatus.toUpperCase()}</span>
                                </span>
                            </div>
                            <div className="command-bar-meta">
                                <button
                                    type="button"
                                    className={`copy-chip ${copiedId ? 'copied' : ''}`}
                                    onClick={() => handleCopySystemId(system.system_id)}
                                    title="Copy System ID"
                                >
                                    <span>{system.system_id}</span>
                                    <span>{copiedId ? 'Copied' : 'Copy'}</span>
                                </button>
                                {system.last_seen && (
                                    <span className="command-bar-meta-item">
                                        Last check-in {new Date(system.last_seen).toLocaleTimeString()}
                                    </span>
                                )}
                                {lastUpdated && (
                                    <span className="command-bar-meta-item">
                                        · Synced {lastUpdated.toLocaleTimeString()}
                                    </span>
                                )}
                            </div>
                        </>
                    ) : (
                        <div>
                            <h1 className="command-bar-title">No Monitored Endpoint</h1>
                            <p className="text-muted" style={{ fontSize: '0.8125rem' }}>
                                Open Settings &amp; Agent to download and bind the Windows monitoring agent.
                            </p>
                        </div>
                    )}
                </div>

                <div className="command-bar-actions">
                    <button
                        type="button"
                        onClick={() => system && navigate(`/system/${system.system_id}`)}
                        className="btn btn-primary"
                        disabled={!system}
                    >
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                        </svg>
                        <span>Live Telemetry</span>
                    </button>
                    <button type="button" onClick={() => navigate('/alerts')} className="btn btn-secondary">
                        Security Alerts
                    </button>
                    <button type="button" onClick={() => navigate('/reports')} className="btn btn-secondary">
                        Reports
                    </button>
                    <button
                        type="button"
                        onClick={() => fetchData({ manual: true })}
                        className="btn btn-secondary"
                        disabled={refreshing}
                        title="Refresh telemetry"
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

            {/* 4-Metric Telemetry Strip */}
            <section className="dashboard-stats stagger-enter" aria-label="Telemetry summary">
                <div
                    className="stat-card clickable"
                    role="button"
                    tabIndex={0}
                    onClick={() => navigate('/alerts')}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/alerts')}
                >
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-danger" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                                <line x1="12" y1="9" x2="12" y2="13" />
                                <line x1="12" y1="17" x2="12.01" y2="17" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Active Alerts</div>
                            <div className={`stat-value tabular-nums ${activeAlerts > 0 ? 'danger' : ''}`}>
                                {activeAlerts}
                            </div>
                        </div>
                    </div>
                    <div className="meter-track">
                        <div
                            className={`meter-fill ${activeAlerts > 0 ? 'tone-danger' : 'tone-success'}`}
                            style={{ '--meter-scale': activeAlerts > 0 ? 1 : 0.12 }}
                        />
                    </div>
                    {activeAlerts > 0 && <div className="stat-pulse" aria-hidden="true"></div>}
                </div>

                <div
                    className="stat-card clickable"
                    role="button"
                    tabIndex={0}
                    onClick={() => system && navigate(`/system/${system.system_id}`)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && system && navigate(`/system/${system.system_id}`)}
                >
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-blue" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
                                <rect x="9" y="9" width="6" height="6" />
                                <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
                                <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">CPU Load</div>
                            <div className="stat-value tabular-nums">
                                {Number.isFinite(cpuPct) ? `${cpuPct.toFixed(1)}%` : '--'}
                            </div>
                        </div>
                    </div>
                    <div className="meter-track">
                        <div
                            className={`meter-fill ${Number.isFinite(cpuPct) && cpuPct >= 90 ? 'tone-danger' : 'tone-primary'}`}
                            style={{ '--meter-scale': Number.isFinite(cpuPct) ? Math.min(1, Math.max(0, cpuPct / 100)) : 0 }}
                        />
                    </div>
                </div>

                <div
                    className="stat-card clickable"
                    role="button"
                    tabIndex={0}
                    onClick={() => system && navigate(`/system/${system.system_id}`)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && system && navigate(`/system/${system.system_id}`)}
                >
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-green" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="2" y="6" width="20" height="12" rx="2" />
                                <line x1="6" y1="12" x2="6.01" y2="12" />
                                <line x1="10" y1="12" x2="10.01" y2="12" />
                                <line x1="14" y1="12" x2="14.01" y2="12" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Memory Allocation</div>
                            <div className="stat-value tabular-nums">
                                {Number.isFinite(memPct) ? `${memPct.toFixed(1)}%` : '--'}
                            </div>
                        </div>
                    </div>
                    <div className="meter-track">
                        <div
                            className="meter-fill tone-success"
                            style={{ '--meter-scale': Number.isFinite(memPct) ? Math.min(1, Math.max(0, memPct / 100)) : 0 }}
                        />
                    </div>
                </div>

                <div
                    className="stat-card clickable"
                    role="button"
                    tabIndex={0}
                    onClick={() => system && navigate(`/system/${system.system_id}`)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && system && navigate(`/system/${system.system_id}`)}
                >
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-cyan" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">GPU / Engine</div>
                            <div className="stat-value tabular-nums">
                                {Number.isFinite(gpuPct) ? `${gpuPct.toFixed(1)}%` : 'Protected'}
                            </div>
                        </div>
                    </div>
                    <div className="meter-track">
                        <div
                            className="meter-fill tone-info"
                            style={{ '--meter-scale': Number.isFinite(gpuPct) ? Math.min(1, Math.max(0, gpuPct / 100)) : 0.15 }}
                        />
                    </div>
                </div>
            </section>

            {/* Live Endpoint Telemetry Pulse Card */}
            {system && recentSeries.length > 1 && (
                <section className="dashboard-telemetry-card">
                    <div className="dashboard-telemetry-head">
                        <div>
                            <h2 className="section-title" style={{ marginBottom: '0.15rem' }}>Live Host Compute Trend</h2>
                            <p className="text-muted" style={{ fontSize: '0.75rem' }}>
                                Recent {recentSeries.length} telemetry intervals · CPU vs Memory (%)
                            </p>
                        </div>
                        <button
                            type="button"
                            className="btn btn-sm btn-secondary"
                            onClick={() => navigate(`/system/${system.system_id}`)}
                        >
                            Full 4-Channel Telemetry →
                        </button>
                    </div>
                    <ResponsiveContainer width="100%" height={190}>
                        <AreaChart data={recentSeries} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
                            <defs>
                                <linearGradient id="dashCpu" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="var(--primary-color)" stopOpacity={0.22} />
                                    <stop offset="95%" stopColor="var(--primary-color)" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="dashMem" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="var(--success-color)" stopOpacity={0.18} />
                                    <stop offset="95%" stopColor="var(--success-color)" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border-color)" strokeOpacity={0.7} />
                            <XAxis
                                dataKey="time"
                                stroke="var(--text-muted)"
                                fontSize={11}
                                tickLine={false}
                                axisLine={false}
                                minTickGap={38}
                                tickMargin={6}
                            />
                            <YAxis
                                stroke="var(--text-muted)"
                                fontSize={11}
                                domain={[0, 100]}
                                tickLine={false}
                                axisLine={false}
                                tickFormatter={(v) => `${v}%`}
                            />
                            <Tooltip content={<TelemetryTooltip defaultUnit="%" />} />
                            <ReferenceLine y={90} stroke="var(--danger-color)" strokeDasharray="4 4" strokeOpacity={0.5} />
                            <Area
                                type="monotone"
                                dataKey="cpu"
                                stroke="var(--primary-color)"
                                strokeWidth={2}
                                fillOpacity={1}
                                fill="url(#dashCpu)"
                                name="CPU Load"
                                isAnimationActive={!hasAnimatedChartRef.current}
                                animationDuration={240}
                                animationEasing="ease-out"
                            />
                            <Area
                                type="monotone"
                                dataKey="memory"
                                stroke="var(--success-color)"
                                strokeWidth={1.75}
                                fillOpacity={1}
                                fill="url(#dashMem)"
                                name="Memory"
                                isAnimationActive={!hasAnimatedChartRef.current}
                                animationDuration={240}
                                animationEasing="ease-out"
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                </section>
            )}

            {/* Operations Split Grid */}
            <div className="dashboard-main-grid">
                <section className="dashboard-section">
                    <div className="section-header">
                        <h2 className="section-title">Recent Security Incidents</h2>
                        <button type="button" onClick={() => navigate('/alerts')} className="btn btn-secondary btn-sm">
                            View All
                        </button>
                    </div>
                    {alerts.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-icon" aria-hidden="true">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <polyline points="8.5 12.5 10.8 14.8 15.5 9.8" />
                                </svg>
                            </div>
                            <p className="empty-title">No Cryptojacking Incidents Detected</p>
                            <p className="empty-subtitle">
                                Host behavioral metrics, network ports, and process hashes are within normal operating bounds.
                            </p>
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
                                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && navigate('/alerts')}
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
                                            {alert.alert_type === 'cryptojacking_detected'
                                                ? 'Cryptojacking Activity Detected'
                                                : 'Suspicious Endpoint Activity'}
                                        </div>
                                        <div className="alert-meta tabular-nums">
                                            {new Date(alert.timestamp).toLocaleString()} · Confidence {(alert.confidence * 100).toFixed(1)}%
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
                </section>

                {system && (
                    <section className="dashboard-section">
                        <div className="section-header">
                            <h2 className="section-title">Endpoint Specification</h2>
                            <button type="button" onClick={() => navigate('/profile')} className="btn btn-secondary btn-sm">
                                Configure
                            </button>
                        </div>
                        <div className="info-card">
                            <div className="info-row">
                                <span className="info-label">System Name</span>
                                <span className="info-value">{system.system_name}</span>
                            </div>
                            <div className="info-row">
                                <span className="info-label">System ID</span>
                                <code className="info-value">{system.system_id}</code>
                            </div>
                            <div className="info-row">
                                <span className="info-label">Telemetry State</span>
                                <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>
                                    {systemStatus}
                                </span>
                            </div>
                            {system.last_seen && (
                                <div className="info-row">
                                    <span className="info-label">Last Check-In</span>
                                    <span className="info-value tabular-nums">{new Date(system.last_seen).toLocaleString()}</span>
                                </div>
                            )}
                            {system.device_info && (
                                <>
                                    <div className="info-row">
                                        <span className="info-label">Platform</span>
                                        <span className="info-value">{system.device_info.system || 'Windows'}</span>
                                    </div>
                                    <div className="info-row">
                                        <span className="info-label">Hostname</span>
                                        <code className="info-value">{system.device_info.node || 'Unknown'}</code>
                                    </div>
                                </>
                            )}
                            <div className="info-row">
                                <span className="info-label">Sampling Cadence</span>
                                <span className="info-value tabular-nums">5s sample · 30s batch</span>
                            </div>
                        </div>
                    </section>
                )}
            </div>
        </div>
    );
};

export default UserDashboard;
