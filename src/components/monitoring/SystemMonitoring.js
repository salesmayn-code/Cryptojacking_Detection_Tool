import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
    AreaChart,
    Area,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ReferenceLine,
    ResponsiveContainer,
} from 'recharts';
import { metricsAPI, systemsAPI, alertsAPI } from '../../services/api';
import TelemetryTooltip from '../common/TelemetryTooltip';
import './Monitoring.css';

const WINDOW_OPTIONS = [25, 50, 100];

const getMeterTone = (pct, defaultTone) => {
    if (!Number.isFinite(pct)) return defaultTone;
    if (pct >= 90) return 'tone-danger';
    if (pct >= 75) return 'tone-warning';
    return defaultTone;
};

const computeStats = (items, key) => {
    if (!items.length) return { peak: 0, mean: 0 };
    let peak = 0;
    let sum = 0;
    for (let i = 0; i < items.length; i += 1) {
        const val = Number(items[i][key]) || 0;
        if (val > peak) peak = val;
        sum += val;
    }
    return { peak, mean: sum / items.length };
};

const SystemMonitoring = () => {
    const { systemId } = useParams();
    const navigate = useNavigate();

    const [system, setSystem] = useState(null);
    const [metrics, setMetrics] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [initialLoading, setInitialLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [livePolling, setLivePolling] = useState(true);
    const [sampleWindow, setSampleWindow] = useState(50);
    const [lastSynced, setLastSynced] = useState(null);
    const [error, setError] = useState('');
    const [copiedId, setCopiedId] = useState(false);

    const hasAnimatedChartsRef = useRef(false);

    const fetchData = useCallback(async ({ manual = false } = {}) => {
        if (manual) setRefreshing(true);
        try {
            const [systemRes, metricsRes, alertsRes] = await Promise.all([
                systemsAPI.getById(systemId),
                metricsAPI.getBySystem(systemId, sampleWindow),
                alertsAPI.getBySystem(systemId, 10),
            ]);

            setSystem(systemRes.data);
            const metricsData = metricsRes.data.metrics || [];

            const transformedMetrics = metricsData.map((m, index) => {
                const prev = index > 0 ? metricsData[index - 1] : null;
                const sent = m.network?.bytes_sent || 0;
                const recv = m.network?.bytes_recv || 0;
                const prevSent = prev?.network?.bytes_sent ?? sent;
                const prevRecv = prev?.network?.bytes_recv ?? recv;

                const currTs = new Date(m.timestamp).getTime();
                const prevTs = prev ? new Date(prev.timestamp).getTime() : currTs - 5000;
                const elapsedSec = Math.max(1, (currTs - prevTs) / 1000);

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
                    time: new Date(m.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                    }),
                    cpu: Number((m.cpu?.cpu_percent || 0).toFixed(1)),
                    memory: Number((m.memory?.memory_percent || 0).toFixed(1)),
                    networkSent: Number(Math.max(0, (sent - prevSent) / 1024 / elapsedSec).toFixed(2)),
                    networkRecv: Number(Math.max(0, (recv - prevRecv) / 1024 / elapsedSec).toFixed(2)),
                    gpuUtil: Number((gpuUtil ?? 0).toFixed(1)),
                    gpuMem: Number((gpuMemPct ?? 0).toFixed(1)),
                    gpuMemUsed: Number.isFinite(gpuBlock.memory_used_mb) ? gpuBlock.memory_used_mb : null,
                    gpuMemTotal: Number.isFinite(gpuBlock.memory_total_mb) ? gpuBlock.memory_total_mb : null,
                    gpuAvailable,
                };
            });

            setMetrics(transformedMetrics);
            setAlerts(alertsRes.data.alerts || []);
            setLastSynced(new Date());
            setError('');

            if (transformedMetrics.length > 0 && !hasAnimatedChartsRef.current) {
                setTimeout(() => {
                    hasAnimatedChartsRef.current = true;
                }, 320);
            }
        } catch (err) {
            console.error('Error fetching monitoring data:', err);
            setError('Unable to reach telemetry endpoint. Retrying automatically.');
        } finally {
            setInitialLoading(false);
            setRefreshing(false);
        }
    }, [systemId, sampleWindow]);

    useEffect(() => {
        fetchData();
        if (!livePolling) return undefined;
        const interval = setInterval(() => fetchData(), 5000);
        return () => clearInterval(interval);
    }, [fetchData, livePolling]);

    const handleCopyId = async () => {
        try {
            await navigator.clipboard.writeText(systemId);
            setCopiedId(true);
            setTimeout(() => setCopiedId(false), 1600);
        } catch {
            // Clipboard unavailable
        }
    };

    if (initialLoading) {
        return (
            <div className="monitoring-container" aria-busy="true" aria-label="Loading endpoint telemetry">
                <div className="monitoring-header">
                    <div className="monitoring-header-main">
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', minWidth: '240px' }}>
                            <div className="skeleton skeleton-line tall" />
                            <div className="skeleton skeleton-line short" />
                        </div>
                        <div className="skeleton" style={{ width: '220px', height: '34px', borderRadius: '8px' }} />
                    </div>
                </div>

                <div className="status-cards">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line short" />
                            <div className="skeleton skeleton-line tall" />
                            <div className="skeleton" style={{ height: '5px', width: '100%' }} />
                        </div>
                    ))}
                </div>

                <div className="charts-grid">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line medium" />
                            <div className="skeleton skeleton-chart" />
                        </div>
                    ))}
                </div>
            </div>
        );
    }

    const latestMetric = metrics[metrics.length - 1] || {};
    const systemStatus = system?.status || 'offline';
    const lastGpuMetric = [...metrics].reverse().find((m) => m.gpuAvailable) || latestMetric;
    const gpuAvailable = !!lastGpuMetric.gpuAvailable;
    const cpuNow = latestMetric.cpu ?? 0;
    const memNow = latestMetric.memory ?? 0;
    const gpuNow = gpuAvailable ? (lastGpuMetric.gpuUtil ?? 0) : 0;
    const gpuUtilLabel = gpuAvailable ? `${gpuNow.toFixed(1)}%` : 'N/A';
    const gpuMemLabel = gpuAvailable && lastGpuMetric.gpuMemTotal
        ? `${lastGpuMetric.gpuMemUsed?.toFixed(0) || 0} / ${lastGpuMetric.gpuMemTotal?.toFixed(0)} MB`
        : 'N/A';
    const gpuMemPercent = gpuAvailable ? Math.min(100, lastGpuMetric.gpuMem || 0) : 0;

    const cpuStats = computeStats(metrics, 'cpu');
    const memStats = computeStats(metrics, 'memory');
    const gpuStats = computeStats(metrics, 'gpuUtil');
    const netOutStats = computeStats(metrics, 'networkSent');
    const netInStats = computeStats(metrics, 'networkRecv');

    const animateMount = !hasAnimatedChartsRef.current;

    return (
        <div className="monitoring-container fade-in">
            {/* Header Toolbar */}
            <header className="monitoring-header">
                <div className="monitoring-header-main">
                    <div className="monitoring-identity">
                        <div className="monitoring-title-row">
                            <h1>{system?.system_name || systemId}</h1>
                            <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>
                                <span className={`status-dot ${systemStatus}`} style={{ width: 6, height: 6 }} />
                                {systemStatus}
                            </span>
                        </div>
                        <div className="monitoring-submeta tabular-nums">
                            <button
                                type="button"
                                className={`copy-chip ${copiedId ? 'copied' : ''}`}
                                onClick={handleCopyId}
                                title="Copy System ID"
                            >
                                <span>{systemId}</span>
                                <span>{copiedId ? 'Copied' : 'Copy'}</span>
                            </button>
                            <span className="monitoring-meta-sep" aria-hidden="true">·</span>
                            <span>{metrics.length} samples</span>
                            {lastSynced && (
                                <>
                                    <span className="monitoring-meta-sep" aria-hidden="true">·</span>
                                    <span>Synced {lastSynced.toLocaleTimeString()}</span>
                                </>
                            )}
                        </div>
                    </div>

                    <div className="monitoring-toolbar">
                        <div className="segmented-control" role="group" aria-label="Telemetry sample window">
                            {WINDOW_OPTIONS.map((win) => (
                                <button
                                    key={win}
                                    type="button"
                                    className={`segmented-btn ${sampleWindow === win ? 'active' : ''}`}
                                    onClick={() => setSampleWindow(win)}
                                >
                                    {win} pts
                                </button>
                            ))}
                        </div>

                        <button
                            type="button"
                            className={`btn btn-sm ${livePolling ? 'btn-secondary' : 'btn-primary'}`}
                            onClick={() => setLivePolling((prev) => !prev)}
                            title={livePolling ? 'Pause 5-second live polling' : 'Resume 5-second live polling'}
                        >
                            <span
                                className="status-dot"
                                style={{
                                    width: 6,
                                    height: 6,
                                    background: livePolling ? 'var(--success-color)' : 'currentColor',
                                }}
                            />
                            <span>{livePolling ? 'Live · 5s' : 'Paused'}</span>
                        </button>

                        <button
                            type="button"
                            className="btn btn-sm btn-secondary"
                            onClick={() => fetchData({ manual: true })}
                            disabled={refreshing}
                        >
                            <svg
                                width="13"
                                height="13"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="2.1"
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
                </div>
            </header>

            {error && <div className="alert alert-warning" role="alert">{error}</div>}

            {/* 4-Column Hardware Telemetry Strip */}
            <section className="status-cards stagger-enter" aria-label="Live hardware metrics">
                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">CPU Utilization</span>
                        <span className="status-card-icon status-card-icon-blue" aria-hidden="true">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="4" y="4" width="16" height="16" rx="2" />
                                <rect x="9" y="9" width="6" height="6" />
                                <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
                                <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
                            </svg>
                        </span>
                    </div>
                    <div className="status-card-value-row">
                        <span className="status-card-value">{cpuNow.toFixed(1)}%</span>
                        <span className="status-card-sub tabular-nums">Peak {cpuStats.peak.toFixed(1)}%</span>
                    </div>
                    <div className="meter-track" role="progressbar" aria-valuenow={Math.round(cpuNow)} aria-valuemin={0} aria-valuemax={100}>
                        <div
                            className={`meter-fill ${getMeterTone(cpuNow, 'tone-primary')}`}
                            style={{ '--meter-scale': Math.min(1, Math.max(0, cpuNow / 100)) }}
                        />
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">Memory Allocation</span>
                        <span className="status-card-icon status-card-icon-green" aria-hidden="true">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M6 19v-3" /><path d="M10 19v-3" /><path d="M14 19v-3" /><path d="M18 19v-3" />
                                <rect x="2" y="8" width="20" height="8" rx="2" />
                            </svg>
                        </span>
                    </div>
                    <div className="status-card-value-row">
                        <span className="status-card-value">{memNow.toFixed(1)}%</span>
                        <span className="status-card-sub tabular-nums">Mean {memStats.mean.toFixed(1)}%</span>
                    </div>
                    <div className="meter-track" role="progressbar" aria-valuenow={Math.round(memNow)} aria-valuemin={0} aria-valuemax={100}>
                        <div
                            className={`meter-fill ${getMeterTone(memNow, 'tone-success')}`}
                            style={{ '--meter-scale': Math.min(1, Math.max(0, memNow / 100)) }}
                        />
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">GPU Core Load</span>
                        <span className="status-card-icon status-card-icon-cyan" aria-hidden="true">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                            </svg>
                        </span>
                    </div>
                    <div className="status-card-value-row">
                        <span className="status-card-value">{gpuUtilLabel}</span>
                        <span className="status-card-sub tabular-nums">
                            {gpuAvailable ? `Peak ${gpuStats.peak.toFixed(1)}%` : 'No NVML/DXGI'}
                        </span>
                    </div>
                    <div className="meter-track">
                        <div
                            className={`meter-fill ${getMeterTone(gpuNow, 'tone-info')}`}
                            style={{ '--meter-scale': Math.min(1, Math.max(0, gpuNow / 100)) }}
                        />
                    </div>
                </div>

                <div className="status-card">
                    <div className="status-card-header">
                        <span className="status-card-title">GPU Memory (VRAM)</span>
                        <span className="status-card-icon status-card-icon-amber" aria-hidden="true">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="2" y="4" width="20" height="16" rx="2" />
                                <line x1="6" y1="8" x2="6" y2="16" />
                                <line x1="10" y1="8" x2="10" y2="16" />
                                <line x1="14" y1="8" x2="14" y2="16" />
                            </svg>
                        </span>
                    </div>
                    <div className="status-card-value-row">
                        <span className="status-card-value status-card-value-sm">{gpuMemLabel}</span>
                        <span className="status-card-sub tabular-nums">
                            {gpuAvailable ? `${gpuMemPercent.toFixed(0)}%` : 'Unreported'}
                        </span>
                    </div>
                    <div className="meter-track">
                        <div
                            className={`meter-fill ${getMeterTone(gpuMemPercent, 'tone-warning')}`}
                            style={{ '--meter-scale': Math.min(1, Math.max(0, gpuMemPercent / 100)) }}
                        />
                    </div>
                </div>
            </section>

            {/* Telemetry Charts or Empty State */}
            {metrics.length === 0 ? (
                <div className="empty-state monitoring-empty-telemetry">
                    <div className="empty-icon empty-icon-neutral" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                        </svg>
                    </div>
                    <p className="empty-title">Awaiting First Telemetry Batch</p>
                    <p className="empty-subtitle">
                        No samples have been ingested for <code>{systemId}</code> yet. Start monitoring in the CryptoDetect Windows tray agent to stream CPU, memory, GPU, and network metrics.
                    </p>
                    <div style={{ marginTop: '1rem' }}>
                        <button type="button" className="btn btn-primary btn-sm" onClick={() => navigate('/profile')}>
                            Open Agent Setup &amp; Credentials
                        </button>
                    </div>
                </div>
            ) : (
                <section className="charts-grid" aria-label="Historical telemetry charts">
                    {/* CPU Chart */}
                    <div className="chart-card">
                        <div className="chart-card-head">
                            <div>
                                <h3 className="chart-title">CPU Utilization</h3>
                                <p className="chart-subtitle">90% dashed line marks sustained-miner heuristic threshold</p>
                            </div>
                            <span className="chart-stat-pill tabular-nums">
                                Avg {cpuStats.mean.toFixed(1)}% · Peak {cpuStats.peak.toFixed(1)}%
                            </span>
                        </div>
                        <ResponsiveContainer width="100%" height={235}>
                            <AreaChart data={metrics} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="var(--primary-color)" stopOpacity={0.25} />
                                        <stop offset="95%" stopColor="var(--primary-color)" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border-color)" strokeOpacity={0.75} />
                                <XAxis
                                    dataKey="time"
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    minTickGap={34}
                                    tickMargin={8}
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
                                <ReferenceLine
                                    y={90}
                                    stroke="var(--danger-color)"
                                    strokeDasharray="4 4"
                                    strokeOpacity={0.65}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="cpu"
                                    stroke="var(--primary-color)"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#colorCpu)"
                                    name="CPU Load"
                                    isAnimationActive={animateMount}
                                    animationDuration={240}
                                    animationEasing="ease-out"
                                    activeDot={{ r: 4, strokeWidth: 0 }}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Memory Chart */}
                    <div className="chart-card">
                        <div className="chart-card-head">
                            <div>
                                <h3 className="chart-title">Memory Allocation</h3>
                                <p className="chart-subtitle">Physical working set &amp; resident page utilization</p>
                            </div>
                            <span className="chart-stat-pill tabular-nums">
                                Avg {memStats.mean.toFixed(1)}% · Peak {memStats.peak.toFixed(1)}%
                            </span>
                        </div>
                        <ResponsiveContainer width="100%" height={235}>
                            <AreaChart data={metrics} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorMemory" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="var(--success-color)" stopOpacity={0.25} />
                                        <stop offset="95%" stopColor="var(--success-color)" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border-color)" strokeOpacity={0.75} />
                                <XAxis
                                    dataKey="time"
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    minTickGap={34}
                                    tickMargin={8}
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
                                <Area
                                    type="monotone"
                                    dataKey="memory"
                                    stroke="var(--success-color)"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#colorMemory)"
                                    name="Memory"
                                    isAnimationActive={animateMount}
                                    animationDuration={240}
                                    animationEasing="ease-out"
                                    activeDot={{ r: 4, strokeWidth: 0 }}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>

                    {/* GPU Usage Chart */}
                    <div className="chart-card">
                        <div className="chart-card-head">
                            <div>
                                <h3 className="chart-title">GPU Compute Engine</h3>
                                <p className="chart-subtitle">NVML / Windows GPU Engine 3D &amp; compute load</p>
                            </div>
                            <span className="chart-stat-pill tabular-nums">
                                {gpuAvailable
                                    ? `Avg ${gpuStats.mean.toFixed(1)}% · Peak ${gpuStats.peak.toFixed(1)}%`
                                    : 'Adapter Unreported'}
                            </span>
                        </div>
                        <ResponsiveContainer width="100%" height={235}>
                            <AreaChart data={metrics} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorGpu" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="var(--info-color)" stopOpacity={0.25} />
                                        <stop offset="95%" stopColor="var(--info-color)" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border-color)" strokeOpacity={0.75} />
                                <XAxis
                                    dataKey="time"
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    minTickGap={34}
                                    tickMargin={8}
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
                                <ReferenceLine
                                    y={90}
                                    stroke="var(--danger-color)"
                                    strokeDasharray="4 4"
                                    strokeOpacity={0.5}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="gpuUtil"
                                    stroke="var(--info-color)"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#colorGpu)"
                                    name="GPU Engine"
                                    isAnimationActive={animateMount}
                                    animationDuration={240}
                                    animationEasing="ease-out"
                                    activeDot={{ r: 4, strokeWidth: 0 }}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Network Throughput Chart */}
                    <div className="chart-card">
                        <div className="chart-card-head">
                            <div>
                                <h3 className="chart-title">Network Throughput Rate</h3>
                                <p className="chart-subtitle">Socket I/O velocity (KB/s) across poll intervals</p>
                            </div>
                            <div className="chart-inline-legend tabular-nums">
                                <span className="chart-legend-chip">
                                    <span className="chart-legend-swatch" style={{ background: 'var(--warning-color)' }} />
                                    Tx {netOutStats.peak.toFixed(1)} KB/s
                                </span>
                                <span className="chart-legend-chip">
                                    <span className="chart-legend-swatch" style={{ background: 'var(--primary-color)' }} />
                                    Rx {netInStats.peak.toFixed(1)} KB/s
                                </span>
                            </div>
                        </div>
                        <ResponsiveContainer width="100%" height={235}>
                            <LineChart data={metrics} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--border-color)" strokeOpacity={0.75} />
                                <XAxis
                                    dataKey="time"
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    minTickGap={34}
                                    tickMargin={8}
                                />
                                <YAxis
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={(v) => `${v}`}
                                />
                                <Tooltip content={<TelemetryTooltip defaultUnit="KB/s" />} />
                                <Line
                                    type="monotone"
                                    dataKey="networkSent"
                                    stroke="var(--warning-color)"
                                    strokeWidth={2}
                                    dot={false}
                                    name="Outbound"
                                    isAnimationActive={animateMount}
                                    animationDuration={240}
                                    animationEasing="ease-out"
                                    activeDot={{ r: 4, strokeWidth: 0 }}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="networkRecv"
                                    stroke="var(--primary-color)"
                                    strokeWidth={2}
                                    dot={false}
                                    name="Inbound"
                                    isAnimationActive={animateMount}
                                    animationDuration={240}
                                    animationEasing="ease-out"
                                    activeDot={{ r: 4, strokeWidth: 0 }}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </section>
            )}

            {/* Alerts Section */}
            <section className="monitoring-section">
                <div className="section-header">
                    <h2 className="section-title">Recent Security Incidents for this Endpoint</h2>
                    <button type="button" className="btn btn-sm btn-secondary" onClick={() => navigate('/alerts')}>
                        Open Triage Queue
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
                        <p className="empty-title">No Alerts Recorded on This Endpoint</p>
                        <p className="empty-subtitle">Behavioral ML inference, mining-pool socket checks, and PE static entropy rules are nominal.</p>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Classification</th>
                                    <th>Confidence</th>
                                    <th>Status</th>
                                    <th>Flagged Processes</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map((alert) => (
                                    <tr key={alert.alert_id} onClick={() => navigate('/alerts')} style={{ cursor: 'pointer' }}>
                                        <td className="tabular-nums">{new Date(alert.timestamp).toLocaleString()}</td>
                                        <td className="capitalize">{alert.alert_type.replace(/_/g, ' ')}</td>
                                        <td className="tabular-nums" style={{ fontWeight: 600 }}>{(alert.confidence * 100).toFixed(1)}%</td>
                                        <td>
                                            <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td>
                                            {alert.suspicious_processes && alert.suspicious_processes.length > 0
                                                ? alert.suspicious_processes.map((proc, idx) => (
                                                    <code key={idx} style={{ marginRight: '0.3rem', fontSize: '0.75rem' }}>{proc}</code>
                                                ))
                                                : <span className="text-muted">None</span>}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
        </div>
    );
};

export default SystemMonitoring;
