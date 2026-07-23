import React, { useEffect, useRef, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, ReferenceLine } from 'recharts';

import { alertsAPI } from '../../services/api';
import './Alerts.css';

const AlertsPage = () => {
    const [alerts, setAlerts] = useState([]);
    const [filteredAlerts, setFilteredAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [toast, setToast] = useState(null);
    const [expandedAlertId, setExpandedAlertId] = useState(null);

    const prevUnreadCountRef = useRef(0);

    useEffect(() => {
        fetchAlerts();
        const interval = setInterval(fetchAlerts, 10000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        applyFilters();
    }, [alerts, filter, searchTerm]);

    useEffect(() => {
        if (!toast) return;
        const timer = setTimeout(() => setToast(null), 5000);
        return () => clearTimeout(timer);
    }, [toast]);

    const fetchAlerts = async () => {
        try {
            const [alertsRes, statsRes] = await Promise.all([
                alertsAPI.getAll({ limit: 100 }),
                alertsAPI.getStats(),
            ]);

            const nextAlerts = alertsRes.data.alerts || [];
            const unreadCount = nextAlerts.filter((a) => a.status === 'unread').length;
            if (unreadCount > prevUnreadCountRef.current && nextAlerts.length > 0) {
                const latestUnread = nextAlerts.find((a) => a.status === 'unread');
                if (latestUnread) {
                    const reasons = buildReasonChips(latestUnread).slice(0, 2).join(', ');
                    const confidencePct = (latestUnread.confidence * 100).toFixed(1);
                    setToast({
                        title: 'New security alert',
                        message: `${latestUnread.system_id} | ${confidencePct}% | ${reasons}`,
                    });
                }
            }
            prevUnreadCountRef.current = unreadCount;

            setAlerts(nextAlerts);
            setStats(statsRes.data);
        } catch (error) {
            console.error('Error fetching alerts:', error);
        } finally {
            setLoading(false);
        }
    };

    const applyFilters = () => {
        let filtered = [...alerts];

        if (filter !== 'all') {
            filtered = filtered.filter((alert) => alert.status === filter);
        }

        if (searchTerm) {
            filtered = filtered.filter(
                (alert) =>
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

    const handleWhitelist = async (alert) => {
        const context = alert.metrics?.process_context || [];
        const candidates = context.map((item) => item?.name).filter(Boolean);
        let processName = candidates[0] || alert.suspicious_processes?.[0] || '';

        if (candidates.length > 1) {
            const choice = window.prompt(
                `Whitelist which process?\n${candidates.join(', ')}`,
                processName
            );
            if (!choice) {
                return;
            }
            processName = choice.trim();
        }

        if (!processName) {
            setToast({
                title: 'Whitelist failed',
                message: 'No process name available to whitelist.',
            });
            return;
        }

        try {
            await alertsAPI.whitelist(alert.alert_id, {
                process_name: processName,
                scope: 'path_signature',
            });
            setToast({
                title: 'Whitelisted',
                message: `${processName} was added to allowlist rules.`,
            });
            fetchAlerts();
        } catch (error) {
            console.error('Error whitelisting process:', error);
            setToast({
                title: 'Whitelist failed',
                message: 'Unable to add allowlist rule. Check alert details.',
            });
        }
    };

    const getAlertLabel = (alertType) => {
        if (alertType === 'cryptojacking_detected') return 'Critical';
        if (alertType === 'suspicious_activity') return 'Warning';
        return 'Info';
    };

    const getConfidenceColor = (confidence) => {
        if (confidence >= 0.8) return 'high';
        if (confidence >= 0.5) return 'medium';
        return 'low';
    };

    const buildReasonChips = (alert) => {
        const metrics = alert.metrics || {};
        const summary = metrics.reason_summary;
        if (Array.isArray(summary) && summary.length) return summary;

        const chips = [];
        const policyHits = metrics.policy_hits || [];
        if (policyHits.some((h) => h?.decision === 'deny')) chips.push('Blacklisted process');
        if ((metrics.miner_network_hits || []).length) chips.push('Mining pool traffic');
        if ((metrics.threat_intel_hits || []).length) chips.push('Threat intel match');
        if ((metrics.static_evidence_hits || []).length) chips.push('Static indicators');
        if ((metrics.dynamic_evidence || {}).dynamic_score) chips.push('Behavioral anomaly');
        if ((alert.suspicious_processes || []).length) chips.push('Suspicious process');
        if ((metrics.miner_indicators || []).length) chips.push('Miner keywords');
        if (chips.length === 0) chips.push('Multiple risk signals');
        return chips;
    };

    const buildReasonDetails = (alert) => {
        const metrics = alert.metrics || {};
        const details = metrics.reason_details;
        if (Array.isArray(details) && details.length) return details;

        const fallback = [];
        const policyHits = metrics.policy_hits || [];
        const denyRules = policyHits
            .filter((h) => h?.decision === 'deny')
            .map((h) => h?.rule_id)
            .filter(Boolean)
            .slice(0, 4);
        if (denyRules.length) {
            fallback.push({ label: 'Blacklisted process', detail: `Rules: ${denyRules.join(', ')}` });
        }

        const networkHits = metrics.miner_network_hits || [];
        if (networkHits.length) {
            const names = networkHits.map((h) => h?.name).filter(Boolean).slice(0, 3);
            const ports = networkHits
                .flatMap((h) => (h?.detail?.remote_ports || []))
                .filter((p) => Number.isFinite(Number(p)))
                .slice(0, 4);
            fallback.push({
                label: 'Mining pool traffic',
                detail: `${ports.length ? `Ports: ${ports.join(', ')}` : ''}${ports.length && names.length ? ' | ' : ''}${names.length ? `Processes: ${names.join(', ')}` : ''}`,
            });
        }

        const intelHits = metrics.threat_intel_hits || [];
        if (intelHits.length) {
            const sources = intelHits.flatMap((h) => h?.sources || []).slice(0, 4);
            fallback.push({ label: 'Threat intel match', detail: sources.join(', ') || 'Known malicious hash' });
        }

        return fallback;
    };

    const normalizeNumber = (value) => {
        const num = Number(value);
        return Number.isFinite(num) ? num : null;
    };

    const handleDeleteAlert = async (alertId) => {
        const confirmed = window.confirm('Remove this alert? This cannot be undone.');
        if (!confirmed) return;

        try {
            await alertsAPI.remove(alertId);
            setToast({ title: 'Alert removed', message: `Alert ${alertId} deleted.` });
            fetchAlerts();
        } catch (error) {
            console.error('Error deleting alert:', error);
            setToast({ title: 'Delete failed', message: 'Unable to delete this alert.' });
        }
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

    const pieData = [
        { name: 'Unread', value: stats?.unread_alerts || 0, color: '#ef4444' },
        { name: 'Acknowledged', value: stats?.acknowledged_alerts || 0, color: '#10b981' },
    ];

    const tooltipStyle = {
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        borderRadius: '10px',
        color: 'var(--text-primary)',
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
        fontSize: '0.8125rem',
    };

    return (
        <div className="alerts-page fade-in">
            {toast && (
                <div className="toast">
                    <strong>{toast.title}</strong>
                    <span>{toast.message}</span>
                </div>
            )}

            <div className="alerts-stats">
                <div className="stat-card alert-stat">
                    <div className="stat-icon stat-icon-purple">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats?.total_alerts || 0}</div>
                        <div className="stat-label">Total Alerts</div>
                    </div>
                </div>

                <div className="stat-card alert-stat">
                    <div className="stat-icon stat-icon-danger">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value danger">{stats?.unread_alerts || 0}</div>
                        <div className="stat-label">Unread</div>
                    </div>
                </div>

                <div className="stat-card alert-stat">
                    <div className="stat-icon stat-icon-green">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value success">{stats?.acknowledged_alerts || 0}</div>
                        <div className="stat-label">Acknowledged</div>
                    </div>
                </div>

                <div className="stat-card chart-stat">
                    <h3 className="chart-title">Alert Distribution</h3>
                    {pieData.some((d) => d.value > 0) ? (
                        <div className="alert-distribution">
                            <div className="alert-distribution-chart">
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
                                        <Tooltip contentStyle={tooltipStyle} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                            <div className="alert-legend">
                                {pieData.map((entry) => (
                                    <div key={entry.name} className="alert-legend-item">
                                        <span className="alert-legend-dot" style={{ background: entry.color }}></span>
                                        <span>{entry.name}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div className="no-data">No alerts yet</div>
                    )}
                </div>
            </div>

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
                        Unread ({alerts.filter((a) => a.status === 'unread').length})
                    </button>
                    <button
                        className={`filter-btn ${filter === 'acknowledged' ? 'active' : ''}`}
                        onClick={() => setFilter('acknowledged')}
                    >
                        Acknowledged ({alerts.filter((a) => a.status === 'acknowledged').length})
                    </button>
                </div>

                <div className="search-box">
                    <input
                        type="text"
                        placeholder="Search by system ID or alert type"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="form-input search-input"
                    />
                </div>
            </div>

            <div className="alerts-section">
                {filteredAlerts.length === 0 ? (
                    <div className="empty-state">
                        <p>
                            {searchTerm
                                ? 'No alerts matching your search criteria.'
                                : filter === 'all'
                                    ? 'No alerts yet. Monitoring is active.'
                                    : `No ${filter} alerts.`}
                        </p>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="table alerts-table">
                            <thead>
                                <tr>
                                    <th>Level</th>
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
                                    <React.Fragment key={alert.alert_id}>
                                    <tr className={`alert-row ${alert.status} ${expandedAlertId === alert.alert_id ? 'expanded' : ''}`}
                                        onClick={() => setExpandedAlertId(expandedAlertId === alert.alert_id ? null : alert.alert_id)}
                                        style={{ cursor: 'pointer' }}
                                    >
                                        <td>
                                            <div className="alert-type-cell">
                                                <span className={`alert-level-badge level-${getAlertLabel(alert.alert_type).toLowerCase()}`}>
                                                    {getAlertLabel(alert.alert_type)}
                                                </span>
                                            </div>
                                        </td>
                                        <td>
                                            <code className="system-id-code">{alert.system_id}</code>
                                        </td>
                                        <td className="timestamp-cell">{new Date(alert.timestamp).toLocaleString()}</td>
                                        <td>
                                            <div className={`confidence-badge ${getConfidenceColor(alert.confidence)}`}>
                                                {(alert.confidence * 100).toFixed(1)}%
                                            </div>
                                        </td>
                                        <td className="processes-cell">
                                            {alert.suspicious_processes?.length ? (
                                                <div className="processes-list">
                                                    {alert.suspicious_processes.slice(0, 3).map((proc, index) => (
                                                        <span key={index} className="process-badge">{proc}</span>
                                                    ))}
                                                    {alert.suspicious_processes.length > 3 && (
                                                        <span className="more-badge">+{alert.suspicious_processes.length - 3}</span>
                                                    )}
                                                </div>
                                            ) : (
                                                <span className="text-muted">none</span>
                                            )}
                                        </td>
                                        <td className="metrics-cell">
                                            {alert.metrics ? (
                                                <div className="metrics-grid">
                                                    <div className="metric-item">
                                                        <span className="metric-label">CPU</span>
                                                        <span className="metric-value">
                                                            {(normalizeNumber(alert.metrics.cpu_usage) ?? 0).toFixed(1)}%
                                                        </span>
                                                    </div>
                                                    <div className="metric-item">
                                                        <span className="metric-label">Memory</span>
                                                        <span className="metric-value">
                                                            {(normalizeNumber(alert.metrics.memory_usage) ?? 0).toFixed(1)}%
                                                        </span>
                                                    </div>
                                                    <div className="metric-item">
                                                        <span className="metric-label">GPU</span>
                                                        <span className="metric-value">
                                                            {normalizeNumber(alert.metrics.gpu_utilization) !== null
                                                                ? `${normalizeNumber(alert.metrics.gpu_utilization).toFixed(1)}%`
                                                                : 'N/A'}
                                                        </span>
                                                    </div>
                                                    <div className="metric-item">
                                                        <span className="metric-label">VRAM</span>
                                                        <span className="metric-value">
                                                            {normalizeNumber(alert.metrics.gpu_memory_used_mb) !== null && normalizeNumber(alert.metrics.gpu_memory_total_mb) !== null
                                                                ? `${normalizeNumber(alert.metrics.gpu_memory_used_mb).toFixed(0)} / ${normalizeNumber(alert.metrics.gpu_memory_total_mb).toFixed(0)} MB`
                                                                : 'N/A'}
                                                        </span>
                                                    </div>
                                                </div>
                                            ) : (
                                                <span className="text-muted">none</span>
                                            )}
                                        </td>
                                        <td>
                                            <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td>
                                            <div className="alert-actions">
                                                {alert.status === 'unread' ? (
                                                    <>
                                                        <button
                                                            className="btn btn-sm btn-success"
                                                            onClick={(e) => { e.stopPropagation(); handleUpdateStatus(alert.alert_id, 'acknowledged'); }}
                                                        >
                                                            Acknowledge
                                                        </button>
                                                        <button
                                                            className="btn btn-sm btn-secondary"
                                                            onClick={(e) => { e.stopPropagation(); handleWhitelist(alert); }}
                                                        >
                                                            Whitelist
                                                        </button>
                                                        <button
                                                            className="btn btn-sm btn-danger"
                                                            onClick={(e) => { e.stopPropagation(); handleDeleteAlert(alert.alert_id); }}
                                                        >
                                                            Remove
                                                        </button>
                                                    </>
                                                ) : (
                                                    <>
                                                        <button className="btn btn-sm btn-secondary" disabled>
                                                            Reviewed
                                                        </button>
                                                        <button
                                                            className="btn btn-sm btn-danger"
                                                            onClick={(e) => { e.stopPropagation(); handleDeleteAlert(alert.alert_id); }}
                                                        >
                                                            Remove
                                                        </button>
                                                    </>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                    {expandedAlertId === alert.alert_id && (
                                        <tr className="shap-expansion-row">
                                            <td colSpan="8">
                                                <div className="shap-panel">
                                                    <div className="reason-panel">
                                                        <div className="reason-header">Detection reasons</div>
                                                        <div className="reason-chips">
                                                            {buildReasonChips(alert).map((reason, idx) => (
                                                                <span key={idx} className="reason-chip">{reason}</span>
                                                            ))}
                                                        </div>
                                                        {buildReasonDetails(alert).length > 0 && (
                                                            <div className="reason-details">
                                                                {buildReasonDetails(alert).map((item, idx) => (
                                                                    <div key={idx} className="reason-detail-row">
                                                                        <span className="reason-detail-label">{item.label}</span>
                                                                        <span className="reason-detail-text">{item.detail}</span>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                        {Array.isArray(alert.metrics?.process_context) && alert.metrics.process_context.length > 0 && (
                                                            <div className="reason-context">
                                                                <div className="reason-context-title">Process context</div>
                                                                <table>
                                                                    <thead>
                                                                        <tr>
                                                                            <th>Process</th>
                                                                            <th>Path</th>
                                                                            <th>Signature</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        {alert.metrics.process_context.slice(0, 4).map((proc, i) => (
                                                                            <tr key={i}>
                                                                                <td>{proc?.name || 'unknown'}</td>
                                                                                <td className="reason-path">{proc?.exe_path || 'N/A'}</td>
                                                                                <td className="reason-signature">{proc?.signature_status || 'unknown'}</td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <h4 className="shap-title">
                                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                            <circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><line x1="12" y1="17" x2="12.01" y2="17" />
                                                        </svg>
                                                        Why was this flagged?
                                                    </h4>
                                                    {alert.feature_importance && Object.keys(alert.feature_importance).length > 0 ? (() => {
                                                        const shapData = Object.entries(alert.feature_importance)
                                                            .map(([name, data]) => ({
                                                                name: name.replace(/_/g, ' '),
                                                                shap: data.shap,
                                                                value: data.value,
                                                                fill: data.shap >= 0 ? '#ef4444' : '#3b82f6',
                                                            }))
                                                            .sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap))
                                                            .slice(0, 8);

                                                        return (
                                                            <div className="shap-content">
                                                                <div className="shap-values-table">
                                                                    <table>
                                                                        <thead><tr><th>Feature</th><th>Value</th><th>SHAP Impact</th></tr></thead>
                                                                        <tbody>
                                                                            {shapData.map((f, i) => (
                                                                                <tr key={i}>
                                                                                    <td>{f.name}</td>
                                                                                    <td>{f.value}</td>
                                                                                    <td style={{ color: f.shap >= 0 ? '#ef4444' : '#3b82f6', fontWeight: 600 }}>{f.shap > 0 ? '+' : ''}{f.shap.toFixed(4)}</td>
                                                                                </tr>
                                                                            ))}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                            </div>
                                                        );
                                                    })() : (
                                                        <p className="shap-no-data">Feature importance data is not available for this alert. SHAP analysis requires the XGBoost ML model.</p>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                    </React.Fragment>
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
