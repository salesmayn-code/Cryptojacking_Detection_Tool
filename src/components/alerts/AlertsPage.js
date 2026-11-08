import React, { useEffect, useRef, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

import { alertsAPI, systemsAPI } from '../../services/api';
import TelemetryTooltip from '../common/TelemetryTooltip';
import './Alerts.css';

const ACTION_LABELS = {
    suspend_process: 'Suspend Process',
    resume_process: 'Resume Process',
    kill_process_tree: 'Kill Process Tree',
    quarantine_binary: 'Quarantine Binary',
    block_ip: 'Block Pool IP',
    audit_persistence: 'Scan Persistence',
};

const DESTRUCTIVE_ACTIONS = new Set(['kill_process_tree', 'quarantine_binary', 'block_ip']);

const AlertsPage = () => {
    const [alerts, setAlerts] = useState([]);
    const [filteredAlerts, setFilteredAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [initialLoading, setInitialLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [filter, setFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [toast, setToast] = useState(null);
    const [expandedAlertId, setExpandedAlertId] = useState(null);
    const [confirmDeleteId, setConfirmDeleteId] = useState(null);
    const [whitelistModal, setWhitelistModal] = useState(null);
    const [actionStateByAlert, setActionStateByAlert] = useState({});
    const [selectedTargetByAlert, setSelectedTargetByAlert] = useState({});
    const [confirmContainment, setConfirmContainment] = useState(null);

    const prevUnreadCountRef = useRef(0);
    const hasAnimatedPieRef = useRef(false);

    useEffect(() => {
        fetchAlerts();
        const interval = setInterval(() => fetchAlerts(), 10000);
        return () => clearInterval(interval);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (!expandedAlertId) return undefined;
        fetchAlertActions(expandedAlertId);
        const pollTimer = setInterval(() => fetchAlertActions(expandedAlertId), 4000);
        return () => clearInterval(pollTimer);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [expandedAlertId]);

    useEffect(() => {
        applyFilters();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [alerts, filter, searchTerm]);

    useEffect(() => {
        if (!toast) return undefined;
        const timer = setTimeout(() => setToast(null), 4200);
        return () => clearTimeout(timer);
    }, [toast]);

    const fetchAlerts = async ({ manual = false } = {}) => {
        if (manual) setRefreshing(true);
        try {
            const [alertsRes, statsRes] = await Promise.all([
                alertsAPI.getAll({ limit: 100 }),
                alertsAPI.getStats(),
            ]);

            const nextAlerts = alertsRes.data.alerts || [];
            const unreadCount = nextAlerts.filter((a) => a.status === 'unread').length;
            if (!initialLoading && unreadCount > prevUnreadCountRef.current && nextAlerts.length > 0) {
                const latestUnread = nextAlerts.find((a) => a.status === 'unread');
                if (latestUnread) {
                    const reasons = buildReasonChips(latestUnread).slice(0, 2).join(', ');
                    const confidencePct = (latestUnread.confidence * 100).toFixed(1);
                    setToast({
                        title: 'New security incident detected',
                        message: `${latestUnread.system_id} · ${confidencePct}% · ${reasons}`,
                    });
                }
            }
            prevUnreadCountRef.current = unreadCount;

            setAlerts(nextAlerts);
            setStats(statsRes.data);
            if (!hasAnimatedPieRef.current) {
                setTimeout(() => {
                    hasAnimatedPieRef.current = true;
                }, 280);
            }
        } catch (error) {
            console.error('Error fetching alerts:', error);
        } finally {
            setInitialLoading(false);
            setRefreshing(false);
        }
    };

    const applyFilters = () => {
        let filtered = [...alerts];

        if (filter !== 'all') {
            filtered = filtered.filter((alert) => alert.status === filter);
        }

        if (searchTerm.trim()) {
            const term = searchTerm.toLowerCase().trim();
            filtered = filtered.filter(
                (alert) =>
                    alert.system_id.toLowerCase().includes(term) ||
                    alert.alert_type.toLowerCase().includes(term) ||
                    (alert.suspicious_processes || []).some((p) => p.toLowerCase().includes(term))
            );
        }

        setFilteredAlerts(filtered);
    };

    const handleUpdateStatus = async (alertId, newStatus) => {
        // Optimistic immediate UI update for sub-16ms feedback
        const prevAlerts = alerts;
        const prevStats = stats;

        setAlerts((curr) =>
            curr.map((a) => (a.alert_id === alertId ? { ...a, status: newStatus } : a))
        );
        if (stats && newStatus === 'acknowledged') {
            setStats({
                ...stats,
                unread_alerts: Math.max(0, (stats.unread_alerts || 0) - 1),
                acknowledged_alerts: (stats.acknowledged_alerts || 0) + 1,
            });
        }

        try {
            await alertsAPI.update(alertId, { status: newStatus });
            fetchAlerts();
        } catch (error) {
            console.error('Error updating alert:', error);
            setAlerts(prevAlerts);
            setStats(prevStats);
            setToast({
                title: 'Status update failed',
                message: 'Could not acknowledge incident. Please retry.',
            });
        }
    };

    const executeWhitelist = async (alertId, processName) => {
        if (!processName) {
            setToast({
                title: 'Allowlist failed',
                message: 'No process name available to allowlist.',
            });
            return;
        }

        try {
            await alertsAPI.whitelist(alertId, {
                process_name: processName,
                scope: 'path_signature',
            });
            setWhitelistModal(null);
            setToast({
                title: 'Process allowlisted',
                message: `${processName} was added to endpoint allowlist rules.`,
            });
            fetchAlerts();
        } catch (error) {
            console.error('Error whitelisting process:', error);
            setToast({
                title: 'Allowlist failed',
                message: 'Unable to add allowlist rule. Check process metadata.',
            });
        }
    };

    const handleWhitelistClick = (alert) => {
        const context = alert.metrics?.process_context || [];
        const candidates = Array.from(
            new Set([
                ...context.map((item) => item?.name).filter(Boolean),
                ...(alert.suspicious_processes || []).filter(Boolean),
            ])
        );

        if (candidates.length === 0) {
            setToast({
                title: 'Allowlist unavailable',
                message: 'No flagged executable was attached to this incident.',
            });
            return;
        }

        if (candidates.length === 1) {
            executeWhitelist(alert.alert_id, candidates[0]);
            return;
        }

        setWhitelistModal({
            alertId: alert.alert_id,
            candidates,
            selected: candidates[0],
        });
    };

    const handleDeleteAlert = async (alertId) => {
        const prevAlerts = alerts;
        setConfirmDeleteId(null);
        setAlerts((curr) => curr.filter((a) => a.alert_id !== alertId));

        try {
            await alertsAPI.remove(alertId);
            setToast({ title: 'Incident removed', message: `Alert #${alertId} deleted.` });
            fetchAlerts();
        } catch (error) {
            console.error('Error deleting alert:', error);
            setAlerts(prevAlerts);
            setToast({ title: 'Delete failed', message: 'Unable to delete this alert.' });
        }
    };

    const fetchAlertActions = async (alertId) => {
        if (!alertId) return;
        try {
            const res = await alertsAPI.getActions(alertId);
            setActionStateByAlert((prev) => ({
                ...prev,
                [alertId]: {
                    ...(prev[alertId] || {}),
                    commands: res.data?.commands || [],
                    latestPersistence: res.data?.latest_persistence_audit || null,
                },
            }));
        } catch (error) {
            console.error('Error fetching containment actions:', error);
        }
    };

    const getAlertTargets = (alert) => {
        const ctx = Array.isArray(alert.metrics?.process_context) ? alert.metrics.process_context : [];
        if (ctx.length > 0) return ctx;
        const fallbackNames = Array.isArray(alert.suspicious_processes) ? alert.suspicious_processes : [];
        return fallbackNames.map((name) => ({ name }));
    };

    const getActiveTargetForAlert = (alert) => {
        const targets = getAlertTargets(alert);
        if (targets.length === 0) return null;
        const selectedIdx = Number(selectedTargetByAlert[alert.alert_id] ?? 0);
        return targets[selectedIdx] || targets[0];
    };

    const executeContainmentAction = async (alert, action, targetOverride = null) => {
        const alertId = alert.alert_id;
        setConfirmContainment(null);
        setActionStateByAlert((prev) => ({
            ...prev,
            [alertId]: { ...(prev[alertId] || {}), busyAction: action },
        }));

        try {
            if (action === 'audit_persistence') {
                await systemsAPI.auditPersistence(alert.system_id);
                setToast({
                    title: 'Persistence scan queued',
                    message: `${alert.system_id} will inspect Scheduled Tasks, Run keys, Services, and WSL2 on next heartbeat.`,
                });
            } else {
                const target = targetOverride || getActiveTargetForAlert(alert) || {};
                const remoteIp = Array.isArray(target.remote_ips_sample) ? target.remote_ips_sample[0] : undefined;
                await alertsAPI.dispatchAction(alertId, {
                    action,
                    pid: target.pid ?? undefined,
                    create_time: target.create_time ?? undefined,
                    process_name: target.name ?? undefined,
                    exe_path: target.exe_path ?? undefined,
                    exe_hash: target.exe_hash ?? undefined,
                    remote_ip: remoteIp,
                });
                setToast({
                    title: `${ACTION_LABELS[action] || action} queued`,
                    message: `Command dispatched to ${alert.system_id} for ${target.name || remoteIp || 'target'}.`,
                });
            }
            await fetchAlertActions(alertId);
        } catch (error) {
            const detail = error?.response?.data?.detail || 'Containment request rejected or endpoint unauthorized.';
            setToast({
                title: `${ACTION_LABELS[action] || 'Action'} blocked`,
                message: String(detail),
            });
        } finally {
            setActionStateByAlert((prev) => ({
                ...prev,
                [alertId]: { ...(prev[alertId] || {}), busyAction: null },
            }));
        }
    };

    const handleContainmentTrigger = (alert, action) => {
        const target = getActiveTargetForAlert(alert) || {};
        if (DESTRUCTIVE_ACTIONS.has(action)) {
            setConfirmContainment({ alertId: alert.alert_id, action, target });
            return;
        }
        executeContainmentAction(alert, action, target);
    };

    const formatCommandOutcome = (cmd) => {
        if (!cmd) return '';
        if (cmd.error_message) return cmd.error_message;
        const data = cmd.result_data || {};
        const qPath = data.quarantined_path || data.quarantine_path;
        if (cmd.action === 'quarantine_binary' && qPath) {
            return `Isolated to ${qPath} (${String(data.sha256 || '').slice(0, 12)}...)`;
        }
        const killedChildren = data.killed_children ?? data.terminated_children;
        if (cmd.action === 'kill_process_tree' && Number.isFinite(killedChildren)) {
            return `Terminated PID ${data.pid ?? '?'} + ${killedChildren} child process(es)`;
        }
        if (cmd.action === 'block_ip' && data.blocked_ip) {
            return `Firewall rule ${data.rule_name || ''} blocking ${data.blocked_ip}`;
        }
        if (cmd.action === 'suspend_process' && data.pid) {
            return `Suspended PID ${data.pid} (memory preserved for forensics)`;
        }
        if (cmd.action === 'resume_process' && data.pid) {
            return `Resumed PID ${data.pid}`;
        }
        if (cmd.action === 'audit_persistence' && data.counts) {
            const totalFlagged = Array.isArray(data.suspicious_entries) ? data.suspicious_entries.length : 0;
            return `${totalFlagged} suspicious persistence artifact(s) found`;
        }
        return cmd.status === 'pending'
            ? 'Waiting for endpoint agent heartbeat'
            : cmd.status === 'dispatched'
                ? 'Delivered to endpoint agent; awaiting execution report'
                : 'Executed';
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
                detail: `${ports.length ? `Ports: ${ports.join(', ')}` : ''}${ports.length && names.length ? ' · ' : ''}${names.length ? `Processes: ${names.join(', ')}` : ''}`,
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

    if (initialLoading) {
        return (
            <div className="alerts-page" aria-busy="true" aria-label="Loading security incidents">
                <div className="alerts-stats">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line short" />
                            <div className="skeleton skeleton-line tall" />
                        </div>
                    ))}
                </div>
                <div className="skeleton-card">
                    <div className="skeleton skeleton-line medium" />
                    <div className="skeleton" style={{ height: '220px', width: '100%', borderRadius: '8px' }} />
                </div>
            </div>
        );
    }

    const pieData = [
        { name: 'Unread', value: stats?.unread_alerts || 0, color: 'var(--danger-color)' },
        { name: 'Acknowledged', value: stats?.acknowledged_alerts || 0, color: 'var(--success-color)' },
    ];

    return (
        <div className="alerts-page fade-in">
            {toast && (
                <div className="toast" role="status" aria-live="polite">
                    <strong>{toast.title}</strong>
                    <span>{toast.message}</span>
                </div>
            )}

            {whitelistModal && (
                <div className="modal-overlay" onClick={() => setWhitelistModal(null)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="allowlist-modal-title">
                        <div className="modal-header">
                            <h2 id="allowlist-modal-title">Allowlist Process Signature</h2>
                            <button type="button" className="modal-close" onClick={() => setWhitelistModal(null)} aria-label="Close modal">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <line x1="18" y1="6" x2="6" y2="18" />
                                    <line x1="6" y1="6" x2="18" y2="18" />
                                </svg>
                            </button>
                        </div>
                        <p className="text-muted" style={{ fontSize: '0.8125rem', marginBottom: '1rem' }}>
                            Select the executable to add to the path &amp; Authenticode allowlist for future evaluations:
                        </p>
                        <div className="form-group">
                            <label className="form-label">Executable Name</label>
                            <select
                                className="form-input"
                                value={whitelistModal.selected}
                                onChange={(e) => setWhitelistModal({ ...whitelistModal, selected: e.target.value })}
                            >
                                {whitelistModal.candidates.map((proc) => (
                                    <option key={proc} value={proc}>{proc}</option>
                                ))}
                            </select>
                        </div>
                        <div className="modal-actions">
                            <button type="button" className="btn btn-secondary" onClick={() => setWhitelistModal(null)}>
                                Cancel
                            </button>
                            <button
                                type="button"
                                className="btn btn-primary"
                                onClick={() => executeWhitelist(whitelistModal.alertId, whitelistModal.selected)}
                            >
                                Add to Allowlist
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <div className="alerts-stats stagger-enter">
                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-blue">
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

                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-danger">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Unread Triage</div>
                            <div className="stat-value danger tabular-nums">{stats?.unread_alerts || 0}</div>
                        </div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-green">
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

                <div className="stat-card chart-stat">
                    <div className="chart-stat-header">
                        <span className="stat-label" style={{ marginBottom: 0 }}>Triage Breakdown</span>
                    </div>
                    {pieData.some((d) => d.value > 0) ? (
                        <div className="alert-distribution">
                            <div className="alert-distribution-chart">
                                <ResponsiveContainer width="100%" height={84}>
                                    <PieChart>
                                        <Pie
                                            data={pieData}
                                            cx="50%"
                                            cy="50%"
                                            innerRadius={24}
                                            outerRadius={38}
                                            paddingAngle={3}
                                            dataKey="value"
                                            stroke="none"
                                            isAnimationActive={!hasAnimatedPieRef.current}
                                            animationDuration={240}
                                        >
                                            {pieData.map((entry, index) => (
                                                <Cell key={`cell-${index}`} fill={entry.color} />
                                            ))}
                                        </Pie>
                                        <Tooltip content={<TelemetryTooltip />} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                            <div className="alert-legend tabular-nums">
                                {pieData.map((entry) => (
                                    <div key={entry.name} className="alert-legend-item">
                                        <span className="alert-legend-dot" style={{ background: entry.color }}></span>
                                        <span>{entry.name}</span>
                                        <strong>{entry.value}</strong>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div className="no-data">No incidents recorded</div>
                    )}
                </div>
            </div>

            <div className="alerts-controls">
                <div className="segmented-control" role="tablist" aria-label="Filter incidents by status">
                    <button
                        type="button"
                        className={`segmented-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >
                        All ({alerts.length})
                    </button>
                    <button
                        type="button"
                        className={`segmented-btn ${filter === 'unread' ? 'active' : ''}`}
                        onClick={() => setFilter('unread')}
                    >
                        Unread ({alerts.filter((a) => a.status === 'unread').length})
                    </button>
                    <button
                        type="button"
                        className={`segmented-btn ${filter === 'acknowledged' ? 'active' : ''}`}
                        onClick={() => setFilter('acknowledged')}
                    >
                        Acknowledged ({alerts.filter((a) => a.status === 'acknowledged').length})
                    </button>
                </div>

                <div className="alerts-controls-right">
                    <div className="search-box">
                        <svg className="search-box-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <circle cx="11" cy="11" r="8" />
                            <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                        <input
                            type="text"
                            placeholder="Filter by endpoint, type, or process..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="form-input search-input"
                        />
                        {searchTerm && (
                            <button
                                type="button"
                                className="search-clear-btn"
                                onClick={() => setSearchTerm('')}
                                aria-label="Clear search"
                            >
                                ×
                            </button>
                        )}
                    </div>

                    <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        onClick={() => fetchAlerts({ manual: true })}
                        disabled={refreshing}
                    >
                        <svg
                            width="13"
                            height="13"
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
                        <span>Sync</span>
                    </button>
                </div>
            </div>

            <div className="alerts-section">
                {filteredAlerts.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon" aria-hidden="true">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                <polyline points="8.5 12.5 10.8 14.8 15.5 9.8" />
                            </svg>
                        </div>
                        <p className="empty-title">
                            {searchTerm
                                ? 'No Matching Security Incidents'
                                : filter === 'all'
                                    ? 'Zero Active Security Alerts'
                                    : `No ${filter} incidents`}
                        </p>
                        <p className="empty-subtitle">
                            {searchTerm
                                ? 'Try clearing the filter query or switching status tabs.'
                                : 'All monitored endpoints are operating within baseline behavioral and signature thresholds.'}
                        </p>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="table alerts-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Endpoint</th>
                                    <th>Timestamp</th>
                                    <th>Confidence</th>
                                    <th>Flagged Processes</th>
                                    <th>Telemetry Snapshot</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredAlerts.map((alert) => {
                                    const isExpanded = expandedAlertId === alert.alert_id;
                                    const isConfirmingDelete = confirmDeleteId === alert.alert_id;

                                    return (
                                        <React.Fragment key={alert.alert_id}>
                                            <tr
                                                className={`alert-row ${alert.status} ${isExpanded ? 'expanded' : ''}`}
                                                onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}
                                                style={{ cursor: 'pointer' }}
                                            >
                                                <td>
                                                    <div className="alert-type-cell">
                                                        <svg
                                                            width="13"
                                                            height="13"
                                                            viewBox="0 0 24 24"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            strokeWidth="2.2"
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            className={`expand-chevron ${isExpanded ? 'open' : ''}`}
                                                            aria-hidden="true"
                                                        >
                                                            <polyline points="9 18 15 12 9 6" />
                                                        </svg>
                                                        <span className={`alert-level-badge level-${getAlertLabel(alert.alert_type).toLowerCase()}`}>
                                                            {getAlertLabel(alert.alert_type)}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td>
                                                    <code className="system-id-code">{alert.system_id}</code>
                                                </td>
                                                <td className="timestamp-cell tabular-nums">{new Date(alert.timestamp).toLocaleString()}</td>
                                                <td>
                                                    <div className={`confidence-badge tabular-nums ${getConfidenceColor(alert.confidence)}`}>
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
                                                        <span className="text-muted">None</span>
                                                    )}
                                                </td>
                                                <td className="metrics-cell">
                                                    {alert.metrics ? (
                                                        <div className="metrics-grid">
                                                            <div className="metric-item">
                                                                <span className="metric-label">CPU</span>
                                                                <span className="metric-value tabular-nums">
                                                                    {(normalizeNumber(alert.metrics.cpu_usage) ?? 0).toFixed(1)}%
                                                                </span>
                                                            </div>
                                                            <div className="metric-item">
                                                                <span className="metric-label">MEM</span>
                                                                <span className="metric-value tabular-nums">
                                                                    {(normalizeNumber(alert.metrics.memory_usage) ?? 0).toFixed(1)}%
                                                                </span>
                                                            </div>
                                                            <div className="metric-item">
                                                                <span className="metric-label">GPU</span>
                                                                <span className="metric-value tabular-nums">
                                                                    {normalizeNumber(alert.metrics.gpu_utilization) !== null
                                                                        ? `${normalizeNumber(alert.metrics.gpu_utilization).toFixed(1)}%`
                                                                        : 'N/A'}
                                                                </span>
                                                            </div>
                                                            <div className="metric-item">
                                                                <span className="metric-label">VRAM</span>
                                                                <span className="metric-value tabular-nums">
                                                                    {normalizeNumber(alert.metrics.gpu_memory_used_mb) !== null && normalizeNumber(alert.metrics.gpu_memory_total_mb) !== null
                                                                        ? `${normalizeNumber(alert.metrics.gpu_memory_used_mb).toFixed(0)}/${normalizeNumber(alert.metrics.gpu_memory_total_mb).toFixed(0)}MB`
                                                                        : 'N/A'}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    ) : (
                                                        <span className="text-muted">None</span>
                                                    )}
                                                </td>
                                                <td>
                                                    <span className={`badge badge-${alert.status === 'unread' ? 'danger' : 'success'}`}>
                                                        {alert.status}
                                                    </span>
                                                </td>
                                                <td onClick={(e) => e.stopPropagation()}>
                                                    <div className="alert-actions">
                                                        {isConfirmingDelete ? (
                                                            <>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-danger"
                                                                    onClick={() => handleDeleteAlert(alert.alert_id)}
                                                                >
                                                                    Confirm
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-secondary"
                                                                    onClick={() => setConfirmDeleteId(null)}
                                                                >
                                                                    Cancel
                                                                </button>
                                                            </>
                                                        ) : alert.status === 'unread' ? (
                                                            <>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-success"
                                                                    onClick={() => handleUpdateStatus(alert.alert_id, 'acknowledged')}
                                                                >
                                                                    Acknowledge
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-secondary"
                                                                    onClick={() => handleWhitelistClick(alert)}
                                                                >
                                                                    Allowlist
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-danger-subtle"
                                                                    onClick={() => setConfirmDeleteId(alert.alert_id)}
                                                                >
                                                                    Remove
                                                                </button>
                                                            </>
                                                        ) : (
                                                            <>
                                                                <button type="button" className="btn btn-xs btn-secondary" disabled>
                                                                    Reviewed
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="btn btn-xs btn-danger-subtle"
                                                                    onClick={() => setConfirmDeleteId(alert.alert_id)}
                                                                >
                                                                    Remove
                                                                </button>
                                                            </>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                            {isExpanded && (
                                                <tr className="shap-expansion-row">
                                                    <td colSpan="8">
                                                        <div className="shap-panel">
                                                            <div className="reason-panel">
                                                                <div className="reason-header">Detection Signals</div>
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
                                                                        <div className="reason-context-title">Process Forensic Context</div>
                                                                        <table>
                                                                            <thead>
                                                                                <tr>
                                                                                    <th>Process &amp; PID</th>
                                                                                    <th>Executable Path &amp; CLI</th>
                                                                                    <th>Signals &amp; Signatures</th>
                                                                                </tr>
                                                                            </thead>
                                                                            <tbody>
                                                                                {alert.metrics.process_context.slice(0, 4).map((proc, i) => (
                                                                                    <tr key={i}>
                                                                                        <td>
                                                                                            <div className="proc-id-cell">
                                                                                                <code>{proc?.name || 'unknown'}</code>
                                                                                                {proc?.pid !== null && proc?.pid !== undefined && (
                                                                                                    <span className="forensic-meta tabular-nums">PID {proc.pid}</span>
                                                                                                )}
                                                                                                {proc?.gpu_compute_active && (
                                                                                                    <span className="forensic-tag forensic-tag-warn tabular-nums">
                                                                                                        GPU {(Number(proc.gpu_memory_mb) || 0).toFixed(0)}MB
                                                                                                    </span>
                                                                                                )}
                                                                                            </div>
                                                                                        </td>
                                                                                        <td>
                                                                                            <div className="reason-path" title={proc?.exe_path || ''}>{proc?.exe_path || 'N/A'}</div>
                                                                                            {proc?.cmdline && (
                                                                                                <div className="reason-cmdline" title={proc.cmdline}>
                                                                                                    <code>{proc.cmdline}</code>
                                                                                                </div>
                                                                                            )}
                                                                                        </td>
                                                                                        <td>
                                                                                            <div className="forensic-badges">
                                                                                                <span className="reason-signature">{proc?.signature_status || 'unknown'}</span>
                                                                                                {Array.isArray(proc?.yara_rules) && proc.yara_rules.map((rule, rIdx) => (
                                                                                                    <span key={rIdx} className="forensic-tag forensic-tag-danger">YARA:{rule}</span>
                                                                                                ))}
                                                                                                {Array.isArray(proc?.resolved_domains) && proc.resolved_domains.slice(0, 2).map((dom, dIdx) => (
                                                                                                    <span key={dIdx} className="forensic-tag forensic-tag-info">{dom}</span>
                                                                                                ))}
                                                                                                {Array.isArray(proc?.remote_ips_sample) && proc.remote_ips_sample.slice(0, 1).map((ip, ipIdx) => (
                                                                                                    <span key={ipIdx} className="forensic-meta tabular-nums">{ip}</span>
                                                                                                ))}
                                                                                            </div>
                                                                                        </td>
                                                                                    </tr>
                                                                                ))}
                                                                            </tbody>
                                                                        </table>
                                                                    </div>
                                                                )}
                                                            </div>

                                                            {(() => {
                                                                const targets = getAlertTargets(alert);
                                                                const selectedIdx = Number(selectedTargetByAlert[alert.alert_id] ?? 0);
                                                                const activeTarget = targets[selectedIdx] || targets[0] || {};
                                                                const alertActionState = actionStateByAlert[alert.alert_id] || {};
                                                                const commands = alertActionState.commands || [];
                                                                const latestPersistence = alertActionState.latestPersistence || null;
                                                                const busyAction = alertActionState.busyAction;
                                                                const isConfirming = confirmContainment?.alertId === alert.alert_id;
                                                                const hasRemoteIp = Array.isArray(activeTarget.remote_ips_sample) && activeTarget.remote_ips_sample.length > 0;
                                                                const hasPidTarget = activeTarget.pid !== null && activeTarget.pid !== undefined;
                                                                const hasExePath = Boolean(activeTarget.exe_path);

                                                                return (
                                                                    <div className="containment-panel">
                                                                        <div className="containment-header">
                                                                            <div>
                                                                                <h4 className="containment-title">Active SOC Containment &amp; Eradication Queue</h4>
                                                                                <p className="containment-subtitle">
                                                                                    Signed operator directives dispatched to <code>{alert.system_id}</code> with PID create-time verification.
                                                                                </p>
                                                                            </div>
                                                                            <div className="containment-header-controls">
                                                                                {targets.length > 1 && (
                                                                                    <select
                                                                                        aria-label="Target process"
                                                                                        className="form-input containment-select"
                                                                                        value={selectedIdx}
                                                                                        onChange={(e) =>
                                                                                            setSelectedTargetByAlert((prev) => ({
                                                                                                ...prev,
                                                                                                [alert.alert_id]: Number(e.target.value),
                                                                                            }))
                                                                                        }
                                                                                    >
                                                                                        {targets.map((t, tIdx) => (
                                                                                            <option key={tIdx} value={tIdx}>
                                                                                                {t.name || 'process'} {t.pid ? `(PID ${t.pid})` : ''}
                                                                                            </option>
                                                                                        ))}
                                                                                    </select>
                                                                                )}
                                                                                <button
                                                                                    type="button"
                                                                                    className="btn btn-xs btn-secondary"
                                                                                    disabled={Boolean(busyAction)}
                                                                                    onClick={() => executeContainmentAction(alert, 'audit_persistence')}
                                                                                >
                                                                                    Scan Persistence
                                                                                </button>
                                                                                <button
                                                                                    type="button"
                                                                                    className="btn btn-xs btn-ghost"
                                                                                    onClick={() => fetchAlertActions(alert.alert_id)}
                                                                                    aria-label="Refresh containment queue"
                                                                                >
                                                                                    Refresh
                                                                                </button>
                                                                            </div>
                                                                        </div>

                                                                        <div className="containment-actions-bar">
                                                                            <button
                                                                                type="button"
                                                                                className="btn btn-xs btn-secondary"
                                                                                disabled={Boolean(busyAction) || !hasPidTarget}
                                                                                title={hasPidTarget ? 'Freeze threads to preserve memory forensics' : 'PID unavailable'}
                                                                                onClick={() => handleContainmentTrigger(alert, 'suspend_process')}
                                                                            >
                                                                                Suspend Process
                                                                            </button>
                                                                            <button
                                                                                type="button"
                                                                                className="btn btn-xs btn-secondary"
                                                                                disabled={Boolean(busyAction) || !hasPidTarget}
                                                                                title={hasPidTarget ? 'Resume suspended process' : 'PID unavailable'}
                                                                                onClick={() => handleContainmentTrigger(alert, 'resume_process')}
                                                                            >
                                                                                Resume Process
                                                                            </button>
                                                                            <button
                                                                                type="button"
                                                                                className="btn btn-xs btn-danger-subtle"
                                                                                disabled={Boolean(busyAction) || !hasPidTarget}
                                                                                title={hasPidTarget ? 'Terminate target PID and child watchdogs' : 'PID unavailable'}
                                                                                onClick={() => handleContainmentTrigger(alert, 'kill_process_tree')}
                                                                            >
                                                                                Kill Process Tree
                                                                            </button>
                                                                            <button
                                                                                type="button"
                                                                                className="btn btn-xs btn-danger-subtle"
                                                                                disabled={Boolean(busyAction) || !hasExePath}
                                                                                title={hasExePath ? `Quarantine ${activeTarget.exe_path}` : 'Executable path unavailable'}
                                                                                onClick={() => handleContainmentTrigger(alert, 'quarantine_binary')}
                                                                            >
                                                                                Quarantine Binary
                                                                            </button>
                                                                            <button
                                                                                type="button"
                                                                                className="btn btn-xs btn-danger-subtle"
                                                                                disabled={Boolean(busyAction) || !hasRemoteIp}
                                                                                title={hasRemoteIp ? `Block outbound traffic to ${activeTarget.remote_ips_sample[0]}` : 'No external remote IP captured'}
                                                                                onClick={() => handleContainmentTrigger(alert, 'block_ip')}
                                                                            >
                                                                                Block Pool IP
                                                                            </button>
                                                                        </div>

                                                                        {isConfirming && (
                                                                            <div className="containment-confirm" role="alert">
                                                                                <div className="containment-confirm-copy">
                                                                                    <strong>Confirm {ACTION_LABELS[confirmContainment.action]}</strong>
                                                                                    <span className="tabular-nums">
                                                                                        Target: <code>{confirmContainment.target?.name || 'endpoint'}</code>
                                                                                        {confirmContainment.target?.pid ? ` · PID ${confirmContainment.target.pid}` : ''}
                                                                                        {confirmContainment.action === 'quarantine_binary' && confirmContainment.target?.exe_path
                                                                                            ? ` · ${confirmContainment.target.exe_path}`
                                                                                            : ''}
                                                                                        {confirmContainment.action === 'block_ip' && confirmContainment.target?.remote_ips_sample?.[0]
                                                                                            ? ` · IP ${confirmContainment.target.remote_ips_sample[0]}`
                                                                                            : ''}
                                                                                    </span>
                                                                                </div>
                                                                                <div className="containment-confirm-btns">
                                                                                    <button
                                                                                        type="button"
                                                                                        className="btn btn-xs btn-danger"
                                                                                        onClick={() =>
                                                                                            executeContainmentAction(
                                                                                                alert,
                                                                                                confirmContainment.action,
                                                                                                confirmContainment.target
                                                                                            )
                                                                                        }
                                                                                    >
                                                                                        Execute
                                                                                    </button>
                                                                                    <button
                                                                                        type="button"
                                                                                        className="btn btn-xs btn-secondary"
                                                                                        onClick={() => setConfirmContainment(null)}
                                                                                    >
                                                                                        Cancel
                                                                                    </button>
                                                                                </div>
                                                                            </div>
                                                                        )}

                                                                        {commands.length > 0 && (
                                                                            <div className="containment-history">
                                                                                <div className="containment-subhead">Command Audit Trail</div>
                                                                                <div className="containment-cmd-list">
                                                                                    {commands.slice(0, 5).map((cmd) => (
                                                                                        <div key={cmd.command_id} className="containment-cmd-row">
                                                                                            <div className="containment-cmd-main">
                                                                                                <span className={`cmd-status-pill cmd-status-${cmd.status}`}>
                                                                                                    {cmd.status}
                                                                                                </span>
                                                                                                <strong>{ACTION_LABELS[cmd.action] || cmd.action}</strong>
                                                                                                <span className="containment-cmd-detail">{formatCommandOutcome(cmd)}</span>
                                                                                            </div>
                                                                                            <span className="containment-cmd-time tabular-nums">
                                                                                                {cmd.created_at ? new Date(cmd.created_at).toLocaleTimeString() : ''}
                                                                                            </span>
                                                                                        </div>
                                                                                    ))}
                                                                                </div>
                                                                            </div>
                                                                        )}

                                                                        {latestPersistence?.result_data && (
                                                                            <div className="persistence-audit-box">
                                                                                <div className="containment-subhead">
                                                                                    Latest Persistence Audit ({latestPersistence.completed_at ? new Date(latestPersistence.completed_at).toLocaleString() : 'completed'})
                                                                                </div>
                                                                                <div className="persistence-counts tabular-nums">
                                                                                    <span>Run Keys: {latestPersistence.result_data.counts?.registry_run ?? 0}</span>
                                                                                    <span>Scheduled Tasks: {latestPersistence.result_data.counts?.scheduled_tasks ?? 0}</span>
                                                                                    <span>Non-System Services: {latestPersistence.result_data.counts?.non_system_services ?? 0}</span>
                                                                                    <span>Startup Items: {latestPersistence.result_data.counts?.startup_items ?? 0}</span>
                                                                                    <span>Running WSL2: {latestPersistence.result_data.counts?.wsl_running_distros ?? 0}</span>
                                                                                </div>
                                                                                {Array.isArray(latestPersistence.result_data.suspicious_entries) && latestPersistence.result_data.suspicious_entries.length > 0 ? (
                                                                                    <div className="persistence-findings">
                                                                                        {latestPersistence.result_data.suspicious_entries.slice(0, 5).map((entry, eIdx) => (
                                                                                            <div key={eIdx} className="persistence-finding-row">
                                                                                                <span className="forensic-tag forensic-tag-danger">{entry.category}</span>
                                                                                                <code>{entry.name}</code>
                                                                                                <span className="persistence-loc">{entry.location}</span>
                                                                                            </div>
                                                                                        ))}
                                                                                    </div>
                                                                                ) : (
                                                                                    <p className="persistence-clean">No suspicious persistence entries flagged on latest scan.</p>
                                                                                )}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })()}

                                                            <div className="shap-header-row">
                                                                <h4 className="shap-title">
                                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                                        <circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><line x1="12" y1="17" x2="12.01" y2="17" />
                                                                    </svg>
                                                                    SHAP Feature Attribution (XGBoost TreeExplainer)
                                                                </h4>
                                                                <div className="shap-direction-legend">
                                                                    <span className="shap-legend-benign">← Benign baseline</span>
                                                                    <span className="shap-legend-threat">Cryptojacking risk →</span>
                                                                </div>
                                                            </div>

                                                            {alert.feature_importance && Object.keys(alert.feature_importance).length > 0 ? (() => {
                                                                const shapData = Object.entries(alert.feature_importance)
                                                                    .map(([name, data]) => ({
                                                                        name: name.replace(/_/g, ' '),
                                                                        shap: Number(data.shap) || 0,
                                                                        value: data.value,
                                                                    }))
                                                                    .sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap))
                                                                    .slice(0, 8);

                                                                const maxAbs = Math.max(
                                                                    ...shapData.map((d) => Math.abs(d.shap)),
                                                                    0.0001
                                                                );

                                                                return (
                                                                    <div className="shap-content">
                                                                        <div className="shap-values-table">
                                                                            <table>
                                                                                <thead>
                                                                                    <tr>
                                                                                        <th>Feature</th>
                                                                                        <th>Observed Value</th>
                                                                                        <th>Directional Impact</th>
                                                                                        <th style={{ textAlign: 'right' }}>Log-Odds</th>
                                                                                    </tr>
                                                                                </thead>
                                                                                <tbody>
                                                                                    {shapData.map((f, i) => {
                                                                                        const ratio = Math.min(1, Math.abs(f.shap) / maxAbs);
                                                                                        const isPositive = f.shap >= 0;
                                                                                        return (
                                                                                            <tr key={i}>
                                                                                                <td style={{ fontWeight: 500 }}>{f.name}</td>
                                                                                                <td className="tabular-nums">{f.value}</td>
                                                                                                <td className="shap-bar-cell">
                                                                                                    <div className="shap-diverging-track">
                                                                                                        <div className="shap-half shap-half-neg">
                                                                                                            {!isPositive && (
                                                                                                                <div
                                                                                                                    className="shap-bar-fill neg"
                                                                                                                    style={{ '--shap-scale': ratio }}
                                                                                                                />
                                                                                                            )}
                                                                                                        </div>
                                                                                                        <div className="shap-axis-line" />
                                                                                                        <div className="shap-half shap-half-pos">
                                                                                                            {isPositive && (
                                                                                                                <div
                                                                                                                    className="shap-bar-fill pos"
                                                                                                                    style={{ '--shap-scale': ratio }}
                                                                                                                />
                                                                                                            )}
                                                                                                        </div>
                                                                                                    </div>
                                                                                                </td>
                                                                                                <td
                                                                                                    className="tabular-nums"
                                                                                                    style={{
                                                                                                        textAlign: 'right',
                                                                                                        color: isPositive ? 'var(--danger-color)' : 'var(--primary-color)',
                                                                                                        fontWeight: 700,
                                                                                                    }}
                                                                                                >
                                                                                                    {f.shap > 0 ? '+' : ''}{f.shap.toFixed(4)}
                                                                                                </td>
                                                                                            </tr>
                                                                                        );
                                                                                    })}
                                                                                </tbody>
                                                                            </table>
                                                                        </div>
                                                                    </div>
                                                                );
                                                            })() : (
                                                                <p className="shap-no-data">SHAP feature attribution is not attached to this incident (triggered by deterministic policy or heuristic gate).</p>
                                                            )}
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AlertsPage;
