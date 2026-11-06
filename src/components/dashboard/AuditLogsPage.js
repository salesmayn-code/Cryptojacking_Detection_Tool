import React, { useState, useEffect, useCallback } from 'react';
import { adminAPI } from '../../services/api';
import './AuditLogs.css';

const ACTION_OPTIONS = [
    { value: '', label: 'All Actions' },
    { value: 'system.create', label: 'System Created' },
    { value: 'system.update', label: 'System Updated' },
    { value: 'system.delete', label: 'System Deleted' },
    { value: 'alert.status_change', label: 'Alert Status Change' },
    { value: 'user.register', label: 'User Registered' },
    { value: 'user.password_change', label: 'Password Changed' },
    { value: 'user.api_key_rotate', label: 'API Key Rotated' },
];

const actionBadgeClass = (action) => {
    if (action.includes('register')) return 'register';
    if (action.includes('create')) return 'create';
    if (action.includes('delete')) return 'delete';
    if (action.includes('change') || action.includes('rotate')) return 'change';
    return 'update';
};

const renderDetails = (details) => {
    if (!details || typeof details !== 'object') {
        return <span className="text-muted">—</span>;
    }
    const entries = Object.entries(details);
    if (entries.length === 0) {
        return <span className="text-muted">—</span>;
    }
    return (
        <div className="audit-detail-chips">
            {entries.slice(0, 4).map(([k, v]) => (
                <span key={k} className="audit-detail-chip">
                    <span className="audit-detail-key">{k}:</span>{' '}
                    <span className="audit-detail-val">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                </span>
            ))}
        </div>
    );
};

const AuditLogsPage = () => {
    const [logs, setLogs] = useState([]);
    const [initialLoading, setInitialLoading] = useState(true);
    const [fetching, setFetching] = useState(false);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    const [filters, setFilters] = useState({
        action: '',
        actor_email: '',
        start_date: '',
        end_date: '',
    });

    const hasActiveFilters = Boolean(
        filters.action || filters.actor_email || filters.start_date || filters.end_date
    );

    const fetchLogs = useCallback(async () => {
        try {
            setFetching(true);
            const params = { page, per_page: 20 };
            if (filters.action) params.action = filters.action;
            if (filters.actor_email) params.actor_email = filters.actor_email;
            if (filters.start_date) params.start_date = filters.start_date;
            if (filters.end_date) params.end_date = filters.end_date;

            const res = await adminAPI.getAuditLogs(params);
            setLogs(res.data.logs || []);
            setTotalPages(res.data.total_pages || 1);
            setTotal(res.data.total || 0);
        } catch (err) {
            console.error('Error fetching audit logs:', err);
        } finally {
            setInitialLoading(false);
            setFetching(false);
        }
    }, [page, filters]);

    useEffect(() => {
        fetchLogs();
    }, [fetchLogs]);

    const handleFilterChange = (key, value) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPage(1);
    };

    const handleResetFilters = () => {
        setFilters({
            action: '',
            actor_email: '',
            start_date: '',
            end_date: '',
        });
        setPage(1);
    };

    const handleExport = async () => {
        try {
            const params = {};
            if (filters.action) params.action = filters.action;
            if (filters.actor_email) params.actor_email = filters.actor_email;
            if (filters.start_date) params.start_date = filters.start_date;
            if (filters.end_date) params.end_date = filters.end_date;

            const res = await adminAPI.exportAuditLogs(params);
            const blob = new Blob([res.data], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'audit_logs.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            console.error('Export failed:', err);
        }
    };

    if (initialLoading) {
        return (
            <div className="audit-page" aria-busy="true" aria-label="Loading audit trail">
                <div className="skeleton-card" style={{ marginBottom: '1.25rem' }}>
                    <div className="skeleton skeleton-line medium" />
                </div>
                <div className="skeleton-card">
                    <div className="skeleton" style={{ height: '280px', width: '100%', borderRadius: '8px' }} />
                </div>
            </div>
        );
    }

    return (
        <div className="audit-page fade-in">
            <div className="audit-controls">
                <div className="filter-group">
                    <label>Action</label>
                    <select
                        value={filters.action}
                        onChange={(e) => handleFilterChange('action', e.target.value)}
                    >
                        {ACTION_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>
                                {opt.label}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label>Actor</label>
                    <input
                        type="text"
                        placeholder="Filter by email"
                        value={filters.actor_email}
                        onChange={(e) => handleFilterChange('actor_email', e.target.value)}
                    />
                </div>

                <div className="filter-group">
                    <label>From</label>
                    <input
                        type="date"
                        value={filters.start_date}
                        onChange={(e) => handleFilterChange('start_date', e.target.value)}
                    />
                </div>

                <div className="filter-group">
                    <label>To</label>
                    <input
                        type="date"
                        value={filters.end_date}
                        onChange={(e) => handleFilterChange('end_date', e.target.value)}
                    />
                </div>

                <div className="audit-actions-bar">
                    {hasActiveFilters && (
                        <button type="button" className="btn btn-ghost btn-sm" onClick={handleResetFilters}>
                            Reset
                        </button>
                    )}
                    <button type="button" className="btn btn-secondary btn-sm" onClick={handleExport}>
                        Export CSV
                    </button>
                </div>
            </div>

            <div className={`audit-table-container ${fetching ? 'is-revalidating' : ''}`}>
                {logs.length === 0 ? (
                    <div className="empty-state" style={{ border: 'none' }}>
                        <p className="empty-title">No Audit Log Entries Found</p>
                        <p className="empty-subtitle">No administrative or credential events match the active filters.</p>
                    </div>
                ) : (
                    <table className="audit-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Actor</th>
                                <th>Action</th>
                                <th>Target</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map((log) => (
                                <tr key={log.id}>
                                    <td className="timestamp-cell tabular-nums">
                                        {new Date(log.timestamp).toLocaleString()}
                                    </td>
                                    <td>{log.actor_email}</td>
                                    <td>
                                        <span className={`action-badge ${actionBadgeClass(log.action)}`}>
                                            {log.action}
                                        </span>
                                    </td>
                                    <td>
                                        {log.target_type && (
                                            <span className="text-muted" style={{ fontSize: '0.75rem' }}>
                                                {log.target_type}:{' '}
                                            </span>
                                        )}
                                        <code>{log.target_id || '—'}</code>
                                    </td>
                                    <td>{renderDetails(log.details)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="audit-pagination">
                <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    disabled={page <= 1}
                    onClick={() => setPage(page - 1)}
                >
                    ← Previous
                </button>
                <span className="page-info tabular-nums">
                    Page {page} of {totalPages} ({total} entries)
                </span>
                <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    disabled={page >= totalPages}
                    onClick={() => setPage(page + 1)}
                >
                    Next →
                </button>
            </div>
        </div>
    );
};

export default AuditLogsPage;
