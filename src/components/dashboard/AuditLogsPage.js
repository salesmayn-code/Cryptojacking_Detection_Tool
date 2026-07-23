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
];

const actionBadgeClass = (action) => {
    if (action.includes('create') || action.includes('register')) return 'create';
    if (action.includes('delete')) return 'delete';
    if (action.includes('update')) return 'update';
    if (action.includes('change')) return 'change';
    return 'update';
};

const AuditLogsPage = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    const [filters, setFilters] = useState({
        action: '',
        actor_email: '',
        start_date: '',
        end_date: '',
    });

    const fetchLogs = useCallback(async () => {
        try {
            setLoading(true);
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
            setLoading(false);
        }
    }, [page, filters]);

    useEffect(() => {
        fetchLogs();
    }, [fetchLogs]);

    const handleFilterChange = (key, value) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
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

    if (loading && logs.length === 0) {
        return (
            <div className="audit-page">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
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
                        placeholder="Search by email"
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
                    <button className="btn btn-secondary btn-sm" onClick={handleExport}>
                        Export CSV
                    </button>
                </div>
            </div>

            <div className="audit-table-container">
                {logs.length === 0 ? (
                    <div className="empty-state" style={{ padding: '2rem' }}>
                        <p>No audit log entries found.</p>
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
                                    <td className="timestamp-cell">
                                        {new Date(log.timestamp).toLocaleString()}
                                    </td>
                                    <td>{log.actor_email}</td>
                                    <td>
                                        <span
                                            className={`action-badge ${actionBadgeClass(
                                                log.action
                                            )}`}
                                        >
                                            {log.action}
                                        </span>
                                    </td>
                                    <td>
                                        {log.target_type && (
                                            <span style={{ opacity: 0.6 }}>
                                                {log.target_type}:{' '}
                                            </span>
                                        )}
                                        <code>{log.target_id || '—'}</code>
                                    </td>
                                    <td>
                                        <span className="details-json" title={JSON.stringify(log.details)}>
                                            {JSON.stringify(log.details)}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="audit-pagination">
                <button disabled={page <= 1} onClick={() => setPage(page - 1)}>
                    ← Previous
                </button>
                <span className="page-info">
                    Page {page} of {totalPages} ({total} entries)
                </span>
                <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
                    Next →
                </button>
            </div>
        </div>
    );
};

export default AuditLogsPage;
