import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import { reportsAPI, systemsAPI } from '../../services/api';
import './Reports.css';

const formatDateInput = (dateObj) => dateObj.toISOString().split('T')[0];

const getPresetDates = (days) => {
    const end = new Date();
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
    return {
        start_date: formatDateInput(start),
        end_date: formatDateInput(end),
    };
};

const ReportsPage = () => {
    const { user } = useAuth();

    const [reports, setReports] = useState([]);
    const [system, setSystem] = useState(null);
    const [initialLoading, setInitialLoading] = useState(true);
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [generating, setGenerating] = useState(false);
    const [downloadingId, setDownloadingId] = useState(null);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');

    const [formData, setFormData] = useState(() => ({
        ...getPresetDates(7),
        metrics: ['cpu', 'memory', 'network', 'gpu'],
        format: 'pdf',
    }));

    const fetchData = useCallback(async () => {
        try {
            setError('');
            const knownId = user?.system_id;

            if (knownId) {
                const [systemsRes, reportsRes] = await Promise.all([
                    systemsAPI.getAll(user?.email),
                    reportsAPI.getAll(knownId, 100).catch(() => ({ data: { reports: [] } })),
                ]);
                const userSystem =
                    systemsRes.data.systems?.find((s) => s.system_id === knownId) ||
                    systemsRes.data.systems?.[0] ||
                    null;
                setSystem(userSystem);
                setReports(reportsRes.data.reports || []);
            } else {
                const systemsRes = await systemsAPI.getAll(user?.email);
                const userSystem = systemsRes.data.systems?.[0] || null;
                setSystem(userSystem);
                if (userSystem) {
                    const reportsRes = await reportsAPI.getAll(userSystem.system_id, 100);
                    setReports(reportsRes.data.reports || []);
                } else {
                    setReports([]);
                }
            }
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load reports data');
        } finally {
            setInitialLoading(false);
        }
    }, [user?.email, user?.system_id]);

    useEffect(() => {
        fetchData();
    }, [fetchData]);

    useEffect(() => {
        if (!showGenerateModal) return undefined;
        const onKeyDown = (e) => {
            if (e.key === 'Escape' && !generating) setShowGenerateModal(false);
        };
        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, [showGenerateModal, generating]);

    const handleApplyPreset = (days) => {
        setFormData((prev) => ({
            ...prev,
            ...getPresetDates(days),
        }));
    };

    const handleGenerateReport = async (e) => {
        e.preventDefault();
        if (!system || formData.metrics.length === 0) return;

        setGenerating(true);
        setError('');
        setMessage('');

        try {
            const reportData = {
                ...formData,
                system_ids: [system.system_id],
            };

            await reportsAPI.generate(reportData);
            setShowGenerateModal(false);
            setMessage('Compliance report compiled and stored.');
            await fetchData();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to generate report');
        } finally {
            setGenerating(false);
        }
    };

    const handleDownload = async (report) => {
        setDownloadingId(report.report_id);
        setError('');
        setMessage('');

        try {
            const response = await reportsAPI.download(report.report_id);
            const contentType = response.headers['content-type'] || 'application/octet-stream';
            const disposition = response.headers['content-disposition'] || '';
            const fileNameMatch = disposition.match(/filename="?([^\\"]+)"?/i);
            const fileName = fileNameMatch?.[1] || `report_${report.report_id}.${report.format}`;

            const blob = new Blob([response.data], { type: contentType });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);

            setMessage(`Download started: ${fileName}`);
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to download report');
        } finally {
            setDownloadingId(null);
        }
    };

    const handleMetricToggle = (metric) => {
        setFormData((prev) => {
            const exists = prev.metrics.includes(metric);
            if (exists && prev.metrics.length === 1) return prev;
            return {
                ...prev,
                metrics: exists
                    ? prev.metrics.filter((m) => m !== metric)
                    : [...prev.metrics, metric],
            };
        });
    };

    if (initialLoading) {
        return (
            <div className="reports-page" aria-busy="true" aria-label="Loading reports">
                <div className="reports-stats">
                    {[1, 2, 3].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line short" />
                            <div className="skeleton skeleton-line tall" />
                        </div>
                    ))}
                </div>
                <div className="skeleton-card">
                    <div className="skeleton skeleton-line medium" />
                    <div className="skeleton" style={{ height: '160px', width: '100%', borderRadius: '8px' }} />
                </div>
            </div>
        );
    }

    return (
        <div className="reports-page fade-in">
            <div className="reports-stats stagger-enter">
                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-blue">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Total Archives</div>
                            <div className="stat-value tabular-nums">{reports.length}</div>
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
                            <div className="stat-label">Ready for Export</div>
                            <div className="stat-value tabular-nums">{reports.filter((r) => r.status === 'completed').length}</div>
                        </div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <div className="stat-icon stat-icon-blue">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                            </svg>
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Target Endpoint</div>
                            <div className="stat-value" style={{ fontSize: '1.125rem' }}>{system ? system.system_name : 'No System'}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="reports-actions">
                <div>
                    <h2 className="section-title" style={{ marginBottom: '0.25rem' }}>Forensic &amp; Telemetry Reports</h2>
                    <p className="text-muted" style={{ fontSize: '0.8125rem', maxWidth: '62ch' }}>
                        Compile PDF or CSV audit summaries covering CPU, memory, network, and GPU telemetry over any date window.
                    </p>
                </div>
                <div className="reports-actions-buttons">
                    <button
                        type="button"
                        onClick={() => setShowGenerateModal(true)}
                        className="btn btn-primary"
                        disabled={!system}
                    >
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="12" y1="5" x2="12" y2="19" />
                            <line x1="5" y1="12" x2="19" y2="12" />
                        </svg>
                        <span>Generate New Report</span>
                    </button>
                </div>
            </div>

            {showGenerateModal && system && (
                <div className="modal-overlay" onClick={() => !generating && setShowGenerateModal(false)}>
                    <div className="modal-content report-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="compile-report-title">
                        <div className="modal-header">
                            <h2 id="compile-report-title">Compile Endpoint Report</h2>
                            <button
                                type="button"
                                onClick={() => setShowGenerateModal(false)}
                                className="modal-close"
                                disabled={generating}
                                aria-label="Close modal"
                            >
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <line x1="18" y1="6" x2="6" y2="18" />
                                    <line x1="6" y1="6" x2="18" y2="18" />
                                </svg>
                            </button>
                        </div>

                        <form onSubmit={handleGenerateReport}>
                            <div className="form-group">
                                <label className="form-label">Target Endpoint</label>
                                <div className="system-info-box">
                                    <strong>{system.system_name}</strong>
                                    <code className="system-id-code">{system.system_id}</code>
                                </div>
                            </div>

                            <div className="form-group">
                                <div className="report-preset-head">
                                    <label className="form-label" style={{ marginBottom: 0 }}>Reporting Window</label>
                                    <div className="report-presets">
                                        <button type="button" className="btn btn-xs btn-secondary" onClick={() => handleApplyPreset(1)}>24h</button>
                                        <button type="button" className="btn btn-xs btn-secondary" onClick={() => handleApplyPreset(7)}>7 Days</button>
                                        <button type="button" className="btn btn-xs btn-secondary" onClick={() => handleApplyPreset(30)}>30 Days</button>
                                    </div>
                                </div>
                                <div className="form-row">
                                    <div>
                                        <span className="report-date-sublabel">From</span>
                                        <input
                                            type="date"
                                            className="form-input"
                                            value={formData.start_date}
                                            onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                                            required
                                        />
                                    </div>
                                    <div>
                                        <span className="report-date-sublabel">To</span>
                                        <input
                                            type="date"
                                            className="form-input"
                                            value={formData.end_date}
                                            onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                                            required
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="form-group">
                                <label className="form-label">Included Telemetry Channels</label>
                                <div className="channel-pills">
                                    {['cpu', 'memory', 'network', 'gpu'].map((metric) => {
                                        const active = formData.metrics.includes(metric);
                                        return (
                                            <button
                                                key={metric}
                                                type="button"
                                                className={`channel-pill-btn ${active ? 'active' : ''}`}
                                                onClick={() => handleMetricToggle(metric)}
                                                aria-pressed={active}
                                            >
                                                <span className="uppercase">{metric}</span>
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>

                            <div className="form-group">
                                <label className="form-label">Export Format</label>
                                <div className="segmented-control" style={{ width: '100%' }}>
                                    <button
                                        type="button"
                                        className={`segmented-btn ${formData.format === 'pdf' ? 'active' : ''}`}
                                        style={{ flex: 1 }}
                                        onClick={() => setFormData({ ...formData, format: 'pdf' })}
                                    >
                                        PDF Document (.pdf)
                                    </button>
                                    <button
                                        type="button"
                                        className={`segmented-btn ${formData.format === 'csv' ? 'active' : ''}`}
                                        style={{ flex: 1 }}
                                        onClick={() => setFormData({ ...formData, format: 'csv' })}
                                    >
                                        Raw Telemetry (.csv)
                                    </button>
                                </div>
                            </div>

                            <div className="modal-actions">
                                <button
                                    type="button"
                                    onClick={() => setShowGenerateModal(false)}
                                    className="btn btn-secondary"
                                    disabled={generating}
                                >
                                    Cancel
                                </button>
                                <button type="submit" className={`btn btn-primary ${generating ? 'is-busy' : ''}`} disabled={generating}>
                                    {generating && <span className="spinner-small" aria-hidden="true" />}
                                    <span className="btn-label">{generating ? 'Compiling...' : 'Generate Report'}</span>
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <div className="reports-section">
                <h2 className="section-title">Generated Archives</h2>

                {error && <div className="profile-banner error" role="alert">{error}</div>}
                {message && <div className="profile-banner success" role="status">{message}</div>}

                {reports.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon empty-icon-neutral" aria-hidden="true">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                <polyline points="14 2 14 8 20 8" />
                            </svg>
                        </div>
                        <p className="empty-title">No Compliance Archives Yet</p>
                        <p className="empty-subtitle">Click &ldquo;Generate New Report&rdquo; above to compile an exportable PDF or CSV archive.</p>
                    </div>
                ) : (
                    <div className="reports-grid">
                        {reports.map((report) => (
                            <div key={report.report_id} className="report-card">
                                <div className="report-header">
                                    <div className={`report-icon ${report.format}`} aria-hidden="true">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                            <polyline points="14 2 14 8 20 8" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h3 className="report-title">Archive #{report.report_id}</h3>
                                        <p className="report-date tabular-nums">{new Date(report.created_at).toLocaleString()}</p>
                                    </div>
                                    <span className={`badge badge-${report.status === 'completed' ? 'success' : 'warning'}`}>
                                        {report.status}
                                    </span>
                                </div>

                                <div className="report-body">
                                    <div className="report-detail">
                                        <span className="detail-label">Window</span>
                                        <span className="detail-value tabular-nums">
                                            {new Date(report.start_date).toLocaleDateString()} – {new Date(report.end_date).toLocaleDateString()}
                                        </span>
                                    </div>
                                    <div className="report-detail">
                                        <span className="detail-label">Channels</span>
                                        <span className="detail-value">
                                            {(report.metrics || []).map((metric) => (
                                                <span key={metric} className="metric-chip">{metric}</span>
                                            ))}
                                        </span>
                                    </div>
                                    <div className="report-detail">
                                        <span className="detail-label">Format</span>
                                        <span className="detail-value uppercase">{report.format}</span>
                                    </div>
                                </div>

                                <div className="report-footer">
                                    <button
                                        type="button"
                                        className={`btn btn-sm ${report.format === 'pdf' ? 'btn-primary' : 'btn-secondary'}`}
                                        onClick={() => handleDownload(report)}
                                        disabled={downloadingId === report.report_id}
                                    >
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                            <polyline points="7 10 12 15 17 10" />
                                            <line x1="12" y1="15" x2="12" y2="3" />
                                        </svg>
                                        <span>
                                            {downloadingId === report.report_id ? 'Downloading...' : `Download ${report.format.toUpperCase()}`}
                                        </span>
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ReportsPage;
