import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { reportsAPI, systemsAPI } from '../../services/api';
import './Reports.css';

const ReportsPage = () => {
    const { user } = useAuth();

    const [reports, setReports] = useState([]);
    const [system, setSystem] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [generating, setGenerating] = useState(false);
    const [downloadingId, setDownloadingId] = useState(null);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');

    const [formData, setFormData] = useState({
        start_date: '',
        end_date: '',
        metrics: ['cpu', 'memory', 'network', 'gpu'],
        format: 'pdf',
    });

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        try {
            setLoading(true);
            setError('');

            const systemsRes = await systemsAPI.getAll(user?.email);
            const userSystem = systemsRes.data.systems?.[0] || null;
            setSystem(userSystem);

            if (userSystem) {
                const reportsRes = await reportsAPI.getAll(userSystem.system_id, 100);
                setReports(reportsRes.data.reports || []);
            } else {
                setReports([]);
            }
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load reports data');
        } finally {
            setLoading(false);
        }
    };

    const handleGenerateReport = async (e) => {
        e.preventDefault();
        if (!system) return;

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
            setMessage('Report generated successfully.');
            setFormData({
                start_date: '',
                end_date: '',
                metrics: ['cpu', 'memory', 'network', 'gpu'],
                format: 'pdf',
            });
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
        setFormData((prev) => ({
            ...prev,
            metrics: prev.metrics.includes(metric)
                ? prev.metrics.filter((m) => m !== metric)
                : [...prev.metrics, metric],
        }));
    };

    if (loading) {
        return (
            <div className="reports-page">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
                </div>
            </div>
        );
    }

    return (
        <div className="reports-page fade-in">
            <div className="reports-stats">
                <div className="stat-card">
                    <div className="stat-icon stat-icon-purple">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{reports.length}</div>
                        <div className="stat-label">Total Reports</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon stat-icon-green">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{reports.filter((r) => r.status === 'completed').length}</div>
                        <div className="stat-label">Completed</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon stat-icon-blue">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{system ? system.system_name : 'No System'}</div>
                        <div className="stat-label">Target System</div>
                    </div>
                </div>
            </div>

            <div className="reports-actions">
                <div>
                    <h2 className="section-title">Reports Center</h2>
                    <p className="text-muted">Generate CSV or PDF reports with CPU, memory, network, and GPU metrics.</p>
                </div>
                <div className="reports-actions-buttons">
                    <button
                        onClick={() => setShowGenerateModal(true)}
                        className="btn btn-primary"
                        disabled={!system}
                    >
                        Generate New Report
                    </button>
                </div>
                {!system && (
                    <p className="text-muted" style={{ marginLeft: '1rem' }}>
                        No system is linked to this account.
                    </p>
                )}
            </div>

            {showGenerateModal && system && (
                <div className="modal-overlay" onClick={() => !generating && setShowGenerateModal(false)}>
                    <div className="modal-content report-modal" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>Generate Report</h2>
                            <button
                                onClick={() => setShowGenerateModal(false)}
                                className="modal-close"
                                disabled={generating}
                            >
                                X
                            </button>
                        </div>

                        <form onSubmit={handleGenerateReport}>
                            <div className="form-group">
                                <label className="form-label">System</label>
                                <div className="system-info-box">
                                    <strong>{system.system_name}</strong>
                                    <code className="system-id-code">{system.system_id}</code>
                                </div>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label className="form-label">Start Date</label>
                                    <input
                                        type="date"
                                        className="form-input"
                                        value={formData.start_date}
                                        onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">End Date</label>
                                    <input
                                        type="date"
                                        className="form-input"
                                        value={formData.end_date}
                                        onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                                        required
                                    />
                                </div>
                            </div>

                            <div className="form-group">
                                <label className="form-label">Include Metrics</label>
                                <div className="checkbox-group horizontal">
                                    {['cpu', 'memory', 'network', 'gpu'].map((metric) => (
                                        <label key={metric} className="checkbox-label">
                                            <input
                                                type="checkbox"
                                                checked={formData.metrics.includes(metric)}
                                                onChange={() => handleMetricToggle(metric)}
                                            />
                                            <span className="capitalize">{metric}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>

                            <div className="form-group">
                                <label className="form-label">Report Format</label>
                                <select
                                    className="form-input"
                                    value={formData.format}
                                    onChange={(e) => setFormData({ ...formData, format: e.target.value })}
                                >
                                    <option value="pdf">PDF</option>
                                    <option value="csv">CSV</option>
                                </select>
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
                                <button type="submit" className="btn btn-primary" disabled={generating}>
                                    {generating ? 'Generating...' : 'Generate Report'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <div className="reports-section">
                <h2 className="section-title">Generated Reports</h2>

                {error && <div className="profile-banner error">{error}</div>}
                {message && <div className="profile-banner success">{message}</div>}

                {reports.length === 0 ? (
                    <div className="empty-state">
                        <p>No reports generated yet. Create your first report to get started.</p>
                    </div>
                ) : (
                    <div className="reports-grid">
                        {reports.map((report) => (
                            <div key={report.report_id} className="report-card">
                                <div className="report-header">
                                    <div className={`report-icon ${report.format}`}>
                                        {report.format === 'pdf' ? 'PDF' : 'CSV'}
                                    </div>
                                    <div>
                                        <h3 className="report-title">Report #{report.report_id}</h3>
                                        <p className="report-date">{new Date(report.created_at).toLocaleString()}</p>
                                    </div>
                                    <span className={`badge badge-${report.status === 'completed' ? 'success' : 'warning'}`}>
                                        {report.status}
                                    </span>
                                </div>

                                <div className="report-body">
                                    <div className="report-detail">
                                        <span className="detail-label">Period:</span>
                                        <span className="detail-value">
                                            {new Date(report.start_date).toLocaleDateString()} - {new Date(report.end_date).toLocaleDateString()}
                                        </span>
                                    </div>
                                    <div className="report-detail">
                                        <span className="detail-label">Metrics:</span>
                                        <span className="detail-value">
                                            {(report.metrics || []).map((metric) => (
                                                <span key={metric} className="metric-chip">{metric}</span>
                                            ))}
                                        </span>
                                    </div>
                                    <div className="report-detail">
                                        <span className="detail-label">Format:</span>
                                        <span className="detail-value uppercase">{report.format}</span>
                                    </div>
                                </div>

                                <div className="report-footer">
                                    <button
                                        className={`btn btn-sm ${report.format === 'pdf' ? 'btn-primary' : 'btn-secondary'}`}
                                        onClick={() => handleDownload(report)}
                                        disabled={downloadingId === report.report_id}
                                    >
                                        {downloadingId === report.report_id ? 'Downloading...' : `Download ${report.format.toUpperCase()}`}
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
