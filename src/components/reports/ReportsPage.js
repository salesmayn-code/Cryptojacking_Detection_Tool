import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { reportsAPI, systemsAPI } from '../../services/api';
import './Reports.css';

const ReportsPage = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();
    const [reports, setReports] = useState([]);
    const [system, setSystem] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [generating, setGenerating] = useState(false);
    const [formData, setFormData] = useState({
        start_date: '',
        end_date: '',
        metrics: ['cpu', 'memory', 'network'],
        format: 'pdf',
    });

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        try {
            setLoading(true);

            // Get user's system
            const systemsRes = await systemsAPI.getAll(user?.email);
            const userSystem = systemsRes.data.systems?.[0];
            setSystem(userSystem);

            // Get reports for this system
            if (userSystem) {
                const reportsRes = await reportsAPI.getAll(userSystem.system_id, 50);
                setReports(reportsRes.data.reports || []);
            }

            setLoading(false);
        } catch (error) {
            console.error('Error fetching data:', error);
            setLoading(false);
        }
    };

    const handleGenerateReport = async (e) => {
        e.preventDefault();
        setGenerating(true);

        try {
            const reportData = {
                ...formData,
                system_ids: system ? [system.system_id] : []
            };

            await reportsAPI.generate(reportData);
            setShowGenerateModal(false);
            fetchData();

            // Reset form
            setFormData({
                start_date: '',
                end_date: '',
                metrics: ['cpu', 'memory', 'network'],
                format: 'pdf',
            });
        } catch (error) {
            console.error('Error generating report:', error);
            alert('Failed to generate report');
        } finally {
            setGenerating(false);
        }
    };

    const handleMetricToggle = (metric) => {
        setFormData(prev => ({
            ...prev,
            metrics: prev.metrics.includes(metric)
                ? prev.metrics.filter(m => m !== metric)
                : [...prev.metrics, metric]
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
        <div className="reports-page">
            {/* Navigation */}
            <nav className="dashboard-nav">
                <div className="nav-brand">
                    <button onClick={() => navigate('/dashboard')} className="btn btn-secondary btn-sm">
                        ← Dashboard
                    </button>
                    <h2>📊 Report Management</h2>
                </div>
                <div className="nav-user">
                    <span className="user-name">{user?.full_name}</span>
                    <span className={`badge badge-${user?.role === 'admin' ? 'success' : 'warning'}`}>
                        {user?.role}
                    </span>
                    <button onClick={logout} className="btn btn-secondary btn-sm">
                        Logout
                    </button>
                </div>
            </nav>

            {/* Stats - Simplified */}
            <div className="reports-stats">
                <div className="stat-card">
                    <div className="stat-icon">📄</div>
                    <div className="stat-content">
                        <div className="stat-value">{reports.length}</div>
                        <div className="stat-label">Total Reports</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-content">
                        <div className="stat-value">
                            {reports.filter(r => r.status === 'completed').length}
                        </div>
                        <div className="stat-label">Completed</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon">🖥️</div>
                    <div className="stat-content">
                        <div className="stat-value">{system ? system.system_name : 'No System'}</div>
                        <div className="stat-label">Your System</div>
                    </div>
                </div>
            </div>

            {/* Actions */}
            <div className="reports-actions">
                <button
                    onClick={() => setShowGenerateModal(true)}
                    className="btn btn-primary"
                    disabled={!system}
                >
                    ➕ Generate New Report
                </button>
                {!system && (
                    <p className="text-muted" style={{ marginLeft: '1rem' }}>
                        No system registered. Please contact administrator.
                    </p>
                )}
            </div>

            {/* Generate Report Modal */}
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
                                ✕
                            </button>
                        </div>

                        <form onSubmit={handleGenerateReport}>
                            {/* System Info */}
                            <div className="form-group">
                                <label className="form-label">System</label>
                                <div className="system-info-box">
                                    <strong>{system.system_name}</strong>
                                    <code className="system-id-code">{system.system_id}</code>
                                </div>
                            </div>

                            {/* Date Range */}
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

                            {/* Select Metrics */}
                            <div className="form-group">
                                <label className="form-label">Include Metrics</label>
                                <div className="checkbox-group horizontal">
                                    {['cpu', 'memory', 'network'].map(metric => (
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

                            {/* Format */}
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
                                <button
                                    type="submit"
                                    className="btn btn-primary"
                                    disabled={generating}
                                >
                                    {generating ? 'Generating...' : 'Generate Report'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Reports List */}
            <div className="reports-section">
                <h2 className="section-title">Generated Reports</h2>
                {reports.length === 0 ? (
                    <div className="empty-state">
                        <p>No reports generated yet. Create your first report to get started.</p>
                    </div>
                ) : (
                    <div className="reports-grid">
                        {reports.map((report) => (
                            <div key={report.report_id} className="report-card">
                                <div className="report-header">
                                    <div className="report-icon">
                                        {report.format === 'pdf' ? '📄' : '📊'}
                                    </div>
                                    <div>
                                        <h3 className="report-title">Report #{report.report_id}</h3>
                                        <p className="report-date">
                                            {new Date(report.created_at).toLocaleDateString()}
                                        </p>
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
                                        <span className="detail-value">{report.metrics?.join(', ')}</span>
                                    </div>
                                    <div className="report-detail">
                                        <span className="detail-label">Format:</span>
                                        <span className="detail-value uppercase">{report.format}</span>
                                    </div>
                                </div>

                                <div className="report-footer">
                                    <button className="btn btn-sm btn-primary" title="Download (Coming soon)">
                                        📥 Download
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
