import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import ThemeToggle from '../ThemeToggle';
import './Auth.css';

const Login = () => {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [formData, setFormData] = useState({
        email: '',
        password: '',
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
        setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!formData.email.trim() || !formData.password) return;
        setLoading(true);
        setError('');

        const result = await login(formData.email, formData.password);

        if (result.success) {
            navigate('/dashboard');
        } else {
            setError(result.error);
        }

        setLoading(false);
    };

    return (
        <div className="auth-container">
            <div className="auth-shell">
                <section className="auth-showcase" aria-label="Platform capabilities">
                    <div className="auth-showcase-brand">
                        <div className="auth-logo-icon" aria-hidden="true">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                <polyline points="8.5 12.5 10.8 14.8 15.5 9.8" />
                            </svg>
                        </div>
                        <span>CryptoDetect Security</span>
                    </div>

                    <h2 className="auth-showcase-title">
                        Host telemetry and static binary defense against unauthorized cryptomining.
                    </h2>
                    <p className="auth-showcase-copy">
                        Continuous 5-second endpoint sampling paired with XGBoost and Random Forest classification, PE entropy analysis, and mining pool port inspection.
                    </p>

                    <div className="auth-spec-list">
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Behavioral Engine</span>
                            <span className="auth-spec-val">20 host features · XGBoost + Random Forest</span>
                        </div>
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Static Analysis</span>
                            <span className="auth-spec-val">PE section entropy, imports &amp; stratum strings</span>
                        </div>
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Endpoint Agent</span>
                            <span className="auth-spec-val">Windows tray v1.0 · 30s batching &amp; offline queue</span>
                        </div>
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Alert Gate</span>
                            <span className="auth-spec-val">3 consecutive detections ≥ 0.70 confidence</span>
                        </div>
                    </div>
                </section>

                <section className="auth-card">
                    <div className="auth-theme-toggle"><ThemeToggle /></div>

                    <div className="auth-header">
                        <h1>Sign in to CryptoDetect</h1>
                        <p className="auth-subtitle">Access your monitored endpoints, telemetry streams, and incident reports.</p>
                    </div>

                    {error && (
                        <div className="alert alert-danger" role="alert">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="12" y1="8" x2="12" y2="12" />
                                <line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                            <span>{error}</span>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="login-email" className="form-label">Email Address</label>
                            <div className="input-wrapper">
                                <span className="input-icon" aria-hidden="true">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                                        <polyline points="22,6 12,13 2,6" />
                                    </svg>
                                </span>
                                <input
                                    type="email"
                                    id="login-email"
                                    name="email"
                                    className="form-input form-input-icon"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    placeholder="operator@organization.com"
                                    autoComplete="email"
                                />
                            </div>
                        </div>

                        <div className="form-group">
                            <label htmlFor="login-password" className="form-label">Password</label>
                            <div className="input-wrapper">
                                <span className="input-icon" aria-hidden="true">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                    </svg>
                                </span>
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    id="login-password"
                                    name="password"
                                    className="form-input form-input-icon"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    placeholder="Enter your password"
                                    autoComplete="current-password"
                                />
                                <button
                                    type="button"
                                    className="input-trailing-btn"
                                    onClick={() => setShowPassword((prev) => !prev)}
                                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                                >
                                    {showPassword ? 'Hide' : 'Show'}
                                </button>
                            </div>
                        </div>

                        <button
                            type="submit"
                            className={`btn btn-primary btn-block ${loading ? 'is-busy' : ''}`}
                            disabled={loading || !formData.email.trim() || !formData.password}
                        >
                            {loading && <span className="spinner-small" aria-hidden="true"></span>}
                            <span className="btn-label">{loading ? 'Signing in...' : 'Sign In'}</span>
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>
                            Need to register a new endpoint?{' '}
                            <Link to="/register" className="auth-link">Create an account</Link>
                        </p>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default Login;
