import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import ThemeToggle from '../ThemeToggle';
import './Auth.css';

const Register = () => {
    const navigate = useNavigate();
    const { register } = useAuth();
    const [formData, setFormData] = useState({
        fullName: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const [registered, setRegistered] = useState(false);
    const [credentials, setCredentials] = useState(null);
    const [copied, setCopied] = useState({ systemId: false, apiKey: false });

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
        setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (!formData.fullName.trim()) {
            setError('Full name is required');
            return;
        }

        if (!formData.email.trim()) {
            setError('Email is required');
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (formData.password.length < 6) {
            setError('Password must be at least 6 characters');
            return;
        }

        setLoading(true);

        const result = await register(
            formData.email.trim(),
            formData.password,
            formData.fullName.trim()
        );

        if (result.success) {
            const storedUser = sessionStorage.getItem('user');
            const userData = result.user || (storedUser ? JSON.parse(storedUser) : null);
            if (userData) {
                setCredentials(userData);
                setRegistered(true);
            } else {
                setError('Registration completed, but user session was not initialized. Please log in.');
                navigate('/login');
            }
        } else {
            setError(result.error);
        }

        setLoading(false);
    };

    const copyToClipboard = (text, field) => {
        navigator.clipboard.writeText(text).then(() => {
            setCopied((prev) => ({ ...prev, [field]: true }));
            setTimeout(() => setCopied((prev) => ({ ...prev, [field]: false })), 2000);
        });
    };

    const handleDownloadAgent = () => {
        const base = process.env.REACT_APP_API_URL || 'http://localhost:8000';
        window.open(`${base}/api/agent/download`, '_blank', 'noopener,noreferrer');
    };

    if (registered && credentials) {
        return (
            <div className="auth-container">
                <div className="auth-card setup-card">
                    <div className="auth-theme-toggle"><ThemeToggle /></div>

                    <div className="auth-header">
                        <div className="auth-logo">
                            <div className="auth-logo-icon success-badge" aria-hidden="true">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
                                    <polyline points="20 6 9 17 4 12" />
                                </svg>
                            </div>
                        </div>
                        <h1>Endpoint Provisioned</h1>
                        <p className="auth-subtitle">
                            Welcome, {credentials.full_name || 'Operator'}. Copy your credentials below before leaving this page.
                        </p>
                    </div>

                    <div className="credentials-card">
                        <div className="credentials-header">
                            <span className="credentials-header-icon" aria-hidden="true">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                            </span>
                            <div>
                                <h3>Endpoint Identity &amp; One-Time Key</h3>
                                <p>Your API key is hashed with SHA-256 at rest and shown in plaintext only once.</p>
                            </div>
                        </div>

                        <div className="credential-item">
                            <label className="credential-label">System ID</label>
                            <div className="credential-value-row">
                                <code className="credential-code">{credentials.system_id}</code>
                                <button
                                    type="button"
                                    className={`btn-copy ${copied.systemId ? 'copied' : ''}`}
                                    onClick={() => copyToClipboard(credentials.system_id, 'systemId')}
                                >
                                    {copied.systemId ? 'Copied' : 'Copy'}
                                </button>
                            </div>
                        </div>

                        {credentials.api_key && (
                            <div className="credential-item">
                                <label className="credential-label">One-Time API Key</label>
                                <div className="credential-value-row">
                                    <code className="credential-code">{credentials.api_key}</code>
                                    <button
                                        type="button"
                                        className={`btn-copy ${copied.apiKey ? 'copied' : ''}`}
                                        onClick={() => copyToClipboard(credentials.api_key, 'apiKey')}
                                    >
                                        {copied.apiKey ? 'Copied' : 'Copy'}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="agent-setup-card">
                        <div className="credentials-header">
                            <span className="credentials-header-icon" aria-hidden="true">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                                    <line x1="8" y1="21" x2="16" y2="21" />
                                    <line x1="12" y1="17" x2="12" y2="21" />
                                </svg>
                            </span>
                            <div>
                                <h3>Deploy Windows Monitoring Agent</h3>
                                <p>Install the v1.0 system-tray executable on the target workstation.</p>
                            </div>
                        </div>

                        <div className="setup-steps">
                            <div className="setup-step">
                                <div className="step-number">1</div>
                                <div className="step-content">
                                    <div className="step-title">Download Agent Executable</div>
                                    <div className="step-desc">Standalone Windows build with NVML GPU and PE static analysis</div>
                                    <button
                                        type="button"
                                        className="btn btn-primary btn-sm btn-download"
                                        onClick={handleDownloadAgent}
                                    >
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                            <polyline points="7 10 12 15 17 10" />
                                            <line x1="12" y1="15" x2="12" y2="3" />
                                        </svg>
                                        <span>Download CryptoDetect-Agent-v1.exe</span>
                                    </button>
                                </div>
                            </div>

                            <div className="setup-step">
                                <div className="step-number">2</div>
                                <div className="step-content">
                                    <div className="step-title">Launch Agent Console</div>
                                    <div className="step-desc">Run <code>CryptoDetect-Agent-v1.exe</code> to open the desktop tray agent</div>
                                </div>
                            </div>

                            <div className="setup-step">
                                <div className="step-number">3</div>
                                <div className="step-content">
                                    <div className="step-title">Bind Credentials &amp; Start</div>
                                    <div className="step-desc">
                                        Click <strong>Configure</strong>, paste your System ID and One-Time API Key, and click <strong>Save and Start</strong>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button
                        type="button"
                        className="btn btn-primary btn-block"
                        onClick={() => navigate('/dashboard')}
                    >
                        Continue to Operations Dashboard
                    </button>
                </div>
            </div>
        );
    }

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
                        Provision a monitored endpoint in under a minute.
                    </h2>
                    <p className="auth-showcase-copy">
                        Each registered account receives a dedicated System ID and a SHA-256 authenticated API key for the Windows system-tray agent.
                    </p>

                    <div className="auth-spec-list">
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Agent Footprint</span>
                            <span className="auth-spec-val">&lt; 2% CPU · ~62 MB resident memory</span>
                        </div>
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Outage Resilience</span>
                            <span className="auth-spec-val">60-sample persistent disk retry queue</span>
                        </div>
                        <div className="auth-spec-row">
                            <span className="auth-spec-key">Key Storage</span>
                            <span className="auth-spec-val">SHA-256 hashed at rest</span>
                        </div>
                    </div>
                </section>

                <section className="auth-card">
                    <div className="auth-theme-toggle"><ThemeToggle /></div>

                    <div className="auth-header">
                        <h1>Create Operator Account</h1>
                        <p className="auth-subtitle">Register your identity and provision a new monitored system.</p>
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
                            <label htmlFor="reg-fullName" className="form-label">Full Name</label>
                            <div className="input-wrapper">
                                <span className="input-icon" aria-hidden="true">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                                        <circle cx="12" cy="7" r="4" />
                                    </svg>
                                </span>
                                <input
                                    type="text"
                                    id="reg-fullName"
                                    name="fullName"
                                    className="form-input form-input-icon"
                                    value={formData.fullName}
                                    onChange={handleChange}
                                    required
                                    placeholder="Alex Morgan"
                                />
                            </div>
                        </div>

                        <div className="form-group">
                            <label htmlFor="reg-email" className="form-label">Email Address</label>
                            <div className="input-wrapper">
                                <span className="input-icon" aria-hidden="true">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                                        <polyline points="22,6 12,13 2,6" />
                                    </svg>
                                </span>
                                <input
                                    type="email"
                                    id="reg-email"
                                    name="email"
                                    className="form-input form-input-icon"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    placeholder="operator@organization.com"
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="reg-password" className="form-label">Password</label>
                                <div className="input-wrapper">
                                    <span className="input-icon" aria-hidden="true">
                                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                        </svg>
                                    </span>
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        id="reg-password"
                                        name="password"
                                        className="form-input form-input-icon"
                                        value={formData.password}
                                        onChange={handleChange}
                                        required
                                        placeholder="Min. 6 chars"
                                        minLength="6"
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

                            <div className="form-group">
                                <label htmlFor="reg-confirmPassword" className="form-label">Confirm</label>
                                <div className="input-wrapper">
                                    <span className="input-icon" aria-hidden="true">
                                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                        </svg>
                                    </span>
                                    <input
                                        type={showConfirmPassword ? 'text' : 'password'}
                                        id="reg-confirmPassword"
                                        name="confirmPassword"
                                        className="form-input form-input-icon"
                                        value={formData.confirmPassword}
                                        onChange={handleChange}
                                        required
                                        placeholder="Repeat"
                                    />
                                    <button
                                        type="button"
                                        className="input-trailing-btn"
                                        onClick={() => setShowConfirmPassword((prev) => !prev)}
                                        aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                                    >
                                        {showConfirmPassword ? 'Hide' : 'Show'}
                                    </button>
                                </div>
                            </div>
                        </div>

                        <button
                            type="submit"
                            className={`btn btn-primary btn-block ${loading ? 'is-busy' : ''}`}
                            disabled={
                                loading ||
                                !formData.fullName.trim() ||
                                !formData.email.trim() ||
                                !formData.password ||
                                !formData.confirmPassword
                            }
                        >
                            {loading && <span className="spinner-small" aria-hidden="true"></span>}
                            <span className="btn-label">{loading ? 'Creating account...' : 'Create Account'}</span>
                        </button>
                    </form>

                    <div className="auth-footer">
                        <p>
                            Already registered?{' '}
                            <Link to="/login" className="auth-link">Sign in</Link>
                        </p>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default Register;
