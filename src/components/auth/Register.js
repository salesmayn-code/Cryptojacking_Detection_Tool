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

    // Post-registration state
    const [registered, setRegistered] = useState(false);
    const [credentials, setCredentials] = useState(null);
    const [copied, setCopied] = useState({ systemId: false });

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
            setCopied(prev => ({ ...prev, [field]: true }));
            setTimeout(() => setCopied(prev => ({ ...prev, [field]: false })), 2000);
        });
    };

    const handleDownloadAgent = () => {
        const base = process.env.REACT_APP_API_URL || 'http://localhost:8000';
        window.open(`${base}/api/agent/download`, '_blank', 'noopener,noreferrer');
    };

    // =====================================================
    // POST-REGISTRATION: Agent Setup Page
    // =====================================================
    if (registered && credentials) {
        return (
            <div className="auth-container">
                <div className="auth-card setup-card">
                    <div className="auth-glow-bar auth-glow-bar-success"></div>
                    <div className="auth-theme-toggle"><ThemeToggle /></div>

                    <div className="auth-header">
                        <div className="auth-logo">
                            <div className="auth-logo-icon success-pulse">OK</div>
                        </div>
                        <h1>Welcome, {credentials.full_name || 'User'}!</h1>
                        <p className="auth-subtitle">Your account is ready. Set up the tray agent below.</p>
                    </div>

                    {/* Credentials Card */}
                    <div className="credentials-card">
                        <div className="credentials-header">
                            <span className="credentials-header-icon">SYSTEM</span>
                            <div>
                                <h3>Your System Identity</h3>
                                <p>Save your System ID now. Open Profile to copy API key when configuring the tray agent.</p>
                            </div>
                        </div>

                        <div className="credential-item">
                            <label className="credential-label">System ID</label>
                            <div className="credential-value-row">
                                <code className="credential-code">{credentials.system_id}</code>
                                <button
                                    className={`btn-copy ${copied.systemId ? 'copied' : ''}`}
                                    onClick={() => copyToClipboard(credentials.system_id, 'systemId')}
                                >
                                    {copied.systemId ? 'Copied' : 'Copy'}
                                </button>
                            </div>
                        </div>

                    </div>

                    {/* Agent Setup Card */}
                    <div className="agent-setup-card">
                        <div className="credentials-header">
                            <span className="credentials-header-icon">GUI</span>
                            <div>
                                <h3>Install Monitoring Agent</h3>
                                <p>Use the tray-based GUI agent from the new build</p>
                            </div>
                        </div>

                        <div className="setup-steps">
                            <div className="setup-step">
                                <div className="step-number">1</div>
                                <div className="step-content">
                                    <div className="step-title">Download Agent</div>
                                    <div className="step-desc">Get the Windows monitoring executable</div>
                                    <button
                                        className="btn btn-primary btn-sm btn-download"
                                        onClick={handleDownloadAgent}
                                    >
                                        Download CryptoDetect-Agent-v9.exe
                                    </button>
                                </div>
                            </div>

                            <div className="setup-step">
                                <div className="step-number">2</div>
                                <div className="step-content">
                                    <div className="step-title">Run the Agent</div>
                                    <div className="step-desc">Double-click the downloaded <code>.exe</code> file</div>
                                </div>
                            </div>

                            <div className="setup-step">
                                <div className="step-number">3</div>
                                <div className="step-content">
                                    <div className="step-title">Enter System ID and API Key</div>
                                    <div className="step-desc">
                                        Open the tray setup window, paste both values, then validate and start monitoring
                                    </div>
                                </div>
                            </div>

                            <div className="setup-step">
                                <div className="step-number step-number-success">DONE</div>
                                <div className="step-content">
                                    <div className="step-title">You're Protected!</div>
                                    <div className="step-desc">
                                        ML-powered monitoring begins immediately. View results on your dashboard.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button
                        className="btn btn-primary btn-block btn-glow"
                        onClick={() => navigate('/dashboard')}
                    >
                        Go to Dashboard
                    </button>

                    <p className="setup-footnote">
                        You can also set up the agent later from your dashboard settings
                    </p>
                </div>
            </div>
        );
    }

    // =====================================================
    // REGISTRATION FORM
    // =====================================================
    return (
        <div className="auth-container">
            <div className="auth-card">
                <div className="auth-glow-bar"></div>
                <div className="auth-theme-toggle"><ThemeToggle /></div>

                <div className="auth-header">
                    <div className="auth-logo">
                        <div className="auth-logo-icon">CD</div>
                        <div className="auth-logo-ring"></div>
                    </div>
                    <h1>Create Account</h1>
                    <p className="auth-subtitle">Start protecting your system from cryptojacking</p>
                </div>

                {error && (
                    <div className="alert alert-danger">
                        <span>!</span>
                        <span>{error}</span>
                    </div>
                )}

                <form onSubmit={handleSubmit} className="auth-form">
                    <div className="form-group">
                        <label htmlFor="reg-fullName" className="form-label">Full Name</label>
                        <div className="input-wrapper">
                            <span className="input-icon">ID</span>
                            <input
                                type="text"
                                id="reg-fullName"
                                name="fullName"
                                className="form-input form-input-icon"
                                value={formData.fullName}
                                onChange={handleChange}
                                required
                                placeholder="John Doe"
                            />
                        </div>
                    </div>

                    <div className="form-group">
                        <label htmlFor="reg-email" className="form-label">Email Address</label>
                        <div className="input-wrapper">
                            <span className="input-icon">@</span>
                            <input
                                type="email"
                                id="reg-email"
                                name="email"
                                className="form-input form-input-icon"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                placeholder="you@example.com"
                            />
                        </div>
                    </div>

                    <div className="form-row">
                        <div className="form-group">
                            <label htmlFor="reg-password" className="form-label">Password</label>
                            <div className="input-wrapper">
                                <span className="input-icon">PW</span>
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    id="reg-password"
                                    name="password"
                                    className="form-input form-input-icon"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    placeholder="********"
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
                                <span className="input-icon">PW</span>
                                <input
                                    type={showConfirmPassword ? 'text' : 'password'}
                                    id="reg-confirmPassword"
                                    name="confirmPassword"
                                    className="form-input form-input-icon"
                                    value={formData.confirmPassword}
                                    onChange={handleChange}
                                    required
                                    placeholder="********"
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
                        className="btn btn-primary btn-block btn-glow"
                        disabled={
                            loading ||
                            !formData.fullName.trim() ||
                            !formData.email.trim() ||
                            !formData.password ||
                            !formData.confirmPassword
                        }
                    >
                        {loading ? (
                            <>
                                <span className="spinner-small"></span>
                                Creating account...
                            </>
                        ) : (
                            <>Create Account</>
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    <p>
                        Already have an account?{' '}
                        <Link to="/login" className="auth-link">Sign in</Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Register;
