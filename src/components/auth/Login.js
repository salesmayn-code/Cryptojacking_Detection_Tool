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
            <div className="auth-card">
                <div className="auth-glow-bar"></div>
                <div className="auth-theme-toggle"><ThemeToggle /></div>

                <div className="auth-header">
                    <div className="auth-logo">
                        <div className="auth-logo-icon">CD</div>
                        <div className="auth-logo-ring"></div>
                    </div>
                    <h1>CryptoDetect</h1>
                    <p className="auth-subtitle">Real-time Cryptojacking Detection System</p>
                </div>

                {error && (
                    <div className="alert alert-danger">
                        <span>!</span>
                        <span>{error}</span>
                    </div>
                )}

                <form onSubmit={handleSubmit} className="auth-form">
                    <div className="form-group">
                        <label htmlFor="login-email" className="form-label">Email Address</label>
                        <div className="input-wrapper">
                            <span className="input-icon">@</span>
                            <input
                                type="email"
                                id="login-email"
                                name="email"
                                className="form-input form-input-icon"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                placeholder="you@example.com"
                                autoComplete="email"
                            />
                        </div>
                    </div>

                    <div className="form-group">
                        <label htmlFor="login-password" className="form-label">Password</label>
                        <div className="input-wrapper">
                            <span className="input-icon">PW</span>
                            <input
                                type={showPassword ? 'text' : 'password'}
                                id="login-password"
                                name="password"
                                className="form-input form-input-icon"
                                value={formData.password}
                                onChange={handleChange}
                                required
                                placeholder="********"
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
                        className="btn btn-primary btn-block btn-glow"
                        disabled={loading || !formData.email.trim() || !formData.password}
                    >
                        {loading ? (
                            <>
                                <span className="spinner-small"></span>
                                Signing in...
                            </>
                        ) : (
                            <>Sign In</>
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    <p>
                        Don't have an account?{' '}
                        <Link to="/register" className="auth-link">Create one</Link>
                    </p>
                </div>

                <div className="auth-features">
                    <div className="auth-feature">
                        <span>ML</span>
                        <span>ML-Powered Detection</span>
                    </div>
                    <div className="auth-feature">
                        <span>RT</span>
                        <span>Real-time Monitoring</span>
                    </div>
                    <div className="auth-feature">
                        <span>AL</span>
                        <span>Instant Alerts</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;
