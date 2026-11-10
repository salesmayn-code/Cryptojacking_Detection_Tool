import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { authAPI, systemsAPI, API_BASE_URL } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import NotificationSettings from './NotificationSettings';
import './Profile.css';



const ProfilePage = () => {
    const { user, setUserData, refreshProfile } = useAuth();
    const [claimingAdmin, setClaimingAdmin] = useState(false);

    const [initialLoading, setInitialLoading] = useState(true);
    const [savingProfile, setSavingProfile] = useState(false);
    const [savingPassword, setSavingPassword] = useState(false);
    const [uploadingPicture, setUploadingPicture] = useState(false);
    const [confirmRotate, setConfirmRotate] = useState(false);
    const [rotatingKey, setRotatingKey] = useState(false);
    const [freshApiKey, setFreshApiKey] = useState('');
    const [copiedField, setCopiedField] = useState('');

    const [profile, setProfile] = useState(null);
    const [systemStatus, setSystemStatus] = useState('offline');
    const [systemLastSeen, setSystemLastSeen] = useState(null);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [agentStatus, setAgentStatus] = useState(null);

    const [fullName, setFullName] = useState('');
    const [passwordForm, setPasswordForm] = useState({
        current_password: '',
        new_password: '',
        confirm_new_password: '',
    });

    const lastSeenLabel = useMemo(() => {
        if (systemStatus === 'online') {
            return 'Active Heartbeat';
        }

        const lastSeenValue = systemLastSeen || profile?.last_seen;
        if (!lastSeenValue) {
            return 'No telemetry yet';
        }
        const lastSeenMs = new Date(lastSeenValue).getTime();
        if (Number.isNaN(lastSeenMs)) {
            return 'No telemetry yet';
        }
        return new Date(lastSeenValue).toLocaleString();
    }, [profile, systemLastSeen, systemStatus]);

    const loadAll = useCallback(async () => {
        try {
            setError('');
            const [profileRes, agentRes] = await Promise.all([
                authAPI.getProfile(),
                fetch(`${API_BASE_URL}/api/agent/status`)
                    .then((r) => (r.ok ? r.json() : null))
                    .catch(() => null),
            ]);

            const data = profileRes.data;
            setProfile(data);
            setFullName(data.full_name || '');
            if (agentRes) setAgentStatus(agentRes);

            if (data?.system_id) {
                try {
                    const systemRes = await systemsAPI.getById(data.system_id);
                    const systemData = systemRes.data || {};
                    setSystemStatus(systemData.status || 'offline');
                    setSystemLastSeen(systemData.last_seen || null);
                } catch (systemErr) {
                    console.error('Error fetching system status:', systemErr);
                }
            }
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load profile');
        } finally {
            setInitialLoading(false);
        }
    }, []);

    useEffect(() => {
        loadAll();
    }, [loadAll]);

    const pictureUrl = useMemo(() => {
        const url = profile?.profile_picture_url;
        if (!url) return null;
        if (url.startsWith('http://') || url.startsWith('https://')) return url;
        return `${API_BASE_URL}${url}`;
    }, [profile]);

    const copyValue = async (val, fieldName) => {
        if (!val) return;
        try {
            await navigator.clipboard.writeText(val);
            setCopiedField(fieldName);
            setTimeout(() => setCopiedField(''), 1800);
        } catch {
            // Clipboard unavailable
        }
    };

    const handleDownloadLatestAgent = () => {
        window.open(`${API_BASE_URL}/api/agent/download`, '_blank', 'noopener,noreferrer');
    };

    const handleRotateApiKey = async () => {
        setConfirmRotate(false);
        setRotatingKey(true);
        setError('');
        setMessage('');
        try {
            const response = await authAPI.regenerateApiKey();
            const newKey = response.data?.api_key || '';
            setFreshApiKey(newKey);
            setMessage(response.data?.message || 'New API key generated. Copy it below — it will not be shown in full again.');
            await loadAll();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to rotate API key');
        } finally {
            setRotatingKey(false);
        }
    };

    const handleProfileSave = async (e) => {
        e.preventDefault();
        setSavingProfile(true);
        setMessage('');
        setError('');

        try {
            const response = await authAPI.updateProfile({ full_name: fullName });
            const updatedUser = response.data.user;
            setUserData({ ...(user || {}), ...updatedUser });
            setMessage('Operator profile saved.');
            await loadAll();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to update profile');
        } finally {
            setSavingProfile(false);
        }
    };

    const handlePasswordSave = async (e) => {
        e.preventDefault();
        setSavingPassword(true);
        setMessage('');
        setError('');

        if (passwordForm.new_password !== passwordForm.confirm_new_password) {
            setSavingPassword(false);
            setError('New password and confirmation do not match.');
            return;
        }

        try {
            await authAPI.changePassword({
                current_password: passwordForm.current_password,
                new_password: passwordForm.new_password,
            });
            setMessage('Account password updated.');
            setPasswordForm({ current_password: '', new_password: '', confirm_new_password: '' });
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to update password');
        } finally {
            setSavingPassword(false);
        }
    };

    const handlePictureUpload = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setUploadingPicture(true);
        setMessage('');
        setError('');

        try {
            const response = await authAPI.uploadProfilePicture(file);
            const profilePictureUrl = response.data.profile_picture_url;
            setUserData({ ...(user || {}), profile_picture_url: profilePictureUrl });
            setMessage('Avatar updated.');
            await loadAll();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to upload profile picture');
        } finally {
            setUploadingPicture(false);
            e.target.value = '';
        }
    };

    const handleClaimAdmin = async () => {
        setClaimingAdmin(true);
        setMessage('');
        setError('');
        try {
            const response = await authAPI.claimInitialAdmin();
            const updatedUser = response.data?.user || { ...(user || {}), role: 'admin' };
            setUserData(updatedUser);
            if (refreshProfile) {
                await refreshProfile();
            }
            setMessage(response.data?.message || 'Organization administrator role granted successfully!');
            await loadAll();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to claim organization administrator role.');
        } finally {
            setClaimingAdmin(false);
        }
    };

    if (initialLoading) {
        return (
            <div className="profile-page" aria-busy="true" aria-label="Loading settings and agent">
                <div className="profile-grid">
                    {[1, 2, 3, 4].map((idx) => (
                        <div key={idx} className="skeleton-card">
                            <div className="skeleton skeleton-line medium" />
                            <div className="skeleton" style={{ height: '120px', width: '100%', borderRadius: '8px' }} />
                        </div>
                    ))}
                </div>
            </div>
        );
    }

    const userRole = profile?.role || user?.role || 'user';

    return (
        <div className="profile-page fade-in">
            {message && <div className="profile-banner success" role="status">{message}</div>}
            {error && <div className="profile-banner error" role="alert">{error}</div>}

            {freshApiKey && (
                <div className="profile-key-reveal">
                    <div className="profile-key-reveal-head">
                        <div>
                            <div className="profile-key-title-row">
                                <h4>Copy your new Endpoint API Key now</h4>
                                <span className="badge badge-info">One-Time Key</span>
                            </div>
                            <p>For security, only the SHA-256 hash is stored at rest. Paste this key into the CryptoDetect Windows Agent Configure dialog.</p>
                        </div>
                        <button type="button" className="btn btn-sm btn-secondary" onClick={() => setFreshApiKey('')}>
                            Dismiss
                        </button>
                    </div>
                    <div className="profile-key-reveal-box">
                        <code>{freshApiKey}</code>
                        <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            onClick={() => copyValue(freshApiKey, 'freshKey')}
                        >
                            {copiedField === 'freshKey' ? 'Copied to Clipboard' : 'Copy Key'}
                        </button>
                    </div>
                </div>
            )}

            <div className="profile-grid">
                {userRole !== 'admin' && (
                    <div className="profile-admin-claim-card">
                        <div className="profile-admin-claim-content">
                            <div className="profile-admin-claim-icon" aria-hidden="true">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <line x1="12" y1="8" x2="12" y2="12" />
                                    <line x1="12" y1="16" x2="12.01" y2="16" />
                                </svg>
                            </div>
                            <div>
                                <h4>Claim Organization Admin</h4>
                                <p>
                                    First operator setup: Activate initial administrator privileges for this deployment to manage audit trails, alert actions, and system-wide security configurations.
                                </p>
                            </div>
                        </div>
                        <button
                            type="button"
                            className={`btn btn-primary ${claimingAdmin ? 'is-busy' : ''}`}
                            onClick={handleClaimAdmin}
                            disabled={claimingAdmin}
                        >
                            {claimingAdmin && <span className="spinner-small" aria-hidden="true" />}
                            <span>{claimingAdmin ? 'Claiming Admin...' : 'Activate Initial Admin Role'}</span>
                        </button>
                    </div>
                )}

                {/* Card 1: Endpoint Identity & Credentials */}
                <section className="profile-card profile-hero">
                    <div className="profile-identity">
                        <div className="profile-picture-wrap">
                            {pictureUrl ? (
                                <img src={pictureUrl} alt="Operator avatar" className="profile-picture" />
                            ) : (
                                <div className="profile-picture placeholder">
                                    {(profile?.full_name || user?.full_name || 'U').slice(0, 1).toUpperCase()}
                                </div>
                            )}
                            <label className="btn btn-secondary btn-xs upload-btn">
                                {uploadingPicture ? 'Uploading...' : 'Change Avatar'}
                                <input
                                    type="file"
                                    accept="image/png,image/jpeg,image/webp"
                                    onChange={handlePictureUpload}
                                    disabled={uploadingPicture}
                                    hidden
                                />
                            </label>
                        </div>

                        <div className="profile-identity-text">
                            <h3>{profile?.full_name || user?.full_name || 'Operator'}</h3>
                            <p className="profile-email">{profile?.email}</p>
                            <div className="profile-badges">
                                <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>
                                    <span className={`status-dot ${systemStatus}`} style={{ width: 6, height: 6 }} />
                                    {systemStatus}
                                </span>
                                <span className="badge badge-neutral tabular-nums">{lastSeenLabel}</span>
                                <span className={`badge badge-${userRole === 'admin' ? 'info' : 'neutral'}`}>
                                    Role: {userRole === 'admin' ? 'Admin' : 'Operator'}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div className="profile-meta-grid">
                        <div className="meta-card">
                            <div className="meta-card-head">
                                <span className="meta-label">Assigned System ID</span>
                                <button
                                    type="button"
                                    className="btn-link-inline"
                                    onClick={() => copyValue(profile?.system_id, 'sysId')}
                                >
                                    {copiedField === 'sysId' ? 'Copied' : 'Copy'}
                                </button>
                            </div>
                            <code className="meta-value">{profile?.system_id}</code>
                        </div>

                        <div className="meta-card">
                            <div className="meta-card-head">
                                <span className="meta-label">Endpoint API Key (Masked)</span>
                                {confirmRotate ? (
                                    <span className="inline-confirm-group">
                                        <button
                                            type="button"
                                            className="btn-link-inline danger"
                                            onClick={handleRotateApiKey}
                                            disabled={rotatingKey}
                                        >
                                            Confirm
                                        </button>
                                        <button
                                            type="button"
                                            className="btn-link-inline muted"
                                            onClick={() => setConfirmRotate(false)}
                                        >
                                            Cancel
                                        </button>
                                    </span>
                                ) : (
                                    <button
                                        type="button"
                                        className="btn-link-inline"
                                        onClick={() => setConfirmRotate(true)}
                                        disabled={rotatingKey}
                                    >
                                        {rotatingKey ? 'Rotating...' : 'Rotate Key'}
                                    </button>
                                )}
                            </div>
                            <code className="meta-value meta-value-compact">{profile?.api_key}</code>
                        </div>
                    </div>
                </section>

                {/* Card 2: Windows Endpoint Agent */}
                <section className="profile-card agent-card">
                    <div className="agent-download-panel">
                        <div className="agent-download-header">
                            <div className="agent-download-badge" aria-hidden="true">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <polyline points="8 12 11 15 16 9" />
                                </svg>
                            </div>
                            <div>
                                <h4>Windows Endpoint Agent</h4>
                                <p>Standalone background tray daemon with single-instance lock &amp; SHA-256 verified auto-update.</p>
                            </div>
                        </div>

                        {agentStatus && (
                            <div className="agent-download-meta">
                                <div className="agent-meta-row">
                                    <span className="agent-meta-label">Release Version</span>
                                    <code className="agent-meta-val tabular-nums">v{agentStatus.agent_version}</code>
                                </div>
                                {agentStatus.checksum && (
                                    <div className="agent-meta-row agent-meta-checksum-row">
                                        <div className="meta-card-head" style={{ width: '100%' }}>
                                            <span className="agent-meta-label">SHA-256 Digest</span>
                                            <button
                                                type="button"
                                                className="btn-link-inline"
                                                onClick={() => copyValue(agentStatus.checksum, 'sha256')}
                                            >
                                                {copiedField === 'sha256' ? 'Copied' : 'Copy Digest'}
                                            </button>
                                        </div>
                                        <code className="agent-checksum">{agentStatus.checksum}</code>
                                    </div>
                                )}
                            </div>
                        )}

                        <button
                            type="button"
                            className="btn btn-primary"
                            onClick={handleDownloadLatestAgent}
                        >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                <polyline points="7 10 12 15 17 10" />
                                <line x1="12" y1="15" x2="12" y2="3" />
                            </svg>
                            <span>Download CryptoDetect-Agent-v1.exe</span>
                        </button>
                    </div>
                </section>

                {/* Card 3: Operator Profile */}
                <section className="profile-card profile-form-card">
                    <h3>Operator Profile</h3>
                    <p className="profile-card-desc">
                        Display name shown across incident triage logs, generated compliance reports, and audit records.
                    </p>
                    <form onSubmit={handleProfileSave} className="profile-card-form">
                        <div className="form-group">
                            <label htmlFor="profile-fullname" className="form-label">Full Name</label>
                            <input
                                id="profile-fullname"
                                type="text"
                                className="form-input"
                                value={fullName}
                                onChange={(e) => setFullName(e.target.value)}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Registered Email</label>
                            <input
                                type="email"
                                className="form-input"
                                value={profile?.email || ''}
                                disabled
                            />
                        </div>
                        <div className="profile-form-footer">
                            <button type="submit" className={`btn btn-primary ${savingProfile ? 'is-busy' : ''}`} disabled={savingProfile}>
                                {savingProfile && <span className="spinner-small" aria-hidden="true" />}
                                <span className="btn-label">{savingProfile ? 'Saving...' : 'Save Profile'}</span>
                            </button>
                        </div>
                    </form>
                </section>

                {/* Card 4: Update Password */}
                <section className="profile-card profile-form-card">
                    <h3>Update Password</h3>
                    <form onSubmit={handlePasswordSave} className="profile-card-form">
                        <div className="form-group">
                            <label htmlFor="pw-current" className="form-label">Current Password</label>
                            <input
                                id="pw-current"
                                type="password"
                                className="form-input"
                                value={passwordForm.current_password}
                                onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                                required
                                autoComplete="current-password"
                            />
                        </div>
                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="pw-new" className="form-label">New Password</label>
                                <input
                                    id="pw-new"
                                    type="password"
                                    className="form-input"
                                    minLength={6}
                                    value={passwordForm.new_password}
                                    onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                                    required
                                    placeholder="Min. 6 chars"
                                    autoComplete="new-password"
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="pw-confirm" className="form-label">Confirm Password</label>
                                <input
                                    id="pw-confirm"
                                    type="password"
                                    className="form-input"
                                    minLength={6}
                                    value={passwordForm.confirm_new_password}
                                    onChange={(e) => setPasswordForm({ ...passwordForm, confirm_new_password: e.target.value })}
                                    required
                                    placeholder="Repeat password"
                                    autoComplete="new-password"
                                />
                            </div>
                        </div>
                        <div className="profile-form-footer">
                            <button type="submit" className={`btn btn-primary ${savingPassword ? 'is-busy' : ''}`} disabled={savingPassword}>
                                {savingPassword && <span className="spinner-small" aria-hidden="true" />}
                                <span className="btn-label">{savingPassword ? 'Updating...' : 'Update Password'}</span>
                            </button>
                        </div>
                    </form>
                </section>

                {/* Card 5: Alert Dispatch Channels */}
                <section className="profile-card" style={{ gridColumn: '1 / -1' }}>
                    <NotificationSettings />
                </section>
            </div>
        </div>
    );
};

export default ProfilePage;
