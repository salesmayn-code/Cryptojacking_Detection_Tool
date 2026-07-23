import React, { useEffect, useMemo, useState } from 'react';
import { authAPI, systemsAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import NotificationSettings from './NotificationSettings';
import './Profile.css';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const ProfilePage = () => {
    const { user, setUserData } = useAuth();

    const [loading, setLoading] = useState(true);
    const [savingProfile, setSavingProfile] = useState(false);
    const [savingPassword, setSavingPassword] = useState(false);
    const [uploadingPicture, setUploadingPicture] = useState(false);

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
            return 'Active';
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

    useEffect(() => {
        fetchProfile();
        fetchAgentStatus();
    }, []);

    const pictureUrl = useMemo(() => {
        const url = profile?.profile_picture_url;
        if (!url) return null;
        if (url.startsWith('http://') || url.startsWith('https://')) return url;
        return `${API_BASE_URL}${url}`;
    }, [profile]);

    const fetchProfile = async () => {
        try {
            setLoading(true);
            setError('');
            const response = await authAPI.getProfile();
            const data = response.data;
            setProfile(data);
            setFullName(data.full_name || '');

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
            setLoading(false);
        }
    };

    const fetchAgentStatus = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/agent/status`);
            if (!response.ok) return;
            const data = await response.json();
            setAgentStatus(data);
        } catch (err) {
            console.error('Error fetching agent status:', err);
        }
    };

    const handleDownloadLatestAgent = () => {
        window.open(`${API_BASE_URL}/api/agent/download`, '_blank', 'noopener,noreferrer');
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
            setMessage('Profile updated successfully.');
            await fetchProfile();
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
            setMessage('Password updated successfully.');
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
            setMessage('Profile picture updated.');
            await fetchProfile();
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to upload profile picture');
        } finally {
            setUploadingPicture(false);
            e.target.value = '';
        }
    };

    if (loading) {
        return (
            <div className="profile-page">
                <div className="flex-center" style={{ minHeight: '400px' }}>
                    <div className="spinner"></div>
                </div>
            </div>
        );
    }

    return (
        <div className="profile-page fade-in">
            {message && <div className="profile-banner success">{message}</div>}
            {error && <div className="profile-banner error">{error}</div>}

            <div className="profile-grid">
                <section className="profile-card profile-hero">
                    <div className="profile-identity">
                        <div className="profile-picture-wrap">
                            {pictureUrl ? (
                                <img src={pictureUrl} alt="Profile" className="profile-picture" />
                            ) : (
                                <div className="profile-picture placeholder">
                                    {(profile?.full_name || user?.full_name || 'U').slice(0, 1).toUpperCase()}
                                </div>
                            )}
                            <label className="btn btn-secondary btn-sm upload-btn">
                                {uploadingPicture ? 'Uploading...' : 'Upload Picture'}
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
                            <h3>{profile?.full_name || user?.full_name || 'User'}</h3>
                            <p className="profile-email">{profile?.email}</p>
                            <div className="profile-badges">
                                <span className={`badge badge-${systemStatus === 'online' ? 'success' : 'warning'}`}>
                                    {systemStatus}
                                </span>
                                <span className="badge badge-muted">{lastSeenLabel}</span>
                            </div>
                        </div>
                    </div>

                    <div className="profile-meta-grid">
                        <div className="meta-card">
                            <span className="meta-label">System ID</span>
                            <code className="meta-value">{profile?.system_id}</code>
                        </div>
                        <div className="meta-card">
                            <span className="meta-label">API Key</span>
                            <code className="meta-value meta-value-compact">{profile?.api_key}</code>
                        </div>
                    </div>
                </section>

                <section className="profile-card agent-card">
                    <div className="agent-download-panel">
                        <div className="agent-download-copy">
                            <h4>Monitoring Agent</h4>
                            <p>Download the latest build for Windows.</p>
                            {agentStatus && (
                                <div className="agent-download-meta">
                                    <span>Version: v{agentStatus.agent_version}</span>
                                    {agentStatus.checksum && (
                                        <span className="agent-checksum">SHA-256: {agentStatus.checksum}</span>
                                    )}
                                </div>
                            )}
                        </div>
                        <button
                            type="button"
                            className="btn btn-primary"
                            onClick={handleDownloadLatestAgent}
                        >
                            Download Agent
                        </button>
                    </div>
                </section>

                <section className="profile-card">
                    <h3>Update Profile</h3>
                    <form onSubmit={handleProfileSave}>
                        <div className="form-group">
                            <label className="form-label">Full Name</label>
                            <input
                                type="text"
                                className="form-input"
                                value={fullName}
                                onChange={(e) => setFullName(e.target.value)}
                                required
                            />
                        </div>
                        <button type="submit" className="btn btn-primary" disabled={savingProfile}>
                            {savingProfile ? 'Saving...' : 'Save Profile'}
                        </button>
                    </form>
                </section>

                <section className="profile-card">
                    <h3>Change Password</h3>
                    <form onSubmit={handlePasswordSave}>
                        <div className="form-group">
                            <label className="form-label">Current Password</label>
                            <input
                                type="password"
                                className="form-input"
                                value={passwordForm.current_password}
                                onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label className="form-label">New Password</label>
                            <input
                                type="password"
                                className="form-input"
                                minLength={6}
                                value={passwordForm.new_password}
                                onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Confirm New Password</label>
                            <input
                                type="password"
                                className="form-input"
                                minLength={6}
                                value={passwordForm.confirm_new_password}
                                onChange={(e) => setPasswordForm({ ...passwordForm, confirm_new_password: e.target.value })}
                                required
                            />
                        </div>
                        <button type="submit" className="btn btn-primary" disabled={savingPassword}>
                            {savingPassword ? 'Updating...' : 'Update Password'}
                        </button>
                    </form>
                </section>

                <section className="profile-card" style={{ gridColumn: '1 / -1' }}>
                    <NotificationSettings />
                </section>
            </div>
        </div>
    );
};

export default ProfilePage;
