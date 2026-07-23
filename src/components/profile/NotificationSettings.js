import React, { useState, useEffect, useCallback } from 'react';
import { notificationsAPI } from '../../services/api';
import './NotificationSettings.css';

const NotificationSettings = () => {
    const [channels, setChannels] = useState([]);
    const [loading, setLoading] = useState(true);
    const [message, setMessage] = useState(null);
    const [newType, setNewType] = useState('email');
    const [newTarget, setNewTarget] = useState('');
    const [adding, setAdding] = useState(false);
    const [verifyState, setVerifyState] = useState({});

    const showMessage = (text, type = 'success') => {
        setMessage({ text, type });
        setTimeout(() => setMessage(null), 4000);
    };

    const fetchChannels = useCallback(async () => {
        try {
            const res = await notificationsAPI.getChannels();
            setChannels(res.data.channels || []);
        } catch (err) {
            console.error('Failed to fetch channels:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchChannels();
    }, [fetchChannels]);

    const handleAdd = async (e) => {
        e.preventDefault();
        if (!newTarget.trim()) return;
        setAdding(true);
        try {
            const res = await notificationsAPI.addChannel({
                channel_type: newType,
                target: newTarget.trim(),
            });
            setNewTarget('');
            await fetchChannels();

            // Show error or success message from backend
            if (res.data?.send_error) {
                showMessage(res.data.send_error, 'error');
            } else {
                showMessage(res.data?.message || 'Channel added! Check your device for the verification code.');
            }
        } catch (err) {
            showMessage(err.response?.data?.detail || 'Failed to add channel', 'error');
        } finally {
            setAdding(false);
        }
    };

    const handleVerify = async (channelId) => {
        const code = verifyState[channelId];
        if (!code || code.length < 6) return;
        try {
            await notificationsAPI.verifyChannel(channelId, { code });
            showMessage('Channel verified successfully!');
            setVerifyState((prev) => ({ ...prev, [channelId]: '' }));
            await fetchChannels();
        } catch (err) {
            showMessage(err.response?.data?.detail || 'Verification failed', 'error');
        }
    };

    const handleResend = async (channelId) => {
        try {
            const res = await notificationsAPI.resendCode(channelId);
            showMessage(res.data?.message || 'Verification code resent! Check your device.');
        } catch (err) {
            showMessage(err.response?.data?.detail || 'Resend failed', 'error');
        }
    };

    const handleToggle = async (channel) => {
        try {
            await notificationsAPI.toggleChannel(channel.id, { enabled: !channel.enabled });
            await fetchChannels();
        } catch (err) {
            showMessage('Toggle failed', 'error');
        }
    };

    const handleDelete = async (channelId) => {
        if (!window.confirm('Remove this notification channel?')) return;
        try {
            await notificationsAPI.deleteChannel(channelId);
            showMessage('Channel removed');
            await fetchChannels();
        } catch (err) {
            showMessage('Delete failed', 'error');
        }
    };

    return (
        <div className="notif-section">
            <h3 className="notif-section-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                </svg>
                Notification Channels
            </h3>

            {message && (
                <div className={`notif-message ${message.type}`}>{message.text}</div>
            )}

            <form className="notif-add-form" onSubmit={handleAdd}>
                <div className="form-group">
                    <label>Type</label>
                    <select value={newType} onChange={(e) => setNewType(e.target.value)}>
                        <option value="email">📧 Email</option>
                        <option value="whatsapp">📱 WhatsApp</option>
                    </select>
                </div>
                <div className="form-group" style={{ flex: 1 }}>
                    <label>{newType === 'email' ? 'Email Address' : 'Phone Number'}</label>
                    <input
                        type={newType === 'email' ? 'email' : 'tel'}
                        placeholder={newType === 'email' ? 'alerts@example.com' : '+923001234567'}
                        value={newTarget}
                        onChange={(e) => setNewTarget(e.target.value)}
                        required
                    />
                </div>
                <button className="btn btn-primary btn-sm" type="submit" disabled={adding}>
                    {adding ? 'Adding...' : 'Add Channel'}
                </button>
            </form>

            {loading ? (
                <div className="notif-empty">Loading channels...</div>
            ) : channels.length === 0 ? (
                <div className="notif-empty">
                    No notification channels configured. Add one to receive alerts via email or WhatsApp.
                </div>
            ) : (
                <div className="notif-channels">
                    {channels.map((ch) => (
                        <div key={ch.id} className="notif-channel-card">
                            <div className={`notif-channel-icon ${ch.channel_type}`}>
                                {ch.channel_type === 'email' ? '📧' : '📱'}
                            </div>
                            <div className="notif-channel-info">
                                <div className="notif-channel-target">{ch.target}</div>
                                <div className="notif-channel-meta">
                                    <span className={`notif-verified-badge ${ch.verified ? 'verified' : 'unverified'}`}>
                                        {ch.verified ? '✓ Verified' : '⏳ Unverified'}
                                    </span>
                                    <span>{ch.channel_type}</span>
                                </div>
                                {!ch.verified && (
                                    <div className="notif-verify-inline">
                                        <input
                                            type="text"
                                            maxLength="6"
                                            placeholder="000000"
                                            value={verifyState[ch.id] || ''}
                                            onChange={(e) =>
                                                setVerifyState((prev) => ({
                                                    ...prev,
                                                    [ch.id]: e.target.value.replace(/\D/g, ''),
                                                }))
                                            }
                                        />
                                        <button
                                            className="btn btn-sm btn-primary"
                                            onClick={() => handleVerify(ch.id)}
                                            disabled={!(verifyState[ch.id]?.length >= 6)}
                                        >
                                            Verify
                                        </button>
                                        <button
                                            className="btn btn-sm btn-secondary"
                                            onClick={() => handleResend(ch.id)}
                                        >
                                            Resend
                                        </button>
                                    </div>
                                )}
                            </div>
                            <div className="notif-channel-actions">
                                <button
                                    className={`notif-toggle ${ch.enabled ? 'active' : ''}`}
                                    onClick={() => handleToggle(ch)}
                                    title={ch.enabled ? 'Disable' : 'Enable'}
                                />
                                <button
                                    className="btn btn-sm btn-secondary"
                                    onClick={() => handleDelete(ch.id)}
                                    title="Remove"
                                    style={{ padding: '0.3rem 0.5rem' }}
                                >
                                    ✕
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default NotificationSettings;
