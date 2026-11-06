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
    const [confirmDeleteId, setConfirmDeleteId] = useState(null);

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

            if (res.data?.send_error) {
                showMessage(res.data.send_error, 'error');
            } else {
                showMessage(res.data?.message || 'Channel added. Check your device for the 6-digit verification code.');
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
            showMessage('Dispatch channel verified.');
            setVerifyState((prev) => ({ ...prev, [channelId]: '' }));
            await fetchChannels();
        } catch (err) {
            showMessage(err.response?.data?.detail || 'Verification failed', 'error');
        }
    };

    const handleResend = async (channelId) => {
        try {
            const res = await notificationsAPI.resendCode(channelId);
            showMessage(res.data?.message || 'Verification code resent.');
        } catch (err) {
            showMessage(err.response?.data?.detail || 'Resend failed', 'error');
        }
    };

    const handleToggle = async (channel) => {
        const prev = channels;
        setChannels((curr) =>
            curr.map((c) => (c.id === channel.id ? { ...c, enabled: !c.enabled } : c))
        );
        try {
            await notificationsAPI.toggleChannel(channel.id, { enabled: !channel.enabled });
        } catch {
            setChannels(prev);
            showMessage('Toggle failed', 'error');
        }
    };

    const handleDelete = async (channelId) => {
        const prev = channels;
        setConfirmDeleteId(null);
        setChannels((curr) => curr.filter((c) => c.id !== channelId));
        try {
            await notificationsAPI.deleteChannel(channelId);
            showMessage('Channel removed.');
        } catch {
            setChannels(prev);
            showMessage('Delete failed', 'error');
        }
    };

    return (
        <div className="notif-section">
            <h3 className="notif-section-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                </svg>
                Alert Dispatch Channels (OTP Verified)
            </h3>

            {message && (
                <div className={`notif-message ${message.type}`} role="status">{message.text}</div>
            )}

            <form className="notif-add-form" onSubmit={handleAdd}>
                <div className="form-group">
                    <label>Channel Type</label>
                    <select value={newType} onChange={(e) => setNewType(e.target.value)}>
                        <option value="email">Email (SMTP)</option>
                        <option value="whatsapp">WhatsApp (Twilio)</option>
                    </select>
                </div>
                <div className="form-group" style={{ flex: 1 }}>
                    <label>{newType === 'email' ? 'Recipient Email Address' : 'Recipient Phone Number (E.164)'}</label>
                    <input
                        type={newType === 'email' ? 'email' : 'tel'}
                        placeholder={newType === 'email' ? 'secops@company.com' : '+15550100100'}
                        value={newTarget}
                        onChange={(e) => setNewTarget(e.target.value)}
                        required
                    />
                </div>
                <button className="btn btn-primary" type="submit" disabled={adding} style={{ height: '38px' }}>
                    {adding ? 'Adding...' : 'Add Channel'}
                </button>
            </form>

            {loading ? (
                <div className="skeleton" style={{ height: '72px', width: '100%', borderRadius: '10px' }} />
            ) : channels.length === 0 ? (
                <div className="notif-empty">
                    No external dispatch channels configured. Add an Email or WhatsApp destination above to receive real-time incident notifications.
                </div>
            ) : (
                <div className="notif-channels">
                    {channels.map((ch) => (
                        <div key={ch.id} className="notif-channel-card">
                            <div className={`notif-channel-icon ${ch.channel_type}`} aria-hidden="true">
                                {ch.channel_type === 'email' ? (
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <rect x="2" y="4" width="20" height="16" rx="2" />
                                        <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
                                    </svg>
                                ) : (
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" />
                                    </svg>
                                )}
                            </div>
                            <div className="notif-channel-info">
                                <div className="notif-channel-target">{ch.target}</div>
                                <div className="notif-channel-meta">
                                    <span className={`notif-verified-badge ${ch.verified ? 'verified' : 'unverified'}`}>
                                        {ch.verified ? 'Verified' : 'Pending OTP'}
                                    </span>
                                    <span className="uppercase">{ch.channel_type}</span>
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
                                            type="button"
                                            className="btn btn-xs btn-primary"
                                            onClick={() => handleVerify(ch.id)}
                                            disabled={!(verifyState[ch.id]?.length >= 6)}
                                        >
                                            Verify OTP
                                        </button>
                                        <button
                                            type="button"
                                            className="btn btn-xs btn-secondary"
                                            onClick={() => handleResend(ch.id)}
                                        >
                                            Resend
                                        </button>
                                    </div>
                                )}
                            </div>
                            <div className="notif-channel-actions">
                                <button
                                    type="button"
                                    role="switch"
                                    aria-checked={ch.enabled}
                                    className={`notif-toggle ${ch.enabled ? 'active' : ''}`}
                                    onClick={() => handleToggle(ch)}
                                    title={ch.enabled ? 'Disable notifications' : 'Enable notifications'}
                                    aria-label={ch.enabled ? 'Disable notifications' : 'Enable notifications'}
                                />
                                {confirmDeleteId === ch.id ? (
                                    <>
                                        <button
                                            type="button"
                                            className="btn btn-xs btn-danger"
                                            onClick={() => handleDelete(ch.id)}
                                        >
                                            Remove
                                        </button>
                                        <button
                                            type="button"
                                            className="btn btn-xs btn-secondary"
                                            onClick={() => setConfirmDeleteId(null)}
                                        >
                                            Cancel
                                        </button>
                                    </>
                                ) : (
                                    <button
                                        type="button"
                                        className="btn btn-xs btn-secondary"
                                        onClick={() => setConfirmDeleteId(ch.id)}
                                        title="Remove channel"
                                        aria-label="Remove channel"
                                        style={{ padding: '0.35rem 0.45rem' }}
                                    >
                                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                            <line x1="18" y1="6" x2="6" y2="18" />
                                            <line x1="6" y1="6" x2="18" y2="18" />
                                        </svg>
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default NotificationSettings;
