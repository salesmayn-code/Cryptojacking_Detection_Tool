import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import ThemeToggle from '../ThemeToggle';
import './MainLayout.css';

const NAV_ITEMS = [
    {
        label: 'Dashboard',
        path: '/dashboard',
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="7" height="7" rx="1.5" />
                <rect x="14" y="3" width="7" height="7" rx="1.5" />
                <rect x="14" y="14" width="7" height="7" rx="1.5" />
                <rect x="3" y="14" width="7" height="7" rx="1.5" />
            </svg>
        ),
    },
    {
        label: 'Live Telemetry',
        pathFn: (user) => (user?.system_id ? `/system/${user.system_id}` : null),
        matchPrefix: '/system/',
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
        ),
    },
    {
        label: 'Security Alerts',
        path: '/alerts',
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
        ),
    },
    {
        label: 'Reports',
        path: '/reports',
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
            </svg>
        ),
    },
    {
        label: 'Audit Trail',
        path: '/admin/audit-logs',
        adminOnly: true,
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 20h9" />
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
            </svg>
        ),
    },
    {
        label: 'Settings & Agent',
        path: '/profile',
        icon: (
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
            </svg>
        ),
    },
];

const MainLayout = ({ children }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, logout, isAdmin } = useAuth();
    const [mobileOpen, setMobileOpen] = useState(false);
    const [copiedSysId, setCopiedSysId] = useState(false);

    useEffect(() => {
        if (!mobileOpen) return undefined;
        const onKeyDown = (e) => {
            if (e.key === 'Escape') setMobileOpen(false);
        };
        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, [mobileOpen]);

    const isActive = (item) => {
        if (item.path) return location.pathname === item.path;
        if (item.matchPrefix) return location.pathname.startsWith(item.matchPrefix);
        return false;
    };

    const activeItem = NAV_ITEMS.find((item) => isActive(item)) || NAV_ITEMS[0];

    const handleNav = (item) => {
        const target = item.path || (item.pathFn && item.pathFn(user));
        if (target) {
            navigate(target);
            setMobileOpen(false);
        }
    };

    const handleCopySystemId = async () => {
        if (!user?.system_id) return;
        try {
            await navigator.clipboard.writeText(user.system_id);
            setCopiedSysId(true);
            setTimeout(() => setCopiedSysId(false), 1600);
        } catch {
            // Clipboard unavailable
        }
    };

    const initials = (user?.full_name || 'U')
        .split(' ')
        .map((w) => w[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);

    return (
        <div className="layout">
            {mobileOpen && (
                <div className="layout-overlay" onClick={() => setMobileOpen(false)} aria-hidden="true" />
            )}

            <header className="layout-mobile-header">
                <button
                    type="button"
                    className={`layout-hamburger ${mobileOpen ? 'open' : ''}`}
                    onClick={() => setMobileOpen(!mobileOpen)}
                    aria-label="Toggle navigation"
                    aria-expanded={mobileOpen}
                >
                    <span /><span /><span />
                </button>
                <div className="layout-mobile-brand">CryptoDetect</div>
                <ThemeToggle />
            </header>

            <aside className={`layout-sidebar ${mobileOpen ? 'open' : ''}`}>
                <div className="sidebar-brand" onClick={() => navigate('/dashboard')} role="button" tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && navigate('/dashboard')}>
                    <div className="sidebar-logo" aria-hidden="true">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            <polyline points="8.5 12.5 10.8 14.8 15.5 9.8" />
                        </svg>
                    </div>
                    <div>
                        <div className="sidebar-brand-name">CryptoDetect</div>
                        <div className="sidebar-brand-sub">Endpoint Threat Console</div>
                    </div>
                </div>

                <div className="sidebar-nav-section-label">Operations</div>
                <nav className="sidebar-nav" aria-label="Primary">
                    {NAV_ITEMS.map((item) => {
                        if (item.adminOnly && !isAdmin) return null;
                        const target = item.path || (item.pathFn && item.pathFn(user));
                        if (!target) return null;
                        const current = isActive(item);
                        return (
                            <button
                                type="button"
                                key={item.label}
                                className={`sidebar-link ${current ? 'active' : ''}`}
                                onClick={() => handleNav(item)}
                                aria-current={current ? 'page' : undefined}
                            >
                                <span className="sidebar-link-icon">{item.icon}</span>
                                <span className="sidebar-link-label">{item.label}</span>
                            </button>
                        );
                    })}
                </nav>

                <div className="sidebar-footer">
                    <div
                        className="sidebar-user"
                        onClick={() => {
                            navigate('/profile');
                            setMobileOpen(false);
                        }}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && navigate('/profile')}
                        title="Open profile & agent settings"
                    >
                        <div className="sidebar-user-avatar">{initials}</div>
                        <div className="sidebar-user-info">
                            <span className="sidebar-user-name">{user?.full_name || 'Operator'}</span>
                            <code className="sidebar-user-id">{user?.system_id || 'No Endpoint'}</code>
                        </div>
                    </div>
                    <button type="button" onClick={logout} className="btn btn-secondary btn-sm sidebar-logout">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                            <polyline points="16 17 21 12 16 7" />
                            <line x1="21" y1="12" x2="9" y2="12" />
                        </svg>
                        <span>Sign Out</span>
                    </button>
                </div>
            </aside>

            <main className="layout-main">
                <header className="layout-topbar">
                    <div className="layout-topbar-left">
                        <span className="layout-topbar-title">{activeItem.label}</span>
                        {user?.system_id && (
                            <button
                                type="button"
                                className={`copy-chip ${copiedSysId ? 'copied' : ''}`}
                                onClick={handleCopySystemId}
                                title="Click to copy System ID"
                            >
                                <span>{user.system_id}</span>
                                {copiedSysId ? (
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                        <polyline points="20 6 9 17 4 12" />
                                    </svg>
                                ) : (
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                                    </svg>
                                )}
                            </button>
                        )}
                    </div>
                    <div className="layout-topbar-right">
                        <span className="layout-agent-pill" title="Packaged Windows tray daemon release">
                            <span className="layout-agent-dot" aria-hidden="true" />
                            Agent v1.0
                        </span>
                        <ThemeToggle />
                    </div>
                </header>
                <div className="layout-content" key={location.pathname}>
                    {children}
                </div>
            </main>
        </div>
    );
};

export default MainLayout;
