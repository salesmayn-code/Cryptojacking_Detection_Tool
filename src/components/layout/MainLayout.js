import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import ThemeToggle from '../ThemeToggle';
import './MainLayout.css';

const NAV_ITEMS = [
    {
        label: 'Profile',
        path: '/profile',
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
            </svg>
        ),
    },
    {
        label: 'Live Metrics',
        pathFn: (user) => user?.system_id ? `/system/${user.system_id}` : null,
        matchPrefix: '/system/',
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
        ),
    },
    {
        label: 'Alerts',
        path: '/alerts',
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
        ),
    },
    {
        label: 'Reports',
        path: '/reports',
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <polyline points="10 9 9 9 8 9" />
            </svg>
        ),
    },
    {
        label: 'Dashboard',
        path: '/dashboard',
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="7" height="7" />
                <rect x="14" y="3" width="7" height="7" />
                <rect x="14" y="14" width="7" height="7" />
                <rect x="3" y="14" width="7" height="7" />
            </svg>
        ),
    },
    {
        label: 'Audit Logs',
        path: '/admin/audit-logs',
        adminOnly: true,
        icon: (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="12" y1="18" x2="12" y2="12" />
                <line x1="9" y1="15" x2="15" y2="15" />
            </svg>
        ),
    },
];

const MainLayout = ({ children }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, logout, isAdmin } = useAuth();
    const [mobileOpen, setMobileOpen] = useState(false);

    const isActive = (item) => {
        if (item.path) return location.pathname === item.path;
        if (item.matchPrefix) return location.pathname.startsWith(item.matchPrefix);
        return false;
    };

    const handleNav = (item) => {
        const target = item.path || (item.pathFn && item.pathFn(user));
        if (target) {
            navigate(target);
            setMobileOpen(false);
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
            {/* Mobile overlay */}
            {mobileOpen && (
                <div className="layout-overlay" onClick={() => setMobileOpen(false)} />
            )}

            {/* Mobile header */}
            <header className="layout-mobile-header">
                <button className="layout-hamburger" onClick={() => setMobileOpen(!mobileOpen)} aria-label="Toggle navigation">
                    <span /><span /><span />
                </button>
                <div className="layout-mobile-brand">CryptoDetect</div>
                <ThemeToggle />
            </header>

            {/* Sidebar */}
            <aside className={`layout-sidebar ${mobileOpen ? 'open' : ''}`}>
                <div className="sidebar-brand">
                    <div className="sidebar-logo">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <div>
                        <div className="sidebar-brand-name">CryptoDetect</div>
                        <div className="sidebar-brand-sub">Security Monitoring</div>
                    </div>
                </div>

                <nav className="sidebar-nav">
                    {NAV_ITEMS.map((item) => {
                        if (item.adminOnly && !isAdmin) return null;
                        const target = item.path || (item.pathFn && item.pathFn(user));
                        if (!target) return null;
                        return (
                            <button
                                key={item.label}
                                className={`sidebar-link ${isActive(item) ? 'active' : ''}`}
                                onClick={() => handleNav(item)}
                            >
                                <span className="sidebar-link-icon">{item.icon}</span>
                                <span className="sidebar-link-label">{item.label}</span>
                                {isActive(item) && <span className="sidebar-link-indicator" />}
                            </button>
                        );
                    })}
                </nav>

                <div className="sidebar-footer">
                    <ThemeToggle />
                    <div className="sidebar-user">
                        <div className="sidebar-user-avatar">{initials}</div>
                        <div className="sidebar-user-info">
                            <span className="sidebar-user-name">{user?.full_name}</span>
                            <code className="sidebar-user-id">{user?.system_id}</code>
                        </div>
                    </div>
                    <button onClick={logout} className="btn btn-secondary btn-sm sidebar-logout">
                        Sign Out
                    </button>
                </div>
            </aside>

            {/* Main content */}
            <main className="layout-main">
                <div className="layout-content">
                    {children}
                </div>
            </main>
        </div>
    );
};

export default MainLayout;
