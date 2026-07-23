import React, { useState, useEffect } from 'react';

const ThemeToggle = () => {
    const [dark, setDark] = useState(() => {
        const saved = localStorage.getItem('theme');
        return saved === 'dark';
    });

    useEffect(() => {
        if (dark) {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('theme', 'light');
        }
    }, [dark]);

    // Apply saved theme on initial mount
    useEffect(() => {
        const saved = localStorage.getItem('theme');
        if (saved === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    }, []);

    return (
        <button
            className="theme-toggle"
            onClick={() => setDark(prev => !prev)}
            title={dark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label="Toggle theme"
        >
            {dark ? 'Light' : 'Dark'}
        </button>
    );
};

export default ThemeToggle;
