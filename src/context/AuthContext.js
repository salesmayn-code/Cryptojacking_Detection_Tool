// Authentication Context
import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);
const TOKEN_KEY = 'token';
const USER_KEY = 'user';

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let isMounted = true;

        const restoreSession = async () => {
            const sessionToken = sessionStorage.getItem(TOKEN_KEY);
            const sessionUser = sessionStorage.getItem(USER_KEY);
            const localToken = localStorage.getItem(TOKEN_KEY);
            const localUser = localStorage.getItem(USER_KEY);

            const storedToken = sessionToken || localToken;
            const storedUser = sessionUser || localUser;

            if (!storedToken || !storedUser) {
                if (isMounted) setLoading(false);
                return;
            }

            try {
                const parsedUser = JSON.parse(storedUser);
                setToken(storedToken);
                setUser(parsedUser);

                // Validate persisted token before treating the session as trusted.
                const profileResponse = await authAPI.getProfile();
                const profile = profileResponse.data;
                const mergedUser = {
                    ...parsedUser,
                    email: profile.email,
                    full_name: profile.full_name,
                    system_id: profile.system_id,
                    role: profile.role || parsedUser.role,
                    api_key: profile.api_key || parsedUser.api_key,
                    profile_picture_url: profile.profile_picture_url || null,
                };

                if (isMounted) {
                    setUser(mergedUser);
                    sessionStorage.setItem(TOKEN_KEY, storedToken);
                    sessionStorage.setItem(USER_KEY, JSON.stringify(mergedUser));
                    localStorage.removeItem(TOKEN_KEY);
                    localStorage.removeItem(USER_KEY);
                }
            } catch {
                if (isMounted) {
                    setToken(null);
                    setUser(null);
                    sessionStorage.removeItem(TOKEN_KEY);
                    sessionStorage.removeItem(USER_KEY);
                    localStorage.removeItem(TOKEN_KEY);
                    localStorage.removeItem(USER_KEY);
                }
            } finally {
                if (isMounted) setLoading(false);
            }
        };

        restoreSession();

        return () => {
            isMounted = false;
        };
    }, []);

    const login = async (email, password) => {
        try {
            const response = await authAPI.login({ email, password });
            const { access_token, user: userData } = response.data;

            setToken(access_token);
            setUser(userData);

            sessionStorage.setItem(TOKEN_KEY, access_token);
            sessionStorage.setItem(USER_KEY, JSON.stringify(userData));

            return { success: true, user: userData };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.detail || 'Login failed'
            };
        }
    };

    const register = async (email, password, fullName) => {
        try {
            const response = await authAPI.register({
                email,
                password,
                full_name: fullName.trim()
            });

            const { access_token, user: userData } = response.data;

            setToken(access_token);
            setUser(userData);

            sessionStorage.setItem(TOKEN_KEY, access_token);
            sessionStorage.setItem(USER_KEY, JSON.stringify(userData));

            return { success: true, user: userData };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.detail || 'Registration failed'
            };
        }
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
    };

    const setUserData = (newUserData) => {
        setUser(newUserData);
        sessionStorage.setItem(USER_KEY, JSON.stringify(newUserData));
    };

    const refreshProfile = async () => {
        try {
            const response = await authAPI.getProfile();
            const profile = response.data;
            const merged = {
                ...(user || {}),
                email: profile.email,
                full_name: profile.full_name,
                system_id: profile.system_id,
                role: profile.role || user?.role,
                api_key: profile.api_key || user?.api_key,
                profile_picture_url: profile.profile_picture_url || null,
            };
            setUserData(merged);
            return { success: true, profile };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.detail || 'Failed to refresh profile',
            };
        }
    };

    const value = {
        user,
        token,
        loading,
        login,
        register,
        logout,
        setUserData,
        refreshProfile,
        isAuthenticated: !!token,
        isAdmin: user?.role === 'admin',
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within AuthProvider');
    }
    return context;
};

export default AuthContext;
