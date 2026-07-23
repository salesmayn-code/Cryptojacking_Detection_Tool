// API Configuration and Service Layer
import axios from 'axios/dist/browser/axios.cjs';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Create axios instance with default config
const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor to add JWT token
api.interceptors.request.use(
    (config) => {
        const token = sessionStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor for error handling
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            // Unauthorized - clear token and redirect to login
            sessionStorage.removeItem('token');
            sessionStorage.removeItem('user');
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// Authentication API
export const authAPI = {
    register: (data) => api.post('/api/auth/register', data),
    login: (data) => api.post('/api/auth/login', data),
    getProfile: () => api.get('/api/auth/profile'),
    updateProfile: (data) => api.put('/api/auth/profile', data),
    changePassword: (data) => api.put('/api/auth/profile/password', data),
    uploadProfilePicture: (file) => {
        const formData = new FormData();
        formData.append('picture', file);
        return api.post('/api/auth/profile/picture', formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
    },
    validateAgent: (data) => api.post('/api/auth/agent/validate', data),
};

// Systems API
export const systemsAPI = {
    getAll: (ownerEmail) => api.get('/api/systems', { params: { owner_email: ownerEmail } }),
    getById: (id) => api.get(`/api/systems/${id}`),
    create: (data) => api.post('/api/systems', data),
    update: (id, data) => api.put(`/api/systems/${id}`, data),
    delete: (id) => api.delete(`/api/systems/${id}`),
};

// Metrics API
export const metricsAPI = {
    submit: (data) => api.post('/api/metrics', data),
    getBySystem: (systemId, limit = 100) =>
        api.get(`/api/metrics/${systemId}`, { params: { limit } }),
    getLatest: (systemId) => api.get(`/api/metrics/${systemId}/latest`),
};

// Alerts API
export const alertsAPI = {
    getAll: (params) => api.get('/api/alerts', { params }),
    getById: (id) => api.get(`/api/alerts/${id}`),
    update: (id, data) => api.put(`/api/alerts/${id}`, data),
    remove: (id) => api.delete(`/api/alerts/${id}`),
    whitelist: (id, data) => api.post(`/api/alerts/${id}/whitelist`, data),
    getBySystem: (systemId, limit = 50) =>
        api.get(`/api/alerts/system/${systemId}`, { params: { limit } }),
    getStats: () => api.get('/api/alerts/stats/summary'),
};

// Reports API
export const reportsAPI = {
    generate: (data) => api.post('/api/reports/generate', data),
    getAll: (systemId, limit = 50) =>
        api.get('/api/reports', { params: { system_id: systemId, limit } }),
    getById: (id) => api.get(`/api/reports/${id}`),
    download: (id) => api.get(`/api/reports/${id}/download`, { responseType: 'blob' }),
    schedule: (data) => api.post('/api/reports/schedule', data),
};

// Admin API
export const adminAPI = {
    getAuditLogs: (params) => api.get('/api/admin/audit-logs', { params }),
    exportAuditLogs: (params) =>
        api.get('/api/admin/audit-logs/export', { params, responseType: 'blob' }),
};

// Notifications API
export const notificationsAPI = {
    getChannels: () => api.get('/api/notifications/channels'),
    addChannel: (data) => api.post('/api/notifications/channels', data),
    verifyChannel: (id, data) => api.post(`/api/notifications/channels/${id}/verify`, data),
    resendCode: (id) => api.post(`/api/notifications/channels/${id}/resend`),
    toggleChannel: (id, data) => api.put(`/api/notifications/channels/${id}`, data),
    deleteChannel: (id) => api.delete(`/api/notifications/channels/${id}`),
};

export default api;
