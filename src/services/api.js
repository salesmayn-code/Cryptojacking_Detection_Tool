// API Configuration and Service Layer
import axios from 'axios';

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
        const token = localStorage.getItem('token');
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

export default api;
