// API Configuration
const API_BASE = 'http://localhost:3000/api';

// Authentication Service
class AuthService {
    // Save user to session storage
    static setUser(user) {
        sessionStorage.setItem('user', JSON.stringify(user));
    }

    // Get current user
    static getUser() {
        return JSON.parse(sessionStorage.getItem('user'));
    }

    // Remove user (logout)
    static logout() {
        sessionStorage.removeItem('user');
        localStorage.removeItem('adminToken');
        window.location.href = 'index.html';
    }

    // Check if user is logged in
    static isLoggedIn() {
        return this.getUser() !== null;
    }

    // Check if user is admin
    static isAdmin() {
        const user = this.getUser();
        return user && user.username === 'admin';
    }

    // Get admin token
    static getAdminToken() {
        return localStorage.getItem('adminToken');
    }

    // Redirect if not authenticated
    static requireAuth(redirectTo = 'login.html') {
        if (!this.isLoggedIn()) {
            window.location.href = redirectTo;
            return false;
        }
        return true;
    }

    // Redirect if not admin
    static requireAdmin() {
        if (!this.isAdmin() || !this.getAdminToken()) {
            window.location.href = 'admin-login.html';
            return false;
        }
        return true;
    }
}

// API Service
class ApiService {
    static async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const config = {
            credentials: 'include', // Important for sessions
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Add admin token if available
        if (AuthService.isAdmin()) {
            const token = AuthService.getAdminToken();
            if (token) {
                config.headers['Authorization'] = `Bearer ${token}`;
            }
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                // Enhanced error handling for email verification
                const error = new Error(data.message || 'Request failed');
                error.response = data; // Include full response for better error handling
                throw error;
            }
            
            return data;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }

    // Auth endpoints
    static async login(username, password) {
        const result = await this.request('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        if (username === 'admin' && result.token) {
            localStorage.setItem('adminToken', result.token);
        }

        return result;
    }

    // UPDATED: Signup now includes email
    static async signup(username, password, email) {
        return this.request('/signup', {
            method: 'POST',
            body: JSON.stringify({ username, password, email })
        });
    }

    static async logout() {
        return this.request('/logout', {
            method: 'POST'
        });
    }

    // NEW: Email verification endpoints
    static async verifyEmail(token) {
        return this.request(`/verify-email?token=${token}`, {
            method: 'GET'
        });
    }

    static async resendVerification(email) {
        return this.request('/resend-verification', {
            method: 'POST',
            body: JSON.stringify({ email })
        });
    }

    // Attendance endpoints
    static async punchIn(location) {
        return this.request('/punch-in', {
            method: 'POST',
            body: JSON.stringify(location)
        });
    }

    static async punchOut(location) {
        return this.request('/punch-out', {
            method: 'POST',
            body: JSON.stringify(location)
        });
    }

    static async getPunches() {
        return this.request('/punches');
    }

    // Admin endpoints
    static async getAllAttendance() {
        return this.request('/admin/attendance');
    }
}

// Location Service
class LocationService {
    static async getCurrentLocation() {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(new Error('Geolocation is not supported by this browser.'));
                return;
            }

            navigator.geolocation.getCurrentPosition(
                (position) => {
                    resolve({
                        lat: position.coords.latitude,
                        lon: position.coords.longitude
                    });
                },
                (error) => {
                    reject(new Error(this.getErrorMessage(error)));
                },
                {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 0
                }
            );
        });
    }

    static getErrorMessage(error) {
        switch (error.code) {
            case error.PERMISSION_DENIED:
                return 'Location access denied. Please enable location permissions.';
            case error.POSITION_UNAVAILABLE:
                return 'Location information unavailable.';
            case error.TIMEOUT:
                return 'Location request timed out.';
            default:
                return 'An unknown error occurred while getting location.';
        }
    }
}

// UI Utilities
class UIUtils {
    static showAlert(message, type = 'success', container = null) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        
        // Support HTML messages for verification links
        if (message.includes('<a ') || message.includes('<br>') || message.includes('<strong>')) {
            alertDiv.innerHTML = message;
        } else {
            alertDiv.textContent = message;
        }
        
        const target = container || document.querySelector('form') || document.body;
        target.insertBefore(alertDiv, target.firstChild);
        
        setTimeout(() => alertDiv.remove(), 5000);
    }

    static setLoading(button, isLoading) {
        if (isLoading) {
            button.disabled = true;
            const originalText = button.innerHTML;
            button.setAttribute('data-original-text', originalText);
            button.innerHTML = '<span class="loading"></span> Processing...';
        } else {
            button.disabled = false;
            const originalText = button.getAttribute('data-original-text');
            if (originalText) {
                button.innerHTML = originalText;
            }
        }
    }

    static addRippleEffect(button) {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.classList.add('ripple');
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    }

    static formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString();
    }

    static formatDuration(start, end) {
        if (!start || !end) return 'N/A';
        
        const startTime = new Date(start);
        const endTime = new Date(end);
        const diffMs = endTime - startTime;
        
        const hours = Math.floor(diffMs / (1000 * 60 * 60));
        const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
        
        return `${hours}h ${minutes}m`;
    }

    // NEW: Enhanced error handling for email verification
    static handleApiError(error) {
        console.error('API Error:', error);
        
        // Check for email verification errors
        if (error.message.includes('verify your email') || 
            error.message.includes('Please verify') ||
            (error.response && error.response.requiresVerification)) {
            
            return {
                type: 'verification_required',
                message: error.message,
                email: error.response?.email || ''
            };
        }
        
        // Check for existing user/email errors
        if (error.message.includes('already exists') || 
            error.message.includes('Username or email')) {
            
            return {
                type: 'duplicate_user',
                message: error.message
            };
        }
        
        // Generic error
        return {
            type: 'generic',
            message: error.message
        };
    }

    // NEW: Show verification success message with link
    static showVerificationSuccess(message, verificationLink = null) {
        let alertMessage = message;
        
        if (verificationLink) {
            alertMessage += `<br><small>For testing: <a href="${verificationLink}" target="_blank" style="color: inherit; text-decoration: underline;">Click here to verify</a></small>`;
        }
        
        this.showAlert(alertMessage, 'success');
    }
}

// Initialize ripple effects on all buttons
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.btn').forEach(button => {
        UIUtils.addRippleEffect(button);
    });
});