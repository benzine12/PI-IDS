// auth.js - Client-side authentication utility
const AUTH = {
    // Initialize authentication state
    init: function() {
        this.attachTokenToRequests();
        this.checkAuthState();
    },
    
    // Get the stored JWT token
    getToken: function() {
        return localStorage.getItem('accessToken');
    },
    
    // Get the current user information
    getUser: function() {
        const userData = localStorage.getItem('user');
        return userData ? JSON.parse(userData) : null;
    },
    
    // Check if the user is authenticated
    isAuthenticated: function() {
        return !!this.getToken();
    },
    
    // Attach JWT token to all fetch requests
    attachTokenToRequests: function() {
        const originalFetch = window.fetch;
        
        window.fetch = async function(url, options = {}) {
            const token = AUTH.getToken();
            
            if (token) {
                options.headers = {
                    ...options.headers,
                    'Authorization': `Bearer ${token}`
                };
            }
            
            return originalFetch(url, options)
                .then(async response => {
                    // Handle 401 Unauthorized responses (token expired/invalid)
                    if (response.status === 401) {
                        // Log the user out if they get an unauthorized response
                        AUTH.logout();
                        window.location.href = '/';
                        throw new Error('Your session has expired. Please log in again.');
                    }
                    return response;
                });
        };
    },
    
    // Update UI elements based on authentication state
    checkAuthState: function() {
        const protectedPages = ['/dashboard', '/ap-scan'];
        const currentPath = window.location.pathname;
        
        if (this.isAuthenticated()) {
            // User is logged in
            if (currentPath === '/') {
                // Redirect to dashboard if on login page
                window.location.href = '/dashboard';
            }
            
            // Update UI for authenticated user
            const user = this.getUser();
            const userInitials = document.querySelector('.rounded-full span');
            const userName = document.querySelector('#sidebar + div nav div:last-child span:nth-of-type(1)');
            
            if (userInitials && user) {
                const initials = user.username.substring(0, 2).toUpperCase();
                userInitials.textContent = initials;
            }
            
            if (userName && user) {
                userName.textContent = user.username;
            }
        } else {
            // User is not logged in
            if (protectedPages.includes(currentPath)) {
                // Redirect to login page if trying to access protected pages
                window.location.href = '/';
            }
        }
    },
    
    // Log the user out
    logout: function() {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('user');
        window.location.href = '/';
    }
};

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', function() {
    AUTH.init();
    
    // Add logout functionality to logout button if it exists
    const logoutButton = document.querySelector('a:has(i.fa-sign-out-alt)');
    if (logoutButton) {
        logoutButton.addEventListener('click', function(e) {
            e.preventDefault();
            AUTH.logout();
        });
    }
});