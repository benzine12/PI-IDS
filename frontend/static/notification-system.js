// notification-system.js - Updated with redirect functionality

class NotificationSystem {
    constructor() {
        // Initialize toast container
        if (!document.getElementById('toast-container')) {
            this.toastContainer = this.createToastContainer();
            document.body.appendChild(this.toastContainer);
        } else {
            this.toastContainer = document.getElementById('toast-container');
        }
        
        // Create the clear toasts button
        this.createClearToastsButton();
        
        // Initialize navbar notification elements
        this.notificationList = document.getElementById('notificationsList');
        this.notificationCount = document.getElementById('notificationCount');
        this.count = 0;
        
        // Add notification cache and rate limiting
        this.notificationCache = new Map();
        this.rateLimits = new Map();
        
        // Configure notification types
        this.typeConfig = {
            warning: {
                icon: 'fa-exclamation-triangle',
                color: 'text-yellow-500',
                bgColor: 'text-yellow-800 bg-yellow-100 dark:bg-yellow-800 dark:text-yellow-100',
                rateLimit: 5000  // 5 seconds between similar warnings
            },
            danger: {
                icon: 'fa-shield-alt',
                color: 'text-red-500',
                bgColor: 'text-red-800 bg-red-100 dark:bg-red-800 dark:text-red-100',
                rateLimit: 10000  // 10 seconds between similar danger alerts
            },
            success: {
                icon: 'fa-check-circle',
                color: 'text-green-500',
                bgColor: 'text-green-800 bg-green-100 dark:bg-green-800 dark:text-green-100',
                rateLimit: 3000  // 3 seconds between similar success messages
            }
        };
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-4 left-1/2 -translate-x-1/2 z-50 flex flex-col gap-2';
        return container;
    }

    shouldThrottleNotification(message, type) {
        const key = `${type}:${message}`;
        const now = Date.now();
        const lastShown = this.rateLimits.get(key) || 0;
        const rateLimit = this.typeConfig[type]?.rateLimit || 5000;

        if (now - lastShown < rateLimit) {
            return true;
        }

        this.rateLimits.set(key, now);
        return false;
    }

    isDuplicateNotification(message, type) {
        const key = `${type}:${message}`;
        const existing = this.notificationCache.get(key);
        
        if (existing) {
            const timeSinceLastShown = Date.now() - existing.timestamp;
            // If the same notification was shown in the last 5 seconds
            if (timeSinceLastShown < 5000) {
                // Update count if it's a duplicate
                existing.count++;
                existing.timestamp = Date.now();
                // Update the existing notification text if it's still visible
                const existingToast = document.getElementById(existing.id);
                if (existingToast) {
                    const messageDiv = existingToast.querySelector('.text-sm');
                    messageDiv.textContent = `${message} (${existing.count}x)`;
                    return true;
                }
            }
        }
        
        // Add new notification to cache
        this.notificationCache.set(key, {
            id: `toast-${Date.now()}`,
            timestamp: Date.now(),
            count: 1
        });
        
        return false;
    }

    show(message, type = 'warning') {
        // Check rate limiting and deduplication
        if (this.shouldThrottleNotification(message, type) || 
            this.isDuplicateNotification(message, type)) {
            return;
        }

        this.showToast(message, type);
        this.addNavbarNotification(message, type);
        
        // Clean up old cache entries
        this.cleanupCache();
    }

    cleanupCache() {
        const now = Date.now();
        // Clean up entries older than 1 minute
        for (const [key, value] of this.notificationCache) {
            if (now - value.timestamp > 60000) {
                this.notificationCache.delete(key);
            }
        }
        
        // Clean up rate limit entries
        for (const [key, timestamp] of this.rateLimits) {
            if (now - timestamp > 60000) {
                this.rateLimits.delete(key);
            }
        }
    }

    showToast(message, type = 'warning') {
        const cacheKey = `${type}:${message}`;
        const cacheEntry = this.notificationCache.get(cacheKey);
        const toastId = cacheEntry ? cacheEntry.id : `toast-${Date.now()}`;
        
        const toast = document.createElement('div');
        toast.id = toastId;
        
        const config = this.typeConfig[type] || this.typeConfig.warning;
        
        // Base classes for all toasts
        const baseClasses = 'flex items-center w-full max-w-sm p-2 mb-2 rounded-lg shadow transition-all duration-300 ease-in-out transform translate-x-0';
        
        toast.className = `${baseClasses} ${config.bgColor} cursor-pointer`;
        
        const count = cacheEntry?.count > 1 ? ` (${cacheEntry.count}x)` : '';
        toast.innerHTML = `
            <i class="fas ${config.icon} mr-2 text-sm"></i>
            <div class="text-sm font-normal">${message}${count}</div>
            <button type="button" 
                    class="ml-auto -mx-1 -my-1 rounded-lg focus:ring-2 focus:ring-gray-300 p-1 inline-flex h-6 w-6 hover:bg-gray-200 dark:hover:bg-gray-700"
                    onclick="event.stopPropagation(); notificationSystem.dismissToast('${toastId}')">
                <i class="fas fa-times text-sm"></i>
            </button>
        `;

        // Add click event to redirect to dashboard
        toast.addEventListener('click', function(e) {
            if (!e.target.closest('button')) {
                window.location.href = '/dashboard';
            }
        });

        // Add to container with entrance animation
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-100%)';
        this.toastContainer.appendChild(toast);
        
        // Trigger entrance animation
        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        });

        // Auto dismiss after 5 seconds
        setTimeout(() => {
            this.dismissToast(toastId);
        }, 5000);
    }

    dismissToast(id) {
        const toast = document.getElementById(id);
        if (toast) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-100%)';
            
            setTimeout(() => {
                toast.remove();
            }, 300);
        }
    }

    clearAllToasts() {
        // Get all toast elements
        const toasts = this.toastContainer.querySelectorAll('[id^="toast-"]');
        
        // Apply exit animation to each toast
        toasts.forEach(toast => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-100%)';
            
            // Remove from DOM after animation completes
            setTimeout(() => {
                toast.remove();
            }, 300);
        });
    }

    createClearToastsButton() {
        const existingButton = document.getElementById('clear-toasts-btn');
        if (existingButton) {
            return;
        }
        
        const clearButton = document.createElement('button');
        clearButton.id = 'clear-toasts-btn';
        clearButton.className = 'fixed top-4 right-4 z-50 bg-gray-700 text-white px-3 py-1.5 rounded-md shadow-md hover:bg-gray-800 transition-all duration-300 flex items-center space-x-1 text-sm';
        clearButton.innerHTML = `
            <i class="fas fa-times-circle"></i>
            <span>Clear Toasts</span>
        `;
        clearButton.style.display = 'none';
        clearButton.onclick = () => this.clearAllToasts();
        
        document.body.appendChild(clearButton);
        
        // Show button when toasts exist, hide when none exist
        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    const hasToasts = this.toastContainer.children.length > 0;
                    clearButton.style.display = hasToasts ? 'flex' : 'none';
                }
            }
        });
        
        observer.observe(this.toastContainer, { childList: true });
    }

    addNavbarNotification(message, type = 'warning') {
        // Only increment counter for non-duplicate notifications
        const key = `${type}:${message}`;
        const existing = this.notificationCache.get(key);
        if (!existing || existing.count === 1) {
            this.count++;
            this.notificationCount.textContent = this.count;
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = 'p-4 border-b border-gray-200 hover:bg-gray-50 cursor-pointer';
        
        const config = this.typeConfig[type] || this.typeConfig.warning;
        const count = existing?.count > 1 ? ` (${existing.count}x)` : '';
        
        notification.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <i class="fas ${config.icon} ${config.color}"></i>
                </div>
                <div class="ml-3 flex-1">
                    <p class="text-sm text-gray-800">${message}${count}</p>
                    <p class="text-xs text-gray-500 mt-1">${new Date().toLocaleTimeString()}</p>
                </div>
                <button onclick="event.stopPropagation(); notificationSystem.dismissNavbarNotification(this.closest('.p-4'))" 
                        class="ml-4 text-gray-400 hover:text-gray-500">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        // Add click event to redirect to dashboard
        notification.addEventListener('click', function(e) {
            if (!e.target.closest('button')) {
                window.location.href = '/dashboard';
                // Close dropdown when navigating
                const dropdown = document.getElementById('notificationsDropdown');
                if (dropdown) dropdown.classList.add('hidden');
            }
        });
        
        // Add to list at the top
        if (this.notificationList.firstChild) {
            this.notificationList.insertBefore(notification, this.notificationList.firstChild);
        } else {
            this.notificationList.appendChild(notification);
        }
    }

    dismissNavbarNotification(element) {
        if (element) {
            element.remove();
            this.count = Math.max(0, this.count - 1);
            this.notificationCount.textContent = this.count;
        }
    }

    clearAll() {
        // Clear notification list
        if (this.notificationList) {
            this.notificationList.innerHTML = '';
        }
        
        // Reset counter and caches
        this.count = 0;
        this.notificationCount.textContent = '0';
        this.notificationCache.clear();
        this.rateLimits.clear();
    }
}

// Initialize notification system
const notificationSystem = new NotificationSystem();