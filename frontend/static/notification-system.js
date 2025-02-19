// Combined Toast and Notification System
class NotificationSystem {
    constructor() {
        // Initialize toast container
        if (!document.getElementById('toast-container')) {
            this.toastContainer = this.createToastContainer();
            document.body.appendChild(this.toastContainer);
        } else {
            this.toastContainer = document.getElementById('toast-container');
        }
        
        // Initialize navbar notification elements
        this.notificationList = document.getElementById('notificationsList');
        this.notificationCount = document.getElementById('notificationCount');
        this.count = 0;
        
        // Configure notification types
        this.typeConfig = {
            warning: {
                icon: 'fa-exclamation-triangle',
                color: 'text-yellow-500',
                bgColor: 'text-yellow-800 bg-yellow-100 dark:bg-yellow-800 dark:text-yellow-100'
            },
            danger: {
                icon: 'fa-shield-alt',
                color: 'text-red-500',
                bgColor: 'text-red-800 bg-red-100 dark:bg-red-800 dark:text-red-100'
            },
            success: {
                icon: 'fa-check-circle',
                color: 'text-green-500',
                bgColor: 'text-green-800 bg-green-100 dark:bg-green-800 dark:text-green-100'
            }
        };
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-4 left-1/2 -translate-x-1/2 z-50 flex flex-col gap-2';
        return container;
    }

    show(message, type = 'warning') {
        // Show toast notification
        this.showToast(message, type);
        
        // Add to navbar notifications
        this.addNavbarNotification(message, type);
    }

    showToast(message, type = 'warning') {
        const toast = document.createElement('div');
        const id = `toast-${Date.now()}`;
        toast.id = id;
        
        const config = this.typeConfig[type] || this.typeConfig.warning;
        
        // Base classes for all toasts
        const baseClasses = 'flex items-center w-full max-w-sm p-2 mb-2 rounded-lg shadow transition-all duration-300 ease-in-out transform translate-x-0';
        
        toast.className = `${baseClasses} ${config.bgColor}`;
        toast.innerHTML = `
            <i class="fas ${config.icon} mr-2 text-sm"></i>
            <div class="text-sm font-normal">${message}</div>
            <button type="button" 
                    class="ml-auto -mx-1 -my-1 rounded-lg focus:ring-2 focus:ring-gray-300 p-1 inline-flex h-6 w-6 hover:bg-gray-200 dark:hover:bg-gray-700"
                    onclick="notificationSystem.dismissToast('${id}')">
                <i class="fas fa-times text-sm"></i>
            </button>
        `;

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
            this.dismissToast(id);
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

    addNavbarNotification(message, type = 'warning') {
        // Increment counter
        this.count++;
        this.notificationCount.textContent = this.count;
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = 'p-4 border-b border-gray-200 hover:bg-gray-50';
        
        const config = this.typeConfig[type] || this.typeConfig.warning;
        
        // Add notification content
        notification.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <i class="fas ${config.icon} ${config.color}"></i>
                </div>
                <div class="ml-3 flex-1">
                    <p class="text-sm text-gray-800">${message}</p>
                    <p class="text-xs text-gray-500 mt-1">${new Date().toLocaleTimeString()}</p>
                </div>
                <button onclick="notificationSystem.dismissNavbarNotification(this.closest('.p-4'))" 
                        class="ml-4 text-gray-400 hover:text-gray-500">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
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
}

// Initialize notification system
const notificationSystem = new NotificationSystem();