// Toast notification system
class ToastNotification {
    constructor() {
        this.container = this.createContainer();
        document.body.appendChild(this.container);
    }

    createContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-4 right-4 z-50 flex flex-col gap-2';
        return container;
    }

    show(message, type = 'warning') {
        const toast = document.createElement('div');
        const id = `toast-${Date.now()}`;
        toast.id = id;
        
        // Base classes for all toasts
        const baseClasses = 'flex items-center w-full max-w-md p-4 mb-4 rounded-lg shadow transition-all duration-300 ease-in-out transform translate-x-0';
        
        // Type-specific classes
        const typeClasses = {
            warning: 'text-yellow-800 bg-yellow-100 dark:bg-yellow-800 dark:text-yellow-100',
            danger: 'text-red-800 bg-red-100 dark:bg-red-800 dark:text-red-100',
            success: 'text-green-800 bg-green-100 dark:bg-green-800 dark:text-green-100'
        };
        
        // Icons for different types
        const icons = {
            warning: '<i class="fas fa-exclamation-triangle mr-3 text-yellow-700 dark:text-yellow-100"></i>',
            danger: '<i class="fas fa-shield-alt mr-3 text-red-700 dark:text-red-100"></i>',
            success: '<i class="fas fa-check-circle mr-3 text-green-700 dark:text-green-100"></i>'
        };

        toast.className = `${baseClasses} ${typeClasses[type]}`;
        toast.innerHTML = `
            ${icons[type]}
            <div class="text-sm font-normal">${message}</div>
            <button type="button" class="ml-auto -mx-1.5 -my-1.5 rounded-lg focus:ring-2 focus:ring-gray-300 p-1.5 inline-flex h-8 w-8 hover:bg-gray-200 dark:hover:bg-gray-700" onclick="toastNotification.dismiss('${id}')">
                <i class="fas fa-times"></i>
            </button>
        `;

        // Add to container with entrance animation
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        this.container.appendChild(toast);
        
        // Trigger entrance animation
        setTimeout(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateX(0)';
        }, 10);

        // Auto dismiss after 5 seconds
        setTimeout(() => {
            this.dismiss(id);
        }, 5000);
    }

    dismiss(id) {
        const toast = document.getElementById(id);
        if (toast) {
            // Exit animation
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            
            // Remove after animation
            setTimeout(() => {
                toast.remove();
            }, 300);
        }
    }
}

// Initialize the toast notification system
const toastNotification = new ToastNotification();

// Modified packet handler to show notifications
let lastNotificationTime = 0;
const NOTIFICATION_COOLDOWN = 2000; // Minimum 2 seconds between notifications

function updatePacketData(data) {
    // Update table and other UI elements as before
    const tableBody = document.getElementById('packet-table-body');
    if (!tableBody) return;

    // Clear existing rows
    tableBody.innerHTML = '';

    // Add new rows and show notifications for new attacks
    data.packets.forEach(packet => {
        // Add table row
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.src_mac}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.dst_mac}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.bssid}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.channel}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.reason_code}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.time}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.signal_strength}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.attack_type}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.count}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${packet.is_flood ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}">
                    ${packet.is_flood ? 'Flood Attack' : 'Potential Threat'}
                </span>
            </td>
        `;
        tableBody.appendChild(row);

        // Show notification if enough time has passed since the last one
        const currentTime = Date.now();
        if (currentTime - lastNotificationTime >= NOTIFICATION_COOLDOWN) {
            const message = `Deauth attack detected from ${packet.src_mac} to ${packet.dst_mac}`;
            const type = packet.is_flood ? 'danger' : 'warning';
            toastNotification.show(message, type);
            lastNotificationTime = currentTime;
        }
    });

    // Update summary statistics
    document.getElementById('totalPackets').textContent = data.total_packets;
    document.getElementById('detectedThreats').textContent = data.threats;
}

// Modify the existing fetch interval to use the new update function
setInterval(async () => {
    try {
        const response = await fetch('/packets');
        const data = await response.json();
        updatePacketData(data);
    } catch (error) {
        console.error('Error fetching packet data:', error);
    }
}, 1000);