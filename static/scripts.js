// Configuration
const CONFIG = {
    REFRESH_INTERVAL: 2000,
    CONNECTION_CHECK_INTERVAL: 3000,
    REQUEST_TIMEOUT: 3000,
    API_ENDPOINTS: {
        HEALTH_CHECK: '/health-check',
        SYSTEM_STATS: '/system-stats',
        PACKETS: '/packets',
        SET_MONITOR: '/set_monitor',
        START_SNIFFING: '/start_sniffing',
        STOP_SNIFFING: '/stop_sniffing'
    }
};

// Network Status Management
let isServerConnected = false;

async function checkServerConnection() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
        
        const response = await fetch(CONFIG.API_ENDPOINTS.HEALTH_CHECK, {
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
            updateConnectionStatus(true);
            isServerConnected = true;
        } else {
            updateConnectionStatus(false);
            isServerConnected = false;
        }
    } catch (error) {
        updateConnectionStatus(false);
        isServerConnected = false;
        console.error('Server connection check failed:', error);
    }
}

function updateConnectionStatus(connected) {
    const networkStatusIcon = document.getElementById('networkStatusIcon');
    const networkStatusText = document.getElementById('networkStatusText');
    
    if (connected) {
        networkStatusIcon.className = 'fas fa-circle text-green-500';
        networkStatusText.textContent = 'Connected';
        networkStatusText.className = 'text-sm text-gray-600';
    } else {
        networkStatusIcon.className = 'fas fa-circle text-red-500';
        networkStatusText.textContent = 'Disconnected';
        networkStatusText.className = 'text-sm text-gray-600';
    }
}

// UI Toggle Functions
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('hidden');
}

function toggleNotifications() {
    const dropdown = document.getElementById('notificationsDropdown');
    dropdown.classList.toggle('hidden');
}

function toggleUserMenu() {
    const userMenu = document.getElementById('userMenuDropdown');
    userMenu.classList.toggle('hidden');
}

// Sniffing Control Functions
async function startSniffing() {
    const interfaceInput = document.getElementById('interfaceInput').value;
    
    try {
        // Set interface to monitor mode
        const monitorResponse = await fetch(CONFIG.API_ENDPOINTS.SET_MONITOR, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: interfaceInput })
        });

        if (!monitorResponse.ok) {
            throw new Error('Failed to set monitor mode');
        }
        
        // Start sniffing
        const sniffResponse = await fetch(CONFIG.API_ENDPOINTS.START_SNIFFING, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: interfaceInput })
        });

        if (!sniffResponse.ok) {
            throw new Error('Failed to start sniffing');
        }

        // Update UI
        const statusIndicator = document.getElementById('status-indicator');
        statusIndicator.textContent = 'Status: Active';
        statusIndicator.classList.remove('bg-red-500');
        statusIndicator.classList.add('bg-green-500');
        
    } catch (error) {
        console.error('Error starting sniffing:', error);
        alert('Failed to start sniffing. Please check the console for details.');
    }
}

async function stopSniffing() {
    try {
        const response = await fetch(CONFIG.API_ENDPOINTS.STOP_SNIFFING, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to stop sniffing');
        }

        const statusIndicator = document.getElementById('status-indicator');
        statusIndicator.textContent = 'Status: Inactive';
        statusIndicator.classList.remove('bg-green-500');
        statusIndicator.classList.add('bg-red-500');
        
    } catch (error) {
        console.error('Error stopping sniffing:', error);
        alert('Failed to stop sniffing. Please check the console for details.');
    }
}

// Data Refresh Functions
async function refreshPacketData() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
        
        const response = await fetch(CONFIG.API_ENDPOINTS.PACKETS, {
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Error('Failed to fetch packet data');
        }

        const data = await response.json();
        
        // Update total packets counter
        document.getElementById('totalPackets').textContent = data.total_packets;
        
        // Update table
        const packetBody = document.getElementById('packet-table-body');
        packetBody.innerHTML = ''; // Clear existing rows

        data.packets.forEach(packet => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50';

            const createCell = (content, isStatus = false) => {
                const td = document.createElement('td');
                td.className = `px-6 py-4 whitespace-nowrap text-sm ${isStatus ? '' : 'text-gray-500'}`;
                td.textContent = content;
                return td;
            };

            row.appendChild(createCell(packet.src_mac));
            row.appendChild(createCell(packet.dst_mac));
            row.appendChild(createCell(packet.reason_code));
            row.appendChild(createCell(packet.time));
            row.appendChild(createCell(packet.signal_strength));
            row.appendChild(createCell(packet.sequence));
            row.appendChild(createCell(packet.count));

            const statusTd = createCell(packet.is_flood ? 'Flood Attack' : 'Detected', true);
            statusTd.className += packet.is_flood ? ' text-red-600 font-medium' : ' text-yellow-600';
            row.appendChild(statusTd);

            packetBody.appendChild(row);
        });
        
        // Update other metrics
        document.getElementById('detectedThreats').textContent = data.threats || 0;
        document.getElementById('activeConnections').textContent = data.active_connections || 0;
        document.getElementById('protectedAPs').textContent = data.protected_aps || 0;
        
    } catch (error) {
        console.error('Error refreshing packet data:', error);
        if (!error.name === 'AbortError') {
            isServerConnected = false;
            updateConnectionStatus(false);
        }
    }
}

async function refreshSystemStats() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
        
        const response = await fetch(CONFIG.API_ENDPOINTS.SYSTEM_STATS, {
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Error('Failed to fetch system stats');
        }

        const data = await response.json();
        updateConnectionStatus(true);
        isServerConnected = true;

        // Update system stats
        document.getElementById('cpuUsage').textContent = `${data.cpu.percent}%`;
        document.getElementById('cpuBar').style.width = `${data.cpu.percent}%`;
        
        document.getElementById('memoryUsage').textContent = `${data.memory.percent}%`;
        document.getElementById('memoryBar').style.width = `${data.memory.percent}%`;
        
        document.getElementById('diskUsage').textContent = `${data.disk.percent}%`;
        document.getElementById('diskBar').style.width = `${data.disk.percent}%`;
        
        document.getElementById('temperature').textContent = 
            data.temperature.celsius !== 'N/A' ? `${data.temperature.celsius}°C` : 'N/A';

    } catch (error) {
        console.error('Error refreshing system stats:', error);
        if (!error.name === 'AbortError') {
            isServerConnected = false;
            updateConnectionStatus(false);
        }
    }
}

// Initialize Event Listeners
document.addEventListener('DOMContentLoaded', function() {
    // Initialize refresh intervals
    setInterval(refreshPacketData, CONFIG.REFRESH_INTERVAL);
    setInterval(refreshSystemStats, CONFIG.REFRESH_INTERVAL);
    setInterval(checkServerConnection, CONFIG.CONNECTION_CHECK_INTERVAL);

    // Close dropdowns when clicking outside
    document.addEventListener('click', function(event) {
        const notificationsDropdown = document.getElementById('notificationsDropdown');
        const userMenuDropdown = document.getElementById('userMenuDropdown');
        
        if (!event.target.closest('.relative')) {
            notificationsDropdown.classList.add('hidden');
            userMenuDropdown.classList.add('hidden');
        }
    });

    // Initial data load
    checkServerConnection();
    refreshPacketData();
    refreshSystemStats();
});

// Tab Switching Function (for future extension)
function switchTab(tabId) {
    // For future extension if you have multiple tabs
    // Hide/show different sections by ID
    console.log(`Switching to tab: ${tabId}`);
}