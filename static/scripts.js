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

// Theme handling
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    // Trigger chart updates
    updateChart();
}

function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

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

// Chart Management
const MAX_POINTS = 60; // Show last 60 seconds
const packetData = new Array(MAX_POINTS).fill(0);
const threatData = new Array(MAX_POINTS).fill(0);
let lastPacketCount = 0;
let lastThreatCount = 0;
let chartUpdateInterval = null;

function updateChart() {
    updateSingleChart('activityChart', packetData, 'activity');
    updateSingleChart('threatChart', threatData, 'threat');
}

function updateSingleChart(chartId, data, type) {
    const svg = document.getElementById(chartId);
    if (!svg) return;

    const width = svg.clientWidth;
    const height = svg.clientHeight;
    const padding = 20;
    
    svg.innerHTML = '';
    
    // Draw grid
    for (let i = 0; i < 5; i++) {
        const y = padding + (height - 2 * padding) * i / 4;
        svg.innerHTML += `<line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" class="chart-grid"/>`;
        
        // Add Y-axis labels
        const maxValue = Math.max(...data, 1);
        const labelValue = Math.round(maxValue * (1 - (i / 4)));
        svg.innerHTML += `
            <text x="${padding - 5}" y="${y}" 
                  class="chart-label" 
                  text-anchor="end" 
                  alignment-baseline="middle">
                ${labelValue}
            </text>
        `;
    }
    
    // Calculate points
    const points = data.map((value, index) => {
        const x = padding + (width - 2 * padding) * index / (MAX_POINTS - 1);
        const y = height - padding - (height - 2 * padding) * value / Math.max(...data, 1);
        return `${x},${y}`;
    }).join(' ');
    
    // Draw line
    svg.innerHTML += `<polyline points="${points}" class="${type === 'threat' ? 'threat-line' : 'chart-line'}"/>`;
    
    // Draw points
    data.forEach((value, index) => {
        const x = padding + (width - 2 * padding) * index / (MAX_POINTS - 1);
        const y = height - padding - (height - 2 * padding) * value / Math.max(...data, 1);
        svg.innerHTML += `<circle cx="${x}" cy="${y}" r="2" class="${type === 'threat' ? 'threat-point' : 'chart-point'}"/>`;
    });
    
    // Draw axes
    svg.innerHTML += `
        <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" class="chart-axis"/>
        <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height - padding}" class="chart-axis"/>
    `;
}

// Monitoring Control
async function toggleMonitoring() {
    const button = document.getElementById('monitoringToggle');
    const statusIndicator = document.getElementById('status-indicator');
    const icon = button.querySelector('i');
    const text = button.querySelector('span');
    const interfaceInput = document.getElementById('interfaceInput').value;
    
    if (text.textContent === 'Start') {
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
            text.textContent = 'Stop';
            icon.classList.remove('fa-play');
            icon.classList.add('fa-stop');
            button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
            button.classList.add('bg-red-500', 'hover:bg-red-600');
            statusIndicator.classList.remove('bg-red-500');
            statusIndicator.classList.add('bg-green-500');
            statusIndicator.textContent = 'Active';

            // Start chart updates
            startChartUpdates();
        } catch (error) {
            console.error('Error starting monitoring:', error);
            alert('Failed to start monitoring. Please check the console for details.');
        }
    } else {
        try {
            // Stop sniffing
            const response = await fetch(CONFIG.API_ENDPOINTS.STOP_SNIFFING, {
                method: 'POST'
            });

            if (!response.ok) {
                throw new Error('Failed to stop sniffing');
            }

            // Update UI
            text.textContent = 'Start';
            icon.classList.remove('fa-stop');
            icon.classList.add('fa-play');
            button.classList.remove('bg-red-500', 'hover:bg-red-600');
            button.classList.add('bg-blue-500', 'hover:bg-blue-600');
            statusIndicator.classList.remove('bg-green-500');
            statusIndicator.classList.add('bg-red-500');
            statusIndicator.textContent = 'Inactive';

            // Stop chart updates
            stopChartUpdates();
        } catch (error) {
            console.error('Error stopping monitoring:', error);
            alert('Failed to stop monitoring. Please check the console for details.');
        }
    }
}

function startChartUpdates() {
    if (chartUpdateInterval) {
        clearInterval(chartUpdateInterval);
    }
    chartUpdateInterval = setInterval(refreshPacketData, CONFIG.REFRESH_INTERVAL);
}

function stopChartUpdates() {
    if (chartUpdateInterval) {
        clearInterval(chartUpdateInterval);
        chartUpdateInterval = null;
    }
}
function updatePacketData(totalPackets, threats) {
    // Shift old data points left
    packetData.shift();
    threatData.shift();
    
    // Calculate packets per second
    const packetDiff = totalPackets - lastPacketCount;
    const threatDiff = threats - lastThreatCount;
    
    // Add new data points
    packetData.push(packetDiff);
    threatData.push(threatDiff);
    
    // Update last counts
    lastPacketCount = totalPackets;
    lastThreatCount = threats;
    
    // Update packets/threats per second display
    document.getElementById('packets-per-second').textContent = `${packetDiff} packets/sec`;
    document.getElementById('threats-per-second').textContent = `${threatDiff} threats/sec`;
    
    // Update charts
    updateChart();
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
        
        // Update total packets counter and chart
        document.getElementById('totalPackets').textContent = data.total_packets;
        updatePacketData(data.total_packets, data.threats || 0);
        
        // Update table
        const packetBody = document.getElementById('packet-table-body');
        packetBody.innerHTML = '';

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
    // Initialize theme
    const savedTheme = localStorage.getItem('theme') || 
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(savedTheme);
    
    // Initialize theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.checked = savedTheme === 'dark';
    }

    // Initialize refresh intervals
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
    refreshSystemStats();
    updateChart();  // Initialize empty chart
});

// Handle window resize
window.addEventListener('resize', () => {
    updateChart();
});
