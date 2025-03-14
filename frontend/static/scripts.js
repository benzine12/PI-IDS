// Configuration
const CONFIG = {
    REFRESH_INTERVAL: 2000,
    REQUEST_TIMEOUT: 3000,
    API_ENDPOINTS: {
        SYSTEM_STATS: '/system-stats',
        PACKETS: '/packets'
    }
};
// Initialize username from localStorage
document.addEventListener('DOMContentLoaded', function() {
    const username = localStorage.getItem('wids_username');
    const usernameDisplay = document.getElementById('username-display');
    const userInitials = document.getElementById('user-initials');
    
    if (username) {
        // Update the displayed username
        usernameDisplay.textContent = username;
        
        // Update initials (first letter of username)
        const initials = username.charAt(0).toUpperCase();
        userInitials.textContent = initials;
    }
});

// Network Status Management flag
let isServerConnected = false;

// Theme handling
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateChart();
}

function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
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
    const padding = 40;
    const labelPadding = 25;
    
    svg.innerHTML = '';
    
    // Get max value for scaling
    const maxValue = Math.max(...data, 1);
    const stepSize = Math.ceil(maxValue / 4);
    
    // Draw grid and labels
    for (let i = 0; i <= 4; i++) {
        const y = padding + (height - 2 * padding) * (1 - i / 4);
        const labelValue = (stepSize * i).toFixed(0);
        
        // Add grid lines
        svg.innerHTML += `
            <line 
                x1="${padding}" 
                y1="${y}" 
                x2="${width - padding}" 
                y2="${y}" 
                class="chart-grid"
            />
        `;
        
        // Add labels with fixed width
        svg.innerHTML += `
            <text 
                x="${padding - 10}" 
                y="${y}"
                class="chart-label"
                text-anchor="end"
                dominant-baseline="middle"
                style="font-size: 12px; font-family: sans-serif;"
            >${labelValue}</text>
        `;
    }
    
    // Calculate and draw points
    const points = data.map((value, index) => {
        const x = padding + (width - 2 * padding) * index / (data.length - 1);
        const y = height - padding - (height - 2 * padding) * (value / maxValue);
        return `${x},${y}`;
    }).join(' ');
    
    // Draw line
    svg.innerHTML += `
        <polyline 
            points="${points}" 
            class="${type === 'threat' ? 'threat-line' : 'chart-line'}"
        />
    `;
    
    // Draw points
    data.forEach((value, index) => {
        const x = padding + (width - 2 * padding) * index / (data.length - 1);
        const y = height - padding - (height - 2 * padding) * (value / maxValue);
        svg.innerHTML += `
            <circle 
                cx="${x}" 
                cy="${y}" 
                r="2" 
                class="${type === 'threat' ? 'threat-point' : 'chart-point'}"
            />
        `;
    });
    
    // Draw axes
    svg.innerHTML += `
        <line 
            x1="${padding}" 
            y1="${height - padding}" 
            x2="${width - padding}" 
            y2="${height - padding}" 
            class="chart-axis"
        />
        <line 
            x1="${padding}" 
            y1="${padding}" 
            x2="${padding}" 
            y2="${height - padding}" 
            class="chart-axis"
        />
    `;
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
class NotificationHandler {
    constructor() {
        this.acknowledgedThreats = new Set(this.loadAcknowledgedThreats());
        this.lastThreatCount = 0;
        this.attackCountNotifications = {}; 
        this.restoreNavbarNotifications();
        this.setupNotificationSystem();
    }

    setupNotificationSystem() {
        document.getElementById('signOutBtn').addEventListener("click", function(event) {
            event.preventDefault();
            localStorage.clear();
            document.cookie = "access_token_cookie=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";

            window.location.href = '/';
        });
        // Override the dismiss notification method
        notificationSystem.dismissNavbarNotification = (element) => {
            if (element) {
                element.remove();
                notificationSystem.count = Math.max(0, notificationSystem.count - 1);
                document.getElementById('notificationCount').textContent = notificationSystem.count;
                this.saveNavbarNotifications();
            }
        };
    }

    loadAcknowledgedThreats() {
        try {
            const saved = localStorage.getItem('acknowledgedThreats');
            return saved ? JSON.parse(saved) : [];
        } catch (error) {
            console.error('Error loading acknowledged threats:', error);
            return [];
        }
    }

    loadNavbarNotifications() {
        try {
            const saved = localStorage.getItem('navbarNotifications');
            return saved ? JSON.parse(saved) : [];
        } catch (error) {
            console.error('Error loading navbar notifications:', error);
            return [];
        }
    }

    saveNavbarNotifications() {
        try {
            const notificationsList = document.getElementById('notificationsList');
            if (!notificationsList) return;
            
            const notifications = Array.from(notificationsList.children).map(notification => {
                const messageEl = notification.querySelector('.text-sm.text-gray-800');
                const timeEl = notification.querySelector('.text-xs.text-gray-500');
                return {
                    message: messageEl ? messageEl.textContent : '',
                    time: timeEl ? timeEl.textContent : '',
                    type: 'danger'
                };
            });
            localStorage.setItem('navbarNotifications', JSON.stringify(notifications));
        } catch (error) {
            console.error('Error saving navbar notifications:', error);
        }
    }

    restoreNavbarNotifications() {
        const notifications = this.loadNavbarNotifications();
        const notificationsList = document.getElementById('notificationsList');
        const notificationCount = document.getElementById('notificationCount');
        
        if (!notificationsList || !notificationCount) return;

        notificationsList.innerHTML = '';
        
        notifications.forEach(notification => {
            const notificationElement = document.createElement('div');
            notificationElement.className = 'p-4 border-b border-gray-200 hover:bg-gray-50';
            
            const config = notificationSystem.typeConfig[notification.type] || notificationSystem.typeConfig.warning;
            
            notificationElement.innerHTML = `
                <div class="flex items-start">
                    <div class="flex-shrink-0">
                        <i class="fas ${config.icon} ${config.color}"></i>
                    </div>
                    <div class="ml-3 flex-1">
                        <p class="text-sm text-gray-800">${notification.message}</p>
                        <p class="text-xs text-gray-500 mt-1">${notification.time}</p>
                    </div>
                    <button onclick="event.stopPropagation(); notificationSystem.dismissNavbarNotification(this.closest('.p-4'))" 
                            class="ml-4 text-gray-400 hover:text-gray-500">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            
            notificationsList.appendChild(notificationElement);
        });

        notificationCount.textContent = notifications.length;
        if (notificationSystem) {
            notificationSystem.count = notifications.length;
        }
    }

    saveAcknowledgedThreats() {
        try {
            localStorage.setItem('acknowledgedThreats', 
                JSON.stringify([...this.acknowledgedThreats]));
        } catch (error) {
            console.error('Error saving acknowledged threats:', error);
        }
    }

    saveAttackCountNotifications() {
        try {
            localStorage.setItem('attackCountNotifications', 
                JSON.stringify(this.attackCountNotifications));
        } catch (error) {
            console.error('Error saving attack count notifications:', error);
        }
    }

    // Load attack count notifications
    loadAttackCountNotifications() {
        try {
            const saved = localStorage.getItem('attackCountNotifications');
            return saved ? JSON.parse(saved) : {};
        } catch (error) {
            console.error('Error loading attack count notifications:', error);
            return {};
        }
    }

    generateThreatKey(threat) {
        return `${threat.src_mac}-${threat.dst_mac}-${threat.attack_type}-${threat.time}`;
    }

    handleNewThreats(threats) {
        if (!Array.isArray(threats)) return;

        // Initialize attack count notifications if not already loaded
        if (Object.keys(this.attackCountNotifications).length === 0) {
            this.attackCountNotifications = this.loadAttackCountNotifications();
        }

        // Process each threat
        threats.forEach(threat => {
            const threatKey = this.generateThreatKey(threat);
            const targetMAC = threat.dst_mac;
            const currentCount = threat.count || 0;
            
            // Only notify on the initial detection or when count reaches a multiple of 10
            const isInitialDetection = !this.acknowledgedThreats.has(threatKey);
            const isMultipleOfTen = currentCount > 0 && currentCount % 10 === 0;
            
            // Get last notified count
            const lastNotifiedCount = this.attackCountNotifications[targetMAC] || 0;
            
            if (isInitialDetection || (isMultipleOfTen && lastNotifiedCount < currentCount)) {
                notificationSystem.show(
                    `Detected attack from ${threat.src_mac} to ${threat.dst_mac} (${threat.attack_type})`,
                    'danger'
                );
                
                // Add to acknowledged threats if it's initial detection
                if (isInitialDetection) {
                    this.acknowledgedThreats.add(threatKey);
                }
                
                // Update the last notified count if it's a multiple of 10
                if (isMultipleOfTen) {
                    this.attackCountNotifications[targetMAC] = currentCount;
                    this.saveAttackCountNotifications();
                }
            }
        });
        
        // Save after all notifications are processed
        setTimeout(() => this.saveNavbarNotifications(), 100);
        this.saveAcknowledgedThreats();
    }
}

// Initialize the notification handler
const notificationHandler = new NotificationHandler();

function refreshPacketData() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
        
        fetch(CONFIG.API_ENDPOINTS.PACKETS, {
            signal: controller.signal,
            credentials: 'include'
        })
        .then(response => {
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error('Failed to fetch packet data');
            }
            return response.json();
        })
        .then(data => {
            // Handle new threats using the notification handler
            notificationHandler.handleNewThreats(data.detected_attacks);
            
            // Update total packets counter and chart
            document.getElementById('totalPackets').textContent = data.total_packets;
            updatePacketData(data.total_packets, data.threats || 0);
            
            // Update table
            const packetBody = document.getElementById('packet-table-body');
            packetBody.innerHTML = '';
            
            data.detected_attacks.forEach(packet => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50';
                row.setAttribute('data-attack-id', packet.id);

                const createCell = (content, isStatus = false) => {
                    const td = document.createElement('td');
                    td.className = `px-6 py-4 whitespace-nowrap text-sm ${isStatus ? '' : 'text-gray-500'}`;
                    td.textContent = content;
                    return td;
                };
                
                row.appendChild(createCell(packet.id));
                row.appendChild(createCell(packet.src_mac));
                row.appendChild(createCell(packet.dst_mac));
                row.appendChild(createCell(packet.essid));
                row.appendChild(createCell(packet.channel));
                row.appendChild(createCell(packet.reason_code));
                row.appendChild(createCell(packet.time));
                row.appendChild(createCell(packet.signal_strength));
                row.appendChild(createCell(packet.attack_type));
                row.appendChild(createCell(packet.count));
                
                const resolveCell = document.createElement('td');
                resolveCell.className = 'px-6 py-4 text-sm text-center';
                resolveCell.innerHTML = `
                    <label class="theme-switch attack-switch">
                        <input type="checkbox" class="attack-resolve-toggle"
                            data-attack-id="${packet.id}">
                        <span class="slider"></span>
                    </label>
                `;
                row.appendChild(resolveCell);
                
                packetBody.appendChild(row);
            });
            
            document.querySelectorAll('.attack-resolve-toggle').forEach(toggle => {
                toggle.addEventListener('change', function() {
                    const attackId = this.getAttribute('data-attack-id');
                    
                    if (this.checked) {
                        resolveAttack(attackId);
                    } else {  
                        this.checked = true;
                    }
                });
            });

            document.getElementById('detectedThreats').textContent = data.threats || 0;
            document.getElementById('protectedAPs').textContent = data.protected_aps || 0;
            
        })
        .catch(error => {
            console.error('Error refreshing packet data:', error);
            if (!error.name === 'AbortError') {
                isServerConnected = false;
                updateConnectionStatus(false);
            }
        });
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
            signal: controller.signal,
            credentials: 'include'
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Error('Failed to fetch system stats');
        }

        const data = await response.json();

        if (data.status === 'ok') {
            updateConnectionStatus(true);
            isServerConnected = true;
        } else {
            throw new Error('Server returned non-ok status');
        }

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
        // Update connection status for any error except timeout
        if (error.name !== 'AbortError') {
            isServerConnected = false;
            updateConnectionStatus(false);
            document.getElementById('cpuUsage').textContent = 'N/A';
            document.getElementById('memoryUsage').textContent = 'N/A';
            document.getElementById('diskUsage').textContent = 'N/A';
            document.getElementById('temperature').textContent = 'N/A';
            
            // Reset progress bars
            document.getElementById('cpuBar').style.width = '0%';
            document.getElementById('memoryBar').style.width = '0%';
            document.getElementById('diskBar').style.width = '0%';
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
    startChartUpdates();
    refreshPacketData();

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
    refreshSystemStats();
    updateChart();  // Initialize empty chart
});

// Handle window resize
window.addEventListener('resize', () => {
    updateChart();
});

async function resolveAttack(attackId) {
    try {
        const response = await fetch(`/resolve_attack/${attackId}`, {
            method: 'PUT',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to resolve attack');
        }
        
        const data = await response.json();
        
        // Show notification if notification system exists
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `${data.msg}`,
                'success'
            );
        }
        
        // Remove the row from the table
        const row = document.querySelector(`tr[data-attack-id="${attackId}"]`);
        if (row) {
            row.remove();
        }
        
    } catch (error) {
        console.error('Error resolving attack:', error);
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `Failed to resolve attack ID: ${attackId}`,
                'warning'
            );
        }
        
        // Reset the toggle if resolution failed
        const toggle = document.querySelector(`.attack-resolve-toggle[data-attack-id="${attackId}"]`);
        if (toggle) {
            toggle.checked = false;
        }
    }
}