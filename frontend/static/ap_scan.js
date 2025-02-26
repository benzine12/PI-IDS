let updateTimer;
let token = localStorage.getItem('accessToken');

function getAuthHeaders() {
    return {
        'Authorization': token ? `Bearer ${token}` : '',
        'Content-Type': 'application/json'
    };
}

async function updateAPList() {
    try {
        const response = await fetch('/get-aps',{
            headers: getAuthHeaders()
        });
        const data = await response.json();

        if (data.status === 'success') {
            const apList = document.getElementById('ap-list');
            const totalAPs = document.getElementById('totalAPs');
            const band24 = document.getElementById('24ghzAPs');
            const band5 = document.getElementById('5ghzAPs');
            const securityStats = document.getElementById('securityStats');
            const lastUpdate = document.getElementById('lastUpdate');

            // Update statistics
            totalAPs.textContent = data.statistics.total_aps;
            band24.textContent = data.statistics.bands['2.4GHz'];
            band5.textContent = data.statistics.bands['5GHz'];

            // Update security stats
            securityStats.innerHTML = '';
            Object.entries(data.statistics.security).forEach(([security, count]) => {
                const div = document.createElement('div');
                div.className = 'bg-gray-50 p-4 rounded-lg';
                div.innerHTML = `
                    <p class="text-sm text-gray-500">${security}</p>
                    <p class="text-xl font-semibold mt-1">${count}</p>
                `;
                securityStats.appendChild(div);
            });

            // Update AP list with hover effect
            apList.innerHTML = '';
            data.access_points.forEach(ap => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50';
                row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${ap.bssid}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">
                    ${ap.essid.length > 15 ? ap.essid.substring(0, 15) + "..." : ap.essid}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.band}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.channel}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.crypto.join(', ')}</td>
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.signal_strength} dBm</td>
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.connected_devices} dBm</td>
                    `;
                apList.appendChild(row);
            });

            lastUpdate.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
        }
    } catch (error) {
        console.error('Error updating AP list:', error);
    }
}

// Update AP list every 10 seconds
document.addEventListener('DOMContentLoaded', () => {
    updateAPList();
    updateTimer = setInterval(updateAPList, 10000);
});

// Clean up timer when leaving page
window.addEventListener('beforeunload', () => {
    if (updateTimer) clearInterval(updateTimer);
});