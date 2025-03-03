let updateTimer;

async function updateAPList() {
    try {
        const response = await fetch('/get-aps', {
            credentials: 'include'
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
                    <td class="px-6 py-4 text-sm text-gray-500">${ap.connected_devices || 'N/A'}</td>
                    <td class="px-6 py-4 text-sm text-center">
                        <label class="theme-switch ap-switch">
                            <input type="checkbox" class="ap-protect-toggle"
                                data-bssid="${ap.bssid}" 
                                data-essid="${ap.essid}" 
                                data-band="${ap.band}" 
                                data-crypto="${ap.crypto.join(',')}"
                                ${ap.protected ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </td>
                `;
                apList.appendChild(row);
            });
            
            // Add event listeners to the toggle switches
            document.querySelectorAll('.ap-protect-toggle').forEach(toggle => {
                toggle.addEventListener('change', function() {
                    const bssid = this.getAttribute('data-bssid');
                    const essid = this.getAttribute('data-essid');
                    const band = this.getAttribute('data-band');
                    const crypto = this.getAttribute('data-crypto');
                    
                    if (this.checked) {
                        setToProtected(bssid, essid, band, crypto);
                    } else {
                        removeFromProtected(bssid, essid);
                    }
                });
            });
            
            lastUpdate.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
        }
    } catch (error) {
        console.error('Error updating AP list:', error);
    }
}

async function setToProtected(bssid, essid, band, crypto) {
    try {
        const response = await fetch('/set_to_protected', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                bssid: bssid,
                essid: essid,
                band: band,
                crypto: crypto
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to add AP to protected list');
        }
        
        const data = await response.json();
        
        // Show notification if notification system exists
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `${data.msg}: ${essid}`,
                'success'
            );
        }
        
    } catch (error) {
        console.error('Error protecting AP:', error);
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `Failed to protect AP: ${essid}`,
                'warning'
            );
        }
        
        // Reset the toggle if protection failed
        const toggle = document.querySelector(`.ap-protect-toggle[data-bssid="${bssid}"]`);
        if (toggle) {
            toggle.checked = false;
        }
    }
}

async function removeFromProtected(bssid, essid) {
    try {
        const response = await fetch('/remove_from_protected', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                bssid: bssid
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to remove AP from protected list');
        }
        
        const data = await response.json();
        
        // Show notification if notification system exists
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `${data.msg}: ${essid}`,
                'success'
            );
        }
        
    } catch (error) {
        console.error('Error removing AP from protection:', error);
        if (typeof notificationSystem !== 'undefined') {
            notificationSystem.show(
                `Failed to remove AP from protection: ${essid}`,
                'warning'
            );
        }
        
        // Reset the toggle if protection removal failed
        const toggle = document.querySelector(`.ap-protect-toggle[data-bssid="${bssid}"]`);
        if (toggle) {
            toggle.checked = true;
        }
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