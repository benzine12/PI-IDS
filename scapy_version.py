from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, Raw
from scapy.layers.dot11 import Dot11, Dot11Deauth
import threading
import subprocess
import logging
import psutil
import time
from collections import defaultdict

app = Flask(__name__, static_folder='static', template_folder='templates')

captured_packets = []
monitor_interface = "wlan1"
log_file = "wids_log.txt"
attack_log = defaultdict(list)  # Store timestamps for each target device
attack_counts = defaultdict(int)  # Count occurrences of attacks by target
packet_counter = 0  # Total packets processed

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def set_monitor_mode(interface):
    """Set the interface to monitor mode."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        return {"status": "success", "message": f"{interface} is now in monitor mode."}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": str(e)}

def is_death_packet(packet):
    """Identify deauthentication attack packets."""
    try:
        if packet.haslayer(Dot11Deauth):
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            src_mac = dot11.addr1 or "Unknown"  # Receiver address
            dst_mac = dot11.addr2 or "Unknown"  # Transmitter address
            reason_code = deauth.reason
            attack_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Log potential deauth packet to terminal
            logging.info(
                f"Deauth Packet Detected: Source={src_mac}, Destination={dst_mac}, Reason={reason_code}, Time={attack_time}"
            )

            # Increment attack count for this target
            attack_counts[dst_mac] += 1

            # Update captured packets for UI
            captured_packets.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "reason_code": reason_code,
                "time": attack_time,
                "summary": f"Deauth attack detected from {src_mac} to {dst_mac} with reason code {reason_code} at {attack_time}",
                "count": attack_counts[dst_mac]
            })

            return True
    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")
    return False

def packet_callback(packet):
    """Process packets and detect potential deauth attacks."""
    global packet_counter
    try:
        packet_counter += 1
        is_death_packet(packet)
    except Exception as e:
        logging.error(f"Error in packet_callback: {e}")

def start_sniffing(interface):
    """Start sniffing packets on the specified interface."""
    sniff(iface=interface, prn=packet_callback, store=False)

@app.route('/')
def home():
    return render_template('scapy_version.html')

@app.route('/packets', methods=['GET'])
def get_packets():
    """Endpoint to get aggregated captured packets and total packet count."""
    # Return aggregated results with counts instead of individual lines
    aggregated_results = {}
    for packet in captured_packets:
        dst_mac = packet["dst_mac"]
        if dst_mac not in aggregated_results:
            aggregated_results[dst_mac] = {
                "src_mac": packet["src_mac"],
                "dst_mac": dst_mac,
                "reason_code": packet["reason_code"],
                "time": packet["time"],
                "count": packet["count"]
            }
        else:
            aggregated_results[dst_mac]["count"] = attack_counts[dst_mac]

    return jsonify({"packets": list(aggregated_results.values()), "total_packets": packet_counter})

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing_endpoint():
    """Endpoint to start sniffing on the monitor interface."""
    global monitor_interface
    interface = request.json.get("interface", monitor_interface)
    monitor_interface = interface
    thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    thread.start()
    return jsonify({"status": "success", "message": f"Started sniffing on {interface}"})

@app.route('/set_monitor', methods=['POST'])
def set_monitor():
    """Endpoint to set the interface to monitor mode."""
    global monitor_interface
    interface = request.json.get("interface", monitor_interface)
    monitor_interface = interface
    result = set_monitor_mode(interface)
    return jsonify(result)

@app.route('/system-stats', methods=['GET'])
def system_stats():
    """Endpoint to fetch system stats."""
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu = psutil.cpu_percent(interval=0.5)
    return jsonify({
        "memory": {
            "total": round(memory.total / (1024**3), 2),  # Convert to GB
            "used": round(memory.used / (1024**3), 2),    # Convert to GB
            "percent": memory.percent,
        },
        "disk": {
            "total": round(disk.total / (1024**3), 2),    # Convert to GB
            "used": round(disk.used / (1024**3), 2),      # Convert to GB
            "percent": disk.percent,
        },
        "cpu": {
            "percent": cpu,
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
