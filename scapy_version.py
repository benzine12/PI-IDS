from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, Raw
from scapy.layers.dot11 import Dot11, Dot11Deauth
import threading
import subprocess
import logging
import psutil
import time
from collections import defaultdict

class DeauthDetector:
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.deauth_history = defaultdict(list)
        self.valid_aps = set()  # Add your valid AP MACs here
        
    def add_valid_ap(self, mac):
        self.valid_aps.add(mac)
        
    def is_legitimate_deauth(self, packet):
        if not packet.haslayer(Dot11Deauth):
            return False
        
        legitimate_reasons = [1, 2, 3, 4]
        if packet[Dot11Deauth].reason not in legitimate_reasons:
            return False
            
        if packet[Dot11].addr2 not in self.valid_aps:
            return False
            
        return True
        
    def detect_pattern(self, packet):
        if not packet.haslayer(Dot11Deauth):
            return False
            
        src = packet[Dot11].addr2
        current_time = time.time()
        
        self.deauth_history[src].append(current_time)
        self.deauth_history[src] = [t for t in self.deauth_history[src] 
                                   if current_time - t <= self.window_size]
        
        if len(self.deauth_history[src]) >= 3:
            intervals = [j-i for i, j in zip(self.deauth_history[src][:-1], 
                                           self.deauth_history[src][1:])]
            avg_interval = sum(intervals) / len(intervals)
            if all(abs(i - avg_interval) < 0.1 for i in intervals):
                return True
                
        return False

app = Flask(__name__, static_folder='static', template_folder='templates')

captured_packets = []
monitor_interface = "wlan1"
log_file = "wids_log.txt"
attack_log = defaultdict(list)  # Store timestamps for each target device
attack_counts = defaultdict(int)  # Count occurrences of attacks by target
packet_counter = 0  # Total packets processed

# Add this with your other global variables
detector = DeauthDetector()

def packet_callback(packet):
    """Enhanced packet processing"""
    global packet_counter
    try:
        packet_counter += 1
        
        if packet.haslayer(Dot11Deauth):
            if detector.is_legitimate_deauth(packet):
                logging.info("Legitimate deauth detected")
                return
                
            if detector.detect_pattern(packet):
                logging.warning("Suspicious deauth pattern detected!")
                
            is_death_packet(packet)
            
    except Exception as e:
        logging.error(f"Error in packet_callback: {e}")

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
    """Enhanced deauthentication packet detection"""
    try:
        if packet.haslayer(Dot11Deauth):
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            
            # Get signal strength
            signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')
            
            src_mac = dot11.addr1 or "Unknown"
            dst_mac = dot11.addr2 or "Unknown"
            reason_code = deauth.reason
            sequence = getattr(dot11, 'SC', 0)
            attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Track attack frequency
            current_time = time.time()
            attack_log[dst_mac].append(current_time)
            
            # Check for flood attacks
            recent_attacks = [t for t in attack_log[dst_mac] 
                            if current_time - t <= 1]
            is_flood = len(recent_attacks) > 10

            # Update attack counts
            attack_counts[dst_mac] += 1
            
            # Log the attack details
            logging.warning(f"Deauth attack detected: {src_mac} -> {dst_mac} "
                          f"(Reason: {reason_code}, Signal: {signal_strength}dBm)")

            captured_packets.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "reason_code": reason_code,
                "time": attack_time,
                "signal_strength": signal_strength,
                "sequence": sequence,
                "count": attack_counts[dst_mac],
                "is_flood": is_flood
            })
            
            return True
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
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
    return render_template('scapy_version_v2.html')

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

    # Read the CPU temperature
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as temp_file:
            temp_c = int(temp_file.read().strip()) / 1000.0  # Convert to Celsius
    except FileNotFoundError:
        temp_c = None  # If the temperature file isn't available

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
        },
        "temperature": {
            "celsius": round(temp_c, 2) if temp_c is not None else "N/A",
        }
    })

@app.route('/add_valid_ap', methods=['POST'])
def add_valid_ap():
    """Add a valid AP MAC address"""
    mac = request.json.get("mac")
    if mac:
        detector.add_valid_ap(mac)
        return jsonify({"status": "success", "message": f"Added {mac} to valid APs"})
    return jsonify({"status": "error", "message": "No MAC address provided"})

@app.route('/health-check')
def health_check():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
