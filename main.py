from flask import Flask, render_template, jsonify, request
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import threading, subprocess, logging, psutil, time
from collections import defaultdict

class DeauthDetector:
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.deauth_history = defaultdict(list)
        
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
attack_log = defaultdict(list)
attack_counts = defaultdict(int)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
detector = DeauthDetector()

def is_death_packet(packet):
    try:
        if packet.haslayer(Dot11Deauth):
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            
            if not detector.detect_pattern(packet):
                return False
                
            signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')
            channel = 'N/A'
            
            if packet.haslayer(RadioTap):
                freq = packet[RadioTap].ChannelFrequency
                channel = (freq - 2407) // 5 if freq else 'N/A'
            
            src_mac = dot11.addr1 or "Unknown"
            dst_mac = dot11.addr2 or "Unknown"
            bssid = dot11.addr3 or "Unknown"
            
            attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
            current_time = time.time()
            
            attack_log[dst_mac].append(current_time)
            recent_attacks = [t for t in attack_log[dst_mac] if current_time - t <= 1]
            is_flood = len(recent_attacks) > 10
            attack_counts[dst_mac] += 1

            logging.warning(f"Deauth attack detected: {src_mac} -> {dst_mac} "
                          f"(Reason: {deauth.reason}, Signal: {signal_strength}dBm)")

            captured_packets.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "bssid": bssid,
                "channel": channel,
                "reason_code": deauth.reason,
                "time": attack_time,
                "signal_strength": signal_strength,
                "attack_type": "Deauth",
                "count": attack_counts[dst_mac],
                "is_flood": is_flood
            })
            return True
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
    return False

@app.get('/')
def home():
    return render_template('index.html')

packet_counter = 0

def packet_handler(packet):
    global packet_counter
    packet_counter += 1
    if is_death_packet(packet):
        logging.info("Attack detected")

@app.get('/packets')
def get_packets():
    aggregated_results = {}
    for packet in captured_packets:
        dst_mac = packet["dst_mac"]
        if dst_mac not in aggregated_results:
            aggregated_results[dst_mac] = packet
        else:
            aggregated_results[dst_mac]["count"] = attack_counts[dst_mac]

    return jsonify({
        "packets": list(aggregated_results.values()),
        "total_packets": packet_counter,
        "threats": len(captured_packets)
    })
        
@app.post('/start_sniffing')
def start_sniffing_endpoint():
    global monitor_interface
    interface = request.json.get("interface", monitor_interface)
    monitor_interface = interface
    try:
        result = set_monitor_endpoint()
        if result.json["status"] != "success":
            return jsonify({"status": "error", "message": "Failed to set monitor mode"})
            
        thread = threading.Thread(target=sniff, kwargs={
            'iface': interface,
            'prn': packet_handler,
            'store': False
        }, daemon=True)
        thread.start()
        
        return jsonify({"status": "success", "message": f"Started sniffing on {interface}"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.post('/set_monitor')
def set_monitor_endpoint():
    global monitor_interface
    interface = request.json.get("interface", monitor_interface)
    monitor_interface = interface
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        return jsonify({"status": "success", "message": f"{interface} is now in monitor mode"})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)})

@app.get('/system-stats')
def system_stats():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu = psutil.cpu_percent(interval=0.5)
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as temp_file:
            temp_c = int(temp_file.read().strip()) / 1000.0
    except FileNotFoundError:
        temp_c = None
    return jsonify({
        "memory": {
            "total": round(memory.total / (1024**3), 2),
            "used": round(memory.used / (1024**3), 2),
            "percent": memory.percent,
        },
        "disk": {
            "total": round(disk.total / (1024**3), 2),
            "used": round(disk.used / (1024**3), 2),
            "percent": disk.percent,
        },
        "cpu": {"percent": cpu},
        "temperature": {"celsius": round(temp_c, 2) if temp_c is not None else "N/A"}
    })

@app.get('/health-check')
def health_check():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)