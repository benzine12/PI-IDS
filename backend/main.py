import os
from flask import Flask, render_template, jsonify, request
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import threading, subprocess, logging, psutil, time
from collections import defaultdict
from module_APscan import APScanner
from module_DeauthDetector import DeauthDetector

# Define the base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'frontend', 'static'),
    template_folder=os.path.join(BASE_DIR, 'frontend', 'templates')
)


captured_packets = []
monitor_interface = "wlan1"
attack_log = defaultdict(list)
attack_counts = defaultdict(int)
packet_counter = 0

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(message)s")

detector = DeauthDetector()
ap_scanner = APScanner()

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
    return render_template('dashboard.html')

def packet_handler(packet):
    global packet_counter
    packet_counter += 1
    if is_death_packet(packet):
        logging.info("Attack detected")

    ap_scanner.process_beacon(packet)

@app.get('/ap-scan')
def ap_scan_page():
    return render_template('ap_scan.html')

@app.get('/get-aps')
def get_aps():
    try:
        aps = ap_scanner.get_active_aps()
        stats = ap_scanner.get_ap_stats()
        return jsonify({
            "status": "success",
            "access_points": aps,
            "statistics": stats
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

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
        "status": "ok",
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)