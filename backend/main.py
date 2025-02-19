import os
import sys
import threading
from scapy.all import sniff
from flask import Flask
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import logging, time
from routes import views
from data import attack_counts, packet_counter, ap_scanner, captured_packets, detector,attack_log

# Get the first argument passed to the script
def get_interface():
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        print('No argument! Enter wlan interface')
        exit()
    
interface = get_interface()
print(f"Selected Interface: {interface}")

# Define the base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'frontend', 'static'),
    template_folder=os.path.join(BASE_DIR, 'frontend', 'templates')
)
app.register_blueprint(views)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(message)s",
                    filename='logs.log',
                    encoding='utf-8')

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

def packet_handler(packet):
    global packet_counter
    packet_counter += 1
    if is_death_packet(packet):
        logging.info("Attack detected")

    ap_scanner.process_beacon(packet)

def start_sniffing(interface):
    try:    
        thread = threading.Thread(target=sniff, kwargs={
            'iface': interface,
            'prn': packet_handler,
            'store': False
        }, daemon=True)
        thread.start()
        
        print(f"Started sniffing on {interface}")
        
    except Exception as e:
        print(f"Error starting sniffing: {e}")

if __name__ == '__main__':
    start_sniffing(interface)
    app.run(host='127.0.0.1', port=5000)