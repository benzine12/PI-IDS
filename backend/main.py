import os
import sys
import threading
from scapy.all import sniff
from flask import Flask
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import logging, time
from routes import views
from data import state, detector, ap_scanner
import subprocess

def get_interface():
    """ get the itnerface from the command line arguments """
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        print('No argument! Enter wlan interface')
        exit()
        
interface = get_interface()
print(f"Selected Interface: {interface}")

def to_monitor(interface):
    """ Put the interface in monitor mode """
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except Exception as e:
        print(f"Error putting interface in monitor mode: {e}")
        exit()
    

# Define the base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

log = logging.getLogger('werkzeug')
log.disabled = True

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'frontend', 'static'),
    template_folder=os.path.join(BASE_DIR, 'frontend', 'templates')
)
app.register_blueprint(views)

logging.basicConfig(level=logging.ERROR,
                    format="%(asctime)s - %(message)s",
                    filename='logs.log',
                    encoding='utf-8')

def is_deauth(packet):
    """ Check if the packet is a deauth attack and add it to the detected_attacks list """ 
    try:
        if packet.haslayer(Dot11Deauth):
            dot11 = packet[Dot11]
            deauth = packet[Dot11Deauth]
            
            # pass the packet to detector to check if it matches the pattern
            if not detector.detect_pattern(packet):
                return False
            
            # get the signal strength
            signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')
            channel = 'N/A'
            
            # get the channel from the RadioTap layer
            if packet.haslayer(RadioTap):
                freq = packet[RadioTap].ChannelFrequency
                channel = (freq - 2407) // 5 if freq else 'N/A'
            
            src_mac = dot11.addr1 or "Unknown" # the attacker
            dst_mac = dot11.addr2 or "Unknown" # the target
            bssid = dot11.addr3 or "Unknown" # the AP
            
            attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
            current_time = time.time()
            
            state.attack_log[dst_mac].append(current_time)
            state.attack_counts[dst_mac] += 1

            logging.warning(f"Deauth attack detected: {src_mac} -> {dst_mac} "
                          f"(Reason: {deauth.reason}, Signal: {signal_strength}dBm)")

            # append the attack to the detected_attacks list
            state.detected_attacks.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "bssid": bssid,
                "channel": channel,
                "reason_code": deauth.reason,
                "time": attack_time,
                "signal_strength": signal_strength,
                "attack_type": "Deauth",
                "count": state.attack_counts[dst_mac],
            })
            return True
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
    return False

def packet_handler(packet):
    """ Handle the packets received by the sniffer """

    state.packet_counter += 1
    if is_deauth(packet):
        logging.warning("Attack detected")

    ap_scanner.process_beacon(packet)

def start_sniffing(interface):
    """ Start the packet sniffing on the specified interface """
    try:
        to_monitor(interface)
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
    app.run(host='0.0.0.0', port=5000, debug=True)