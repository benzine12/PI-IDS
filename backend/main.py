import os
import sys
import threading
from datetime import timedelta
from flask_cors import CORS
from scapy.all import sniff
from flask import Flask, redirect
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
import logging, time
from routes import views
from data import state, BASE_DIR, DB, bcrypt, jwt
from modules import detector, ap_scanner, probe_detector
import subprocess

def create_app():
    """Create and configure the Flask application"""
    app = Flask(
        __name__,
        static_folder=os.path.join(BASE_DIR, 'frontend', 'static'),
        template_folder=os.path.join(BASE_DIR, 'frontend', 'templates')
    )
    # Configure the application
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wids.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
    app.config['JWT_ALGORITHM'] = "HS256"
    app.config['JWT_TOKEN_LOCATION'] = ["cookies"]
    app.config['JWT_COOKIE_NAME'] = "access_token_cookie"
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False 
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_ERROR_MESSAGE_KEY'] = 'msg'

    # Initialize extensions
    CORS(app)
    DB.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    
# JWT error handlers for redirecting to login
    @jwt.unauthorized_loader
    def handle_unauthorized_loader(msg):
        """Called when no JWT is present in the request"""
        return redirect('/')

    @jwt.invalid_token_loader
    def handle_invalid_token(msg):
        """Called when the JWT is invalid, malformed, or tampered with"""
        return redirect('/')

    @jwt.expired_token_loader
    def handle_expired_token(jwt_header, jwt_payload):
        """Called when the JWT has expired"""
        return redirect('/')

    # Register blueprints
    app.register_blueprint(views)
    
    return app

def get_interface():
    """Get the interface from the command line arguments"""
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        print('No argument! Enter wlan interface')
        exit()

def to_monitor(interface):
    """Put the interface in monitor mode"""
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except Exception as e:
        print(f"Error putting interface in monitor mode: {e}")
        exit()

def is_deauth(packet):
    """Check if the packet is a deauth attack and add it to the detected_attacks list"""
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
            essid = ap_scanner.detected_aps.get(bssid, {}).get("essid") or bssid or "Unknown"
            attack_type = "Deauth"

            attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
            current_time = time.time()
            
            state.attack_log[dst_mac].append(current_time)
            state.attack_counts[dst_mac] += 1

            logging.warning(f"{attack_type} attack detected on {essid} at {attack_time}")

            # append the attack to the detected_attacks list
            state.detected_attacks.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "essid": essid,
                "channel": channel,
                "reason_code": deauth.reason,
                "time": attack_time,
                "signal_strength": signal_strength,
                "attack_type": attack_type,
                "count": state.attack_counts[dst_mac],
            })
            return True
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
    return False

def is_prob_scanner(packet):
    try:
        probe_detection = probe_detector.process_packet(packet)
        if probe_detection:
            # Add to the state's detected_attacks list
            src_mac = probe_detection["src_mac"]
            state.attack_counts[src_mac] += 1
            probe_detection["count"] = state.attack_counts[src_mac]
            state.detected_attacks.append(probe_detection)
        
            current_time = time.time()
            state.attack_log[src_mac].append(current_time)
            logging.warning(f"Probe scanner detected from {src_mac} at {probe_detection['time']}")

            return True
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
    return False

def packet_handler(packet):
    """Handle the packets received by the sniffer"""
    state.packet_counter += 1
    is_deauth(packet)
    is_prob_scanner(packet)
    ap_scanner.process_beacon(packet)


def start_sniffing(interface):
    """Start the packet sniffing on the specified interface"""
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
    interface = get_interface()
    print(f"Selected Interface: {interface}")
    
    app = create_app()
    with app.app_context():
        DB.create_all()
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("logs.log"),
            logging.StreamHandler()
        ]
    )
    log = logging.getLogger('werkzeug')
    log.disabled = True

    
    start_sniffing(interface)
    app.run(host='0.0.0.0', port=5000, debug=False)