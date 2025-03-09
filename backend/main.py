import os
import sys
import argparse
import threading
from datetime import timedelta
from flask_cors import CORS
from scapy.all import sniff
from flask import Flask, redirect
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap,Dot11Beacon,Dot11Beacon,Dot11ProbeResp
import logging, time
from models import AP, Attack, User
from routes import views
from data import BASE_DIR, DB, bcrypt, jwt, state
from modules import deauth_detector, ap_scanner, probe_detector,beacon_spam_detector
import subprocess
from datetime import datetime, timezone
import argparse
import re
from collections import defaultdict

interface = ''

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

def get_password():
    password = input("Enter password: ")
            
    # check for correct password
    while True:
        if len(password) <=8:
            print("password should be longer that 8 characters")
            exit()
        elif not re.search("[a-z]", password):
            print("The alphabet must be between a-z")
            exit()
        elif not re.search("[A-Z]", password):
            print('At least one alphabet should be of Upper Case')
            exit()
        elif not re.search("[0-9]", password):
            print('At least 1 number or digit between')
            exit()
        elif not re.search("[_@$]" , password):
            print('At least 1 character from')
            exit()
        elif re.search(r"\s" , password):
            print('No whitespace character')
            exit()
        else:
            return password

def arguments_handler():
    """ handle different arguments from user"""
    try:
        global interface
        # Initialize parser
        parser = argparse.ArgumentParser()

        # Adding optional argument
        parser.add_argument("-c", "--Create", help = "add new user")
        parser.add_argument("-u", "--Update", help = "update user password")
        parser.add_argument("-d", "--Delete", help = "Delete user")
        parser.add_argument("-i", "--Interface", help = "Add wlan interface to work with")

        # Read arguments from command line
        args = parser.parse_args()

        # check wich arguments written
        if args.Create:
            username = args.Create

            if len(args.Create) <=8:
                print('Username should be longer then 8 letters')
                exit()
            elif User.query.filter_by(username=username).first():
                print('This username already exist')
                exit()
            
            password = get_password()

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)

            DB.session.add(new_user)
            DB.session.commit()
            print('Added new user')
            exit()

        elif args.Update:

            username = args.Update
            old_password = input("Enter your existing password to update it: ")

            user = User.query.filter_by(username=username).first()

            if user and bcrypt.check_password_hash(user.password, old_password):
                new_password = input('Enter new passowrd: ')
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

                updated_user = User(username=username, password=hashed_password)
                DB.session.add(updated_user)
                DB.session.commit()
                print('Updated new user')
            exit()

        elif args.Delete:
            username = args.Delete
            password = input("Enter your password: ")

            user = User.query.filter_by(username=username).first()

            if user and bcrypt.check_password_hash(user.password, password):
                User.query.filter_by(username=username).delete()
                DB.session.commit()
                print('User deleted')
            else:
                print('there is an error username or password is wrong')
            exit()

        elif args.Interface:
            interface = args.Interface
        elif not args.Interface:
            print('Enter wlan interface to work with')
            sys.exit(1)

    except argparse.ArgumentError as e:
        print('Catching an argumentError, ' + e)

def channel_hopper(interface):
    """Hops between wireless channels to scan all networks (2.4GHz & 5GHz)"""
    
    # 2.4GHz channels
    channels_2ghz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    
    # 5GHz channels (non-radar channels first)
    channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]
    
    # Combine all channels
    all_channels = channels_2ghz + channels_5ghz
    
    def hop_channels():
        while True:
            for channel in all_channels:
                try:
                    subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(channel)], 
                                  stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                    time.sleep(0.3)  # Hop every 0.3 seconds
                except:
                    # Skip channels not supported by the adapter
                    pass
    
    # Start hopping in background thread
    hopper = threading.Thread(target=hop_channels)
    hopper.daemon = True
    hopper.start()

def to_monitor(interface):
    """Put the interface in monitor mode and start channel hopping"""
    try:
        # Enable monitor mode
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
        
        # Start channel hopping
        channel_hopper(interface)
        
        print(f"Started {interface} in monitor mode with channel hopping")
    except Exception as e:
        print(f"Error putting interface in monitor mode: {e}")
        exit()

def is_deauth(packet):
    """Check if the packet is a deauth attack and save it to the database"""
    try:
        if packet.haslayer(Dot11Deauth):
            dot11 = packet[Dot11]
            
            # pass the packet to detector to check if it matches the pattern
            if not deauth_detector.detect_pattern(packet):
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
            
            # update the state manager 
            state.attack_log[dst_mac].append(time.time())
            state.attack_counts[dst_mac] += 1

            logging.warning(f"{attack_type} attack detected on {essid} at {attack_time}")

            # Find existing attack or create new one
            with app.app_context():
                existing = Attack.query.filter_by(
                    attack_type=attack_type,
                    src_mac=src_mac,
                    dst_mac=dst_mac
                ).first()
                
                if existing:
                    existing.count += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.signal_strength = signal_strength
                else:
                    new_attack = Attack(
                        attack_type=attack_type,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        essid=essid,
                        bssid=bssid,
                        channel=channel,
                        signal_strength=signal_strength,
                        count=1
                    )
                    DB.session.add(new_attack)
                
                DB.session.commit()
            
            return True
            
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
    return False

def is_prob_scanner(packet):
    """Check if the packet is from a probe scanner and save it to the database"""
    try:
        probe_detection = probe_detector.process_packet(packet)
        if probe_detection:
            src_mac = probe_detection["src_mac"]
            essid = probe_detection.get("essid", "Multiple")
            signal_strength = probe_detection.get("signal_strength", "N/A")
            attack_time = probe_detection.get("time", time.strftime("%Y-%m-%d %H:%M:%S"))
            
            state.attack_log[src_mac].append(time.time())
            state.attack_counts[src_mac] += 1
            
            logging.warning(f"Probe scanner detected from {src_mac} at {attack_time}")
            
            # Save to database
            with app.app_context():
                existing = Attack.query.filter_by(
                    attack_type="Probe Scanner",
                    src_mac=src_mac
                ).first()
                
                if existing:
                    existing.count += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.signal_strength = signal_strength
                else:
                    new_attack = Attack(
                        attack_type="Probe Scanner",
                        src_mac=src_mac,
                        essid=essid,
                        signal_strength=signal_strength,
                        count=1,
                        channel=probe_detection.get("channel", "N/A")
                    )
                    DB.session.add(new_attack)
                
                DB.session.commit()
            
            return True
            
    except Exception as e:
        logging.error(f"Error processing packet in is_prob_scanner: {e}")
    return False

def is_rogue_ap(packet):
    """
    Detects rogue APs and karma attacks by checking for:
    1. Same ESSID as protected AP but different crypto (rogue AP)
    2. Same ESSID, different crypto AND lots of probe responses (karma attack)
    3. Uses OUI (first 8 digits of BSSID) comparison for better detection
    """
    
    # Initialize the probe response counter if it doesn't exist
    if not hasattr(state, 'probe_resp_counter'):
        state.probe_resp_counter = defaultdict(int)
    
    # Track probe responses by BSSID
    if packet.haslayer(Dot11ProbeResp):
        try:
            dot11 = packet[Dot11]
            bssid = dot11.addr3
            state.probe_resp_counter[bssid] += 1
            return False  # Continue processing other packets
        except Exception as e:
            logging.error(f"Error processing probe response: {e}")
            return False
    
    # Check for rogue APs via beacon frames
    if packet.haslayer(Dot11Beacon):
        try:
            dot11 = packet[Dot11]
            bssid = dot11.addr3
            stats = packet[Dot11Beacon].network_stats()
            
            essid = stats.get("ssid")
            crypto = stats.get("crypto", set())

            if not essid:
                return False
                
            with app.app_context():
                # Check for protected APs with this ESSID
                protected_aps = AP.query.filter_by(essid=essid).all()
                
                if not protected_aps:
                    return False
                
                for p_ap in protected_aps:
                    # Extract first 8 digits (OUI) from BSSID for comparison
                    p_ap_oui = p_ap.bssid[:8] if p_ap.bssid else ""
                    current_ap_oui = bssid[:8] if bssid else ""
                    
                    p_crypto = p_ap.crypto.split(',') if isinstance(p_ap.crypto, str) else p_ap.crypto
                    
                    p_crypto_normalized = set(p_crypto) if isinstance(p_crypto, list) else {p_crypto}
                    crypto_normalized = set(crypto) if isinstance(crypto, set) else {crypto}
                
                    # Check for same ESSID but different OUI or different crypto
                    is_different_device = p_ap_oui != current_ap_oui
                    is_different_crypto = p_crypto_normalized != crypto_normalized
                    
                    if p_ap.essid == essid and (is_different_device or is_different_crypto):
                        # Get probe response count for this BSSID
                        probe_resp_count = state.probe_resp_counter.get(bssid, 0)
                        karma_threshold = 20  # minimum probe responses to trigger karma attack
                        
                        attack_type = "Karma Attack" if probe_resp_count >= karma_threshold else "Rogue AP"
                        
                        if attack_type == "Karma Attack":
                            logging.warning(f"KARMA ATTACK DETECTED: ESSID={essid}, BSSID={bssid}, OUI={current_ap_oui}, "
                                        f"Crypto={crypto}, Protected BSSID={p_ap.bssid}, Protected OUI={p_ap_oui}, "
                                        f"Protected Crypto={p_ap.crypto}, "
                                        f"Probe Responses: {probe_resp_count}")
                        else:
                            logging.warning(f"ROGUE AP DETECTED: ESSID={essid}, BSSID={bssid}, OUI={current_ap_oui}, "
                                        f"Crypto={crypto}, Protected BSSID={p_ap.bssid}, Protected OUI={p_ap_oui}, "
                                        f"Protected Crypto={p_ap.crypto}")

                        attack_time = datetime.now(timezone.utc)
                        existing = Attack.query.filter_by(
                                    attack_type=attack_type,
                                    bssid=bssid,
                                    essid=essid
                                ).first()
                        if existing:
                            existing.count += 1
                            existing.last_seen = attack_time
                        else:
                            new_attack = Attack(
                                attack_type=attack_type,
                                src_mac=bssid, 
                                dst_mac="Broadcast",
                                essid=essid,
                                bssid=bssid,
                                channel=stats.get("channel", "N/A"),
                                signal_strength=getattr(packet, 'dBm_AntSignal', 'N/A'),
                                count=1
                            )
                            DB.session.add(new_attack)
                        
                        DB.session.commit()
                        return True
            
            return False

        except Exception as e:
            logging.error(f"Error in rogue AP detection: {e}")
            return False
    
    return False

def is_beacon_spam(packet):
    """Check if the packet is part of a beacon spam attack and save it to the database"""
    try:
        # Track all beacon frames
        if not beacon_spam_detector.track_beacon(packet):
            return False
            
        # Get the BSSID
        if not packet.haslayer(Dot11Beacon):
            return False
            
        bssid = packet[Dot11].addr3
        
        # Update AP info in the beacon spam detector
        if bssid in ap_scanner.detected_aps:
            beacon_spam_detector.update_ap_info(bssid, ap_scanner.detected_aps[bssid])
        
        # Add a static variable to track last alert time for each BSSID
        if not hasattr(is_beacon_spam, "last_alert"):
            is_beacon_spam.last_alert = {}
        
        # Check for spam (this will only return results when threshold is exceeded)
        spam_results = beacon_spam_detector.check_for_beacon_spam()
        
        if not spam_results:
            return False
            
        # Process each detected spam result
        for result in spam_results:
            if result["bssid"] == bssid:
                current_time = time.time()
                
                # Only alert once every 60 seconds for the same BSSID
                if bssid in is_beacon_spam.last_alert and current_time - is_beacon_spam.last_alert[bssid] < 60:
                    return False
                
                is_beacon_spam.last_alert[bssid] = current_time
                
                # Get necessary information for attack record
                essid = result["essid"]
                signal_strength = result["signal_strength"]
                channel = result["channel"]
                count = result["beacon_count"]
                beacon_rate = result.get("beacon_rate", count / 60.0)  # Beacons per second
                
                attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
                
                # Update attack count in state manager
                state.attack_log[bssid].append(time.time())
                state.attack_counts[bssid] += 1
                
                logging.warning(f"Beacon Spam attack detected from {bssid} ({essid}) at {attack_time}")
                
                # Save to database
                with app.app_context():
                    existing = Attack.query.filter_by(
                        attack_type="Beacon Spam",
                        src_mac=bssid
                    ).first()
                    
                    if existing:
                        existing.count = count
                        existing.last_seen = datetime.now(timezone.utc)
                        existing.signal_strength = signal_strength
                    else:
                        new_attack = Attack(
                            attack_type="Beacon Spam",
                            src_mac=bssid,
                            essid=essid,
                            channel=str(channel),
                            signal_strength=str(signal_strength),
                            count=count
                        )
                        DB.session.add(new_attack)
                    
                    DB.session.commit()
                
                return True
                
    except Exception as e:
        logging.error(f"Error processing packet in is_beacon_spam: {e}")
    
    return False

def packet_handler(packet):
    """Handle the packets received by the sniffer"""
    state.packet_counter += 1
    is_deauth(packet)
    is_prob_scanner(packet)
    ap_scanner.process_beacon(packet)
    is_beacon_spam(packet)
    is_rogue_ap(packet)

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
    
    app = create_app()
    with app.app_context():
        DB.create_all()
        arguments_handler()
    
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