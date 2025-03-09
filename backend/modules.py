from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap,Dot11Deauth,Dot11ProbeReq
import logging
from collections import defaultdict
import time
from data import DB
from models import AP

class DeauthDetector:
    """ Class to detect deauth attacks """
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.deauth_history = defaultdict(list)
        
    def detect_pattern(self, packet):
        """ Check if the packet matches the pattern of a deauth attack """
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

deauth_detector = DeauthDetector()

class APScanner:

    """Class to scan for APs and extract information from beacon frames"""
    def __init__(self,threshold=15,unique_ssids_threshold=5):
        self.detected_aps = {}
 
    def process_beacon(self, packet):
        """Process beacon frames to extract AP information"""
        if not packet.haslayer(Dot11Beacon):
            return
            
        try:
            bssid = packet[Dot11].addr3
            stats = packet[Dot11Beacon].network_stats()
            
            essid = stats.get("ssid")
            channel = stats.get("channel", 0)
            crypto = stats.get("crypto", set())
            signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')
            
            # Determine frequency band (2.4GHz or 5GHz)
            freq = None
            if packet.haslayer(RadioTap):
                freq = packet[RadioTap].ChannelFrequency
            band = "5GHz" if freq and freq > 3000 else "2.4GHz"
            
            self.detected_aps[bssid] = {
                "bssid": bssid,
                "essid": essid,
                "channel": channel,
                "crypto": list(crypto),
                "signal_strength": signal_strength,
                "band": band,
                "last_seen": time.time()
            }
            
        except Exception as e:
            logging.error(f"Error processing beacon frame: {e}")
    
    def get_active_aps(self, timeout=300):
        """Get list of APs seen within the timeout period"""
        current_time = time.time()
        active_aps = {
            bssid: ap for bssid, ap in self.detected_aps.items()
            if current_time - ap['last_seen'] <= timeout
        }
        return list(active_aps.values())
    
    def get_ap_stats(self):
        """Get statistics about detected APs"""
        active_aps = self.get_active_aps()
        
        bands_count = {
            "2.4GHz": len([ap for ap in active_aps if ap["band"] == "2.4GHz"]),
            "5GHz": len([ap for ap in active_aps if ap["band"] == "5GHz"])
        }
        
        security_count = defaultdict(int)
        for ap in active_aps:
            for crypto in ap["crypto"]:
                security_count[crypto] += 1
        
        return {
            "total_aps": len(active_aps),
            "bands": bands_count,
            "security": dict(security_count)
        }

ap_scanner = APScanner()

class ProbeScannerDetector:
    """Class to detect unusual probe request scanning activity"""
    def __init__(self, time_window=30, threshold=15, unique_ssids_threshold=5):
        """Initialize the probe scanner detector.
        
        Args:
            time_window (int): Time window in seconds to analyze probe requests
            threshold (int): Number of probe requests within time window to trigger detection
            unique_ssids_threshold (int): Minimum number of unique SSIDs requested to consider it scanning
        """
        self.time_window = time_window
        self.threshold = threshold
        self.unique_ssids_threshold = unique_ssids_threshold
        
        # Store probe requests with timestamp
        self.probe_history = defaultdict(list)  # MAC -> [(timestamp, ssid), ...]
        self.detected_scanners = set()  # Track MACs already detected as scanners
        self.last_alert_time = defaultdict(float)  # MAC -> last alert timestamp
        self.alert_cooldown = 300  # 5 minutes between repeated alerts for the same MAC
        
    def process_packet(self, packet):
        """Process a packet to detect if it's a probe request part of a scanning pattern"""
        if not packet.haslayer(Dot11ProbeReq):
            return None
            
        try:
            dot11 = packet[Dot11]
            src_mac = dot11.addr2
            
            ssid = ''
            if packet.haslayer(Dot11ProbeReq):
                if packet[Dot11ProbeReq].info:
                    ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='replace')
            
            current_time = time.time()
            
            # Add the probe request to history
            self.probe_history[src_mac].append((current_time, ssid))
            
            # Clean up old entries
            self.cleanup_history(src_mac, current_time)
            
            # Check if this MAC is scanning
            if self.is_scanning(src_mac, current_time):
                # Avoid repeated alerts for the same MAC
                if (current_time - self.last_alert_time[src_mac] > self.alert_cooldown or
                    src_mac not in self.detected_scanners):
                    
                    self.detected_scanners.add(src_mac)
                    self.last_alert_time[src_mac] = current_time
                    
                    # Get signal strength if available
                    signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')
                    
                    # Count unique SSIDs
                    unique_ssids = set(ssid for _, ssid in self.probe_history[src_mac])
                    
                    # Log the detection
                    attack_time = time.strftime("%Y-%m-%d %H:%M:%S")
                    logging.warning(f"Probe scanner detected from {src_mac} at {attack_time}")
                    
                    # Return detection information
                    return {
                        "src_mac": src_mac,
                        "essid": "Multiple" if len(unique_ssids) > 1 else next(iter(unique_ssids), "Unknown"),
                        "unique_ssids": len(unique_ssids),
                        "probe_count": len(self.probe_history[src_mac]),
                        "time": attack_time,
                        "signal_strength": signal_strength,
                        "attack_type": "Probe Scanner",
                    }
            
        except Exception as e:
            logging.error(f"Error processing probe request: {e}")
            
        return None
    
    def cleanup_history(self, mac, current_time):
        """Remove probe requests older than the time window.
        
        Args:
            mac (str): MAC address to cleanup
            current_time (float): Current timestamp
        """
        self.probe_history[mac] = [
            (ts, ssid) for ts, ssid in self.probe_history[mac]
            if current_time - ts <= self.time_window
        ]
    
    def is_scanning(self, mac, current_time):
        """Determine if a MAC address is exhibiting scanning behavior.
        
        A MAC is considered to be scanning if:
        1. It has sent more probe requests than the threshold within the time window
        2. It has requested more unique SSIDs than the unique SSIDs threshold
        
        Args:
            mac (str): MAC address to check
            current_time (float): Current timestamp
            
        Returns:
            bool: True if scanning detected, False otherwise
        """
        # Get probes within the time window
        probes = [p for p in self.probe_history[mac] 
                if current_time - p[0] <= self.time_window]
        
        if len(probes) < self.threshold:
            return False
        
        # Count unique SSIDs being probed
        unique_ssids = set(ssid for _, ssid in probes)
        
        # Detect based on volume and uniqueness
        return (len(probes) >= self.threshold and 
                len(unique_ssids) >= self.unique_ssids_threshold)
    
probe_detector = ProbeScannerDetector()

class BeaconSpamDetector:
    def __init__(self, time_window=60, threshold=550):
        self.detected_aps = {}
        self.beacon_timestamps = defaultdict(list)  # BSSID -> list of timestamps
        self.time_window = time_window
        self.threshold = threshold
        
    def update_ap_info(self, bssid, ap_info):
        """Update access point information for a BSSID"""
        self.detected_aps[bssid] = ap_info
        
    def track_beacon(self, packet):
        """Track beacon frames for spam detection"""
        if not packet.haslayer(Dot11Beacon):
            return False
            
        try:
            bssid = packet[Dot11].addr3
            current_time = time.time()
            
            # Add timestamp to the list for this BSSID
            self.beacon_timestamps[bssid].append(current_time)
            
            # Periodically clean up old timestamps (keep last 5 minutes)
            if len(self.beacon_timestamps[bssid]) % 100 == 0:  # Every 100 beacons
                self.beacon_timestamps[bssid] = [t for t in self.beacon_timestamps[bssid] 
                                              if current_time - t <= 300]  # 5 minutes
            
            return True
        except Exception as e:
            logging.error(f"Error tracking beacon: {e}")
            return False
    
    def check_for_beacon_spam(self):
        """
        Detect beacon frame spamming based on beacon frequency.
        
        Returns:
            list: List of dictionaries containing information about detected beacon spammers
        """
        current_time = time.time()
        spam_results = []
        
        for bssid, timestamps in self.beacon_timestamps.items():
            # Count beacons in the time window
            recent_beacons = [t for t in timestamps if current_time - t <= self.time_window]
            count = len(recent_beacons)
            
            # Check if count exceeds threshold
            if count >= self.threshold:
                # Get AP info if available
                ap_info = self.detected_aps.get(bssid, {})
                essid = ap_info.get('essid', 'Unknown')
                channel = ap_info.get('channel', 'Unknown')
                signal = ap_info.get('signal_strength', 'N/A')
                
                logging.warning(f"Beacon spam detected! BSSID: {bssid}, ESSID: {essid}, "
                              f"Count: {count} beacons in {self.time_window}s")
                
                spam_results.append({
                    "bssid": bssid,
                    "essid": essid,
                    "beacon_count": count,
                    "time_window": self.time_window,
                    "channel": channel,
                    "signal_strength": signal,
                    "detection_time": time.strftime("%Y-%m-%d %H:%M:%S")
                })
        
        return spam_results
    
    def cleanup_old_data(self):
        """Remove old data to prevent memory leaks"""
        current_time = time.time()
        # Clean up timestamps older than 10 minutes
        for bssid in list(self.beacon_timestamps.keys()):
            self.beacon_timestamps[bssid] = [t for t in self.beacon_timestamps[bssid] 
                                          if current_time - t <= 600]  # 10 minutes
            # Remove entry if empty
            if not self.beacon_timestamps[bssid]:
                del self.beacon_timestamps[bssid]

beacon_spam_detector = BeaconSpamDetector()