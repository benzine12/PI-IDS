from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap,Dot11Deauth
import logging
from collections import defaultdict
import time

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

detector = DeauthDetector()

class APScanner:

    """Class to scan for APs and extract information from beacon frames"""
    def __init__(self):
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

    def check_for_rogue_ap(self):
        # if the bssid or essid the same as the as one of the list
        # and the crypto is OPEN 
        # and the signal strenght is not the same
        # its rogue ap
        pass

ap_scanner = APScanner()

# class KarmaDetector:
#     def __init__(self):

