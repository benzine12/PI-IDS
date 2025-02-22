from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap
import logging
import time
from collections import defaultdict

class APScanner:
    """Class to scan for APs and extract information from beacon frames"""
    def __init__(self):
        self.detected_aps = {}
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
        
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