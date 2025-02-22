from collections import defaultdict
from scapy.layers.dot11 import Dot11, Dot11Deauth
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