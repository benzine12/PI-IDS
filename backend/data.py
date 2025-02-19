from collections import defaultdict
from module_DeauthDetector import DeauthDetector
from module_APscan import APScanner

captured_packets = []
attack_log = defaultdict(list)
attack_counts = defaultdict(int)
packet_counter = 0
detector = DeauthDetector()
ap_scanner = APScanner()