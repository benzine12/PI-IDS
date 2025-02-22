from collections import defaultdict
from modules import DeauthDetector
from backend.modules import APScanner

class StateManager:
    def __init__(self):
        self.packet_counter = 0
        self.detected_attacks = []
        self.attack_log = defaultdict(list)
        self.attack_counts = defaultdict(int)

state = StateManager()
detector = DeauthDetector()
ap_scanner = APScanner()