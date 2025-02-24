from collections import defaultdict
from modules import DeauthDetector, APScanner
from flask_sqlalchemy import SQLAlchemy

class StateManager:
    def __init__(self):
        self.packet_counter = 0
        self.detected_attacks = []
        self.attack_log = defaultdict(list)
        self.attack_counts = defaultdict(int)

state = StateManager()
detector = DeauthDetector()
ap_scanner = APScanner()
DB = SQLAlchemy()