# data.py
from collections import defaultdict
import os
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Define the base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class StateManager:
    def __init__(self):
        self.packet_counter = 0
        self.attack_log = defaultdict(list)
        self.attack_counts = defaultdict(int)

# Initialize Flask extensions
DB = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

# Initialize application state
state = StateManager()