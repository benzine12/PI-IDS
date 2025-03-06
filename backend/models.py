# models.py
from datetime import datetime, timezone
from data import DB

class User(DB.Model):
    __tablename__ = 'users'

    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(15), nullable=False, unique=True)
    password = DB.Column(DB.String(), nullable=False)
    added_at = DB.Column(DB.DateTime, default=lambda: datetime.now(timezone.utc))

class AP(DB.Model):

    id = DB.Column(DB.Integer, primary_key=True)
    bssid = DB.Column(DB.String(), nullable=False)
    essid = DB.Column(DB.String(), nullable=False)
    band = DB.Column(DB.String(), nullable=False)
    crypto = DB.Column(DB.String(), nullable=False)
    added_at = DB.Column(DB.DateTime, default=lambda: datetime.now(timezone.utc))

class Attack(DB.Model):
    __tablename__ = 'attacks'

    id = DB.Column(DB.Integer, primary_key=True)
    
    # Common fields
    attack_type = DB.Column(DB.String(), nullable=False)  # 'Deauth', 'Probe Scanner', etc.
    src_mac = DB.Column(DB.String(), nullable=False)      # Source MAC address (attacker)
    essid = DB.Column(DB.String())                       # Network name if applicable
    signal_strength = DB.Column(DB.String())             # Signal strength
    count = DB.Column(DB.Integer, default=1)             # Number of occurrences
    first_seen = DB.Column(DB.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = DB.Column(DB.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Optional common fields that might be NULL for some attack types
    dst_mac = DB.Column(DB.String())                     # Target MAC (might be null for some attacks)
    channel = DB.Column(DB.String())                     # Channel (might be null)
    bssid = DB.Column(DB.String())                       # AP BSSID (might be null)
    
    # Status
    resolved = DB.Column(DB.Boolean, default=False)