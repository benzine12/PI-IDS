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
