# models.py
from datetime import datetime, timezone
from data import DB

class User(DB.Model):
    __tablename__ = 'users'

    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(15), nullable=False, unique=True)
    password = DB.Column(DB.String(15), nullable=False)
    added_at = DB.Column(DB.DateTime, default=lambda: datetime.now(timezone.utc))