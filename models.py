from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import pytz
import secrets

db = SQLAlchemy()

def get_indonesia_time():
    tz = pytz.timezone('Asia/Jakarta')
    return datetime.now(tz)

def generate_access_code():
    return secrets.token_hex(4).upper()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='admin')
    created_at = db.Column(db.DateTime, default=get_indonesia_time)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(1024), nullable=False)
    public_id = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=get_indonesia_time)

class PaymentProof(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    user_phone = db.Column(db.String(20), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_amount = db.Column(db.Integer, nullable=False)
    proof_image = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    access_code = db.Column(db.String(10), unique=True)
    device_id = db.Column(db.String(200))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=get_indonesia_time)
    approved_at = db.Column(db.DateTime)

class AccessCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    device_id = db.Column(db.String(200))
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=get_indonesia_time)
    used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)  # Tambahan baru untuk nonaktifkan
    notes = db.Column(db.String(200))  # Tambahan baru untuk catatan