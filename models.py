from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import json

db = SQLAlchemy()

# Generate a key for encryption
def get_encryption_key():
    key_file = 'encryption_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# Initialize Fernet cipher
cipher_suite = Fernet(get_encryption_key())

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    passwords = db.relationship('Password', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Password(db.Model):
    __tablename__ = 'passwords'
    
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(256), nullable=False)
    username = db.Column(db.String(128), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    strength_history = db.Column(db.Text, default='[]')  # JSON array of historical strength data
    breach_status = db.Column(db.Boolean, default=False)
    breach_count = db.Column(db.Integer, default=0)
    last_breach_check = db.Column(db.DateTime)
    
    def __init__(self, *args, **kwargs):
        super(Password, self).__init__(*args, **kwargs)
        if self.strength_history is None:
            self.strength_history = '[]'
        # Always initialize the fernet cipher using the global cipher_suite
        self.fernet = cipher_suite
    
    def set_password(self, password):
        # Ensure fernet is initialized
        if not hasattr(self, 'fernet'):
            self.fernet = cipher_suite
        self.encrypted_password = self.fernet.encrypt(password.encode())
        self.password_hash = generate_password_hash(password)
        # Add strength data to history
        strength_data = {
            'date': datetime.utcnow().isoformat(),
            'strength': self.calculate_password_strength(password)
        }
        try:
            history = json.loads(self.strength_history or '[]')
        except (json.JSONDecodeError, TypeError):
            history = []
        history.append(strength_data)
        self.strength_history = json.dumps(history)
    
    def calculate_password_strength(self, password):
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(not c.isalnum() for c in password): score += 1
        return (score / 6) * 100  # Convert to percentage
    
    def get_password(self):
        # Ensure fernet is initialized
        if not hasattr(self, 'fernet'):
            self.fernet = cipher_suite
        return self.fernet.decrypt(self.encrypted_password).decode()
    
    def get_strength_history(self):
        try:
            return json.loads(self.strength_history or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def __repr__(self):
        return f'<Password {self.website}>' 