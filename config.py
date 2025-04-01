import os
from datetime import timedelta

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://barcrypt_user:Barcrypt123!@localhost/barcrypt'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Password configuration
    PASSWORD_SALT = os.environ.get('PASSWORD_SALT') or 'your-password-salt-here' 