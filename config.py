import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Dynamically generate a new SECRET_KEY on each run
    SECRET_KEY = secrets.token_hex(32)  # Generates a new secret key every time
    
    # Database Configuration
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'smart_water_manage')
    DATABASE_USER = os.getenv('DATABASE_USER', 'postgres')
    DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
    DATABASE_HOST = os.getenv('DATABASE_HOST', 'localhost')
    DATABASE_PORT = os.getenv('DATABASE_PORT', 5432)
    DATABASE_URL = os.getenv('DATABASE_URL') or f"postgresql://{os.getenv('DATABASE_USER', 'postgres')}:{os.getenv('DATABASE_PASSWORD')}@{os.getenv('DATABASE_HOST', 'localhost')}:{os.getenv('DATABASE_PORT', 5432)}/{os.getenv('DATABASE_NAME', 'smart_water_manage')}"
    
    # OAuth2 Configuration
    OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
    SERVER_METADATA_URL = os.getenv('SERVER_METADATA_URL', 'https://accounts.google.com/.well-known/openid-configuration')
    OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://127.0.0.1:5000/auth/google/callback')

    # Email Configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = os.getenv('MAIL_PORT', 465)
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', False) == 'True'  # Convert to bool
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', True) == 'True'   # Convert to bool
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')
