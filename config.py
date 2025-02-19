import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = secrets.token_hex(32)  # Secure key for your app
    DATABASE_NAME = "smart_water_manage"
    DATABASE_USER = "postgres"
    DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')  # .env faylından alır
    DATABASE_HOST = "localhost"
    DATABASE_URL = os.getenv("DATABASE_URL", None)
    DATABASE_PORT = 5432
    OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')  # .env faylından alır
    OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')  # .env faylından alır
    SERVER_METADATA_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    OAUTH2_REDIRECT_URI = 'http://127.0.0.1:5000/auth/google/callback'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465  # Use 587 for TLS
    MAIL_USE_TLS = False  # If using SSL (use True if you're using TLS)
    MAIL_USE_SSL = True  # If using SSL (use False if you're using TLS)
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # .env faylından alır
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # .env faylından alır
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')  # .env faylından alır
