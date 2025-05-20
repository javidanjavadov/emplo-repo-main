import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Secret key - Railway və ya lokal üçün
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))

    # Railway ümumiyyətlə tam bağlantı URL-si verir, bunu istifadə et:
    DATABASE_URL = os.getenv('DATABASE_URL')

    # Əgər DATABASE_URL yoxdursa, fallback olaraq lokal ayarlar (inkişaf mühiti üçün)
    if not DATABASE_URL:
        DATABASE_NAME = os.getenv('DATABASE_NAME', 'smart_water_manage')
        DATABASE_USER = os.getenv('DATABASE_USER', 'postgres')
        DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
        DATABASE_HOST = os.getenv('DATABASE_HOST', 'localhost')
        DATABASE_PORT = os.getenv('DATABASE_PORT', 5432)
        DATABASE_URL = f"postgresql+psycopg2://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"
    else:
        DATABASE_NAME = None
        DATABASE_USER = None
        DATABASE_PASSWORD = None
        DATABASE_HOST = None
        DATABASE_PORT = None

    # OAuth2 Konfiqurasiyası
    OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
    SERVER_METADATA_URL = os.getenv('SERVER_METADATA_URL', 'https://accounts.google.com/.well-known/openid-configuration')
    OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://127.0.0.1:5000/auth/google/callback')

    # Email Konfiqurasiyası
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'javidan.javadov@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # App password kimi .env-dən alınır
    MAIL_DEFAULT_SENDER = MAIL_USERNAME
