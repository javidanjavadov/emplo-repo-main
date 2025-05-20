import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Secret key - Railway ya da local için
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))

    # Railway genelde tam bağlantı URL'si veriyor, bunu kullan:
    DATABASE_URL = os.getenv('DATABASE_URL')

    # Eğer DATABASE_URL yoksa fallback olarak local ayarlar (dev ortamı için)
    if not DATABASE_URL:
        DATABASE_NAME = os.getenv('DATABASE_NAME', 'smart_water_manage')
        DATABASE_USER = os.getenv('DATABASE_USER', 'postgres')
        DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
        DATABASE_HOST = os.getenv('DATABASE_HOST', 'localhost')
        DATABASE_PORT = os.getenv('DATABASE_PORT', 5432)
        DATABASE_URL = f"postgresql+psycopg2://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"

    # OAuth2 Configuration
    OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
    SERVER_METADATA_URL = os.getenv('SERVER_METADATA_URL', 'https://accounts.google.com/.well-known/openid-configuration')
    OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://127.0.0.1:5000/auth/google/callback')

    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'javidan.javadov@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # Bu app password olarak env'den gelsin
    MAIL_DEFAULT_SENDER = MAIL_USERNAME
