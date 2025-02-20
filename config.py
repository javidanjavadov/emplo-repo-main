import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Dynamically generate a new SECRET_KEY on each run
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))  # Use environment variable
    
    # Database Configuration
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'smart_water_manage')
    DATABASE_USER = os.getenv('DATABASE_USER', 'postgres')
    DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
    DATABASE_HOST = os.getenv('DATABASE_HOST', 'localhost')
    DATABASE_PORT = os.getenv('DATABASE_PORT', 5432)
    DATABASE_URL = os.getenv('DATABASE_URL') or f"postgresql+psycopg2://{os.getenv('DATABASE_USER', 'postgres')}:{os.getenv('DATABASE_PASSWORD')}@{os.getenv('DATABASE_HOST', 'localhost')}:{os.getenv('DATABASE_PORT', 5432)}/{os.getenv('DATABASE_NAME', 'smart_water_manage')}"
    
    # OAuth2 Configuration
    OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
    SERVER_METADATA_URL = os.getenv('SERVER_METADATA_URL', 'https://accounts.google.com/.well-known/openid-configuration')
    OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://127.0.0.1:5000/auth/google/callback')

    # Email Configuration
    # Update Mail Configuration in Config class
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'javidan.javadov@gmail.com'
    MAIL_PASSWORD = 'euvb bfbf cqpk kvop'  # The app password you provided
    MAIL_DEFAULT_SENDER = 'javidan.javadov@gmail.com'