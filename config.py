import secrets
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    def __init__(self):
        # Secret Key
        self.SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_hex(32)

        # DB Config
        self.DATABASE_URL = os.getenv('DATABASE_URL')
        if not self.DATABASE_URL:
            db_name = os.getenv('DATABASE_NAME', 'smart_water_manage')
            db_user = os.getenv('DATABASE_USER', 'postgres')
            db_password = os.getenv('DATABASE_PASSWORD', '')
            db_host = os.getenv('DATABASE_HOST', 'localhost')
            db_port = os.getenv('DATABASE_PORT', 5432)
            self.DATABASE_URL = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

        # OAuth2
        self.OAUTH2_CLIENT_ID = os.getenv('OAUTH2_CLIENT_ID')
        self.OAUTH2_CLIENT_SECRET = os.getenv('OAUTH2_CLIENT_SECRET')
        self.SERVER_METADATA_URL = os.getenv('SERVER_METADATA_URL', 'https://accounts.google.com/.well-known/openid-configuration')
        self.OAUTH2_REDIRECT_URI = os.getenv('OAUTH2_REDIRECT_URI', 'http://127.0.0.1:5000/auth/google/callback')

        # Email
        self.MAIL_SERVER = 'smtp.gmail.com'
        self.MAIL_PORT = 465
        self.MAIL_USE_SSL = True
        self.MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'javidan.javadov@gmail.com')
        self.MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
        self.MAIL_DEFAULT_SENDER = self.MAIL_USERNAME
