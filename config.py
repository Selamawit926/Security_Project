import os
from dotenv import load_dotenv


load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # MAIL_SERVER='smtp.gmail.com'
    # MAIL_PORT=587
    # MAIL_USERNAME="venthere49@gmail.com"
    # MAIL_PASSWORD="vzlbxsrfguocgupw"
    # MAIL_DEFAULT_SENDER="venthere49@gmail.com"
    # MAIL_USE_TLS=True
    # MAIL_USE_SSL=True

    # Limiter Configuration
    # RATELIMIT_DEFAULT = "100 per day"
    # RATELIMIT_HEADERS_ENABLED = True

    # reCAPTCHA configuration
    RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')

    LOG_DIR = os.getenv('LOG_DIR')
    LOG_LEVEL = os.getenv('LOG_LEVEL')
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

# Set the appropriate configuration class based on the environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}

