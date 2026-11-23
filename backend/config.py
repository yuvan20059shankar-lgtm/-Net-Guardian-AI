"""
NetGuardian AI - Configuration Module
Manages environment variables, database locations, CORS policies, and security settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the backend package
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / '.env')


class Config:
    """Base configuration class with safe defaults."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'netguardian-default-secret-key')
    DEBUG = False
    TESTING = False
    
    # Database path (defaults to backend/data/netguardian.db)
    DB_RELATIVE_PATH = os.getenv('DATABASE_PATH', 'data/netguardian.db')
    DATABASE_PATH = str(BASE_DIR / DB_RELATIVE_PATH)
    
    # Server network settings
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5000))
    
    # CORS Origin Configuration
    CORS_ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.getenv(
            'CORS_ORIGINS',
            'http://localhost:3000,http://127.0.0.1:3000'
        ).split(',')
        if origin.strip()
    ]
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

    # Threat Intelligence Configurable Parameters (Prompt 4)
    THREAT_INTEL_SCORE_THRESHOLDS = {
        'CRITICAL': 80,
        'HIGH': 65,
        'MEDIUM': 45,
        'LOW': 0
    }
    THREAT_INTEL_CONFIDENCE_FACTORS = {
        'high_threshold': 3,     # >= 3 corroborating evidence factors -> HIGH
        'medium_threshold': 1    # 1-2 corroborating evidence factors -> MEDIUM, 0 -> LOW
    }
    THREAT_INTEL_REPEAT_WINDOW_HOURS = 24
    THREAT_INTEL_REPEAT_THRESHOLD = 2   # >= 2 previous alerts -> Repeated Anomalous Behaviour candidate


class DevelopmentConfig(Config):
    """Local development configuration with debug capabilities."""
    DEBUG = True
    ENV = 'development'


class TestingConfig(Config):
    """Configuration used for automated unit and integration tests."""
    TESTING = True
    DEBUG = True
    # In-memory or isolated test database
    DATABASE_PATH = str(BASE_DIR / 'data' / 'netguardian_test.db')


class ProductionConfig(Config):
    """Hardened production configuration."""
    DEBUG = False
    TESTING = False
    ENV = 'production'


# Configuration dictionary lookup
CONFIG_MAP = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Retrieve the active configuration based on FLASK_ENV."""
    env_name = os.getenv('FLASK_ENV', 'development').lower()
    return CONFIG_MAP.get(env_name, DevelopmentConfig)
