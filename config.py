import os
import base64
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables if .env file exists
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base application security and operational configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-insecure-flask-secret-key-change-in-production-ehr-2026'
    
    # Master AES-256 encryption key (32 bytes).
    # If provided in base64 format in environment, decode it; otherwise use a secure default for dev
    _env_master_key = os.environ.get('MASTER_ENCRYPTION_KEY')
    if _env_master_key:
        try:
            MASTER_KEY = base64.b64decode(_env_master_key)
            if len(MASTER_KEY) != 32:
                raise ValueError("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits).")
        except Exception:
            # Fallback derivation if raw string
            import hashlib
            MASTER_KEY = hashlib.sha256(_env_master_key.encode('utf-8')).digest()
    else:
        # 32-byte default key for local development (MUST be overridden in production)
        MASTER_KEY = b'EHR_AES256_GCM_DEV_KEY_32BYTES!!'
        
    KEY_ROTATION_VERSION = int(os.environ.get('KEY_ROTATION_VERSION', '1'))
    
    # Key Ring supporting key rotation (maps version string/int -> 32-byte key)
    KEY_RING = {
        1: MASTER_KEY
    }

    # Database Configuration (PostgreSQL with graceful SQLite fallback)
    # Default to PostgreSQL connection string if specified, or SQLite for zero-config local runs
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'ehr_system.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }

    # Secure Upload Directory (isolated from static web assets)
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'encrypted_records')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB maximum file upload limit
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx', 'dicom'}

    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=45)
    
    # Security Headers
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
