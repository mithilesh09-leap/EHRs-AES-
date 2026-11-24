"""
Authentication and Security Module.
- Secure Password Hashing (Argon2 / PBKDF2:SHA256 with 600,000 rounds).
- Role-Based Access Control (RBAC) decorators.
- Password Complexity validation.
- Rate Limiting helpers.
"""

import re
import time
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort, current_app
from werkzeug.security import generate_password_hash, check_password_hash

# Try importing argon2-cffi if available, else use hardened PBKDF2
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _argon2_hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    HAS_ARGON2 = True
except ImportError:
    _argon2_hasher = None
    HAS_ARGON2 = False


def hash_password(password: str) -> str:
    """
    Hashes a password securely using Argon2id if available,
    otherwise PBKDF2:SHA256 with 600,000 iterations (OWASP standard).
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if HAS_ARGON2 and _argon2_hasher:
        return _argon2_hasher.hash(password)
    # 600,000 rounds of PBKDF2-HMAC-SHA256 with 16-byte random salt
    return generate_password_hash(password, method='pbkdf2:sha256:600000', salt_length=16)


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """
    Verifies a candidate password against the stored secure hash.
    Safely handles both Argon2 and PBKDF2 formats.
    """
    if not stored_hash or not candidate_password:
        return False
    if stored_hash.startswith('$argon2'):
        if HAS_ARGON2 and _argon2_hasher:
            try:
                return _argon2_hasher.verify(stored_hash, candidate_password)
            except VerifyMismatchError:
                return False
            except Exception:
                return False
        return False
    return check_password_hash(stored_hash, candidate_password)


from typing import Tuple, Optional

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates password strength:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_]', password):
        return False, "Password must contain at least one special symbol (!@#$%^&*...)."
    return True, "Password meets security requirements."


# Simple in-memory rate limiter for login protection
_FAILED_ATTEMPTS = {}
_LOCKOUT_DURATION = 300  # 5 minutes
_MAX_FAILED_ATTEMPTS = 5

def check_rate_limit(ip_address: str) -> bool:
    """Returns True if the IP is permitted, False if locked out."""
    now = time.time()
    record = _FAILED_ATTEMPTS.get(ip_address)
    if not record:
        return True
    count, lock_time = record
    if lock_time and (now - lock_time < _LOCKOUT_DURATION):
        return False
    if lock_time and (now - lock_time >= _LOCKOUT_DURATION):
        _FAILED_ATTEMPTS.pop(ip_address, None)
        return True
    return True

def record_failed_attempt(ip_address: str):
    """Tracks failed login attempts for brute-force defense."""
    now = time.time()
    count, lock_time = _FAILED_ATTEMPTS.get(ip_address, (0, None))
    count += 1
    if count >= _MAX_FAILED_ATTEMPTS:
        _FAILED_ATTEMPTS[ip_address] = (count, now)
    else:
        _FAILED_ATTEMPTS[ip_address] = (count, None)

def reset_failed_attempts(ip_address: str):
    """Resets failed login attempts counter on successful login."""
    _FAILED_ATTEMPTS.pop(ip_address, None)


def login_required(f):
    """Ensures a user is authenticated in the current session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def role_required(allowed_roles):
    """
    Enforces Role-Based Access Control.
    Allowed roles may be a string ('admin') or list of strings (['doctor', 'admin']).
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for('auth.login', next=request.url))

            user_role = session.get('role')
            if user_role not in allowed_roles:
                # Log unauthorized access event via audit logger
                from modules.audit_logger import audit_logger
                audit_logger.log_event(
                    user_id=session.get('user_id'),
                    action="UNAUTHORIZED_ACCESS_DENIED",
                    details=f"User with role '{user_role}' attempted to access route '{request.path}' restricted to {allowed_roles}",
                    ip_address=request.remote_addr,
                    status="FAILURE"
                )
                flash("Access denied: You do not have permission to view this resource.", "danger")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
