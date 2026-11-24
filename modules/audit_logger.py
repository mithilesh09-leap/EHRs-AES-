"""
Audit Logging Service for Electronic Health Records.
Maintains an append-only, tamper-evident record of all security-sensitive events:
- Authentication (login success/failure, logout, password resets)
- Authorization decisions (access granted/denied)
- Record lifecycle (creation, view, update, export, download)
- Cryptographic operations (key rotation, authenticated decryption events)

Complies with standard security practices:
- NEVER logs passwords, encryption keys, or sensitive medical plaintext.
- Captures actor user ID, client IP address, action code, timestamp, and status.
"""

from datetime import datetime
from flask import request, session

class AuditLogger:
    def __init__(self, db_session=None):
        self._db_session = db_session

    def log_event(self, action: str, details: str = "", user_id: int = None, 
                  record_id: int = None, record_type: str = None, 
                  status: str = "SUCCESS", ip_address: str = None):
        """
        Persists a secure audit log entry.
        Never throws unhandled exceptions to avoid breaking caller operations.
        """
        from models import db, AuditLog

        # Resolve context if not explicitly provided
        resolved_user_id = user_id
        if resolved_user_id is None and session and 'user_id' in session:
            resolved_user_id = session.get('user_id')

        resolved_ip = ip_address
        if resolved_ip is None and request:
            try:
                resolved_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                if resolved_ip and ',' in resolved_ip:
                    resolved_ip = resolved_ip.split(',')[0].strip()
            except Exception:
                resolved_ip = "127.0.0.1"

        try:
            entry = AuditLog(
                user_id=resolved_user_id,
                action=action,
                details=details[:500] if details else None,
                record_id=record_id,
                record_type=record_type,
                status=status,
                ip_address=resolved_ip[:45] if resolved_ip else None,
                timestamp=datetime.utcnow()
            )
            db.session.add(entry)
            db.session.commit()
        except Exception as e:
            # Audit failures are safely rolled back and outputted to stderr without crashing
            try:
                db.session.rollback()
            except Exception:
                pass
            import sys
            sys.stderr.write(f"[AUDIT_LOG_ERROR] Failed to record audit log: {str(e)}\n")

# Singleton audit logger instance
audit_logger = AuditLogger()
