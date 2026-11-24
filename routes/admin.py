"""
Administrator Blueprint and Management Routes.
- System statistics & analytics
- User account management (status toggle, roles)
- Filterable Audit Log viewer
- Cryptographic Key Ring status
"""

from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User, Role, Doctor, Patient, MedicalRecord, RecordDocument, AuditLog
from modules.auth_security import role_required
from modules.audit_logger import audit_logger
from modules.crypto_engine import crypto_engine

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@role_required('admin')
def dashboard():
    total_users = User.query.count()
    total_patients = Patient.query.count()
    total_doctors = Doctor.query.count()
    total_records = MedicalRecord.query.count()
    total_documents = RecordDocument.query.count()
    total_audit_events = AuditLog.query.count()

    recent_audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()

    # Encryption stats
    key_version = crypto_engine.active_version
    available_keys = len(crypto_engine.key_ring)

    stats = {
        'total_users': total_users,
        'total_patients': total_patients,
        'total_doctors': total_doctors,
        'total_records': total_records,
        'total_documents': total_documents,
        'total_audit_events': total_audit_events,
        'active_key_version': key_version,
        'key_ring_count': available_keys
    }

    return render_template('admin/dashboard.html', stats=stats, recent_audits=recent_audits, recent_users=recent_users)


@admin_bp.route('/users')
@role_required('admin')
def users():
    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '').strip()
    
    query = User.query.join(Role)
    if search:
        query = query.filter((User.username.ilike(f'%{search}%')) | (User.email.ilike(f'%{search}%')) | (User.full_name.ilike(f'%{search}%')))
    if role_filter:
        query = query.filter(Role.name == role_filter)

    users_list = query.order_by(User.created_at.desc()).all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users_list, roles=roles, search=search, current_role=role_filter)


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@role_required('admin')
def toggle_user_status(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot deactivate your own administrative account.", "danger")
        return redirect(url_for('admin.users'))

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()

    action = "USER_ACTIVATED" if user.is_active else "USER_DEACTIVATED"
    audit_logger.log_event(
        action=action,
        user_id=session.get('user_id'),
        details=f"Admin {session.get('username')} updated status of {user.username} to {'Active' if user.is_active else 'Inactive'}"
    )
    flash(f"User '{user.username}' status updated to {'Active' if user.is_active else 'Inactive'}.", "success")
    return redirect(url_for('admin.users'))


@admin_bp.route('/audit-logs')
@role_required('admin')
def audit_logs():
    action_filter = request.args.get('action', '').strip()
    status_filter = request.args.get('status', '').strip()
    page = request.args.get('page', 1, type=int)

    query = AuditLog.query
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=25, error_out=False)
    
    # Distinct actions for filter dropdown
    distinct_actions = [r[0] for r in db.session.query(AuditLog.action).distinct().all()]

    return render_template('admin/audit_logs.html', 
                           pagination=pagination, 
                           actions=distinct_actions, 
                           current_action=action_filter, 
                           current_status=status_filter)
