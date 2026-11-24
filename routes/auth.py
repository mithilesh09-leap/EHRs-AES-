"""
Authentication and User Account Routes.
Handles Login, Registration, Logout, Password Reset, and Profile Settings.
"""

from datetime import datetime
import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from models import db, User, Role, Doctor, Patient
from modules.auth_security import (
    hash_password, verify_password, validate_password_strength,
    check_rate_limit, record_failed_attempt, reset_failed_attempts,
    login_required
)
from modules.audit_logger import audit_logger

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor.dashboard'))
        else:
            return redirect(url_for('patient.dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr
        if not check_rate_limit(ip):
            flash("Too many failed login attempts. Please wait 5 minutes before trying again.", "danger")
            audit_logger.log_event("LOGIN_RATE_LIMITED", details=f"IP {ip} exceeded attempt limit", status="DENIED", ip_address=ip)
            return render_template('auth/login.html')

        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username_or_email or not password:
            flash("Please provide both username/email and password.", "warning")
            return render_template('auth/login.html')

        # Lookup by username or email
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user or not verify_password(user.password_hash, password):
            record_failed_attempt(ip)
            audit_logger.log_event(
                action="LOGIN_FAILED",
                details=f"Invalid credentials for identifier: {username_or_email}",
                status="FAILURE",
                ip_address=ip
            )
            flash("Invalid username or password.", "danger")
            return render_template('auth/login.html')

        if not user.is_active:
            audit_logger.log_event(
                action="LOGIN_INACTIVE_USER",
                user_id=user.id,
                details=f"Account '{user.username}' is disabled",
                status="DENIED",
                ip_address=ip
            )
            flash("Your account has been deactivated. Please contact the administrator.", "danger")
            return render_template('auth/login.html')

        # Successful Login
        reset_failed_attempts(ip)
        user.last_login = datetime.utcnow()
        user.failed_login_count = 0
        db.session.commit()

        # Secure Session Initialization
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['full_name'] = user.full_name
        session['role'] = user.role_name
        session.permanent = True

        audit_logger.log_event(
            action="LOGIN_SUCCESS",
            user_id=user.id,
            details=f"User '{user.username}' ({user.role_name}) logged in successfully",
            status="SUCCESS",
            ip_address=ip
        )

        flash(f"Welcome back, {user.full_name}!", "success")
        next_url = request.args.get('next')
        if next_url and next_url.startswith('/'):
            return redirect(next_url)

        if user.role_name == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif user.role_name == 'doctor':
            return redirect(url_for('doctor.dashboard'))
        else:
            return redirect(url_for('patient.dashboard'))

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('auth.login'))

    roles = Role.query.filter(Role.name.in_(['patient', 'doctor'])).all()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        role_name = request.form.get('role', 'patient').lower()

        # Validation
        if not username or not email or not password or not full_name:
            flash("All required fields must be completed.", "warning")
            return render_template('auth/register.html', roles=roles)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('auth/register.html', roles=roles)

        is_valid_pw, pw_msg = validate_password_strength(password)
        if not is_valid_pw:
            flash(pw_msg, "danger")
            return render_template('auth/register.html', roles=roles)

        # Check existing user
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email is already registered.", "warning")
            return render_template('auth/register.html', roles=roles)

        role = Role.query.filter_by(name=role_name).first()
        if not role or role.name not in ['patient', 'doctor']:
            flash("Invalid role selection.", "danger")
            return render_template('auth/register.html', roles=roles)

        # Create user
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            full_name=full_name,
            phone=phone,
            role_id=role.id,
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()

        # Role-specific profiles
        if role.name == 'doctor':
            license_number = request.form.get('license_number', '').strip() or f"MD-{secrets.randbelow(90000) + 10000}"
            specialization = request.form.get('specialization', '').strip() or "General Medicine"
            department = request.form.get('department', '').strip() or "Internal Medicine"

            doctor = Doctor(
                user_id=new_user.id,
                license_number=license_number,
                specialization=specialization,
                department=department,
                office_phone=phone
            )
            db.session.add(doctor)

        elif role.name == 'patient':
            dob_str = request.form.get('date_of_birth')
            gender = request.form.get('gender', 'Other')
            blood_group = request.form.get('blood_group', 'Unknown')
            emergency_contact = request.form.get('emergency_contact', '')
            address = request.form.get('address', '')

            try:
                dob = datetime.strptime(dob_str, '%Y-%m-%d').date() if dob_str else datetime(1995, 1, 1).date()
            except ValueError:
                dob = datetime(1995, 1, 1).date()

            # Generate unique Patient UID: PAT-YYYY-XXXXX
            random_digits = secrets.randbelow(90000) + 10000
            patient_uid = f"PAT-{datetime.utcnow().year}-{random_digits}"

            patient = Patient(
                user_id=new_user.id,
                patient_uid=patient_uid,
                full_name=full_name,
                date_of_birth=dob,
                gender=gender,
                blood_group=blood_group,
                emergency_contact=emergency_contact,
                address=address
            )
            db.session.add(patient)

        db.session.commit()

        audit_logger.log_event(
            action="USER_REGISTERED",
            user_id=new_user.id,
            details=f"New {role.name} account registered: {username}",
            status="SUCCESS"
        )

        flash("Registration successful! You may now sign in.", "success")
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', roles=roles)


@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    if user_id:
        audit_logger.log_event("LOGOUT", user_id=user_id, details=f"User '{username}' logged out")
    session.clear()
    flash("You have been securely signed out.", "info")
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')

            if not verify_password(user.password_hash, current_pw):
                flash("Current password is incorrect.", "danger")
            elif new_pw != confirm_pw:
                flash("New passwords do not match.", "danger")
            else:
                is_valid, msg = validate_password_strength(new_pw)
                if not is_valid:
                    flash(msg, "danger")
                else:
                    user.password_hash = hash_password(new_pw)
                    db.session.commit()
                    audit_logger.log_event("PASSWORD_CHANGED", user_id=user.id, details="Password changed by user")
                    flash("Your password has been securely updated.", "success")
                    
        elif action == 'update_profile':
            user.full_name = request.form.get('full_name', user.full_name).strip()
            user.phone = request.form.get('phone', user.phone).strip()
            db.session.commit()
            session['full_name'] = user.full_name
            audit_logger.log_event("PROFILE_UPDATED", user_id=user.id, details="Profile information updated")
            flash("Profile updated successfully.", "success")

    return render_template('auth/profile.html', user=user)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate simulated secure reset token
            audit_logger.log_event("PASSWORD_RESET_REQUESTED", user_id=user.id, details=f"Reset link requested for {email}")
        # Always display the same message to prevent account enumeration
        flash("If an account exists with that email, instructions to reset your password have been logged.", "info")
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html')
