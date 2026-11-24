"""
Authentication and Role-Based Access Control (RBAC) Tests.
Verifies password hashing, password complexity, login authentication,
and strict role segregation.
"""

import pytest
from app import create_app
from models import db, User, Role, Patient, Doctor
from modules.auth_security import hash_password, verify_password, validate_password_strength

@pytest.fixture
def test_app():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        # Seed test roles
        r_admin = Role(name='admin', description='Administrator')
        r_doc = Role(name='doctor', description='Doctor')
        r_pat = Role(name='patient', description='Patient')
        db.session.add_all([r_admin, r_doc, r_pat])
        db.session.commit()
        
        # Seed test admin
        admin = User(
            username='admin_test',
            email='admin@test.org',
            password_hash=hash_password('Admin@2026Test!'),
            full_name='Admin User',
            role_id=r_admin.id
        )
        # Seed test doctor
        doctor_user = User(
            username='doc_test',
            email='doctor@test.org',
            password_hash=hash_password('Doctor@2026Test!'),
            full_name='Dr. Test',
            role_id=r_doc.id
        )
        db.session.add_all([admin, doctor_user])
        db.session.flush()

        doc_profile = Doctor(
            user_id=doctor_user.id,
            license_number='MD-TEST-001',
            specialization='General',
            department='Medicine'
        )
        db.session.add(doc_profile)

        # Seed test patients
        pat_user1 = User(
            username='patient1',
            email='pat1@test.org',
            password_hash=hash_password('Patient@2026Key!'),
            full_name='Patient One',
            role_id=r_pat.id
        )
        pat_user2 = User(
            username='patient2',
            email='pat2@test.org',
            password_hash=hash_password('Patient@2026Key!'),
            full_name='Patient Two',
            role_id=r_pat.id
        )
        db.session.add_all([pat_user1, pat_user2])
        db.session.flush()

        from datetime import date
        p1 = Patient(
            user_id=pat_user1.id,
            patient_uid='PAT-2026-0001',
            full_name='Patient One',
            date_of_birth=date(1990, 1, 1),
            gender='Male'
        )
        p2 = Patient(
            user_id=pat_user2.id,
            patient_uid='PAT-2026-0002',
            full_name='Patient Two',
            date_of_birth=date(1992, 2, 2),
            gender='Female'
        )
        db.session.add_all([p1, p2])
        db.session.commit()

        yield app

        db.session.remove()
        db.drop_all()


def test_password_hashing():
    pw = "SuperSecure@2026Key!"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(hashed, pw) is True
    assert verify_password(hashed, "WrongPassword123!") is False


def test_password_strength_validation():
    # Weak
    assert validate_password_strength("short")[0] is False
    assert validate_password_strength("alllowercase123!")[0] is False
    assert validate_password_strength("ALLUPPERCASE123!")[0] is False
    assert validate_password_strength("NoDigitsHere!")[0] is False
    assert validate_password_strength("NoSpecialSymbols123")[0] is False
    # Strong
    valid, msg = validate_password_strength("Valid@Pass2026!")
    assert valid is True


def test_unauthenticated_access_redirect(test_app):
    client = test_app.test_client()
    resp = client.get('/admin/dashboard')
    assert resp.status_code == 302
    assert '/auth/login' in resp.headers['Location']


def test_role_based_access_patient_blocked_from_admin(test_app):
    client = test_app.test_client()
    # Login as patient
    with client.session_transaction() as sess:
        sess['user_id'] = 3
        sess['username'] = 'patient1'
        sess['role'] = 'patient'
    
    resp = client.get('/admin/dashboard')
    assert resp.status_code == 403


def test_role_based_access_doctor_allowed_on_doctor_dashboard(test_app):
    client = test_app.test_client()
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['username'] = 'doc_test'
        sess['role'] = 'doctor'
    
    resp = client.get('/doctor/dashboard')
    assert resp.status_code == 200
    assert b'Clinical Workspace' in resp.data
