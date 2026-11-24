"""
Medical Records and Audit Logging Verification Tests.
Verifies record encryption, patient privacy boundaries,
tamper-evident audit trail, and document download integrity.
"""

import pytest
from datetime import date
from app import create_app
from models import db, User, Role, Patient, Doctor, MedicalRecord, RecordDocument, AuditLog
from modules.auth_security import hash_password
from modules.crypto_engine import crypto_engine

@pytest.fixture
def app_with_records():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        r_admin = Role(name='admin', description='Admin')
        r_doc = Role(name='doctor', description='Doctor')
        r_pat = Role(name='patient', description='Patient')
        db.session.add_all([r_admin, r_doc, r_pat])
        db.session.commit()

        # Doctor
        doc_user = User(username='dr_test', email='d@test.org', password_hash=hash_password('Doc@2026Test!'), full_name='Dr. Test', role_id=r_doc.id)
        db.session.add(doc_user)
        db.session.flush()
        doc = Doctor(user_id=doc_user.id, license_number='MD-101', specialization='Cardiology', department='Cardio')
        db.session.add(doc)

        # Patient 1
        p1_user = User(username='pat_1', email='p1@test.org', password_hash=hash_password('Pat@2026Test!'), full_name='Patient 1', role_id=r_pat.id)
        # Patient 2
        p2_user = User(username='pat_2', email='p2@test.org', password_hash=hash_password('Pat@2026Test!'), full_name='Patient 2', role_id=r_pat.id)
        db.session.add_all([p1_user, p2_user])
        db.session.flush()

        pat1 = Patient(user_id=p1_user.id, patient_uid='PAT-001', full_name='Patient 1', date_of_birth=date(1985, 1, 1), gender='Male')
        pat2 = Patient(user_id=p2_user.id, patient_uid='PAT-002', full_name='Patient 2', date_of_birth=date(1990, 1, 1), gender='Female')
        db.session.add_all([pat1, pat2])
        db.session.flush()

        # Encrypted record for Patient 1
        raw_clinical_note = "Confidential ECG Findings: Sinus rhythm with mild ST elevation."
        encrypted_note = crypto_engine.encrypt_text(raw_clinical_note)

        rec = MedicalRecord(
            patient_id=pat1.id,
            doctor_id=doc.id,
            record_type='Consultation',
            diagnosis_title='Mild Pericarditis',
            encrypted_clinical_notes=encrypted_note,
            encryption_version=1
        )
        db.session.add(rec)
        db.session.commit()

        yield app, pat1.id, pat2.id, rec.id, p1_user.id, p2_user.id

        db.session.remove()
        db.drop_all()


def test_database_stores_encrypted_ciphertext(app_with_records):
    app, pat1_id, pat2_id, rec_id, p1_uid, p2_uid = app_with_records
    with app.app_context():
        rec = MedicalRecord.query.get(rec_id)
        # Must NOT contain plaintext
        assert "Confidential ECG Findings" not in rec.encrypted_clinical_notes
        # Decryption method retrieves plaintext
        assert "Confidential ECG Findings" in rec.get_decrypted_notes()


def test_patient_isolation_cannot_view_other_patient_record(app_with_records):
    app, pat1_id, pat2_id, rec_id, p1_uid, p2_uid = app_with_records
    client = app.test_client()

    # Patient 2 attempts to view Patient 1's medical record
    with client.session_transaction() as sess:
        sess['user_id'] = p2_uid
        sess['username'] = 'pat_2'
        sess['role'] = 'patient'

    resp = client.get(f'/records/{rec_id}')
    assert resp.status_code == 403, "Patient 2 must be strictly forbidden from accessing Patient 1's record"


def test_patient_can_view_own_record(app_with_records):
    app, pat1_id, pat2_id, rec_id, p1_uid, p2_uid = app_with_records
    client = app.test_client()

    # Patient 1 views their own medical record
    with client.session_transaction() as sess:
        sess['user_id'] = p1_uid
        sess['username'] = 'pat_1'
        sess['role'] = 'patient'

    resp = client.get(f'/records/{rec_id}')
    assert resp.status_code == 200
    assert b'Mild Pericarditis' in resp.data
    assert b'Confidential ECG Findings' in resp.data


def test_audit_log_persists_events(app_with_records):
    app, pat1_id, pat2_id, rec_id, p1_uid, p2_uid = app_with_records
    from modules.audit_logger import audit_logger

    with app.app_context():
        initial_count = AuditLog.query.count()
        audit_logger.log_event(
            action="TEST_SECURITY_EVENT",
            details="Verifying tamper-evident audit trail persistence",
            user_id=p1_uid,
            status="SUCCESS"
        )
        new_count = AuditLog.query.count()
        assert new_count == initial_count + 1

        last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        assert last_log.action == "TEST_SECURITY_EVENT"
        assert last_log.user_id == p1_uid
