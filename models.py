"""
Database Schema Models for Electronic Health Records (EHR).
Built with SQLAlchemy.
Enforces normalized relationships, foreign keys, indexes, and constraints.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from modules.crypto_engine import crypto_engine

db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=True)

    users = db.relationship('User', backref='role_ref', lazy='dynamic')

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(32), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)

    # Relationships
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, cascade='all, delete-orphan')
    patient_profile = db.relationship('Patient', backref='user', uselist=False, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    @property
    def role_name(self):
        return self.role_ref.name if self.role_ref else 'patient'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role_name,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else 'Never'
        }


class Doctor(db.Model):
    __tablename__ = 'doctors'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    license_number = db.Column(db.String(64), unique=True, nullable=False, index=True)
    specialization = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    office_phone = db.Column(db.String(32), nullable=True)

    # Assigned patients
    patients = db.relationship('Patient', backref='primary_doctor', lazy='dynamic', foreign_keys='Patient.primary_doctor_id')
    medical_records = db.relationship('MedicalRecord', backref='author_doctor', lazy='dynamic')

    def __repr__(self):
        return f"<Doctor Dr. {self.user.full_name} ({self.specialization})>"


class Patient(db.Model):
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), unique=True, nullable=True)
    patient_uid = db.Column(db.String(32), unique=True, nullable=False, index=True)  # e.g., PAT-2026-10492
    full_name = db.Column(db.String(128), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(16), nullable=False)
    blood_group = db.Column(db.String(8), nullable=True)
    emergency_contact = db.Column(db.String(64), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    
    primary_doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Medical associations
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy='dynamic', cascade='all, delete-orphan')
    prescriptions = db.relationship('Prescription', backref='patient', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('RecordDocument', backref='patient', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def age(self):
        if not self.date_of_birth:
            return None
        today = datetime.utcnow().date()
        return today.year - self.date_of_birth.year - (
            (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
        )

    def to_dict(self):
        return {
            'id': self.id,
            'patient_uid': self.patient_uid,
            'full_name': self.full_name,
            'age': self.age,
            'gender': self.gender,
            'blood_group': self.blood_group or 'N/A',
            'emergency_contact': self.emergency_contact or 'N/A',
            'primary_doctor': self.primary_doctor.user.full_name if self.primary_doctor else 'Unassigned'
        }


class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='RESTRICT'), nullable=False, index=True)
    
    record_type = db.Column(db.String(64), nullable=False)  # Consultation, Diagnosis, Lab Report, Surgery, Discharge
    visit_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    diagnosis_title = db.Column(db.String(255), nullable=False)
    
    # AES-256-GCM Encrypted Payloads (stored as versioned base64 envelopes)
    encrypted_clinical_notes = db.Column(db.Text, nullable=False)
    encrypted_treatment_plan = db.Column(db.Text, nullable=True)
    encryption_version = db.Column(db.Integer, default=1, nullable=False)
    
    is_sensitive = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Documents & Prescriptions linked
    prescriptions = db.relationship('Prescription', backref='medical_record', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('RecordDocument', backref='medical_record', lazy='dynamic', cascade='all, delete-orphan')

    def get_decrypted_notes(self) -> str:
        """Decrypts and authenticates clinical notes."""
        return crypto_engine.decrypt_text(self.encrypted_clinical_notes)

    def get_decrypted_treatment(self) -> str:
        """Decrypts and authenticates treatment plan."""
        if not self.encrypted_treatment_plan:
            return ""
        return crypto_engine.decrypt_text(self.encrypted_treatment_plan)


class Prescription(db.Model):
    __tablename__ = 'prescriptions'

    id = db.Column(db.Integer, primary_key=True)
    medical_record_id = db.Column(db.Integer, db.ForeignKey('medical_records.id', ondelete='CASCADE'), nullable=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='RESTRICT'), nullable=False)
    
    medication_name = db.Column(db.String(128), nullable=False)
    # AES-256-GCM encrypted dosage instructions
    encrypted_dosage_instructions = db.Column(db.Text, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False, default=7)
    status = db.Column(db.String(32), default='Active', nullable=False)  # Active, Completed, Discontinued
    issued_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author_doctor = db.relationship('Doctor', backref='issued_prescriptions')

    def get_decrypted_dosage(self) -> str:
        return crypto_engine.decrypt_text(self.encrypted_dosage_instructions)


class RecordDocument(db.Model):
    __tablename__ = 'record_documents'

    id = db.Column(db.Integer, primary_key=True)
    medical_record_id = db.Column(db.Integer, db.ForeignKey('medical_records.id', ondelete='CASCADE'), nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='RESTRICT'), nullable=False)
    
    original_filename = db.Column(db.String(255), nullable=False)
    storage_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(128), nullable=False)
    file_checksum_sha256 = db.Column(db.String(64), nullable=False)
    encryption_version = db.Column(db.Integer, default=1, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    uploader_doctor = db.relationship('Doctor', backref='uploaded_documents')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(db.String(500), nullable=True)
    record_id = db.Column(db.Integer, nullable=True)
    record_type = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), default='SUCCESS', nullable=False)  # SUCCESS, FAILURE, DENIED
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref='reset_tokens')
