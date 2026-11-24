"""
Synthetic Healthcare Demo Data Seeder for EHR Guardian.
Safely provisions synthetic patients, doctors, encrypted clinical records,
prescriptions, sample encrypted diagnostic files, and audit logs.
Uses NO real patient identifiers.
"""

import os
import hashlib
import secrets
from datetime import datetime, date, timedelta
from app import create_app
from models import db, Role, User, Doctor, Patient, MedicalRecord, Prescription, RecordDocument, AuditLog
from modules.auth_security import hash_password
from modules.crypto_engine import crypto_engine
from config import Config

def seed_database():
    app = create_app()
    with app.app_context():
        print("[*] Initializing EHR database schema...")
        db.create_all()

        # 1. Seed Roles
        roles_data = [
            ('admin', 'System Administrator with security and user oversight privileges'),
            ('doctor', 'Licensed Physician authorized to author records and issue prescriptions'),
            ('patient', 'Healthcare patient authorized to view personal health portal')
        ]
        roles = {}
        for r_name, r_desc in roles_data:
            role = Role.query.filter_by(name=r_name).first()
            if not role:
                role = Role(name=r_name, description=r_desc)
                db.session.add(role)
                db.session.flush()
            roles[r_name] = role

        # 2. Seed Admin User
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@hospital.org',
                password_hash=hash_password('Admin@2026Secure!'),
                full_name='System Administrator',
                phone='+1 (555) 010-0001',
                role_id=roles['admin'].id,
                is_active=True
            )
            db.session.add(admin_user)
            db.session.flush()
            print("[+] Created Admin: admin / Admin@2026Secure!")

        # 3. Seed Doctors
        doc_sarah = User.query.filter_by(username='dr.sarah').first()
        if not doc_sarah:
            doc_sarah = User(
                username='dr.sarah',
                email='sarah.sharma@hospital.org',
                password_hash=hash_password('Doctor@2026Pass!'),
                full_name='Dr. Sarah Sharma, MD',
                phone='+1 (555) 010-0002',
                role_id=roles['doctor'].id,
                is_active=True
            )
            db.session.add(doc_sarah)
            db.session.flush()

            doctor_profile1 = Doctor(
                user_id=doc_sarah.id,
                license_number='MD-84920',
                specialization='Cardiology',
                department='Cardiovascular Medicine',
                office_phone='+1 (555) 010-2001'
            )
            db.session.add(doctor_profile1)
            db.session.flush()
            print("[+] Created Doctor: dr.sarah / Doctor@2026Pass!")
        else:
            doctor_profile1 = doc_sarah.doctor_profile

        doc_chen = User.query.filter_by(username='dr.chen').first()
        if not doc_chen:
            doc_chen = User(
                username='dr.chen',
                email='michael.chen@hospital.org',
                password_hash=hash_password('Doctor@2026Pass!'),
                full_name='Dr. Michael Chen, MD',
                phone='+1 (555) 010-0003',
                role_id=roles['doctor'].id,
                is_active=True
            )
            db.session.add(doc_chen)
            db.session.flush()

            doctor_profile2 = Doctor(
                user_id=doc_chen.id,
                license_number='MD-55219',
                specialization='Neurology',
                department='Neurological Sciences',
                office_phone='+1 (555) 010-2002'
            )
            db.session.add(doctor_profile2)
            db.session.flush()
            print("[+] Created Doctor: dr.chen / Doctor@2026Pass!")
        else:
            doctor_profile2 = doc_chen.doctor_profile

        # 4. Seed Patients
        patients_data = [
            {
                'username': 'patient.john',
                'email': 'john.davis@example.org',
                'password': 'Patient@2026Key!',
                'full_name': 'Johnathan Davis',
                'phone': '+1 (555) 020-0001',
                'dob': date(1982, 5, 14),
                'gender': 'Male',
                'blood_group': 'O+',
                'emergency': 'Jane Davis (+1-555-020-0002)',
                'address': '742 Evergreen Terrace, Springfield',
                'doc': doctor_profile1
            },
            {
                'username': 'patient.emily',
                'email': 'emily.watson@example.org',
                'password': 'Patient@2026Key!',
                'full_name': 'Emily Watson',
                'phone': '+1 (555) 020-0003',
                'dob': date(1989, 9, 23),
                'gender': 'Female',
                'blood_group': 'A+',
                'emergency': 'Robert Watson (+1-555-020-0004)',
                'address': '104 Beacon Hill Rd, Boston',
                'doc': doctor_profile2
            }
        ]

        patient_objs = []
        for p_data in patients_data:
            p_user = User.query.filter_by(username=p_data['username']).first()
            if not p_user:
                p_user = User(
                    username=p_data['username'],
                    email=p_data['email'],
                    password_hash=hash_password(p_data['password']),
                    full_name=p_data['full_name'],
                    phone=p_data['phone'],
                    role_id=roles['patient'].id,
                    is_active=True
                )
                db.session.add(p_user)
                db.session.flush()

                p_profile = Patient(
                    user_id=p_user.id,
                    patient_uid=f"PAT-{datetime.utcnow().year}-{secrets.randbelow(90000) + 10000}",
                    full_name=p_data['full_name'],
                    date_of_birth=p_data['dob'],
                    gender=p_data['gender'],
                    blood_group=p_data['blood_group'],
                    emergency_contact=p_data['emergency'],
                    address=p_data['address'],
                    primary_doctor_id=p_data['doc'].id
                )
                db.session.add(p_profile)
                db.session.flush()
                patient_objs.append(p_profile)
                print(f"[+] Created Patient: {p_data['username']} / {p_data['password']} ({p_profile.patient_uid})")
            else:
                patient_objs.append(p_user.patient_profile)

        # 5. Seed Encrypted Medical Records and Prescriptions
        if MedicalRecord.query.count() == 0 and patient_objs:
            p1 = patient_objs[0]
            # Encrypt clinical notes and treatment with AES-256-GCM
            notes_plaintext = (
                "Patient presented with intermittent palpitations, mild shortness of breath on exertion, "
                "and resting BP of 142/90 mmHg. Heart sounds S1/S2 present, regular rate without murmurs. "
                "12-lead ECG indicates normal sinus rhythm with occasional premature ventricular contractions (PVCs). "
                "Echocardiogram advised to rule out structural cardiomyopathy."
            )
            treatment_plaintext = (
                "1. Initiate Lisinopril 10 mg orally once daily in the morning.\n"
                "2. Maintain daily blood pressure log (morning & evening).\n"
                "3. Follow sodium-restricted dietary regimen (<2,000 mg/day).\n"
                "4. Return for follow-up review in 4 weeks."
            )

            rec1 = MedicalRecord(
                patient_id=p1.id,
                doctor_id=doctor_profile1.id,
                record_type="Consultation",
                visit_date=date.today() - timedelta(days=5),
                diagnosis_title="Essential Hypertension with Benign PVCs",
                encrypted_clinical_notes=crypto_engine.encrypt_text(notes_plaintext),
                encrypted_treatment_plan=crypto_engine.encrypt_text(treatment_plaintext),
                encryption_version=crypto_engine.active_version,
                is_sensitive=False
            )
            db.session.add(rec1)
            db.session.flush()

            # Prescription
            rx1 = Prescription(
                medical_record_id=rec1.id,
                patient_id=p1.id,
                doctor_id=doctor_profile1.id,
                medication_name="Lisinopril 10mg Tablets",
                encrypted_dosage_instructions=crypto_engine.encrypt_text("Take 1 tablet orally once daily each morning with water."),
                duration_days=30,
                status="Active"
            )
            db.session.add(rx1)

            # Sample Encrypted Document
            os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
            doc_sample_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Synthetic ECG Report) /Patient (" + p1.patient_uid.encode() + b") >>\nendobj\nSynthetic Diagnostic Report - Resting ECG Within Normal Limits."
            encrypted_doc_bytes = crypto_engine.encrypt_binary(doc_sample_content)
            storage_filename = f"ENC_{secrets.token_hex(16)}_ecg_diagnostic_report.pdf.enc"
            storage_path = os.path.join(Config.UPLOAD_FOLDER, storage_filename)

            with open(storage_path, 'wb') as f:
                f.write(encrypted_doc_bytes)

            doc_entry = RecordDocument(
                medical_record_id=rec1.id,
                patient_id=p1.id,
                doctor_id=doctor_profile1.id,
                original_filename="ecg_diagnostic_report.pdf",
                storage_filename=storage_filename,
                file_size_bytes=len(doc_sample_content),
                mime_type="application/pdf",
                file_checksum_sha256=hashlib.sha256(doc_sample_content).hexdigest(),
                encryption_version=crypto_engine.active_version
            )
            db.session.add(doc_entry)

            # Audit Log Event
            db.session.add(AuditLog(
                user_id=admin_user.id,
                action="SYSTEM_INITIALIZED",
                details="Initial synthetic health system records encrypted with AES-256-GCM",
                status="SUCCESS",
                ip_address="127.0.0.1"
            ))

        db.session.commit()
        print("[*] Database seeded successfully!")

if __name__ == '__main__':
    seed_database()
