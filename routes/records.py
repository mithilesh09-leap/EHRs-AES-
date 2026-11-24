"""
Medical Records and Secure Document Management Blueprint.
- AES-256-GCM authenticated encryption for clinical notes and treatment plans.
- Secure binary encryption for medical attachments and diagnostic reports.
- Nonce & Tag verification, integrity checks, and authorization verification.
- Enforces strict no-plaintext-storage policy.
"""

import os
import io
import hashlib
import secrets
from datetime import datetime
from flask import (
    Blueprint, render_template, request, redirect, url_for, 
    flash, session, abort, send_file, current_app
)
from werkzeug.utils import secure_filename
from models import db, Patient, Doctor, MedicalRecord, Prescription, RecordDocument
from modules.auth_security import login_required, role_required
from modules.crypto_engine import crypto_engine, DecryptionError
from modules.audit_logger import audit_logger
from config import Config

records_bp = Blueprint('records', __name__, url_prefix='/records')

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@records_bp.route('/new/<int:patient_id>', methods=['GET', 'POST'])
@role_required(['doctor', 'admin'])
def new_record(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    
    # Resolve doctor
    user_id = session.get('user_id')
    doctor = Doctor.query.filter_by(user_id=user_id).first()
    if not doctor:
        # Fallback to patient's primary doctor or first doctor if admin
        doctor = patient.primary_doctor or Doctor.query.first()

    if request.method == 'POST':
        record_type = request.form.get('record_type', 'Consultation').strip()
        visit_date_str = request.form.get('visit_date')
        diagnosis_title = request.form.get('diagnosis_title', '').strip()
        clinical_notes = request.form.get('clinical_notes', '').strip()
        treatment_plan = request.form.get('treatment_plan', '').strip()
        is_sensitive = request.form.get('is_sensitive') == 'on'

        # Prescription fields (optional)
        medication_name = request.form.get('medication_name', '').strip()
        dosage_instructions = request.form.get('dosage_instructions', '').strip()
        duration_days = request.form.get('duration_days', 7, type=int)

        if not diagnosis_title or not clinical_notes:
            flash("Diagnosis title and clinical notes are required.", "warning")
            return render_template('records/add.html', patient=patient, doctor=doctor)

        try:
            visit_date = datetime.strptime(visit_date_str, '%Y-%m-%d').date() if visit_date_str else datetime.utcnow().date()
        except ValueError:
            visit_date = datetime.utcnow().date()

        # AES-256-GCM Authenticated Encryption for sensitive fields
        try:
            encrypted_notes = crypto_engine.encrypt_text(clinical_notes)
            encrypted_treatment = crypto_engine.encrypt_text(treatment_plan) if treatment_plan else ""
        except Exception as e:
            flash(f"Cryptographic failure: {str(e)}", "danger")
            return render_template('records/add.html', patient=patient, doctor=doctor)

        record = MedicalRecord(
            patient_id=patient.id,
            doctor_id=doctor.id,
            record_type=record_type,
            visit_date=visit_date,
            diagnosis_title=diagnosis_title,
            encrypted_clinical_notes=encrypted_notes,
            encrypted_treatment_plan=encrypted_treatment,
            encryption_version=crypto_engine.active_version,
            is_sensitive=is_sensitive
        )
        db.session.add(record)
        db.session.flush()

        # Optional Prescription
        if medication_name and dosage_instructions:
            encrypted_dosage = crypto_engine.encrypt_text(dosage_instructions)
            prescription = Prescription(
                medical_record_id=record.id,
                patient_id=patient.id,
                doctor_id=doctor.id,
                medication_name=medication_name,
                encrypted_dosage_instructions=encrypted_dosage,
                duration_days=duration_days,
                status='Active'
            )
            db.session.add(prescription)

        # Optional Document Attachment (Encrypted on write)
        uploaded_file = request.files.get('document')
        if uploaded_file and uploaded_file.filename:
            orig_filename = secure_filename(uploaded_file.filename)
            if allowed_file(orig_filename):
                file_bytes = uploaded_file.read()
                file_size = len(file_bytes)
                checksum = hashlib.sha256(file_bytes).hexdigest()

                # Encrypt binary contents using AES-256-GCM
                encrypted_file_bytes = crypto_engine.encrypt_binary(file_bytes)
                
                # Ensure storage directory exists
                os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

                # Storage filename with unique token and .enc extension
                storage_filename = f"ENC_{secrets.token_hex(16)}_{orig_filename}.enc"
                storage_path = os.path.join(Config.UPLOAD_FOLDER, storage_filename)

                with open(storage_path, 'wb') as f:
                    f.write(encrypted_file_bytes)

                doc_entry = RecordDocument(
                    medical_record_id=record.id,
                    patient_id=patient.id,
                    doctor_id=doctor.id,
                    original_filename=orig_filename,
                    storage_filename=storage_filename,
                    file_size_bytes=file_size,
                    mime_type=uploaded_file.content_type or 'application/octet-stream',
                    file_checksum_sha256=checksum,
                    encryption_version=crypto_engine.active_version
                )
                db.session.add(doc_entry)

        db.session.commit()

        audit_logger.log_event(
            action="MEDICAL_RECORD_CREATED",
            user_id=session.get('user_id'),
            record_id=record.id,
            record_type="MedicalRecord",
            details=f"Encrypted medical record #{record.id} created for {patient.patient_uid}"
        )

        flash("Medical record encrypted and saved successfully.", "success")
        return redirect(url_for('doctor.patient_detail', patient_id=patient.id))

    return render_template('records/add.html', patient=patient, doctor=doctor)


@records_bp.route('/<int:record_id>')
@login_required
def view_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    user_role = session.get('role')
    user_id = session.get('user_id')

    # Authorization Check
    if user_role == 'patient':
        # Patient must own the record
        if not record.patient.user_id or record.patient.user_id != user_id:
            audit_logger.log_event(
                action="UNAUTHORIZED_RECORD_ACCESS_ATTEMPT",
                user_id=user_id,
                record_id=record.id,
                record_type="MedicalRecord",
                status="DENIED",
                details=f"Patient user #{user_id} attempted to view record of patient #{record.patient_id}"
            )
            abort(403)

    # Authenticated Decryption
    try:
        decrypted_notes = record.get_decrypted_notes()
        decrypted_treatment = record.get_decrypted_treatment()
    except DecryptionError as e:
        audit_logger.log_event(
            action="DECRYPTION_FAILED",
            user_id=user_id,
            record_id=record.id,
            record_type="MedicalRecord",
            status="FAILURE",
            details=f"Integrity check failed: {str(e)}"
        )
        flash("Record decryption failed: The encrypted data has been tampered with or corrupted.", "danger")
        decrypted_notes = "[DECRYPTION ERROR: AUTHENTICATION TAG VERIFICATION FAILED]"
        decrypted_treatment = "[DECRYPTION ERROR: AUTHENTICATION TAG VERIFICATION FAILED]"

    audit_logger.log_event(
        action="RECORD_DECRYPTED_AND_VIEWED",
        user_id=user_id,
        record_id=record.id,
        record_type="MedicalRecord",
        details=f"Authorized user {session.get('username')} ({user_role}) decrypted record #{record.id}"
    )

    return render_template(
        'records/view.html',
        record=record,
        decrypted_notes=decrypted_notes,
        decrypted_treatment=decrypted_treatment
    )


@records_bp.route('/document/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    doc = RecordDocument.query.get_or_404(doc_id)
    user_role = session.get('role')
    user_id = session.get('user_id')

    # Authorization check
    if user_role == 'patient':
        if not doc.patient.user_id or doc.patient.user_id != user_id:
            audit_logger.log_event(
                action="UNAUTHORIZED_DOCUMENT_DOWNLOAD_ATTEMPT",
                user_id=user_id,
                record_id=doc.id,
                record_type="RecordDocument",
                status="DENIED"
            )
            abort(403)

    file_path = os.path.join(Config.UPLOAD_FOLDER, doc.storage_filename)
    if not os.path.exists(file_path):
        flash("Stored encrypted file not found on server storage.", "danger")
        return redirect(request.referrer or url_for('records.view_record', record_id=doc.medical_record_id))

    try:
        with open(file_path, 'rb') as f:
            encrypted_file_bytes = f.read()

        # Decrypt binary using AES-256-GCM
        decrypted_bytes = crypto_engine.decrypt_binary(encrypted_file_bytes)

        # Integrity verification against stored SHA-256 checksum
        computed_checksum = hashlib.sha256(decrypted_bytes).hexdigest()
        if computed_checksum != doc.file_checksum_sha256:
            raise DecryptionError("Checksum mismatch: decrypted file does not match original SHA-256 hash.")

    except DecryptionError as e:
        audit_logger.log_event(
            action="DOCUMENT_DECRYPTION_FAILED",
            user_id=user_id,
            record_id=doc.id,
            record_type="RecordDocument",
            status="FAILURE",
            details=str(e)
        )
        flash("Document decryption or integrity check failed: file has been tampered with.", "danger")
        return redirect(request.referrer or url_for('records.view_record', record_id=doc.medical_record_id))

    audit_logger.log_event(
        action="DOCUMENT_DOWNLOADED",
        user_id=user_id,
        record_id=doc.id,
        record_type="RecordDocument",
        details=f"User {session.get('username')} safely downloaded decrypted document '{doc.original_filename}'"
    )

    import io
    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=doc.mime_type,
        as_attachment=True,
        download_name=doc.original_filename
    )
