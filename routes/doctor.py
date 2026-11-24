"""
Doctor Blueprint and Clinical Management Routes.
- Assigned and general patient management
- Patient creation & profile editing
- Clinical consultation timeline
- Medical record & prescription drafting
"""

import secrets
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User, Doctor, Patient, MedicalRecord, Prescription, RecordDocument
from modules.auth_security import role_required
from modules.audit_logger import audit_logger

doctor_bp = Blueprint('doctor', __name__, url_prefix='/doctor')

def get_current_doctor():
    """Helper to retrieve Doctor instance for active session."""
    user_id = session.get('user_id')
    return Doctor.query.filter_by(user_id=user_id).first()


@doctor_bp.route('/dashboard')
@role_required(['doctor', 'admin'])
def dashboard():
    doctor = get_current_doctor()
    
    if doctor:
        assigned_patients = Patient.query.filter_by(primary_doctor_id=doctor.id).order_by(Patient.updated_at.desc()).all()
        recent_records = MedicalRecord.query.filter_by(doctor_id=doctor.id).order_by(MedicalRecord.visit_date.desc()).limit(5).all()
        active_prescriptions_count = Prescription.query.filter_by(doctor_id=doctor.id, status='Active').count()
    else:
        # If admin is accessing doctor dashboard for oversight
        assigned_patients = Patient.query.order_by(Patient.updated_at.desc()).limit(10).all()
        recent_records = MedicalRecord.query.order_by(MedicalRecord.visit_date.desc()).limit(5).all()
        active_prescriptions_count = Prescription.query.filter_by(status='Active').count()

    stats = {
        'patient_count': len(assigned_patients),
        'record_count': MedicalRecord.query.filter_by(doctor_id=doctor.id).count() if doctor else MedicalRecord.query.count(),
        'prescription_count': active_prescriptions_count
    }

    return render_template('doctor/dashboard.html', doctor=doctor, patients=assigned_patients, recent_records=recent_records, stats=stats)


@doctor_bp.route('/patients')
@role_required(['doctor', 'admin'])
def patients():
    search = request.args.get('search', '').strip()
    query = Patient.query
    
    if search:
        query = query.filter(
            (Patient.full_name.ilike(f'%{search}%')) |
            (Patient.patient_uid.ilike(f'%{search}%')) |
            (Patient.blood_group.ilike(f'%{search}%'))
        )
    
    patients_list = query.order_by(Patient.full_name.asc()).all()
    doctors = Doctor.query.all()
    return render_template('doctor/patients.html', patients=patients_list, doctors=doctors, search=search)


@doctor_bp.route('/patients/new', methods=['POST'])
@role_required(['doctor', 'admin'])
def create_patient():
    full_name = request.form.get('full_name', '').strip()
    dob_str = request.form.get('date_of_birth')
    gender = request.form.get('gender', 'Other')
    blood_group = request.form.get('blood_group', 'Unknown')
    emergency_contact = request.form.get('emergency_contact', '').strip()
    address = request.form.get('address', '').strip()
    primary_doctor_id = request.form.get('primary_doctor_id', type=int)

    if not full_name or not dob_str:
        flash("Patient full name and date of birth are required.", "warning")
        return redirect(url_for('doctor.patients'))

    try:
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format. Use YYYY-MM-DD.", "danger")
        return redirect(url_for('doctor.patients'))

    # Generate unique UID
    random_digits = secrets.randbelow(90000) + 10000
    patient_uid = f"PAT-{datetime.utcnow().year}-{random_digits}"

    current_doc = get_current_doctor()
    assigned_doc_id = primary_doctor_id or (current_doc.id if current_doc else None)

    patient = Patient(
        patient_uid=patient_uid,
        full_name=full_name,
        date_of_birth=dob,
        gender=gender,
        blood_group=blood_group,
        emergency_contact=emergency_contact,
        address=address,
        primary_doctor_id=assigned_doc_id
    )
    db.session.add(patient)
    db.session.commit()

    audit_logger.log_event(
        action="PATIENT_CREATED",
        user_id=session.get('user_id'),
        record_id=patient.id,
        record_type="Patient",
        details=f"Doctor created patient record: {patient.full_name} ({patient.patient_uid})"
    )

    flash(f"Patient profile created successfully with ID: {patient.patient_uid}", "success")
    return redirect(url_for('doctor.patient_detail', patient_id=patient.id))


@doctor_bp.route('/patients/<int:patient_id>')
@role_required(['doctor', 'admin'])
def patient_detail(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.visit_date.desc()).all()
    prescriptions = Prescription.query.filter_by(patient_id=patient.id).order_by(Prescription.issued_at.desc()).all()
    documents = RecordDocument.query.filter_by(patient_id=patient.id).order_by(RecordDocument.uploaded_at.desc()).all()

    # Log patient record access in audit trail
    audit_logger.log_event(
        action="PATIENT_CHART_ACCESSED",
        user_id=session.get('user_id'),
        record_id=patient.id,
        record_type="Patient",
        details=f"Chart accessed for {patient.full_name} ({patient.patient_uid})"
    )

    return render_template(
        'doctor/patient_detail.html',
        patient=patient,
        records=records,
        prescriptions=prescriptions,
        documents=documents
    )
