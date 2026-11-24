"""
Patient Portal Blueprint and Self-Service Routes.
- Strict isolation: Patient can ONLY view their own records.
- Authenticated decryption of personal clinical notes and prescriptions.
- Download personal diagnostic documents.
"""

from flask import Blueprint, render_template, abort, flash, session
from models import db, Patient, MedicalRecord, Prescription, RecordDocument
from modules.auth_security import role_required
from modules.audit_logger import audit_logger

patient_bp = Blueprint('patient', __name__, url_prefix='/patient')

def get_current_patient():
    """Resolves Patient profile strictly linked to current session user_id."""
    user_id = session.get('user_id')
    return Patient.query.filter_by(user_id=user_id).first()


@patient_bp.route('/dashboard')
@role_required('patient')
def dashboard():
    patient = get_current_patient()
    if not patient:
        flash("Your account does not yet have an associated medical profile. Please contact clinical staff.", "warning")
        return render_template('patient/dashboard.html', patient=None, records=[], prescriptions=[], documents=[])

    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.visit_date.desc()).all()
    prescriptions = Prescription.query.filter_by(patient_id=patient.id).order_by(Prescription.issued_at.desc()).all()
    documents = RecordDocument.query.filter_by(patient_id=patient.id).order_by(RecordDocument.uploaded_at.desc()).all()

    audit_logger.log_event(
        action="PATIENT_SELF_PORTAL_ACCESSED",
        user_id=session.get('user_id'),
        record_id=patient.id,
        record_type="Patient",
        details=f"Patient {patient.full_name} ({patient.patient_uid}) viewed personal portal"
    )

    return render_template(
        'patient/dashboard.html',
        patient=patient,
        records=records,
        prescriptions=prescriptions,
        documents=documents
    )
