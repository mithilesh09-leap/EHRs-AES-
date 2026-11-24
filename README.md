# EHR Guardian - Enterprise Electronic Health Records (EHR) Security System

![Security](https://img.shields.io/badge/Security-AES--256--GCM-teal.svg)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)
![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2F%20SQLAlchemy-navy.svg)
![Tests](https://img.shields.io/badge/Tests-17%20Passed%20(100%25)-success.svg)

**EHR Guardian** is a production-grade, cryptographically hardened Electronic Health Records (EHR) management application designed with a zero-plaintext architecture for patient data, medical consultation notes, prescriptions, and diagnostic documents.

---

## 1. Architectural Overview

```
                                  [ Client Browser ]
                                          |
                                    HTTPS / TLS
                                          v
                      [ Security Headers & Rate Limiting ]
                                          |
                                [ Flask App Router ]
                                          |
                +-------------------------+-------------------------+
                |                         |                         |
        [ /admin/ ]                  [ /doctor/ ]              [ /patient/ ]
     Admin Dashboard              Clinical Workspace       Self-Service Portal
                |                         |                         |
                +-------------------------+-------------------------+
                                          |
                            [ Role-Based Access Control ]
                                          |
                         [ Cryptographic Engine (AES-256-GCM) ]
                           - NIST SP 800-38D Standard
                           - 96-bit Unique Nonce per Operation
                           - 128-bit Authentication Tag Check
                           - Key Ring & Rotation Pipeline
                                          |
              +---------------------------+---------------------------+
              |                                                       |
    [ Encrypted Database ]                                  [ Encrypted File Store ]
 PostgreSQL / SQLAlchemy                                   storage/encrypted_records/
  - User credentials (PBKDF2/Argon2)                        - AES-GCM Encrypted Blobs
  - AES-GCM Envelope Payloads                               - SHA-256 Integrity Verification
  - Append-Only Audit Trail
```

---

## 2. Cryptographic Specifications

Sensitive healthcare data is protected according to federal standards:

| Component | Standard / Algorithm | Details |
| :--- | :--- | :--- |
| **Record Cipher** | AES-256-GCM (Galois/Counter Mode) | Authenticated Encryption with Associated Data (AEAD) as specified in NIST SP 800-38D. |
| **Nonce Generation** | 96-bit (12-byte) CSPRNG Nonce | Cryptographically generated via `Crypto.Random.get_random_bytes(12)` for **every single encryption**. Nonces are never reused. |
| **Integrity Tag** | 128-bit (16-byte) Auth Tag | Strictly verified during decryption. If even a single bit in the ciphertext or tag is modified, a `DecryptionError` is raised immediately. |
| **Silent Fallback** | Prohibited | If decryption or authentication fails, the system **never** silently falls back to plaintext. |
| **File Encryption** | Streaming AES-256-GCM + Magic Header | Binary files (PDF, DICOM, images) are stored as `.enc` files with magic header `EHR_GCM_V1\0`, version byte, nonce, tag, and ciphertext. |
| **File Integrity** | SHA-256 Checksum | Re-computed and verified against database checksum upon in-memory decryption before delivery to the client. |
| **Password Hashing** | Argon2id / PBKDF2:SHA256 | OWASP standard: 600,000 iterations with 16-byte salt (or Argon2id memory-hard hashing). |
| **Key Management** | Key Ring Versioning | Envelope encryption stores key version (`v1`, `v2`, etc.). Supports seamless zero-downtime key rotation. |

---

## 3. Core Modules & Features

### 1. Role-Based Access Control (RBAC)
- **Administrator**:
  - Full system health oversight, cryptographic engine status, user management directory.
  - Ability to activate/deactivate user accounts.
  - Complete, filterable security audit trail.
- **Doctor (Clinical Staff)**:
  - Patient directory with real-time search (by name, UID, blood group).
  - Patient creation and clinical assignment.
  - Clinical chart view with history timeline.
  - Authoring encrypted consultation notes and treatment plans.
  - Issuing encrypted prescriptions and uploading diagnostic reports.
- **Patient**:
  - Strict data isolation: Patients are authenticated against their own profile and **can never view or decrypt records belonging to other patients**.
  - Self-service portal to view personal consultations, active medications, and verified diagnostic files.

### 2. Append-Only Security Audit Logging
Every security-sensitive operation is recorded in the `audit_logs` table:
- **Recorded Events**: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_RATE_LIMITED`, `UNAUTHORIZED_ACCESS_DENIED`, `PATIENT_CREATED`, `MEDICAL_RECORD_CREATED`, `RECORD_DECRYPTED_AND_VIEWED`, `DOCUMENT_DOWNLOADED`, `PASSWORD_CHANGED`.
- **Captured Metadata**: Actor user ID, action code, target record ID & type, outcome (`SUCCESS`, `FAILURE`, `DENIED`), client IP address, and UTC timestamp.
- **Privacy Assurance**: Plaintext passwords, private keys, and patient clinical notes are **never** logged.

### 3. Healthcare SaaS UI/UX Design System
- Modern visual design with a Navy (`#0f172a`), Medical Blue (`#2563eb`), and Health Teal (`#0d9488`) color palette.
- Interactive Bootstrap 5 dashboard components with FontAwesome 6 icons and Chart.js integration.
- Instant demo account switcher on login screen for quick evaluation.
- Responsive mobile, tablet, and desktop layouts.

---

## 4. Directory Structure

```
ehr_app/
├── app.py                      # Application factory, security headers & error handlers
├── config.py                   # Environment, key ring, database, and upload configurations
├── models.py                   # SQLAlchemy schema (User, Role, Doctor, Patient, Record, etc.)
├── seed_data.py                # Synthetic demo data initializer
├── requirements.txt            # Python dependencies
├── .env.example                # Sample environment configuration
├── modules/
│   ├── __init__.py
│   ├── crypto_engine.py        # AES-256-GCM AEAD encryption/decryption module
│   ├── auth_security.py        # Password hashing, password complexity, RBAC decorators
│   └── audit_logger.py         # Append-only audit logging service
├── routes/
│   ├── __init__.py
│   ├── auth.py                 # Login, register, logout, profile, password reset
│   ├── admin.py                # Admin dashboard, user management, audit logs
│   ├── doctor.py               # Doctor dashboard, patient directory, clinical chart
│   ├── patient.py              # Patient self-service health portal
│   └── records.py              # Medical record CRUD, file upload, authenticated decryption
├── static/
│   ├── css/
│   │   └── custom.css          # Healthcare SaaS styles and badge components
│   └── js/
│       └── main.js             # Password strength meter, alert dismissals, demo filler
├── templates/
│   ├── base.html               # Master layout with security headers and responsive nav
│   ├── auth/
│   │   ├── login.html          # Login card with demo account buttons
│   │   ├── register.html       # Patient/Doctor registration with complexity meter
│   │   ├── profile.html        # Profile settings and password change
│   │   └── reset_password.html # Password recovery
│   ├── admin/
│   │   ├── dashboard.html      # Admin metrics, key status, recent logs
│   │   ├── users.html          # User directory and status toggles
│   │   └── audit_logs.html     # Security audit trail with filters & pagination
│   ├── doctor/
│   │   ├── dashboard.html      # Doctor clinical dashboard & recent records
│   │   ├── patients.html       # Searchable patient directory & add patient modal
│   │   └── patient_detail.html # Patient chart with decrypted records & prescriptions
│   ├── patient/
│   │   └── dashboard.html      # Personal health portal (isolated view)
│   ├── records/
│   │   ├── add.html            # Encrypted record & document attachment form
│   │   └── view.html           # Authenticated record inspection
│   └── errors/
│       ├── 403.html            # Access restricted / forbidden
│       ├── 404.html            # Not found
│       └── 500.html            # Internal server error
├── storage/
│   └── encrypted_records/      # Secure folder storing .enc encrypted binary blobs
└── tests/
    ├── __init__.py
    ├── test_crypto.py          # AES-GCM, unique nonce, tampering, key rotation tests
    ├── test_auth_rbac.py       # Password hashing, login, RBAC protection tests
    └── test_records_and_audit.py # Record encryption, patient isolation, audit trail tests
```

---

## 5. Getting Started & Installation

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Optional: PostgreSQL 14+ (SQLite fallback is configured out of the box for zero-setup development)

### Step 1: Clone and Enter the Directory
```bash
cd c:\Users\HARSHITA\ehr_app
```

### Step 2: Create and Activate Virtual Environment (Optional)
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
copy .env.example .env
```

To configure PostgreSQL, set `DATABASE_URL` in `.env`:
```ini
DATABASE_URL=postgresql+psycopg2://ehr_user:your_password@localhost:5432/ehr_db
```
*(If omitted, SQLite `ehr_system.db` will be used automatically).*

To generate a new 256-bit base64 master key:
```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

### Step 5: Seed the Database with Synthetic Demo Data
```bash
python seed_data.py
```

### Step 6: Start the Application
```bash
python app.py
```
Open your browser to: **`http://localhost:5000`**

---

## 6. Demo Accounts (Synthetic Demonstration Only)

| Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@2026Secure!` | Full system metrics, user activation/deactivation, audit logs. |
| **Doctor** | `dr.sarah` | `Doctor@2026Pass!` | Cardiology physician, clinical notes authoring, patient chart. |
| **Doctor** | `dr.chen` | `Doctor@2026Pass!` | Neurology physician. |
| **Patient** | `patient.john` | `Patient@2026Key!` | Patient portal (`PAT-2026-...`), views own ECG reports & Lisinopril prescription. |
| **Patient** | `patient.emily` | `Patient@2026Key!` | Patient portal, isolated from Patient John's records. |

*Quick login buttons are available directly on the login screen.*

---

## 7. Running the Automated Test Suite

Run pytest to execute the complete verification suite:
```bash
python -m pytest -v
```

### Verified Test Categories (17 / 17 Passed):
- `test_crypto.py`:
  - `test_aes_gcm_encryption_structure`: Validates 12-byte nonce, 16-byte tag, envelope versioning.
  - `test_unique_nonce_per_operation`: Verifies unique nonce generation for identical plaintexts.
  - `test_authenticated_decryption_roundtrip`: Verifies roundtrip decryption.
  - `test_tampering_detection_ciphertext_modification`: Verifies that altering 1 bit in ciphertext triggers `DecryptionError`.
  - `test_tampering_detection_tag_modification`: Verifies that altering tag triggers `DecryptionError`.
  - `test_binary_file_encryption_roundtrip`: Tests raw binary document encryption and decryption.
  - `test_binary_tampering_detection`: Verifies tamper detection in binary files.
  - `test_key_rotation`: Verifies envelope key rotation from version 1 to version 2.
- `test_auth_rbac.py`:
  - `test_password_hashing`: Tests PBKDF2/Argon2 verification and negative checks.
  - `test_password_strength_validation`: Tests uppercase, lowercase, digit, and symbol rules.
  - `test_unauthenticated_access_redirect`: Unauthenticated requests redirect to login.
  - `test_role_based_access_patient_blocked_from_admin`: Patients receive HTTP 403 Forbidden on `/admin/dashboard`.
  - `test_role_based_access_doctor_allowed_on_doctor_dashboard`: Doctors access `/doctor/dashboard`.
- `test_records_and_audit.py`:
  - `test_database_stores_encrypted_ciphertext`: Confirms zero plaintext stored in database.
  - `test_patient_isolation_cannot_view_other_patient_record`: Strict patient isolation (Patient A cannot view Patient B).
  - `test_patient_can_view_own_record`: Authorized patient decrypts own record.
  - `test_audit_log_persists_events`: Append-only audit logger persistence.

---

## 8. Compliance & Security Notice

> [!IMPORTANT]
> **Regulatory Notice (HIPAA / GDPR / HITECH)**:
> This application implements modern security engineering controls (AES-256-GCM AEAD, PBKDF2/Argon2, append-only audit trails, role-based access control, CSP headers, rate-limiting). However, **regulatory compliance (such as HIPAA in the United States or GDPR in the European Union) requires formal administrative, physical, and technical assessments, signed Business Associate Agreements (BAAs), encrypted storage-at-rest at the hardware/OS level, and audited institutional policies.** This software is provided as a secure technical foundation and must undergo formal certification before handling production Protected Health Information (PHI).

All test data included in `seed_data.py` is entirely synthetic. No real patient data is used.
