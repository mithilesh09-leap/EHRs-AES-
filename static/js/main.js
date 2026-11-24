/**
 * EHR Guardian - Interactive UI Scripts
 */

document.addEventListener('DOMContentLoaded', () => {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });

    // Password strength evaluator for registration & profile
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');

    if (passwordInput && strengthBar && strengthText) {
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            let score = 0;
            if (val.length >= 8) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[a-z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[!@#$%^&*(),.?":{}|<>\-_]/.test(val)) score++;

            let percent = (score / 5) * 100;
            strengthBar.style.width = percent + '%';

            if (score <= 2) {
                strengthBar.className = 'progress-bar bg-danger';
                strengthText.innerText = 'Weak (Needs upper, lower, digit & symbol)';
                strengthText.className = 'form-text text-danger';
            } else if (score <= 4) {
                strengthBar.className = 'progress-bar bg-warning';
                strengthText.innerText = 'Moderate (Good, add special character)';
                strengthText.className = 'form-text text-warning';
            } else {
                strengthBar.className = 'progress-bar bg-success';
                strengthText.innerText = 'Strong (Meets all security requirements)';
                strengthText.className = 'form-text text-success';
            }
        });
    }

    // Role switcher dynamic fields in Registration
    const roleSelect = document.getElementById('role-select');
    const doctorFields = document.getElementById('doctor-fields');
    const patientFields = document.getElementById('patient-fields');

    if (roleSelect && doctorFields && patientFields) {
        const toggleFields = () => {
            if (roleSelect.value === 'doctor') {
                doctorFields.classList.remove('d-none');
                patientFields.classList.add('d-none');
            } else {
                doctorFields.classList.add('d-none');
                patientFields.classList.remove('d-none');
            }
        };
        roleSelect.addEventListener('change', toggleFields);
        toggleFields();
    }
});

// Quick demo login credential filler
function fillDemoCredentials(username, password) {
    const userInput = document.getElementById('username');
    const passInput = document.getElementById('password');
    if (userInput && passInput) {
        userInput.value = username;
        passInput.value = password;
        userInput.focus();
    }
}
