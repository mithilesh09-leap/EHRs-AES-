"""
Main Application Entry Point and Application Factory for Secure EHR.
Configures security headers, CSRF, blueprints, database, and error handlers.
"""

import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, session, request
from config import Config
from models import db, User, Role

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Ensure secure storage directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.admin import admin_bp
    from routes.doctor import doctor_bp
    from routes.patient import patient_bp
    from routes.records import records_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(records_bp)

    # Root routing - Serves the 3D Cyber Landing Page
    @app.route('/')
    def index():
        # If user is already logged in and requests dashboard explicitly
        if 'user_id' in session and request.args.get('dashboard'):
            role = session.get('role')
            if role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif role == 'doctor':
                return redirect(url_for('doctor.dashboard'))
            elif role == 'patient':
                return redirect(url_for('patient.dashboard'))
        return render_template('index.html')

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Content Security Policy (allowing Bootstrap 5, FontAwesome, Chart.js CDNs)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:;"
        )
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    # Global Template Context
    @app.context_processor
    def inject_global_template_context():
        return {
            'now': datetime.utcnow(),
            'current_year': datetime.utcnow().year,
            'logged_in_user': session.get('username'),
            'logged_in_name': session.get('full_name'),
            'logged_in_role': session.get('role')
        }

    # Custom Error Handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    return app


app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
