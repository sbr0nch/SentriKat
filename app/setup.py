"""
First-time setup wizard for SentriKat
Provides a GUI-based setup process for initial configuration
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from app import db, csrf
from app.models import Organization, User, ServiceCatalog
from app.cisa_sync import sync_cisa_kev
import os

setup_bp = Blueprint('setup', __name__)

# Exempt setup routes from CSRF (initial setup before auth is configured)
csrf.exempt(setup_bp)

def is_setup_complete():
    """Check if initial setup has been completed"""
    try:
        # Check if at least one organization exists
        org_count = Organization.query.count()
        # Check if at least one user exists (only if auth is enabled)
        user_count = User.query.count()

        # Setup is complete if we have at least one organization
        # and either auth is disabled or we have at least one user
        auth_enabled = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'

        if auth_enabled:
            return org_count > 0 and user_count > 0
        else:
            return org_count > 0
    except Exception as e:
        # If database doesn't exist or has schema issues, setup is not complete
        return False

@setup_bp.route('/setup', methods=['GET'])
def setup_wizard():
    """Display setup wizard"""
    # If setup is already complete, redirect to main page
    if is_setup_complete():
        return redirect(url_for('main.index'))

    # Check auth status
    auth_enabled = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'

    return render_template('setup.html', auth_enabled=auth_enabled)

@setup_bp.route('/api/setup/status', methods=['GET'])
def setup_status():
    """Check setup status"""
    return jsonify({
        'setup_complete': is_setup_complete(),
        'auth_enabled': os.environ.get('ENABLE_AUTH', 'false').lower() == 'true',
        'org_count': Organization.query.count(),
        'user_count': User.query.count(),
        'service_count': ServiceCatalog.query.count()
    })

@setup_bp.route('/api/setup/create-organization', methods=['POST'])
def create_initial_organization():
    """Create the default organization"""
    try:
        data = request.get_json()

        # Check if default org already exists
        existing = Organization.query.filter_by(name='default').first()
        if existing:
            # Update existing organization instead of error
            existing.display_name = data.get('display_name', existing.display_name)
            existing.description = data.get('description', existing.description)
            existing.notification_emails = data.get('notification_emails', existing.notification_emails)

            # Update SMTP settings if provided
            if data.get('smtp_host'):
                existing.smtp_host = data['smtp_host']
                existing.smtp_port = data.get('smtp_port', 587)
                existing.smtp_username = data.get('smtp_username')
                # Encrypt SMTP password if provided
                if data.get('smtp_password'):
                    from app.encryption import encrypt_value
                    existing.smtp_password = encrypt_value(data['smtp_password'])
                existing.smtp_from_email = data.get('smtp_from_email')
                existing.smtp_from_name = data.get('smtp_from_name', 'SentriKat')
                existing.smtp_use_tls = data.get('smtp_use_tls', True)

            db.session.commit()
            session['organization_id'] = existing.id

            return jsonify({
                'success': True,
                'organization': existing.to_dict(),
                'message': 'Organization already exists, updated with new information'
            }), 200

        # Create default organization
        org = Organization(
            name='default',
            display_name=data.get('display_name', 'Default Organization'),
            description=data.get('description', 'Default organization for SentriKat'),
            notification_emails=data.get('notification_emails', '[]'),
            alert_on_critical=True,
            alert_on_high=False,
            alert_on_new_cve=True,
            alert_on_ransomware=True,
            active=True
        )

        # SMTP settings if provided
        if data.get('smtp_host'):
            org.smtp_host = data['smtp_host']
            org.smtp_port = data.get('smtp_port', 587)
            org.smtp_username = data.get('smtp_username')
            # Encrypt SMTP password if provided
            if data.get('smtp_password'):
                from app.encryption import encrypt_value
                org.smtp_password = encrypt_value(data['smtp_password'])
            org.smtp_from_email = data.get('smtp_from_email')
            org.smtp_from_name = data.get('smtp_from_name', 'SentriKat')
            org.smtp_use_tls = data.get('smtp_use_tls', True)

        db.session.add(org)
        db.session.commit()

        # Set in session
        session['organization_id'] = org.id

        return jsonify({
            'success': True,
            'organization': org.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/setup/create-admin', methods=['POST'])
def create_admin_user():
    """Create the initial admin user"""
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400

        # Validate password strength
        password = data.get('password')
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400

        # Validate email format if provided
        email = data.get('email')
        if email and '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400

        # Check if user already exists
        existing = User.query.filter_by(username=data['username']).first()
        if existing:
            # Update existing user instead of error
            existing.email = data.get('email', existing.email)
            existing.full_name = data.get('full_name', existing.full_name)
            existing.role = 'super_admin'
            existing.is_admin = True
            existing.is_active = True
            existing.can_manage_products = True
            existing.can_view_all_orgs = True

            # Update password
            existing.set_password(data['password'])

            db.session.commit()

            return jsonify({
                'success': True,
                'user': existing.to_dict(),
                'message': 'User already exists, updated password and permissions'
            }), 200

        # Get default organization
        org = Organization.query.filter_by(name='default').first()

        # Create admin user
        admin = User(
            username=data['username'],
            email=data.get('email', f"{data['username']}@localhost"),
            full_name=data.get('full_name', 'System Administrator'),
            role='super_admin',
            is_admin=True,
            is_active=True,
            auth_type='local',
            organization_id=org.id if org else None,
            can_manage_products=True,
            can_view_all_orgs=True
        )

        # Set password
        admin.set_password(data['password'])

        db.session.add(admin)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': admin.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/setup/save-proxy', methods=['POST'])
def save_proxy_settings():
    """Save proxy settings to system settings"""
    try:
        from app.models import SystemSettings
        data = request.get_json()

        proxy_server = data.get('proxy_server', '').strip()
        proxy_port = data.get('proxy_port', '8080')
        proxy_username = data.get('proxy_username', '').strip()
        proxy_password = data.get('proxy_password', '')

        if not proxy_server:
            return jsonify({'error': 'Proxy server is required'}), 400

        # Build proxy URL
        if proxy_username and proxy_password:
            proxy_url = f"http://{proxy_username}:{proxy_password}@{proxy_server}:{proxy_port}"
        else:
            proxy_url = f"http://{proxy_server}:{proxy_port}"

        # Delete existing proxy settings
        SystemSettings.query.filter(SystemSettings.key.like('proxy_%')).delete()

        # Save new proxy settings
        proxy_settings = [
            SystemSettings(key='proxy_enabled', value='true'),
            SystemSettings(key='proxy_url', value=proxy_url),
            SystemSettings(key='proxy_server', value=proxy_server),
            SystemSettings(key='proxy_port', value=str(proxy_port)),
        ]

        if proxy_username:
            proxy_settings.append(SystemSettings(key='proxy_username', value=proxy_username))
        if proxy_password:
            proxy_settings.append(SystemSettings(key='proxy_password', value=proxy_password))

        for setting in proxy_settings:
            db.session.add(setting)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Proxy settings saved'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/setup/seed-services', methods=['POST'])
def seed_service_catalog():
    """Seed the service catalog with common services"""
    try:
        # Check if services already exist
        existing_count = ServiceCatalog.query.count()
        if existing_count > 0:
            return jsonify({
                'success': True,
                'message': f'Service catalog already contains {existing_count} services',
                'count': existing_count
            })

        # Import and run the seed script
        import subprocess
        import sys

        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        seed_script = os.path.join(project_root, 'seed_service_catalog.py')

        # Check if seed script exists
        if not os.path.exists(seed_script):
            return jsonify({
                'success': False,
                'error': f'Seed script not found at: {seed_script}'
            }), 500

        result = subprocess.run(
            [sys.executable, seed_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_root
        )

        if result.returncode == 0:
            # Count services
            service_count = ServiceCatalog.query.count()
            return jsonify({
                'success': True,
                'message': f'Successfully seeded {service_count} services',
                'count': service_count
            })
        else:
            return jsonify({
                'success': False,
                'error': result.stderr or 'Failed to seed services'
            }), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/setup/initial-sync', methods=['POST'])
def run_initial_sync():
    """Run initial CISA KEV sync"""
    try:
        # Check if proxy is configured
        has_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')

        # Run sync with CVSS enrichment
        result = sync_cisa_kev(enrich_cvss=True, cvss_limit=50)

        if result['status'] == 'success':
            return jsonify({
                'success': True,
                'stored': result.get('stored', 0),
                'updated': result.get('updated', 0),
                'matches': result.get('matches', 0),
                'duration': result.get('duration', 0),
                'has_proxy': has_proxy is not None
            })
        else:
            error_msg = result.get('error', 'Sync failed')
            # Add helpful message for network errors
            if 'connection' in error_msg.lower() or 'network' in error_msg.lower():
                if not has_proxy:
                    error_msg += '. If you are behind a proxy, configure HTTP_PROXY and HTTPS_PROXY in .env'
            return jsonify({
                'success': False,
                'error': error_msg
            }), 500

    except Exception as e:
        error_msg = str(e)
        # Provide helpful context for common errors
        if 'connection' in error_msg.lower():
            error_msg += '. Check your internet connection and proxy settings.'
        return jsonify({'error': error_msg}), 500

@setup_bp.route('/api/setup/complete', methods=['POST'])
def complete_setup():
    """Mark setup as complete"""
    try:
        # Verify setup is actually complete
        if not is_setup_complete():
            return jsonify({
                'success': False,
                'error': 'Setup is not complete. Please complete all steps.'
            }), 400

        return jsonify({
            'success': True,
            'message': 'Setup completed successfully!',
            'redirect': url_for('main.index')
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
