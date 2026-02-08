"""
First-time setup wizard for SentriKat
Provides a GUI-based setup process for initial configuration
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from app import db, csrf
from sqlalchemy import func
from app.models import Organization, User, ServiceCatalog
from app.cisa_sync import sync_cisa_kev
import os
import json

setup_bp = Blueprint('setup', __name__)

# Exempt setup routes from CSRF (initial setup before auth is configured)
csrf.exempt(setup_bp)

def is_setup_complete():
    """Check if initial setup has been completed"""
    try:
        # Check if at least one organization exists
        org_count = Organization.query.count() or 0
        # Check if at least one user exists (only if auth is enabled)
        user_count = User.query.count() or 0

        # Setup is complete if we have at least one organization
        # and either auth is disabled or we have at least one user
        # Match auth.py: AUTH_ENABLED = DISABLE_AUTH != 'true' (auth is ON by default)
        auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

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

    # Check auth status - match auth.py: auth is ON by default
    auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

    return render_template('setup.html', auth_enabled=auth_enabled)

@setup_bp.route('/api/setup/status', methods=['GET'])
def setup_status():
    """Check setup status"""
    return jsonify({
        'setup_complete': is_setup_complete(),
        'auth_enabled': os.environ.get('DISABLE_AUTH', 'false').lower() != 'true',
        'org_count': Organization.query.count() or 0,
        'user_count': User.query.count() or 0,
        'service_count': ServiceCatalog.query.count() or 0
    })

@setup_bp.route('/api/setup/create-organization', methods=['POST'])
def create_initial_organization():
    """Create the default organization"""
    try:
        # Block access after setup is complete
        if is_setup_complete():
            return jsonify({'error': 'Setup already completed. Use admin panel to manage organizations.'}), 403

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
        # Block access after setup is complete
        if is_setup_complete():
            return jsonify({'error': 'Setup already completed. Use admin panel to manage users.'}), 403

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
        # Block access after setup is complete
        if is_setup_complete():
            return jsonify({'error': 'Setup already completed. Use admin panel to manage proxy settings.'}), 403

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
            from app.encryption import encrypt_value
            proxy_settings.append(SystemSettings(key='proxy_password', value=encrypt_value(proxy_password)))

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
    """Seed the service catalog with common enterprise services"""
    try:
        # Block access after setup is complete
        if is_setup_complete():
            return jsonify({'error': 'Setup already completed.'}), 403

        # Check if services already exist
        existing_count = ServiceCatalog.query.count()
        if existing_count > 0:
            return jsonify({
                'success': True,
                'message': f'Service catalog already contains {existing_count} services',
                'count': existing_count
            })

        # Common enterprise services organized by category
        # Note: versions is an array since (vendor, product_name) must be unique
        services = [
            # Microsoft Products
            {"vendor": "Microsoft", "product": "Windows Server", "versions": ["2019", "2022", "2016"], "category": "Operating System"},
            {"vendor": "Microsoft", "product": "Windows 10", "versions": ["Enterprise", "Pro"], "category": "Operating System"},
            {"vendor": "Microsoft", "product": "Windows 11", "versions": ["Enterprise", "Pro"], "category": "Operating System"},
            {"vendor": "Microsoft", "product": "Exchange Server", "versions": ["2019", "2016"], "category": "Email Server"},
            {"vendor": "Microsoft", "product": "SQL Server", "versions": ["2022", "2019", "2017"], "category": "Database"},
            {"vendor": "Microsoft", "product": "SharePoint Server", "versions": ["2019", "2016"], "category": "Collaboration"},
            {"vendor": "Microsoft", "product": "Active Directory", "versions": ["2019", "2016"], "category": "Identity"},
            {"vendor": "Microsoft", "product": ".NET Framework", "versions": ["4.8", "4.7"], "category": "Runtime"},
            {"vendor": "Microsoft", "product": "IIS", "versions": ["10.0", "8.5"], "category": "Web Server"},
            {"vendor": "Microsoft", "product": "Office", "versions": ["365", "2021", "2019"], "category": "Productivity"},
            {"vendor": "Microsoft", "product": "Defender for Endpoint", "versions": ["Latest"], "category": "EDR"},

            # Database Systems
            {"vendor": "Oracle", "product": "Database", "versions": ["21c", "19c", "18c"], "category": "Database"},
            {"vendor": "MySQL", "product": "MySQL", "versions": ["8.0", "5.7"], "category": "Database"},
            {"vendor": "PostgreSQL", "product": "PostgreSQL", "versions": ["16", "15", "14"], "category": "Database"},
            {"vendor": "MongoDB", "product": "MongoDB", "versions": ["7.0", "6.0"], "category": "Database"},
            {"vendor": "Redis", "product": "Redis", "versions": ["7.0", "6.2"], "category": "Database"},
            {"vendor": "Elastic", "product": "Elasticsearch", "versions": ["8.x", "7.x"], "category": "Database"},

            # Web Servers & Frameworks
            {"vendor": "Apache", "product": "HTTP Server", "versions": ["2.4"], "category": "Web Server"},
            {"vendor": "Nginx", "product": "Nginx", "versions": ["1.24", "1.22"], "category": "Web Server"},
            {"vendor": "Apache", "product": "Tomcat", "versions": ["10", "9"], "category": "Application Server"},
            {"vendor": "Node.js", "product": "Node.js", "versions": ["20 LTS", "18 LTS"], "category": "Runtime"},
            {"vendor": "PHP", "product": "PHP", "versions": ["8.2", "8.1", "7.4"], "category": "Runtime"},
            {"vendor": "Python", "product": "Python", "versions": ["3.12", "3.11", "3.10"], "category": "Runtime"},
            {"vendor": "Java", "product": "OpenJDK", "versions": ["21", "17", "11"], "category": "Runtime"},

            # Network Equipment
            {"vendor": "Cisco", "product": "IOS", "versions": ["17.x", "16.x"], "category": "Network"},
            {"vendor": "Cisco", "product": "ASA", "versions": ["9.x"], "category": "Firewall"},
            {"vendor": "Cisco", "product": "Firepower", "versions": ["7.x", "6.x"], "category": "Firewall"},
            {"vendor": "Palo Alto", "product": "PAN-OS", "versions": ["11.x", "10.x"], "category": "Firewall"},
            {"vendor": "Fortinet", "product": "FortiOS", "versions": ["7.x", "6.x"], "category": "Firewall"},
            {"vendor": "Juniper", "product": "Junos OS", "versions": ["23.x", "22.x"], "category": "Network"},
            {"vendor": "F5", "product": "BIG-IP", "versions": ["17.x", "16.x"], "category": "Load Balancer"},

            # Virtualization & Cloud
            {"vendor": "VMware", "product": "vSphere", "versions": ["8.0", "7.0"], "category": "Virtualization"},
            {"vendor": "VMware", "product": "ESXi", "versions": ["8.0", "7.0"], "category": "Hypervisor"},
            {"vendor": "VMware", "product": "vCenter", "versions": ["8.0", "7.0"], "category": "Management"},
            {"vendor": "Citrix", "product": "XenServer", "versions": ["8.x"], "category": "Hypervisor"},
            {"vendor": "Docker", "product": "Docker Engine", "versions": ["24.x", "23.x"], "category": "Container"},
            {"vendor": "Kubernetes", "product": "Kubernetes", "versions": ["1.29", "1.28", "1.27"], "category": "Container Orchestration"},

            # Security Products
            {"vendor": "CrowdStrike", "product": "Falcon", "versions": ["Latest"], "category": "EDR"},
            {"vendor": "Splunk", "product": "Enterprise", "versions": ["9.x", "8.x"], "category": "SIEM"},
            {"vendor": "Elastic", "product": "Security", "versions": ["8.x", "7.x"], "category": "SIEM"},
            {"vendor": "Tenable", "product": "Nessus", "versions": ["Latest"], "category": "Vulnerability Scanner"},
            {"vendor": "Qualys", "product": "VMDR", "versions": ["Latest"], "category": "Vulnerability Scanner"},

            # Linux Distributions
            {"vendor": "Red Hat", "product": "Enterprise Linux", "versions": ["9", "8", "7"], "category": "Operating System"},
            {"vendor": "Canonical", "product": "Ubuntu", "versions": ["24.04 LTS", "22.04 LTS", "20.04 LTS"], "category": "Operating System"},
            {"vendor": "SUSE", "product": "Linux Enterprise Server", "versions": ["15", "12"], "category": "Operating System"},
            {"vendor": "Debian", "product": "Debian", "versions": ["12", "11"], "category": "Operating System"},

            # Backup & Storage
            {"vendor": "Veeam", "product": "Backup & Replication", "versions": ["12", "11"], "category": "Backup"},
            {"vendor": "Commvault", "product": "Complete Backup", "versions": ["Latest"], "category": "Backup"},
            {"vendor": "NetApp", "product": "ONTAP", "versions": ["9.x"], "category": "Storage"},
            {"vendor": "Dell EMC", "product": "PowerStore", "versions": ["Latest"], "category": "Storage"},
        ]

        # Insert services
        added = 0
        for svc in services:
            versions = svc.get('versions', [])
            service = ServiceCatalog(
                vendor=svc['vendor'],
                product_name=svc['product'],
                category=svc.get('category', 'Other'),
                typical_versions=json.dumps(versions) if versions else None,
                description=f"{svc['vendor']} {svc['product']}",
                is_popular=True,
                is_active=True
            )
            db.session.add(service)
            added += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully seeded {added} services',
            'count': added
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@setup_bp.route('/api/setup/initial-sync', methods=['POST'])
def run_initial_sync():
    """Run initial CISA KEV sync"""
    try:
        # Block access after setup is complete
        if is_setup_complete():
            return jsonify({'error': 'Setup already completed. Use admin panel to trigger sync.'}), 403

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
