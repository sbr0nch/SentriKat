"""
Tenant provisioning service for SentriKat.

Automates the creation of new tenants (organizations) with:
- Organization creation with default settings
- Admin user creation
- Agent API key generation
- Welcome email sending (optional)

This module is the foundation for both:
- On-premise: Scripted multi-tenant setup
- SaaS: Self-serve signup and automated provisioning

Usage:
    from app.provisioning import provision_tenant

    result = provision_tenant(
        org_name='acme-corp',
        org_display_name='ACME Corporation',
        admin_username='admin@acme.com',
        admin_email='admin@acme.com',
        admin_password='secure-password-here',
        send_welcome_email=True
    )

    # result = {
    #     'success': True,
    #     'organization': { id, name, display_name },
    #     'admin_user': { id, username, email },
    #     'api_key': { id, name, key (raw, only on creation) },
    # }
"""

import logging
import re
import secrets
from datetime import datetime

from app import db
from app.models import Organization, User, AgentApiKey, UserOrganization

logger = logging.getLogger(__name__)


class ProvisioningError(Exception):
    """Raised when tenant provisioning fails."""
    pass


def validate_org_name(name):
    """
    Validate organization name format.

    Rules:
    - 3-100 characters
    - Lowercase alphanumeric, hyphens, underscores
    - Must start with a letter
    """
    if not name or len(name) < 3 or len(name) > 100:
        return False, "Organization name must be 3-100 characters"

    if not re.match(r'^[a-z][a-z0-9_-]*$', name):
        return False, "Organization name must be lowercase, start with a letter, and contain only letters, numbers, hyphens, and underscores"

    return True, None


def provision_tenant(
    org_name,
    org_display_name,
    admin_username,
    admin_email,
    admin_password,
    org_description=None,
    notification_emails=None,
    send_welcome_email=False,
    created_by_user_id=None,
):
    """
    Provision a complete new tenant with organization, admin user, and API key.

    This is an atomic operation - if any step fails, all changes are rolled back.

    Args:
        org_name: Unique organization slug (lowercase, alphanumeric)
        org_display_name: Human-readable organization name
        admin_username: Username for the org admin
        admin_email: Email for the org admin
        admin_password: Password for the org admin (must meet policy)
        org_description: Optional description
        notification_emails: Optional list of email addresses for alerts
        send_welcome_email: Whether to send a welcome email
        created_by_user_id: ID of the user who initiated provisioning (for audit)

    Returns:
        dict with organization, admin_user, and api_key details

    Raises:
        ProvisioningError: If provisioning fails
    """
    # Validate inputs
    valid, error = validate_org_name(org_name)
    if not valid:
        raise ProvisioningError(error)

    if not admin_username or len(admin_username) < 3:
        raise ProvisioningError("Admin username must be at least 3 characters")

    if not admin_email or '@' not in admin_email:
        raise ProvisioningError("Valid admin email is required")

    if not admin_password or len(admin_password) < 8:
        raise ProvisioningError("Admin password must be at least 8 characters")

    # Check for duplicates first (before license limits, so users get
    # the more specific "already exists" error instead of "limit reached")
    if Organization.query.filter_by(name=org_name).first():
        raise ProvisioningError(f"Organization '{org_name}' already exists")

    if User.query.filter(
        db.or_(User.username == admin_username, User.email == admin_email)
    ).first():
        raise ProvisioningError(f"Username or email already exists")

    # Check license limits
    try:
        from app.licensing import check_org_limit, check_user_limit, check_agent_api_key_limit

        can_add_org, _, org_msg = check_org_limit()
        if not can_add_org:
            raise ProvisioningError(f"Organization limit reached: {org_msg}")

        can_add_user, _, user_msg = check_user_limit()
        if not can_add_user:
            raise ProvisioningError(f"User limit reached: {user_msg}")

        can_add_key, _, key_msg = check_agent_api_key_limit()
        if not can_add_key:
            raise ProvisioningError(f"API key limit reached: {key_msg}")
    except ImportError:
        pass  # Licensing module not available (dev/test)

    try:
        # Step 1: Create organization
        import json
        org = Organization(
            name=org_name,
            display_name=org_display_name,
            description=org_description,
            notification_emails=json.dumps(notification_emails) if notification_emails else '[]',
            alert_on_critical=True,
            alert_on_high=False,
            alert_on_new_cve=True,
            alert_on_ransomware=True,
            alert_time_start='08:00',
            alert_time_end='18:00',
            alert_days='mon,tue,wed,thu,fri',
            active=True,
        )
        db.session.add(org)
        db.session.flush()  # Get org.id without committing

        logger.info(f"Provisioning: Created organization '{org_name}' (id={org.id})")

        # Step 2: Create admin user
        admin = User(
            username=admin_username,
            email=admin_email,
            full_name=f"{org_display_name} Admin",
            organization_id=org.id,
            role='org_admin',
            is_admin=True,
            is_active=True,
            auth_type='local',
            can_manage_products=True,
            can_view_all_orgs=False,
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.flush()  # Get admin.id

        # Step 3: Create UserOrganization membership
        membership = UserOrganization(
            user_id=admin.id,
            organization_id=org.id,
            role='org_admin',
        )
        db.session.add(membership)

        logger.info(f"Provisioning: Created admin user '{admin_username}' (id={admin.id})")

        # Step 4: Generate agent API key
        raw_key = AgentApiKey.generate_key()
        key_hash = AgentApiKey.hash_key(raw_key)
        key_prefix = raw_key[:10]

        encrypted_raw = None
        try:
            from app.encryption import encrypt_value
            encrypted_raw = encrypt_value(raw_key)
        except Exception:
            pass

        api_key = AgentApiKey(
            organization_id=org.id,
            name=f"{org_display_name} - Default Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            encrypted_key=encrypted_raw,
            key_type='server',
            scan_os_packages=True,
            scan_extensions=False,
            scan_dependencies=False,
            auto_approve=False,
            created_by=admin.id,
        )
        db.session.add(api_key)

        # Commit everything atomically
        db.session.commit()

        logger.info(
            f"Provisioning: Tenant '{org_name}' fully provisioned "
            f"(org_id={org.id}, user_id={admin.id}, key_id={api_key.id})"
        )

        result = {
            'success': True,
            'organization': {
                'id': org.id,
                'name': org.name,
                'display_name': org.display_name,
            },
            'admin_user': {
                'id': admin.id,
                'username': admin.username,
                'email': admin.email,
            },
            'api_key': {
                'id': api_key.id,
                'name': api_key.name,
                'key_prefix': key_prefix,
                'key': raw_key,  # Only returned on creation!
            },
        }

        # Step 5: Send welcome email (optional, non-blocking)
        if send_welcome_email:
            try:
                sent = _send_welcome_email(admin, org, raw_key)
            except Exception as e:
                logger.warning(f"Provisioning: Welcome email failed for {admin_email}: {e}")
                result['welcome_email_sent'] = False
            else:
                result['welcome_email_sent'] = bool(sent)

        return result

    except ProvisioningError:
        db.session.rollback()
        raise
    except Exception as e:
        db.session.rollback()
        logger.error(f"Provisioning failed for '{org_name}': {e}")
        raise ProvisioningError(f"Provisioning failed: {str(e)}")


def deprovision_tenant(org_id, confirm_name=None):
    """
    Remove a tenant and all associated data.

    This is a destructive operation. CASCADE deletes will remove:
    - All products, assets, vulnerability matches
    - All users and their sessions
    - All agent API keys
    - All alert logs, sync logs

    Args:
        org_id: Organization ID to remove
        confirm_name: Must match the org name for safety

    Returns:
        dict with success status

    Raises:
        ProvisioningError: If deprovisioning fails
    """
    org = Organization.query.get(org_id)
    if not org:
        raise ProvisioningError(f"Organization {org_id} not found")

    if confirm_name and confirm_name != org.name:
        raise ProvisioningError(
            f"Confirmation name '{confirm_name}' does not match organization name '{org.name}'"
        )

    org_name = org.name
    try:
        # Explicitly delete related records first to avoid NOT NULL constraint
        # violations when the ORM tries to nullify foreign keys
        UserOrganization.query.filter_by(organization_id=org_id).delete()
        AgentApiKey.query.filter_by(organization_id=org_id).delete()
        User.query.filter_by(organization_id=org_id).delete()
        db.session.delete(org)
        db.session.commit()
        logger.info(f"Deprovisioning: Removed organization '{org_name}' (id={org_id})")
        return {'success': True, 'message': f"Organization '{org_name}' and all data removed"}
    except Exception as e:
        db.session.rollback()
        logger.error(f"Deprovisioning failed for org {org_id}: {e}")
        raise ProvisioningError(f"Deprovisioning failed: {str(e)}")


def _send_welcome_email(user, org, api_key):
    """Send welcome email to new tenant admin."""
    from app.settings_api import get_setting

    smtp_host = get_setting('smtp_host')
    if not smtp_host:
        logger.info("Provisioning: No SMTP configured, skipping welcome email")
        return False

    sentrikat_url = os.environ.get('SENTRIKAT_URL', 'https://your-sentrikat-instance.com')

    subject = f"Welcome to SentriKat - {org.display_name}"
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to SentriKat</h2>
        <p>Your organization <strong>{org.display_name}</strong> has been set up.</p>

        <h3>Your Login Credentials</h3>
        <ul>
            <li><strong>URL:</strong> <a href="{sentrikat_url}">{sentrikat_url}</a></li>
            <li><strong>Username:</strong> {user.username}</li>
            <li><strong>Password:</strong> (the password you set during registration)</li>
        </ul>

        <h3>Your Agent API Key</h3>
        <p>Use this key to connect your agents:</p>
        <code style="background: #f4f4f4; padding: 8px; display: block; word-break: break-all;">
            {api_key}
        </code>
        <p><em>Save this key securely. It will not be shown again.</em></p>

        <h3>Next Steps</h3>
        <ol>
            <li>Log in to SentriKat</li>
            <li>Deploy agents on your servers/workstations</li>
            <li>Configure alert settings for your organization</li>
        </ol>

        <p style="color: #666; font-size: 12px;">
            This is an automated message from SentriKat.
        </p>
    </body>
    </html>
    """

    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_config = {
        'host': smtp_host,
        'port': int(get_setting('smtp_port', '587') or '587'),
        'username': get_setting('smtp_username'),
        'password': get_setting('smtp_password'),
        'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
        'from_email': get_setting('smtp_from_email'),
        'from_name': get_setting('smtp_from_name', 'SentriKat'),
    }

    # Decrypt password if encrypted
    if smtp_config['password']:
        from app.encryption import is_encrypted, decrypt_value
        if is_encrypted(smtp_config['password']):
            smtp_config['password'] = decrypt_value(smtp_config['password'])

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
    msg['To'] = user.email
    msg.attach(MIMEText(html_body, 'html'))

    if smtp_config['use_tls']:
        server = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=30)
        server.starttls()
    else:
        server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=30)

    if smtp_config['username'] and smtp_config['password']:
        server.login(smtp_config['username'], smtp_config['password'])

    server.sendmail(smtp_config['from_email'], [user.email], msg.as_string())
    server.quit()

    logger.info(f"Provisioning: Welcome email sent to {user.email}")
    return True


# Required import for _send_welcome_email
import os
