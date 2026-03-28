"""
GDPR Compliance API — Data Export and Deletion (Right to be Forgotten)

Endpoints:
- GET  /api/gdpr/export     — Export all personal data for the current user (JSON)
- POST /api/gdpr/delete      — Request account and personal data deletion
"""

import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, session, request
from app import db, limiter
from app.auth import login_required
from app.models import (
    User, Organization, UserOrganization, Product, Asset,
    AgentApiKey
)

logger = logging.getLogger(__name__)

gdpr_bp = Blueprint('gdpr', __name__, url_prefix='/api/gdpr')


@gdpr_bp.route('/export', methods=['GET'])
@login_required
@limiter.limit("5/hour")
def export_personal_data():
    """
    Export all personal data for the current user (GDPR Art. 15 — Right of Access).
    Returns JSON with all user-related data.
    """
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Collect all personal data
    export = {
        'export_date': datetime.utcnow().isoformat(),
        'gdpr_article': 'Art. 15 — Right of Access',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': getattr(user, 'full_name', None),
            'role': user.role,
            'auth_type': user.auth_type,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'totp_enabled': getattr(user, 'totp_enabled', False),
        },
        'organizations': [],
    }

    # Organization memberships
    memberships = UserOrganization.query.filter_by(user_id=user.id).all()
    for m in memberships:
        org = Organization.query.get(m.organization_id)
        if org:
            export['organizations'].append({
                'id': org.id,
                'name': org.display_name or org.name,
                'role': m.role,
            })

    # Also check legacy org assignment
    if user.organization_id and not any(
        o['id'] == user.organization_id for o in export['organizations']
    ):
        org = Organization.query.get(user.organization_id)
        if org:
            export['organizations'].append({
                'id': org.id,
                'name': org.display_name or org.name,
                'role': user.role,
            })

    # API keys created by this user
    export['api_keys'] = []
    try:
        keys = AgentApiKey.query.filter_by(created_by=user.id).all()
        for key in keys:
            export['api_keys'].append({
                'id': key.id,
                'name': getattr(key, 'name', None),
                'active': key.active,
                'created_at': key.created_at.isoformat() if key.created_at else None,
            })
    except Exception:
        pass

    logger.info(f"GDPR data export requested by user {user.username} (id={user.id})")

    response = jsonify(export)
    response.headers['Content-Disposition'] = f'attachment; filename="sentrikat-data-export-{user.id}.json"'
    return response


@gdpr_bp.route('/delete', methods=['POST'])
@login_required
@limiter.limit("3/day")
def request_deletion():
    """
    Request account and personal data deletion (GDPR Art. 17 — Right to Erasure).

    This anonymizes the user's personal data and deactivates the account.
    Vulnerability data is retained (anonymized) for security purposes (Art. 17(3)(d)).
    """
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Prevent super_admin from self-deleting (would lock out the system)
    if user.role == 'super_admin':
        from app.models import User as UserModel
        other_admins = UserModel.query.filter(
            UserModel.role == 'super_admin',
            UserModel.id != user.id,
            UserModel.is_active == True
        ).count()
        if other_admins == 0:
            return jsonify({
                'error': 'Cannot delete the only super_admin account. '
                         'Promote another user to super_admin first.'
            }), 409

    try:
        original_username = user.username
        original_email = user.email

        # Anonymize personal data (retain account structure for audit integrity)
        user.username = f'deleted_user_{user.id}'
        user.email = f'deleted_{user.id}@anonymized.local'
        user.full_name = None
        user.is_active = False
        user.totp_secret = None
        user.totp_enabled = False
        user.password_reset_token = None
        user.password_reset_expires = None

        # Invalidate password (set to random impossible hash)
        import secrets
        user.password_hash = f'DELETED_{secrets.token_hex(32)}'

        # Remove org memberships
        UserOrganization.query.filter_by(user_id=user.id).delete()

        # Deactivate API keys created by this user
        AgentApiKey.query.filter_by(created_by=user.id).update(
            {'active': False}, synchronize_session=False
        )

        db.session.commit()

        # Clear session
        session.clear()

        logger.info(
            f"GDPR deletion completed for user {original_username} "
            f"(id={user.id}, email={original_email})"
        )

        return jsonify({
            'success': True,
            'message': 'Your account has been anonymized and deactivated. '
                       'Vulnerability data is retained in anonymized form for security purposes '
                       '(GDPR Art. 17(3)(d) — public security exception).',
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"GDPR deletion failed for user {user.id}: {e}")
        return jsonify({'error': 'Deletion failed. Please contact support@sentrikat.com'}), 500
