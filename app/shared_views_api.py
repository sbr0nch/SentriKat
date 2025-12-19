"""
Shared Views API
Endpoints for creating and accessing shared filtered views
"""

from flask import Blueprint, request, jsonify, session, redirect, url_for
from app import db
from app.models import User
from app.shared_views import SharedView
from app.auth import login_required
from datetime import datetime, timedelta
import json

shared_views_bp = Blueprint('shared_views', __name__, url_prefix='/api/shared')

@shared_views_bp.route('/create', methods=['POST'])
@login_required
def create_shared_view():
    """
    Create a new shareable filtered view

    Request body:
    {
        "name": "Critical Windows Vulnerabilities",
        "description": "All critical priority Windows vulnerabilities",
        "filters": {
            "priority": "critical",
            "vendor": "Microsoft",
            "product": "Windows",
            ...
        },
        "is_public": true,
        "expires_days": 30  # Optional, null for no expiration
    }
    """
    import time
    from app.logging_config import log_performance, log_audit_event

    start_time = time.time()

    try:
        data = request.get_json()
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)

        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        filters = data.get('filters', {})

        # Generate unique token (more efficient with retry limit)
        max_retries = 10
        token = None
        for attempt in range(max_retries):
            candidate_token = SharedView.generate_token()
            # Use EXISTS for faster check (doesn't fetch the whole row)
            if not db.session.query(
                db.exists().where(SharedView.share_token == candidate_token)
            ).scalar():
                token = candidate_token
                break

        if not token:
            return jsonify({'error': 'Failed to generate unique token, please try again'}), 500

        # Calculate expiration
        expires_at = None
        if data.get('expires_days'):
            expires_at = datetime.utcnow() + timedelta(days=int(data['expires_days']))

        # Create shared view
        shared_view = SharedView(
            share_token=token,
            name=data.get('name'),
            description=data.get('description'),
            created_by=current_user_id,
            organization_id=current_user.organization_id,
            filter_priority=filters.get('priority'),
            filter_severity=filters.get('severity'),
            filter_urgency=filters.get('urgency'),
            filter_age=filters.get('age'),
            filter_cve=filters.get('cve'),
            filter_vendor=filters.get('vendor'),
            filter_product=filters.get('product'),
            filter_ransomware=filters.get('ransomware', False),
            filter_unack=filters.get('unack', False),
            is_public=data.get('is_public', True),
            expires_at=expires_at
        )

        db.session.add(shared_view)
        db.session.commit()

        share_url = request.host_url.rstrip('/') + shared_view.get_share_url()

        # Log audit event
        log_audit_event(
            'CREATE',
            'shared_views',
            shared_view.id,
            new_value={
                'name': shared_view.name,
                'filters': filters,
                'is_public': shared_view.is_public
            },
            details=f"Created shared view: {shared_view.name}"
        )

        # Log performance if slow
        duration_ms = (time.time() - start_time) * 1000
        if duration_ms > 1000:
            log_performance('/api/shared/create', duration_ms)

        return jsonify({
            'success': True,
            'shared_view': shared_view.to_dict(),
            'share_url': share_url,
            'message': 'Shareable link created successfully'
        }), 201

    except Exception as e:
        db.session.rollback()
        import logging
        logging.error(f"Error creating shared view: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@shared_views_bp.route('/view/<share_token>', methods=['GET'])
@login_required
def get_shared_view(share_token):
    """
    Get a shared view by token
    Requires authentication
    """
    try:
        shared_view = SharedView.query.filter_by(
            share_token=share_token,
            is_active=True
        ).first()

        if not shared_view:
            return jsonify({'error': 'Shared view not found or has been deactivated'}), 404

        # Check if expired
        if shared_view.expires_at and shared_view.expires_at < datetime.utcnow():
            return jsonify({'error': 'This shared link has expired'}), 410

        # Update access tracking
        shared_view.access_count += 1
        shared_view.last_accessed = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'success': True,
            'shared_view': shared_view.to_dict()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@shared_views_bp.route('/list', methods=['GET'])
@login_required
def list_shared_views():
    """
    List all shared views created by the current user
    """
    try:
        current_user_id = session.get('user_id')

        shared_views = SharedView.query.filter_by(
            created_by=current_user_id,
            is_active=True
        ).order_by(SharedView.created_at.desc()).all()

        return jsonify({
            'success': True,
            'shared_views': [sv.to_dict() for sv in shared_views]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@shared_views_bp.route('/delete/<int:view_id>', methods=['DELETE'])
@login_required
def delete_shared_view(view_id):
    """
    Delete (deactivate) a shared view
    Only the creator can delete their own shared views
    """
    try:
        current_user_id = session.get('user_id')

        shared_view = SharedView.query.filter_by(
            id=view_id,
            created_by=current_user_id
        ).first()

        if not shared_view:
            return jsonify({'error': 'Shared view not found or you do not have permission'}), 404

        # Soft delete
        shared_view.is_active = False
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Shared view deleted successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
