"""
Enterprise LDAP Group Synchronization Engine
Handles automatic user provisioning, role assignment, and group sync
"""

from app import db
from app.models import User, Organization
from app.ldap_models import LDAPGroupMapping, LDAPSyncLog, LDAPAuditLog
from app.ldap_manager import LDAPManager
from datetime import datetime
import uuid
import json
import logging

logger = logging.getLogger(__name__)


class LDAPSyncEngine:
    """Enterprise LDAP synchronization engine"""

    @staticmethod
    def sync_user_from_ldap(user, ldap_groups=None, sync_id=None, initiated_by=None):
        """
        Sync a user's role and organization based on LDAP group memberships

        Args:
            user: User object to sync
            ldap_groups: List of LDAP group DNs (fetches if not provided)
            sync_id: Batch sync identifier for logging
            initiated_by: User ID who initiated sync (for audit)

        Returns:
            dict: {success: bool, changes: list, role: str, errors: list}
        """
        if not sync_id:
            sync_id = str(uuid.uuid4())[:8]

        changes = []
        errors = []

        try:
            # Get user's LDAP groups if not provided
            if not ldap_groups:
                result = LDAPManager.get_user_groups(user.username)
                if not result['success']:
                    error_msg = f"Failed to get LDAP groups: {result.get('error', 'Unknown error')}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    return {'success': False, 'error': error_msg, 'changes': [], 'errors': errors}
                ldap_groups = result['groups']

            # Find all active mappings that match user's LDAP groups
            mappings = LDAPGroupMapping.query.filter(
                LDAPGroupMapping.ldap_group_dn.in_(ldap_groups),
                LDAPGroupMapping.is_active == True,
                LDAPGroupMapping.sync_enabled == True
            ).order_by(LDAPGroupMapping.priority.desc()).all()

            if not mappings:
                # No mappings found - log but don't error
                logger.info(f"No group mappings found for user {user.username}")
                return {
                    'success': True,
                    'message': 'No group mappings found',
                    'changes': [],
                    'role': user.role,
                    'errors': []
                }

            # Determine highest priority role
            # Role hierarchy: super_admin > org_admin > manager > user
            role_priority = {'super_admin': 4, 'org_admin': 3, 'manager': 2, 'user': 1}

            highest_mapping = max(mappings, key=lambda m: (
                role_priority.get(m.role, 0),
                m.priority
            ))

            # Update role if changed
            old_role = user.role
            if user.role != highest_mapping.role:
                user.role = highest_mapping.role
                changes.append(f"Role: {old_role} → {highest_mapping.role}")

                # Log audit event
                audit_log = LDAPAuditLog(
                    sync_id=sync_id,
                    event_type='role_changed',
                    user_id=initiated_by,
                    target_user_id=user.id,
                    organization_id=user.organization_id,
                    ldap_groups=json.dumps(ldap_groups),
                    field_changed='role',
                    old_value=old_role,
                    new_value=highest_mapping.role,
                    description=f"Role updated via LDAP group: {highest_mapping.ldap_group_cn}",
                    success=True
                )
                db.session.add(audit_log)

            # Handle organization assignment
            # If user is super_admin, can access all orgs - no specific org needed
            # Otherwise, assign to org from highest priority mapping
            if user.role != 'super_admin':
                org_mappings = [m for m in mappings if m.organization_id]
                if org_mappings:
                    # Get highest priority org mapping
                    org_mapping = max(org_mappings, key=lambda m: (
                        role_priority.get(m.role, 0),
                        m.priority
                    ))

                    old_org_id = user.organization_id
                    if user.organization_id != org_mapping.organization_id:
                        user.organization_id = org_mapping.organization_id
                        old_org_name = Organization.query.get(old_org_id).display_name if old_org_id else 'None'
                        new_org_name = org_mapping.organization.display_name
                        changes.append(f"Organization: {old_org_name} → {new_org_name}")

                        # Log audit event
                        audit_log = LDAPAuditLog(
                            sync_id=sync_id,
                            event_type='user_updated',
                            user_id=initiated_by,
                            target_user_id=user.id,
                            organization_id=user.organization_id,
                            field_changed='organization_id',
                            old_value=str(old_org_id),
                            new_value=str(org_mapping.organization_id),
                            description=f"Organization updated via LDAP group: {org_mapping.ldap_group_cn}",
                            success=True
                        )
                        db.session.add(audit_log)

            # Ensure user is active (reactivate if was deactivated)
            if not user.is_active:
                user.is_active = True
                changes.append("Status: Inactive → Active (reactivated)")

                audit_log = LDAPAuditLog(
                    sync_id=sync_id,
                    event_type='user_reactivated',
                    user_id=initiated_by,
                    target_user_id=user.id,
                    organization_id=user.organization_id,
                    ldap_groups=json.dumps(ldap_groups),
                    description=f"User reactivated via LDAP sync",
                    success=True
                )
                db.session.add(audit_log)

            db.session.commit()

            return {
                'success': True,
                'changes': changes,
                'role': user.role,
                'organization_id': user.organization_id,
                'errors': errors
            }

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error syncing user {user.username}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)

            # Log failed audit event
            try:
                audit_log = LDAPAuditLog(
                    sync_id=sync_id,
                    event_type='sync_failed',
                    user_id=initiated_by,
                    target_user_id=user.id,
                    error_message=error_msg,
                    success=False
                )
                db.session.add(audit_log)
                db.session.commit()
            except Exception:
                pass

            return {
                'success': False,
                'error': error_msg,
                'changes': changes,
                'errors': errors
            }

    @staticmethod
    def _handle_auto_deprovisioning(ldap_users, organization_id=None, sync_id=None, initiated_by=None):
        """
        Handle auto-deprovisioning of users who no longer belong to any LDAP groups
        with auto_deprovision enabled.

        Args:
            ldap_users: List of LDAP User objects that were synced
            organization_id: Organization ID filter (or None for all)
            sync_id: Sync ID for audit logging
            initiated_by: User ID who initiated sync

        Returns:
            int: Number of users deprovisioned
        """
        deprovisioned_count = 0

        # Get all mappings with auto_deprovision enabled
        deprovision_mappings = LDAPGroupMapping.query.filter(
            LDAPGroupMapping.auto_deprovision == True,
            LDAPGroupMapping.is_active == True,
            LDAPGroupMapping.sync_enabled == True
        )

        if organization_id:
            deprovision_mappings = deprovision_mappings.filter(
                LDAPGroupMapping.organization_id == organization_id
            )

        deprovision_mappings = deprovision_mappings.all()

        if not deprovision_mappings:
            logger.debug("No auto-deprovision mappings configured")
            return 0

        # Get the LDAP group DNs that have auto_deprovision enabled
        deprovision_groups = {m.ldap_group_dn for m in deprovision_mappings}

        logger.info(f"Checking {len(ldap_users)} users against {len(deprovision_groups)} auto-deprovision groups")

        for user in ldap_users:
            if not user.is_active:
                continue  # Already deactivated

            try:
                # Get user's current LDAP groups
                result = LDAPManager.get_user_groups(user.username)

                if not result['success']:
                    logger.warning(f"Could not get LDAP groups for {user.username}: {result.get('error')}")
                    continue

                user_groups = set(result['groups'])

                # Check if user was previously in any auto-deprovision group
                # by checking their organization assignment matches a deprovision mapping
                user_org_deprovision_mappings = [
                    m for m in deprovision_mappings
                    if m.organization_id == user.organization_id
                ]

                if not user_org_deprovision_mappings:
                    continue  # User's org doesn't have deprovision mappings

                # Get the groups for user's org that have auto_deprovision
                org_deprovision_groups = {m.ldap_group_dn for m in user_org_deprovision_mappings}

                # Check if user is NO LONGER in ANY of the deprovision groups
                # but is still assigned to this organization (meaning they were removed)
                user_in_deprovision_groups = user_groups.intersection(org_deprovision_groups)

                # Also check if they have ANY active mapping
                any_active_mapping = LDAPGroupMapping.query.filter(
                    LDAPGroupMapping.ldap_group_dn.in_(user_groups),
                    LDAPGroupMapping.is_active == True,
                    LDAPGroupMapping.sync_enabled == True
                ).first()

                # Deprovision if:
                # 1. User is not in any deprovision groups for their org, AND
                # 2. User has no other active mappings
                if not user_in_deprovision_groups and not any_active_mapping:
                    # Deactivate user
                    user.is_active = False
                    deprovisioned_count += 1

                    logger.info(f"Auto-deprovisioned user {user.username} - no longer in required LDAP groups")

                    # Log audit event
                    audit_log = LDAPAuditLog(
                        sync_id=sync_id,
                        event_type='user_deprovisioned',
                        user_id=initiated_by,
                        target_user_id=user.id,
                        organization_id=user.organization_id,
                        ldap_groups=json.dumps(list(user_groups)),
                        field_changed='is_active',
                        old_value='True',
                        new_value='False',
                        description=f"User auto-deprovisioned - removed from all mapped LDAP groups",
                        success=True
                    )
                    db.session.add(audit_log)

            except Exception as e:
                logger.error(f"Error checking deprovision for user {user.username}: {str(e)}")
                continue

        if deprovisioned_count > 0:
            db.session.commit()
            logger.info(f"Auto-deprovisioned {deprovisioned_count} users")

        return deprovisioned_count

    @staticmethod
    def sync_all_ldap_users(organization_id=None, initiated_by=None):
        """
        Sync all LDAP users in system or specific organization

        Args:
            organization_id: Limit to specific organization (None = all)
            initiated_by: User ID who initiated sync

        Returns:
            dict: Sync statistics and results
        """
        sync_id = str(uuid.uuid4())[:8]
        start_time = datetime.utcnow()

        stats = {
            'users_updated': 0,
            'users_deactivated': 0,
            'roles_changed': 0,
            'errors': [],
            'ldap_queries': 0
        }

        try:
            # Get all active LDAP users
            query = User.query.filter_by(auth_type='ldap', is_active=True)
            if organization_id:
                query = query.filter_by(organization_id=organization_id)

            ldap_users = query.all()
            total_users = len(ldap_users)

            logger.info(f"Starting LDAP sync {sync_id} for {total_users} users")

            # Sync each user
            for user in ldap_users:
                try:
                    result = LDAPSyncEngine.sync_user_from_ldap(
                        user,
                        sync_id=sync_id,
                        initiated_by=initiated_by
                    )

                    stats['ldap_queries'] += 1

                    if result['success']:
                        if result['changes']:
                            stats['users_updated'] += 1
                            if any('Role:' in c for c in result['changes']):
                                stats['roles_changed'] += 1
                    else:
                        stats['errors'].append({
                            'user': user.username,
                            'error': result.get('error', 'Unknown error')
                        })

                except Exception as e:
                    error_msg = f"Error syncing user {user.username}: {str(e)}"
                    logger.error(error_msg)
                    stats['errors'].append({
                        'user': user.username,
                        'error': error_msg
                    })

            # Handle deprovisioning (users removed from all groups)
            deprovisioned_count = LDAPSyncEngine._handle_auto_deprovisioning(
                ldap_users=ldap_users,
                organization_id=organization_id,
                sync_id=sync_id,
                initiated_by=initiated_by
            )
            stats['users_deactivated'] = deprovisioned_count

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()

            # Create sync log
            sync_log = LDAPSyncLog(
                sync_id=sync_id,
                sync_type='manual_sync' if initiated_by else 'scheduled_sync',
                organization_id=organization_id,
                initiated_by=initiated_by,
                status='success' if not stats['errors'] else ('partial' if stats['users_updated'] > 0 else 'failed'),
                users_updated=stats['users_updated'],
                users_deactivated=stats['users_deactivated'],
                roles_changed=stats['roles_changed'],
                users_processed=total_users,
                duration_seconds=duration,
                ldap_queries=stats['ldap_queries'],
                errors=json.dumps(stats['errors']) if stats['errors'] else None,
                summary=f"Processed {total_users} users, updated {stats['users_updated']}, {len(stats['errors'])} errors"
            )
            db.session.add(sync_log)
            db.session.commit()

            logger.info(f"Completed LDAP sync {sync_id}: {stats['users_updated']} updated, {len(stats['errors'])} errors")

            return {
                'success': True,
                'sync_id': sync_id,
                'stats': stats,
                'duration': duration,
                'total_users': total_users
            }

        except Exception as e:
            db.session.rollback()
            error_msg = f"Fatal error during LDAP sync: {str(e)}"
            logger.error(error_msg)

            # Log failed sync
            try:
                sync_log = LDAPSyncLog(
                    sync_id=sync_id,
                    sync_type='manual_sync' if initiated_by else 'scheduled_sync',
                    organization_id=organization_id,
                    initiated_by=initiated_by,
                    status='failed',
                    duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                    error_message=error_msg
                )
                db.session.add(sync_log)
                db.session.commit()
            except Exception:
                pass

            return {
                'success': False,
                'error': error_msg,
                'stats': stats
            }

    @staticmethod
    def auto_provision_user_on_login(username, ldap_groups):
        """
        Automatically create user account when they login if they match auto-provision rules

        Args:
            username: LDAP username
            ldap_groups: List of LDAP group DNs user belongs to

        Returns:
            dict: {success: bool, user: User|None, created: bool, error: str}
        """
        try:
            # Find mappings that allow auto-provisioning
            mappings = LDAPGroupMapping.query.filter(
                LDAPGroupMapping.ldap_group_dn.in_(ldap_groups),
                LDAPGroupMapping.is_active == True,
                LDAPGroupMapping.auto_provision == True
            ).order_by(LDAPGroupMapping.priority.desc()).all()

            if not mappings:
                return {
                    'success': False,
                    'error': 'No auto-provision rules match your LDAP groups',
                    'user': None,
                    'created': False
                }

            # Get user info from LDAP
            ldap_result = LDAPManager.search_users(username, max_results=1)
            if not ldap_result['success'] or not ldap_result['users']:
                return {
                    'success': False,
                    'error': 'User not found in LDAP directory',
                    'user': None,
                    'created': False
                }

            ldap_user_data = ldap_result['users'][0]

            # Determine role and organization from highest priority mapping
            role_priority = {'super_admin': 4, 'org_admin': 3, 'manager': 2, 'user': 1}
            highest_mapping = max(mappings, key=lambda m: (
                role_priority.get(m.role, 0),
                m.priority
            ))

            # Create user
            user = User(
                username=username,
                email=ldap_user_data['email'],
                full_name=ldap_user_data.get('full_name'),
                auth_type='ldap',
                ldap_dn=ldap_user_data['dn'],
                role=highest_mapping.role,
                organization_id=highest_mapping.organization_id,
                is_admin=(highest_mapping.role in ['super_admin', 'org_admin']),
                can_manage_products=True,
                is_active=True
            )

            db.session.add(user)

            # Log audit event
            audit_log = LDAPAuditLog(
                event_type='user_created',
                target_user_id=user.id,
                organization_id=user.organization_id,
                ldap_dn=ldap_user_data['dn'],
                ldap_groups=json.dumps(ldap_groups),
                description=f"User auto-provisioned via LDAP group: {highest_mapping.ldap_group_cn}",
                success=True
            )
            db.session.add(audit_log)

            db.session.commit()

            logger.info(f"Auto-provisioned user {username} with role {highest_mapping.role}")

            return {
                'success': True,
                'user': user,
                'created': True,
                'role': highest_mapping.role
            }

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error auto-provisioning user {username}: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'user': None,
                'created': False
            }
