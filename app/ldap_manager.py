"""
LDAP User Discovery and Management
Handles LDAP user search, group discovery, and synchronization
"""

from app.models import SystemSettings, User, Organization
from app import db
import logging

logger = logging.getLogger(__name__)


class LDAPManager:
    """Manages LDAP user discovery and synchronization"""

    @staticmethod
    def get_ldap_config():
        """Get LDAP configuration from system settings"""
        def get_setting(key, default=None):
            setting = SystemSettings.query.filter_by(key=key).first()
            return setting.value if setting else default

        return {
            'enabled': get_setting('ldap_enabled', 'false') == 'true',
            'server': get_setting('ldap_server'),
            'port': int(get_setting('ldap_port', '389')),
            'base_dn': get_setting('ldap_base_dn'),
            'bind_dn': get_setting('ldap_bind_dn'),
            'bind_password': get_setting('ldap_bind_password'),
            'search_filter': get_setting('ldap_search_filter', '(sAMAccountName={username})'),
            'username_attr': get_setting('ldap_username_attr', 'sAMAccountName'),
            'email_attr': get_setting('ldap_email_attr', 'mail'),
            'use_tls': get_setting('ldap_use_tls', 'false') == 'true'
        }

    @staticmethod
    def search_users(search_query='*', max_results=50):
        """
        Search LDAP directory for users

        Args:
            search_query: Search term (defaults to all users)
            max_results: Maximum number of results to return

        Returns:
            dict with 'success' and either 'users' or 'error'
        """
        try:
            import ldap3

            config = LDAPManager.get_ldap_config()

            if not config['enabled']:
                return {'success': False, 'error': 'LDAP is not enabled'}

            if not config['server'] or not config['bind_dn'] or not config['bind_password']:
                return {'success': False, 'error': 'LDAP not fully configured'}

            # Parse server URL
            server_url = config['server'].replace('ldap://', '').replace('ldaps://', '').split(':')[0]
            use_ssl = 'ldaps://' in config['server']

            # Create server and connection
            server = ldap3.Server(server_url, port=config['port'], use_ssl=use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=config['bind_dn'], password=config['bind_password'], auto_bind=True)

            # Build search filter
            if search_query and search_query != '*':
                # Search for users matching the query - use configured username attribute
                username_attr = config['username_attr']
                search_filter = f"(&(objectClass=person)(|(cn=*{search_query}*)(mail=*{search_query}*)({username_attr}=*{search_query}*)))"
            else:
                # Get all users
                search_filter = "(objectClass=person)"

            # Search LDAP
            conn.search(
                search_base=config['base_dn'],
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=[config['username_attr'], config['email_attr'], 'cn', 'displayName', 'memberOf'],
                size_limit=max_results
            )

            users = []
            for entry in conn.entries:
                try:
                    username = str(entry[config['username_attr']].value) if entry[config['username_attr']] else None
                    email = str(entry[config['email_attr']].value) if entry[config['email_attr']] else None
                    full_name = str(entry.displayName.value) if entry.displayName else str(entry.cn.value) if entry.cn else None
                    dn = str(entry.entry_dn)

                    # Get groups
                    groups = []
                    if entry.memberOf:
                        if isinstance(entry.memberOf.value, list):
                            groups = [str(g) for g in entry.memberOf.value]
                        else:
                            groups = [str(entry.memberOf.value)]

                    # Check if user already exists in database
                    existing_user = User.query.filter_by(username=username).first() if username else None

                    if username and email:
                        users.append({
                            'username': username,
                            'email': email,
                            'full_name': full_name,
                            'dn': dn,
                            'groups': groups,
                            'exists_in_db': existing_user is not None,
                            'is_active': existing_user.is_active if existing_user else None,
                            'organization': existing_user.organization.display_name if existing_user and existing_user.organization else None
                        })
                except Exception as e:
                    logger.warning(f"Error processing LDAP entry: {e}")
                    continue

            conn.unbind()

            return {
                'success': True,
                'users': users,
                'count': len(users)
            }

        except ImportError:
            return {'success': False, 'error': 'ldap3 library not installed. Run: pip install ldap3'}
        except Exception as e:
            logger.error(f"LDAP search error: {e}")
            return {'success': False, 'error': str(e)}

    @staticmethod
    def get_user_groups(username):
        """
        Get LDAP groups for a specific user

        Args:
            username: Username to search for

        Returns:
            dict with 'success' and either 'groups' or 'error'
        """
        try:
            import ldap3

            config = LDAPManager.get_ldap_config()

            if not config['enabled']:
                return {'success': False, 'error': 'LDAP is not enabled'}

            # Parse server URL
            server_url = config['server'].replace('ldap://', '').replace('ldaps://', '').split(':')[0]
            use_ssl = 'ldaps://' in config['server']

            # Create server and connection
            server = ldap3.Server(server_url, port=config['port'], use_ssl=use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=config['bind_dn'], password=config['bind_password'], auto_bind=True)

            # Search for user
            search_filter = config['search_filter'].replace('{username}', username)
            conn.search(
                search_base=config['base_dn'],
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['memberOf', 'cn']
            )

            if not conn.entries:
                return {'success': False, 'error': f'User {username} not found in LDAP'}

            entry = conn.entries[0]
            groups = []

            if entry.memberOf:
                if isinstance(entry.memberOf.value, list):
                    groups = [str(g) for g in entry.memberOf.value]
                else:
                    groups = [str(entry.memberOf.value)]

            conn.unbind()

            return {
                'success': True,
                'groups': groups,
                'count': len(groups)
            }

        except Exception as e:
            logger.error(f"LDAP group search error: {e}")
            return {'success': False, 'error': str(e)}

    @staticmethod
    def invite_ldap_user(username, email, full_name, dn, organization_id, role='user'):
        """
        Create/invite an LDAP user to the system

        Args:
            username: LDAP username
            email: User email
            full_name: User's full name
            dn: LDAP distinguished name
            organization_id: Organization to assign user to
            role: User role (default: user)

        Returns:
            dict with 'success' and either 'user' or 'error'
        """
        from app.logging_config import log_audit_event, log_ldap_operation
        from app.email_alerts import send_user_invite_email

        try:
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                # Reactivate if inactive
                if not existing_user.is_active:
                    old_state = {
                        'is_active': False,
                        'organization_id': existing_user.organization_id,
                        'role': existing_user.role
                    }

                    existing_user.is_active = True
                    existing_user.organization_id = organization_id
                    existing_user.role = role
                    db.session.commit()

                    # Log audit event
                    log_audit_event(
                        'REACTIVATE',
                        'users',
                        existing_user.id,
                        old_value=old_state,
                        new_value={
                            'is_active': True,
                            'organization_id': organization_id,
                            'role': role
                        },
                        details=f"Reactivated LDAP user {username}"
                    )

                    log_ldap_operation('USER_REACTIVATE', f"{username} reactivated and invited", True)

                    # Send welcome email
                    email_sent = False
                    email_details = None
                    try:
                        email_sent, email_details = send_user_invite_email(existing_user)
                    except Exception as email_error:
                        email_details = str(email_error)
                        logger.warning(f"Failed to send invite email to {email}: {email_error}")

                    result_message = f'User {username} reactivated'
                    if email_sent:
                        result_message += f' ({email_details})'
                    elif email_details:
                        result_message += f' (email failed: {email_details})'
                    else:
                        result_message += ' (no email sent - SMTP not configured)'

                    return {'success': True, 'message': result_message, 'user': existing_user.to_dict(), 'email_sent': email_sent}
                else:
                    return {'success': False, 'error': f'User {username} already exists and is active'}

            # Create new LDAP user
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                organization_id=organization_id,
                auth_type='ldap',
                ldap_dn=dn,
                role=role,
                is_active=True,
                can_manage_products=role in ['manager', 'org_admin', 'super_admin']
            )

            db.session.add(user)
            db.session.commit()

            # Log audit event
            log_audit_event(
                'INVITE',
                'users',
                user.id,
                new_value={
                    'username': username,
                    'email': email,
                    'role': role,
                    'organization_id': organization_id,
                    'auth_type': 'ldap'
                },
                details=f"Invited LDAP user {username}"
            )

            log_ldap_operation('USER_INVITE', f"{username} invited to organization {organization_id}", True)

            # Send welcome email
            email_sent = False
            email_details = None
            try:
                email_sent, email_details = send_user_invite_email(user)
            except Exception as email_error:
                email_details = str(email_error)
                logger.warning(f"Failed to send invite email to {email}: {email_error}")

            result_message = f'User {username} invited successfully'
            if email_sent:
                result_message += f' ({email_details})'
            elif email_details:
                result_message += f' (email failed: {email_details})'
            else:
                result_message += ' (no email sent - SMTP not configured)'

            return {'success': True, 'message': result_message, 'user': user.to_dict(), 'email_sent': email_sent}

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error inviting LDAP user: {e}")
            log_ldap_operation('USER_INVITE', f"Failed to invite {username}: {str(e)}", False)
            return {'success': False, 'error': str(e)}

    @staticmethod
    def sync_user_groups(user_id):
        """
        Synchronize user's LDAP groups

        Args:
            user_id: User ID to sync

        Returns:
            dict with 'success' and either 'groups' or 'error'
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return {'success': False, 'error': 'User not found'}

            if user.auth_type != 'ldap':
                return {'success': False, 'error': 'User is not an LDAP user'}

            # Get user's current groups from LDAP
            result = LDAPManager.get_user_groups(user.username)

            if not result['success']:
                return result

            return {
                'success': True,
                'groups': result['groups'],
                'count': result['count']
            }

        except Exception as e:
            logger.error(f"Error syncing user groups: {e}")
            return {'success': False, 'error': str(e)}

    @staticmethod
    def search_groups(search_base='', search_filter='(objectClass=group)'):
        """
        Search LDAP directory for groups

        Args:
            search_base: Base DN to search from (e.g., 'OU=Groups,DC=company,DC=com')
            search_filter: LDAP filter for groups (default: all groups)

        Returns:
            dict with 'success' and either 'groups' or 'error'
        """
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SUBTREE

            config = LDAPManager.get_ldap_config()

            if not config['enabled']:
                return {'success': False, 'error': 'LDAP is not enabled'}

            # Use provided search_base or fall back to base_dn
            base_dn = search_base if search_base else config['base_dn']

            # Connect to LDAP
            server = Server(config['server'], port=config['port'], get_info=ALL, use_ssl=config['use_tls'])
            conn = Connection(
                server,
                user=config['bind_dn'],
                password=config['bind_password'],
                auto_bind=True
            )

            # Search for groups
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['cn', 'distinguishedName', 'description', 'member', 'memberOf']
            )

            groups = []
            for entry in conn.entries:
                group_data = {
                    'dn': str(entry.distinguishedName) if hasattr(entry, 'distinguishedName') else str(entry.entry_dn),
                    'cn': str(entry.cn) if hasattr(entry, 'cn') else '',
                    'description': str(entry.description) if hasattr(entry, 'description') else '',
                    'member_count': len(entry.member) if hasattr(entry, 'member') and entry.member else 0
                }
                groups.append(group_data)

            conn.unbind()

            return {
                'success': True,
                'groups': groups,
                'count': len(groups)
            }

        except Exception as e:
            logger.error(f"Error searching LDAP groups: {e}")
            return {'success': False, 'error': str(e)}
