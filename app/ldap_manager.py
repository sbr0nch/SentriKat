"""
LDAP User Discovery and Management
Handles LDAP user search, group discovery, and synchronization
"""

from app.models import SystemSettings, User, Organization
from app import db
import logging

logger = logging.getLogger(__name__)


def _parse_ldap_server(server_str):
    """Parse LDAP server URL, handling ldap://, ldaps://, and bare hostname formats.

    Returns (hostname, use_ssl) tuple. Port is handled separately from settings.
    Strips protocol prefix to avoid double-protocol issues with ldap3.Server().
    """
    if not server_str:
        return '', False
    server_str = server_str.strip()
    use_ssl = False
    if server_str.startswith('ldaps://'):
        use_ssl = True
        server_str = server_str[len('ldaps://'):]
    elif server_str.startswith('ldap://'):
        server_str = server_str[len('ldap://'):]
    # Strip any trailing port (e.g. "host:389" -> "host"), port comes from settings
    hostname = server_str.split(':')[0].strip('/')
    return hostname, use_ssl


class LDAPManager:
    """Manages LDAP user discovery and synchronization"""

    @staticmethod
    def get_ldap_config():
        """Get LDAP configuration from system settings with automatic decryption"""
        # Use centralized get_setting that handles decryption
        from app.settings_api import get_setting

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
            server_host, use_ssl = _parse_ldap_server(config['server'])
            if not server_host:
                return {'success': False, 'error': 'LDAP server URL is empty'}

            # Create server and connection
            server = ldap3.Server(server_host, port=config['port'], use_ssl=use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=config['bind_dn'], password=config['bind_password'], auto_bind=True)

            # Build search filter
            if search_query and search_query != '*':
                # Search for users matching the query - use configured username attribute
                username_attr = config['username_attr']
                # Escape LDAP special characters to prevent LDAP injection
                from ldap3.utils.conv import escape_filter_chars
                safe_query = escape_filter_chars(search_query)
                search_filter = f"(&(objectClass=person)(|(cn=*{safe_query}*)(mail=*{safe_query}*)({username_attr}=*{safe_query}*)))"
            else:
                # Get all users
                search_filter = "(objectClass=person)"

            # Search LDAP with paged search to handle large directories
            # Active Directory often limits results - use paged search to bypass
            # Try with memberOf first (AD), fall back without it (OpenLDAP without overlay)
            base_attrs = [config['username_attr'], config['email_attr'], 'cn', 'displayName']
            search_attrs = base_attrs + ['memberOf']
            _memberof_supported = True

            def _do_search(attrs, **kwargs):
                """Execute search, retry without memberOf if unsupported."""
                nonlocal _memberof_supported, search_attrs
                try:
                    result = conn.search(
                        search_base=config['base_dn'],
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attrs,
                        **kwargs
                    )
                    # Check conn.result for errors (ldap3 may not raise with raise_exceptions=False)
                    result_desc = conn.result.get('description', '') if conn.result else ''
                    if 'memberOf' in result_desc or 'undefined' in result_desc.lower():
                        raise ldap3.core.exceptions.LDAPAttributeError(result_desc)
                    return result
                except Exception as e:
                    if _memberof_supported and ('memberOf' in str(e) or 'attribute' in str(e).lower()):
                        logger.info("LDAP server does not support memberOf attribute, searching without it")
                        _memberof_supported = False
                        search_attrs = base_attrs
                        return conn.search(
                            search_base=config['base_dn'],
                            search_filter=search_filter,
                            search_scope=ldap3.SUBTREE,
                            attributes=base_attrs,
                            **kwargs
                        )
                    raise

            _do_search(search_attrs, paged_size=500, size_limit=0)

            users = []
            # Collect all results from paged search
            all_entries = list(conn.entries)

            # Handle paged results - continue fetching if there are more pages
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
            while cookie:
                conn.search(
                    search_base=config['base_dn'],
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=search_attrs,
                    paged_size=500,
                    paged_cookie=cookie
                )
                all_entries.extend(conn.entries)
                cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                # Stop if we've reached max_results
                if max_results > 0 and len(all_entries) >= max_results:
                    all_entries = all_entries[:max_results]
                    break

            for entry in all_entries:
                try:
                    username = str(entry[config['username_attr']].value) if entry[config['username_attr']] else None
                    email = str(entry[config['email_attr']].value) if entry[config['email_attr']] else None
                    full_name = str(entry.displayName.value) if entry.displayName else str(entry.cn.value) if entry.cn else None
                    dn = str(entry.entry_dn)

                    # Get groups (memberOf may not be available on OpenLDAP)
                    groups = []
                    if hasattr(entry, 'memberOf') and entry.memberOf:
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
            server_host, use_ssl = _parse_ldap_server(config['server'])
            if not server_host:
                return {'success': False, 'error': 'LDAP server URL is empty'}

            # Create server and connection
            server = ldap3.Server(server_host, port=config['port'], use_ssl=use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=config['bind_dn'], password=config['bind_password'], auto_bind=True)

            # Search for user - try with memberOf (AD), fall back without it (OpenLDAP)
            search_filter = config['search_filter'].replace('{username}', username)
            memberof_ok = True
            try:
                conn.search(
                    search_base=config['base_dn'],
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=['memberOf', 'cn']
                )
                result_desc = conn.result.get('description', '') if conn.result else ''
                if 'memberOf' in result_desc or 'undefined' in result_desc.lower():
                    raise Exception(result_desc)
            except Exception as member_err:
                if 'memberOf' in str(member_err) or 'attribute' in str(member_err).lower():
                    logger.info("LDAP server does not support memberOf, searching without it")
                    memberof_ok = False
                    conn.search(
                        search_base=config['base_dn'],
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=['cn']
                    )
                else:
                    raise

            if not conn.entries:
                return {'success': False, 'error': f'User {username} not found in LDAP'}

            entry = conn.entries[0]
            groups = []

            if hasattr(entry, 'memberOf') and entry.memberOf:
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
            # Check if user already exists by username
            existing_user = User.query.filter_by(username=username).first()

            # Also check by email (different username but same email)
            if not existing_user:
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    # User exists with different username but same email
                    if not existing_user.is_active:
                        # Reactivate and update username
                        old_state = {
                            'is_active': False,
                            'username': existing_user.username,
                            'organization_id': existing_user.organization_id,
                            'role': existing_user.role
                        }

                        existing_user.username = username
                        existing_user.is_active = True
                        existing_user.organization_id = organization_id
                        existing_user.role = role
                        existing_user.ldap_dn = dn
                        existing_user.full_name = full_name
                        db.session.commit()

                        log_audit_event(
                            'REACTIVATE',
                            'users',
                            existing_user.id,
                            old_value=old_state,
                            new_value={
                                'is_active': True,
                                'username': username,
                                'organization_id': organization_id,
                                'role': role
                            },
                            details=f"Reactivated LDAP user {username} (email: {email})"
                        )

                        log_ldap_operation('USER_REACTIVATE', f"{username} reactivated (email match)", True)

                        # Send welcome email
                        email_sent = False
                        email_details = None
                        try:
                            email_sent, email_details = send_user_invite_email(existing_user)
                        except Exception as email_error:
                            email_details = str(email_error)
                            logger.warning(f"Failed to send invite email to {email}: {email_error}")

                        result_message = f'User {username} reactivated (matched by email)'
                        if email_sent:
                            result_message += f' ({email_details})'
                        elif email_details:
                            result_message += f' (email failed: {email_details})'

                        return {'success': True, 'message': result_message, 'user': existing_user.to_dict(), 'email_sent': email_sent}
                    else:
                        return {'success': False, 'error': f'Email {email} is already used by another active user ({existing_user.username})'}

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
                    # User is active - check if they're already in the target organization
                    if existing_user.organization_id == organization_id:
                        return {'success': False, 'error': f'User {username} already exists in this organization'}
                    elif existing_user.has_access_to_org(organization_id):
                        return {'success': False, 'error': f'User {username} already has access to this organization'}
                    else:
                        # Add user to the new organization as secondary membership
                        from flask import session
                        current_user_id = session.get('user_id')
                        existing_user.add_to_organization(organization_id, role, current_user_id)
                        db.session.commit()

                        log_audit_event(
                            'ADD_ORG_MEMBERSHIP',
                            'users',
                            existing_user.id,
                            new_value={'organization_id': organization_id, 'role': role},
                            details=f"Added {username} to organization via LDAP invite"
                        )

                        return {
                            'success': True,
                            'message': f'User {username} already exists. Added to organization with role: {role}',
                            'user': existing_user.to_dict(),
                            'added_to_org': True
                        }

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
            server_host, use_ssl = _parse_ldap_server(config['server'])
            if not server_host:
                return {'success': False, 'error': 'LDAP server URL is empty'}
            # Use SSL from URL prefix (ldaps://) or fall back to TLS setting
            server = Server(server_host, port=config['port'], get_info=ALL, use_ssl=use_ssl or config['use_tls'])
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
                attributes=['cn', 'distinguishedName', 'description', 'member']
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

    @staticmethod
    def get_group_members(group_dn):
        """
        Get members of a specific LDAP group by its DN.

        Args:
            group_dn: Distinguished Name of the LDAP group

        Returns:
            dict with 'success' and either 'members' or 'error'
        """
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, SUBTREE

            config = LDAPManager.get_ldap_config()

            if not config['enabled']:
                return {'success': False, 'error': 'LDAP is not enabled'}

            if not config['server'] or not config['bind_dn'] or not config['bind_password']:
                return {'success': False, 'error': 'LDAP not fully configured'}

            server_host, use_ssl = _parse_ldap_server(config['server'])
            if not server_host:
                return {'success': False, 'error': 'LDAP server URL is empty'}

            server = Server(server_host, port=config['port'], get_info=ALL, use_ssl=use_ssl or config['use_tls'])
            conn = Connection(
                server,
                user=config['bind_dn'],
                password=config['bind_password'],
                auto_bind=True
            )

            # Read the group entry to get its member attribute
            conn.search(
                search_base=group_dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['member', 'cn']
            )

            if not conn.entries:
                conn.unbind()
                return {'success': False, 'error': f'Group not found: {group_dn}'}

            entry = conn.entries[0]
            members = []

            if hasattr(entry, 'member') and entry.member:
                member_dns = entry.member.values if hasattr(entry.member, 'values') else (
                    entry.member.value if isinstance(entry.member.value, list) else [entry.member.value]
                )

                for member_dn in member_dns:
                    member_dn = str(member_dn)
                    # Look up each member to get their attributes
                    try:
                        conn.search(
                            search_base=member_dn,
                            search_filter='(objectClass=person)',
                            search_scope=ldap3.BASE,
                            attributes=[config['username_attr'], config['email_attr'], 'cn', 'displayName']
                        )
                        if conn.entries:
                            m = conn.entries[0]
                            username = str(m[config['username_attr']].value) if hasattr(m, config['username_attr']) and m[config['username_attr']] else None
                            email = str(m[config['email_attr']].value) if hasattr(m, config['email_attr']) and m[config['email_attr']] else None
                            display = str(m.displayName.value) if hasattr(m, 'displayName') and m.displayName else str(m.cn.value) if hasattr(m, 'cn') and m.cn else member_dn

                            members.append({
                                'dn': member_dn,
                                'username': username,
                                'email': email,
                                'display_name': display
                            })
                    except Exception:
                        # Member DN might be a nested group or deleted entry
                        members.append({
                            'dn': member_dn,
                            'username': None,
                            'email': None,
                            'display_name': member_dn
                        })

            conn.unbind()

            return {
                'success': True,
                'members': members,
                'count': len(members)
            }

        except Exception as e:
            logger.error(f"Error getting group members: {e}")
            return {'success': False, 'error': str(e)}
