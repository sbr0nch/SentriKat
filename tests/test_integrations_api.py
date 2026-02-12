"""
Tests for integrations API multi-tenant isolation and error handling.
Verifies fixes for cross-org data leaks, org permission checks, and race conditions.
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import session


def make_professional_license():
    """Create a mock professional license."""
    mock_license = MagicMock()
    mock_license.is_professional.return_value = True
    mock_license.get_effective_edition.return_value = 'professional'
    mock_license.get_effective_limits.return_value = {
        'max_products': -1,
        'max_integrations': -1,
        'max_agent_api_keys': -1,
    }
    mock_license.features = ['push_agents', 'Integrations']
    mock_license.has_feature.return_value = True
    return mock_license


@pytest.fixture
def pro_license():
    """Patch licensing to always return professional."""
    mock_license = make_professional_license()
    with patch('app.licensing.get_license', return_value=mock_license):
        with patch('app.integrations_api.requires_professional',
                   lambda feature=None: lambda f: f):
            yield mock_license


def setup_two_orgs(db_session):
    """Create two orgs, each with a manager user, and integration queue items."""
    from app.models import User, Organization
    from app.integrations_models import Integration, ImportQueue, AgentRegistration

    org1 = Organization(name='org1', display_name='Org 1', active=True)
    org2 = Organization(name='org2', display_name='Org 2', active=True)
    db_session.add_all([org1, org2])
    db_session.flush()

    # Org1 user (manager)
    user1 = User(
        username='mgr1', email='mgr1@org1.com',
        role='org_admin', is_active=True, auth_type='local',
        organization_id=org1.id
    )
    user1.set_password('password1')
    db_session.add(user1)

    # Org2 user (manager)
    user2 = User(
        username='mgr2', email='mgr2@org2.com',
        role='org_admin', is_active=True, auth_type='local',
        organization_id=org2.id
    )
    user2.set_password('password2')
    db_session.add(user2)

    # Super admin
    admin = User(
        username='superadmin', email='admin@system.com',
        role='super_admin', is_admin=True, is_active=True,
        auth_type='local', organization_id=org1.id,
        can_view_all_orgs=True
    )
    admin.set_password('adminpass')
    db_session.add(admin)

    # Integrations
    int1 = Integration(
        name='Agent Org1', integration_type='agent',
        organization_id=org1.id, api_key='key1', is_active=True
    )
    int2 = Integration(
        name='Agent Org2', integration_type='agent',
        organization_id=org2.id, api_key='key2', is_active=True
    )
    db_session.add_all([int1, int2])
    db_session.flush()

    # Queue items for org1
    q1 = ImportQueue(
        vendor='Apache', product_name='Tomcat',
        detected_version='10.0', status='pending',
        organization_id=org1.id, integration_id=int1.id
    )
    # Queue items for org2
    q2 = ImportQueue(
        vendor='Microsoft', product_name='Exchange',
        detected_version='2019', status='pending',
        organization_id=org2.id, integration_id=int2.id
    )
    q3 = ImportQueue(
        vendor='Oracle', product_name='Java',
        detected_version='21', status='pending',
        organization_id=org2.id, integration_id=int2.id
    )
    db_session.add_all([q1, q2, q3])

    # Agent registrations
    agent1 = AgentRegistration(
        agent_id='agent-uuid-1', hostname='server1.org1.local',
        os_type='windows', integration_id=int1.id,
        organization_id=org1.id, is_active=True
    )
    agent2 = AgentRegistration(
        agent_id='agent-uuid-2', hostname='server2.org2.local',
        os_type='linux', integration_id=int2.id,
        organization_id=org2.id, is_active=True
    )
    db_session.add_all([agent1, agent2])
    db_session.commit()

    return {
        'org1': org1, 'org2': org2,
        'user1': user1, 'user2': user2, 'admin': admin,
        'int1': int1, 'int2': int2,
        'q1': q1, 'q2': q2, 'q3': q3,
        'agent1': agent1, 'agent2': agent2,
    }


class TestQueueCountIsolation:
    """Queue count endpoint should only show items from user's orgs."""

    def test_org_user_sees_only_own_queue_count(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        # Login as org1 manager
        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.get('/api/import/queue/count')
        assert response.status_code == 200
        result = response.get_json()

        # org1 has 1 pending item, org2 has 2 — should only see 1
        assert result['pending'] == 1

    def test_super_admin_sees_all_queue_count(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['admin'].id
            sess['_fresh'] = True

        response = client.get('/api/import/queue/count')
        assert response.status_code == 200
        result = response.get_json()

        # Super admin sees all 3
        assert result['pending'] == 3


class TestQueueVendorsIsolation:
    """Queue vendors endpoint should only show vendors from user's orgs."""

    def test_org_user_sees_only_own_vendors(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.get('/api/import/queue/vendors')
        assert response.status_code == 200
        result = response.get_json()

        vendors = [v['vendor'] for v in result['vendors']]
        assert 'Apache' in vendors
        assert 'Microsoft' not in vendors
        assert 'Oracle' not in vendors

    def test_super_admin_sees_all_vendors(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['admin'].id
            sess['_fresh'] = True

        response = client.get('/api/import/queue/vendors')
        assert response.status_code == 200
        result = response.get_json()

        vendors = [v['vendor'] for v in result['vendors']]
        assert 'Apache' in vendors
        assert 'Microsoft' in vendors
        assert 'Oracle' in vendors


class TestAgentsIsolation:
    """Agents endpoint should only show agents from user's orgs."""

    def test_org_admin_sees_only_own_agents(self, app, client, db_session, pro_license):
        """An org_admin with is_admin=True should only see agents in their org."""
        data = setup_two_orgs(db_session)
        from app.models import User

        # Create an admin-level user for org1 (is_admin=True so @admin_required passes)
        org1_admin = User(
            username='org1admin', email='org1admin@org1.com',
            role='org_admin', is_admin=True, is_active=True,
            auth_type='local', organization_id=data['org1'].id
        )
        org1_admin.set_password('password')
        db_session.add(org1_admin)
        db_session.commit()

        with client.session_transaction() as sess:
            sess['user_id'] = org1_admin.id
            sess['_fresh'] = True

        response = client.get('/api/agents')
        assert response.status_code == 200
        agents = response.get_json()

        hostnames = [a['hostname'] for a in agents]
        assert 'server1.org1.local' in hostnames
        assert 'server2.org2.local' not in hostnames

    def test_super_admin_sees_all_agents(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['admin'].id
            sess['_fresh'] = True

        response = client.get('/api/agents')
        assert response.status_code == 200
        agents = response.get_json()

        hostnames = [a['hostname'] for a in agents]
        assert 'server1.org1.local' in hostnames
        assert 'server2.org2.local' in hostnames


class TestOrgPermissionOnApprove:
    """Approve endpoint should reject unauthorized org_id overrides."""

    def test_cannot_approve_to_other_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        # Login as org1 user
        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        # Try to approve org1's queue item but assign to org2
        response = client.post(f'/api/import/queue/{data["q1"].id}/approve', json={
            'organization_id': data['org2'].id
        })

        # Should be forbidden
        assert response.status_code == 403

    def test_can_approve_to_own_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        # Login as org1 user
        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.post(f'/api/import/queue/{data["q1"].id}/approve', json={
            'organization_id': data['org1'].id
        })

        # Should succeed
        assert response.status_code == 200
        result = response.get_json()
        assert result['success'] is True


class TestOrgPermissionOnBulkProcess:
    """Bulk process should reject unauthorized org_id overrides."""

    def test_bulk_cannot_assign_to_other_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.post('/api/import/queue/bulk', json={
            'action': 'approve',
            'item_ids': [data['q1'].id],
            'organization_id': data['org2'].id
        })

        assert response.status_code == 403


class TestOrgPermissionOnUpdateQueueItem:
    """Update queue item should reject unauthorized org_id changes."""

    def test_cannot_reassign_to_other_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.put(f'/api/import/queue/{data["q1"].id}', json={
            'organization_id': data['org2'].id
        })

        assert response.status_code == 403

    def test_can_reassign_to_own_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.put(f'/api/import/queue/{data["q1"].id}', json={
            'organization_id': data['org1'].id
        })

        assert response.status_code == 200


class TestOrgPermissionOnIntegrationCreate:
    """Creating integration should validate org access."""

    def test_cannot_create_integration_for_other_org(self, app, client, db_session, pro_license):
        data = setup_two_orgs(db_session)

        with client.session_transaction() as sess:
            sess['user_id'] = data['user1'].id
            sess['_fresh'] = True

        response = client.post('/api/integrations', json={
            'name': 'Sneaky Integration',
            'integration_type': 'agent',
            'organization_id': data['org2'].id
        })

        assert response.status_code == 403
