"""
Pytest configuration and fixtures.
"""
import pytest
import sys
import os
import hashlib

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set environment variables BEFORE importing anything from the app
# This ensures the Config class picks up SQLite instead of PostgreSQL
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key-for-testing-only'
# Valid Fernet key for testing (generated with Fernet.generate_key())
os.environ['ENCRYPTION_KEY'] = 'pCa0H5vlTAQ9eTmZt846gr-nePl__Fy0F157GpYofd0='


class TestConfig:
    """Test configuration that uses SQLite in-memory database."""
    SECRET_KEY = 'test-secret-key-for-testing-only'
    # Valid Fernet key for testing (generated with Fernet.generate_key())
    ENCRYPTION_KEY = 'pCa0H5vlTAQ9eTmZt846gr-nePl__Fy0F157GpYofd0='
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {}  # No PostgreSQL-specific options
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False  # Disable rate limiting in tests
    SENTRIKAT_URL = 'http://localhost:5000'
    CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    SYNC_HOUR = 2
    SYNC_MINUTE = 0
    ITEMS_PER_PAGE = 50
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    VERIFY_SSL = True
    # Disable login requirement for testing
    LOGIN_DISABLED = False

    from datetime import timedelta
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)


@pytest.fixture
def app():
    """Create application for testing."""
    from app import create_app, db

    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Create database session for testing."""
    from app import db
    with app.app_context():
        yield db.session


@pytest.fixture
def setup_complete(db_session):
    """Ensure setup is complete (org + user exist) so check_setup() doesn't return 503."""
    from app.models import Organization, User
    from werkzeug.security import generate_password_hash

    org = Organization(name='Setup Org', display_name='Setup Org', active=True)
    db_session.add(org)
    db_session.flush()
    user = User(
        username='setupuser', email='setup@test.local',
        password_hash=generate_password_hash('pass'),
        role='user', organization_id=org.id,
        is_active=True, auth_type='local'
    )
    db_session.add(user)
    db_session.commit()
    return org


@pytest.fixture
def test_org(db_session):
    """Create a test organization."""
    from app.models import Organization
    org = Organization(name='Test Organization', display_name='Test Organization', active=True)
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def test_user(db_session, test_org):
    """Create a regular test user."""
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='testuser',
        email='testuser@test.local',
        password_hash=generate_password_hash('testpass123'),
        role='user',
        organization_id=test_org.id,
        is_active=True,
        auth_type='local'
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def admin_user(db_session, test_org):
    """Create an admin test user."""
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='adminuser',
        email='adminuser@test.local',
        password_hash=generate_password_hash('adminpass123'),
        role='super_admin',
        is_admin=True,
        organization_id=test_org.id,
        is_active=True,
        auth_type='local'
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def authenticated_client(client, test_user, app):
    """Create a test client with an authenticated session."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_user.id
        sess['_fresh'] = True
    return client


@pytest.fixture
def admin_client(client, admin_user, app):
    """Create a test client with an admin authenticated session."""
    with client.session_transaction() as sess:
        sess['user_id'] = admin_user.id
        sess['_fresh'] = True
    return client


@pytest.fixture
def sample_product(db_session, test_org):
    """Create a sample product for testing."""
    from app.models import Product

    product = Product(
        vendor='Apache',
        product_name='Tomcat',
        version='10.1.18',
        criticality='high',
        active=True,
        cpe_vendor='apache',
        cpe_product='tomcat',
        match_type='auto',
        organization_id=test_org.id
    )
    db_session.add(product)
    db_session.commit()
    return product


@pytest.fixture
def sample_vulnerability(db_session):
    """Create a sample vulnerability for testing."""
    from app.models import Vulnerability
    from datetime import date

    vuln = Vulnerability(
        cve_id='CVE-2024-1234',
        vendor_project='Apache',
        product='Tomcat',
        vulnerability_name='Test Vulnerability',
        date_added=date.today(),
        short_description='A test vulnerability',
        required_action='Update to latest version',
        cvss_score=8.5,
        severity='HIGH'
    )
    db_session.add(vuln)
    db_session.flush()

    # Add CPE data with version range covering 10.1.18 (the sample_product version).
    # Real vulnerabilities get this from NVD after the first sync.
    vuln.set_cpe_entries([{
        'vendor': 'apache',
        'product': 'tomcat',
        'version_start': '10.0.0',
        'version_end': '10.1.25',
        'version_start_type': 'including',
        'version_end_type': 'excluding',
    }])

    db_session.commit()
    return vuln


@pytest.fixture
def test_api_key(db_session, test_org):
    """Create a test agent API key."""
    from app.models import AgentApiKey

    raw_key = 'sk_test_1234567890abcdef'
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Test API Key',
        key_hash=key_hash,
        key_prefix=raw_key[:8],
        active=True,
        auto_approve=True
    )
    db_session.add(api_key)
    db_session.commit()
    return {'api_key': api_key, 'raw_key': raw_key}


# =============================================================================
# RBAC fixtures (Sprint 6 — prevention of the viewer/manager regression class
# we fixed manually on claude/fix-test-checklist).
#
# These fixtures give every test a cheap way to assert that a specific role
# gets the expected ALLOW / DENY verdict on a given endpoint without having
# to re-create users and organizations by hand. They also include a second
# organization + a user in it so cross-tenant isolation can be asserted
# directly.
# =============================================================================

@pytest.fixture
def viewer_user(db_session, test_org):
    """Create a plain 'user' (aka viewer) in the primary test org.

    NOTE #1: SentriKat has no separate 'viewer' role — `user` IS the
    read-only role. This fixture name mirrors the mental model the
    product team uses ('viewer = read-only'). If a test needs a user
    that can create products, use `manager_user` instead.

    NOTE #2: The User.can_manage_products column defaults to TRUE in
    the model (models.py:1163). That default leaks through
    @manager_required which treats can_manage_products=True as a
    capability override. In the RBAC tests we set it to False
    EXPLICITLY so the fixture represents a true read-only user. In
    production, this means a new row with role='user' gets write
    access to products / exclusions / import queue unless an org_admin
    actively flips the flag off — that's a footgun tracked as a
    follow-up (see docstring of test_rbac_regression.py).
    """
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='viewer',
        email='viewer@test.local',
        password_hash=generate_password_hash('viewerpass123'),
        role='user',
        can_manage_products=False,  # see NOTE #2 — explicit for the RBAC contract
        organization_id=test_org.id,
        is_active=True,
        auth_type='local',
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def manager_user(db_session, test_org):
    """Create a 'manager' user in the primary test org.

    Manager can manage products / run imports / use integrations but
    cannot manage users, settings, or billing.
    """
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='manageruser',
        email='manager@test.local',
        password_hash=generate_password_hash('managerpass123'),
        role='manager',
        can_manage_products=True,
        organization_id=test_org.id,
        is_active=True,
        auth_type='local',
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def org_admin_user(db_session, test_org):
    """Create an 'org_admin' user in the primary test org.

    Org-admin can do everything except cross-tenant operations and
    platform-wide settings (those require super_admin).
    """
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='orgadmin',
        email='orgadmin@test.local',
        password_hash=generate_password_hash('orgadminpass123'),
        role='org_admin',
        organization_id=test_org.id,
        is_active=True,
        auth_type='local',
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def second_org(db_session):
    """A second, unrelated organization for cross-tenant tests."""
    from app.models import Organization
    org = Organization(
        name='Second Test Organization',
        display_name='Second Test Org',
        active=True,
    )
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def second_org_admin(db_session, second_org):
    """An org_admin whose only org is `second_org` — used to check that
    cross-tenant GET / POST / PATCH actions are refused.
    """
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        username='secondorgadmin',
        email='secondorgadmin@test.local',
        password_hash=generate_password_hash('secondpass123'),
        role='org_admin',
        organization_id=second_org.id,
        is_active=True,
        auth_type='local',
    )
    db_session.add(user)
    db_session.commit()
    return user


def _login_client(client, user):
    """Attach a session cookie for ``user`` to ``client``.

    The login decorator requires both ``user_id`` and, for tenant-scoped
    endpoints, ``organization_id`` in the session. We mirror what the
    real /api/auth/login endpoint does on success.
    """
    with client.session_transaction() as sess:
        sess['user_id'] = user.id
        if user.organization_id:
            sess['organization_id'] = user.organization_id
        sess['_fresh'] = True
    return client


@pytest.fixture
def viewer_client(client, viewer_user):
    """Test client authenticated as role='user' in the primary org."""
    return _login_client(client, viewer_user)


@pytest.fixture
def manager_client(client, manager_user):
    """Test client authenticated as role='manager' in the primary org."""
    return _login_client(client, manager_user)


@pytest.fixture
def org_admin_client(client, org_admin_user):
    """Test client authenticated as role='org_admin' in the primary org."""
    return _login_client(client, org_admin_user)


@pytest.fixture
def second_org_client(client, second_org_admin):
    """Test client authenticated as org_admin of the OTHER organization."""
    return _login_client(client, second_org_admin)
