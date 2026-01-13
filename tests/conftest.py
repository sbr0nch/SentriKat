"""
Pytest configuration and fixtures.
"""
import pytest
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app():
    """Create application for testing."""
    from app import create_app, db

    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False

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
def sample_product(db_session):
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
        match_type='auto'
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
    db_session.commit()
    return vuln
