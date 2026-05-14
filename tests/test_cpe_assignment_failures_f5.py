"""F.5 CpeAssignmentFailure model + endpoints regression tests."""
import json

import pytest

from app import db
from app.models import CpeAssignmentFailure, Product


@pytest.fixture
def stale_failure(db_session, test_org):
    product = Product(
        vendor='ApacheFoundation',
        product_name='Tomcat Server',
        version='9.0.50',
        criticality='medium',
        active=True,
        organization_id=test_org.id,
        match_type='auto',
    )
    db_session.add(product)
    db_session.commit()

    f = CpeAssignmentFailure(
        product_id=product.id,
        product_vendor=product.vendor,
        product_name=product.product_name,
        rejected_cpe_vendor='apache',
        rejected_cpe_product='tomcat',
        reason='word_overlap_validation_failed',
    )
    db_session.add(f)
    db_session.commit()
    return f, product


def test_cpe_failure_to_dict(stale_failure):
    f, _ = stale_failure
    d = f.to_dict()
    assert d['rejected_cpe_vendor'] == 'apache'
    assert d['rejected_cpe_product'] == 'tomcat'
    assert d['reason'] == 'word_overlap_validation_failed'
    assert d['resolved_at'] is None
    assert d['resolution'] is None


def test_list_cpe_failures_endpoint_unresolved(stale_failure, admin_client):
    resp = admin_client.get('/api/admin/cpe-failures?status=unresolved')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['total'] >= 1
    assert any(it['rejected_cpe_vendor'] == 'apache' for it in data['items'])


def test_list_cpe_failures_endpoint_resolved_filter(stale_failure, admin_client, db_session):
    f, _ = stale_failure
    # First call: unresolved → contains the row
    resp = admin_client.get('/api/admin/cpe-failures?status=unresolved')
    assert resp.status_code == 200
    assert any(it['id'] == f.id for it in resp.get_json()['items'])

    # Mark resolved manually
    from datetime import datetime
    f.resolved_at = datetime.utcnow()
    f.resolution = 'dismissed'
    db_session.commit()

    # Now unresolved → empty for this row
    resp = admin_client.get('/api/admin/cpe-failures?status=unresolved')
    assert all(it['id'] != f.id for it in resp.get_json()['items'])

    # And resolved → present
    resp = admin_client.get('/api/admin/cpe-failures?status=resolved')
    assert any(it['id'] == f.id for it in resp.get_json()['items'])


def test_force_apply_sets_cpe_and_resolves(stale_failure, admin_client, db_session):
    f, product = stale_failure
    assert product.cpe_vendor in (None, '')

    resp = admin_client.post(f'/api/admin/cpe-failures/{f.id}/force-apply')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'ok'
    assert data['product_id'] == product.id

    db_session.refresh(product)
    db_session.refresh(f)
    assert product.cpe_vendor == 'apache'
    assert product.cpe_product == 'tomcat'
    assert f.resolved_at is not None
    assert f.resolution == 'force_applied'


def test_force_apply_already_resolved_returns_409(stale_failure, admin_client, db_session):
    f, _ = stale_failure
    from datetime import datetime
    f.resolved_at = datetime.utcnow()
    f.resolution = 'dismissed'
    db_session.commit()
    resp = admin_client.post(f'/api/admin/cpe-failures/{f.id}/force-apply')
    assert resp.status_code == 409


def test_dismiss_marks_resolved(stale_failure, admin_client, db_session):
    f, _ = stale_failure
    resp = admin_client.post(f'/api/admin/cpe-failures/{f.id}/dismiss')
    assert resp.status_code == 200
    db_session.refresh(f)
    assert f.resolved_at is not None
    assert f.resolution == 'dismissed'


def test_admin_only_requires_login(client, stale_failure):
    """Anonymous user cannot list failures."""
    resp = client.get('/api/admin/cpe-failures')
    # 302 redirect to login or 401/403 — all acceptable, just not 200
    assert resp.status_code in (302, 401, 403)
