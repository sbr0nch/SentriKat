"""
Tests for remediation_api correctness fixes:
  - B6: RiskException auto-expire + create validation
  - M3: Assignment state machine (no ping-pong out of terminal states)
  - M4: ProductAlias duplicate returns 409
  - M15: Assignment notes visible only to admins

These tests target the helper functions directly where possible to avoid
the overhead of spinning up full HTTP flows for every case.
"""
from datetime import date, timedelta

import pytest


# ---------------------------------------------------------------------------
# M3 — assignment state machine (unit tests on the pure validator)
# ---------------------------------------------------------------------------


class TestAssignmentStateMachine:
    def test_allowed_forward_transitions(self):
        from app.remediation_api import _validate_assignment_transition

        for old, new in [
            ('open', 'in_progress'),
            ('open', 'resolved'),
            ('open', 'accepted_risk'),
            ('in_progress', 'resolved'),
            ('in_progress', 'accepted_risk'),
            ('in_progress', 'open'),
        ]:
            ok, err = _validate_assignment_transition(old, new)
            assert ok, f"{old}->{new} should be allowed ({err})"

    def test_terminal_cannot_reopen(self):
        from app.remediation_api import _validate_assignment_transition

        for old in ('resolved', 'accepted_risk'):
            for new in ('open', 'in_progress'):
                ok, err = _validate_assignment_transition(old, new)
                assert not ok
                assert 'terminal' in err.lower() or 'cannot reopen' in err.lower()

    def test_self_transition_is_noop(self):
        from app.remediation_api import _validate_assignment_transition

        for s in ('open', 'in_progress', 'resolved', 'accepted_risk'):
            ok, err = _validate_assignment_transition(s, s)
            assert ok, err

    def test_terminal_to_other_terminal_blocked(self):
        # Once an assignment reaches a terminal state, the only valid
        # transition is to itself. Swapping between resolved and
        # accepted_risk is also rejected — create a new assignment if you
        # need to reclassify how a finding was closed.
        from app.remediation_api import _validate_assignment_transition

        ok, _ = _validate_assignment_transition('resolved', 'accepted_risk')
        assert not ok
        ok, _ = _validate_assignment_transition('accepted_risk', 'resolved')
        assert not ok


# ---------------------------------------------------------------------------
# M3 — HTTP-level ping-pong blocking
# ---------------------------------------------------------------------------


class TestAssignmentUpdateHttp:
    @pytest.fixture
    def assignment(self, db_session, test_org):
        from app.models import RemediationAssignment
        a = RemediationAssignment(
            organization_id=test_org.id,
            assigned_to='alice@example.com',
            assigned_by='bob',
            status='resolved',
            priority='high',
            notes='sensitive remediation steps',
        )
        db_session.add(a)
        db_session.commit()
        return a

    def test_reopen_resolved_returns_400(self, app, client, test_org, assignment):
        # Authenticate as org admin
        from app.models import User
        from werkzeug.security import generate_password_hash
        from app import db as _db

        admin = User(
            username='orgadmin', email='orgadmin@test.local',
            password_hash=generate_password_hash('pw'),
            role='org_admin', organization_id=test_org.id,
            is_active=True, auth_type='local',
        )
        _db.session.add(admin)
        _db.session.commit()

        with client.session_transaction() as sess:
            sess['user_id'] = admin.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        resp = client.put(
            f'/api/remediation/assignments/{assignment.id}',
            json={'status': 'open'},
        )
        assert resp.status_code == 400, resp.data
        data = resp.get_json()
        assert 'terminal' in data['error'].lower()


# ---------------------------------------------------------------------------
# B6 — risk exception auto-expire + create validation
# ---------------------------------------------------------------------------


class TestRiskExceptionExpiry:
    def test_auto_expire_marks_past_active_as_expired(self, app, db_session, test_org):
        from app.models import RiskException
        from app.remediation_api import auto_expire_risk_exceptions

        past = RiskException(
            organization_id=test_org.id,
            cve_id='CVE-2020-0001',
            justification='j',
            approved_by='u',
            status='active',
            expires_at=date.today() - timedelta(days=5),
        )
        future = RiskException(
            organization_id=test_org.id,
            cve_id='CVE-2020-0002',
            justification='j',
            approved_by='u',
            status='active',
            expires_at=date.today() + timedelta(days=5),
        )
        permanent = RiskException(
            organization_id=test_org.id,
            cve_id='CVE-2020-0003',
            justification='j',
            approved_by='u',
            status='active',
            expires_at=None,
        )
        db_session.add_all([past, future, permanent])
        db_session.commit()

        n = auto_expire_risk_exceptions(organization_id=test_org.id)
        assert n == 1

        db_session.refresh(past)
        db_session.refresh(future)
        db_session.refresh(permanent)
        assert past.status == 'expired'
        assert future.status == 'active'
        assert permanent.status == 'active'

    def test_create_endpoint_rejects_past_expires_at(self, app, client, test_org, db_session):
        from app.models import User
        from werkzeug.security import generate_password_hash
        from app import db as _db

        admin = User(
            username='orgadmin2', email='orgadmin2@test.local',
            password_hash=generate_password_hash('pw'),
            role='org_admin', organization_id=test_org.id,
            is_active=True, auth_type='local',
        )
        _db.session.add(admin)
        _db.session.commit()

        with client.session_transaction() as sess:
            sess['user_id'] = admin.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        past_str = (date.today() - timedelta(days=1)).isoformat()
        resp = client.post(
            '/api/risk-exceptions',
            json={
                'cve_id': 'CVE-2020-1111',
                'justification': 'trying to backdate',
                'expires_at': past_str,
            },
        )
        assert resp.status_code == 400, resp.data
        assert 'past' in resp.get_json()['error'].lower()


# ---------------------------------------------------------------------------
# M4 — product alias duplicate
# ---------------------------------------------------------------------------


class TestProductAliasDuplicate:
    def test_duplicate_alias_returns_409(self, app, client, test_org, db_session):
        from app.models import Product, User, product_organizations
        from werkzeug.security import generate_password_hash
        from app import db as _db

        # Create admin
        admin = User(
            username='orgadmin3', email='orgadmin3@test.local',
            password_hash=generate_password_hash('pw'),
            role='org_admin', organization_id=test_org.id,
            is_active=True, auth_type='local',
        )
        _db.session.add(admin)

        # Create a product owned by the org (via M2M)
        prod = Product(
            vendor='Acme', product_name='Widget', version='1.0',
            active=True, organization_id=test_org.id,
        )
        _db.session.add(prod)
        _db.session.commit()

        # Ensure M2M ownership row exists so _validate_product_ownership passes
        _db.session.execute(
            product_organizations.insert().values(
                product_id=prod.id, organization_id=test_org.id,
            )
        )
        _db.session.commit()

        with client.session_transaction() as sess:
            sess['user_id'] = admin.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        payload = {
            'product_id': prod.id,
            'alias_vendor': 'AcmeCorp',
            'alias_product': 'Widget Pro',
        }

        r1 = client.post('/api/product-aliases', json=payload)
        assert r1.status_code == 201, r1.data

        r2 = client.post('/api/product-aliases', json=payload)
        assert r2.status_code == 409, r2.data
        assert 'already exists' in r2.get_json()['error'].lower()


# ---------------------------------------------------------------------------
# M10 — compliance reports awaiting analysis counters
# ---------------------------------------------------------------------------


class TestComplianceAwaitingCounters:
    def test_awaiting_counter_flags_provisional_matches(
        self, app, db_session, test_org, sample_product, sample_vulnerability
    ):
        from app.models import VulnerabilityMatch
        from app.compliance_reports import _compute_vuln_posture

        # Make the vulnerability "Awaiting Analysis"
        sample_vulnerability.nvd_status = 'Awaiting Analysis'
        db_session.commit()

        # Ensure a match row exists for the product + vulnerability
        m = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
            match_reason='test',
            match_method='keyword',
            match_confidence='medium',
        )
        db_session.add(m)
        db_session.commit()

        posture = _compute_vuln_posture([test_org.id])
        assert posture['total_matches'] >= 1
        assert posture['total_awaiting'] >= 1
        assert posture['matches_high_awaiting'] >= 1
        assert posture['pct_awaiting'] > 0.0

    def test_report_includes_data_quality_notice(
        self, app, db_session, test_org, sample_product, sample_vulnerability
    ):
        from app.models import VulnerabilityMatch
        from app.compliance_reports import (
            _compute_vuln_posture, _build_report, _evaluate_pci_dss,
        )

        sample_vulnerability.nvd_status = 'Awaiting Analysis'
        db_session.commit()

        m = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
            match_reason='test',
            match_method='keyword',
            match_confidence='low',
        )
        db_session.add(m)
        db_session.commit()

        posture = _compute_vuln_posture([test_org.id])
        reqs = _evaluate_pci_dss(posture)
        # user=None is fine; _build_report guards against missing user
        report = _build_report('pci-dss', 'PCI-DSS v4.0', reqs, None, 'Test Org', posture=posture)

        assert 'data_quality_notice' in report
        notice = report['data_quality_notice']
        assert notice['total_awaiting'] >= 1
        assert notice['pct_awaiting'] > 0.0
        assert 'by_severity' in notice


# ---------------------------------------------------------------------------
# M15 — assignment notes visibility
# ---------------------------------------------------------------------------


class TestAssignmentNotesVisibility:
    @pytest.fixture
    def seed(self, db_session, test_org):
        from app.models import RemediationAssignment
        a = RemediationAssignment(
            organization_id=test_org.id,
            assigned_to='carol@example.com',
            assigned_by='bob',
            status='open',
            priority='medium',
            notes='SECRET: internal rationale + ticket #1234',
            resolution_notes='REDACT_ME',
        )
        db_session.add(a)
        db_session.commit()
        return a

    def test_regular_user_sees_no_notes(self, app, client, test_org, test_user, seed):
        with client.session_transaction() as sess:
            sess['user_id'] = test_user.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        resp = client.get(f'/api/remediation/assignments/{seed.id}')
        assert resp.status_code == 200, resp.data
        d = resp.get_json()
        assert d['notes'] is None
        assert d['resolution_notes'] is None

    def test_admin_sees_notes(self, app, client, test_org, admin_user, seed):
        with client.session_transaction() as sess:
            sess['user_id'] = admin_user.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        resp = client.get(f'/api/remediation/assignments/{seed.id}')
        assert resp.status_code == 200, resp.data
        d = resp.get_json()
        assert d['notes'] is not None
        assert 'SECRET' in d['notes']
