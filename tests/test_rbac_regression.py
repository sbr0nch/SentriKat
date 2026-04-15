"""
RBAC & cross-tenant regression tests.

These tests codify the bug classes that were found + fixed during the
manual launch QA (see PR #331 and the follow-on feature PR). The intent is
to freeze the current correct behavior so nobody can silently reintroduce
the same class of bug.

Covered regressions:

1. **Viewer UI write gates** — a role='user' account must not be able to
   trigger write endpoints that are gated to manager+ / org_admin+.

2. **Manager scope** — a role='manager' account CAN manage products and
   integrations, but CANNOT manage users or change org settings (those
   are org_admin+).

3. **Cross-tenant POST** — an org_admin of Org A cannot attach one of
   their products to Org B by passing `organization_ids: [B.id]` in the
   POST /api/products/<id>/organizations payload. (This was the CRITICAL
   bug #1 in the QA pass.)

4. **Cross-tenant GET product orgs** — an org_admin of Org A who has a
   product shared with Org B should see ONLY the orgs they themselves
   belong to in the response, not the full list with Org B's
   display_name leaking. (This was the MEDIUM bug in the audit.)

5. **Remediation assignment M15 note redaction** — role='user' /
   'manager' requesting GET /api/remediation/assignments must see
   notes=null and resolution_notes=null. Only admin/org_admin/super_admin
   see them plaintext.

6. **/api/remediation/assignments never 500s** — a broken row (missing
   product FK, orphan match) must be skipped with a log line, not turn
   the whole list endpoint into a 500 for the calling user.

The tests use the fixtures defined in conftest.py: test_org, second_org,
viewer_user, manager_user, org_admin_user, second_org_admin, plus the
*_client variants that attach a pre-authenticated session cookie.

---

Known design footgun (TODO for a separate PR): the User model has
`can_manage_products = db.Column(db.Boolean, default=True)` at
models.py:1163. `manager_required` accepts `can_manage_products=True`
as an explicit capability override, which means every row with
role='user' is in practice a de-facto manager unless an org_admin
actively flips the flag off. This was discovered by this test suite
(`viewer_user` was initially failing assertions that it couldn't
POST to /api/products because the default was True). The `viewer_user`
fixture now pins `can_manage_products=False` so the tests here
describe the *intended* read-only contract, but the production
default should probably be flipped to False in a follow-up migration
(or the override path removed from `manager_required`). The tests
below assume the fixture-level override; the production default is
tracked separately.
"""

import pytest
from datetime import date


# =============================================================================
# 1. Viewer role — UI write gates
# =============================================================================

class TestViewerWriteGates:
    """Role='user' (viewer) must not be able to write tenant-owned data."""

    def test_viewer_cannot_create_product_exclusion(self, viewer_client, test_org):
        """POST /api/product-exclusions requires org_admin+."""
        response = viewer_client.post('/api/product-exclusions', json={
            'vendor': 'acme',
            'product_name': 'frobnicator',
            'organization_id': test_org.id,
            'reason': 'test exclusion',
        })
        assert response.status_code in (401, 403), (
            f"Viewer should NOT be able to create exclusions "
            f"(got {response.status_code}: {response.get_data(as_text=True)[:200]})"
        )

    def test_viewer_cannot_delete_product_exclusion(self, viewer_client):
        """DELETE /api/product-exclusions/<id> requires org_admin+."""
        # We don't need a real exclusion — the decorator should reject
        # before the DB lookup.
        response = viewer_client.delete('/api/product-exclusions/999')
        assert response.status_code in (401, 403)

    def test_viewer_cannot_create_product(self, viewer_client, test_org):
        """POST /api/products requires manager+ (or can_manage_products)."""
        response = viewer_client.post('/api/products', json={
            'vendor': 'test',
            'product_name': 'test-product',
            'version': '1.0.0',
            'organization_id': test_org.id,
        })
        assert response.status_code in (401, 403), (
            f"Viewer should NOT be able to create products "
            f"(got {response.status_code})"
        )

    def test_viewer_cannot_delete_product(self, viewer_client, sample_product):
        """DELETE /api/products/<id> requires manager+ / org_admin."""
        response = viewer_client.delete(f'/api/products/{sample_product.id}')
        assert response.status_code in (401, 403)

    def test_viewer_cannot_invite_user(self, viewer_client, test_org):
        """POST /api/users requires org_admin+."""
        response = viewer_client.post('/api/users', json={
            'username': 'newuser',
            'email': 'new@test.local',
            'password': 'NewPassword!23',
            'role': 'user',
            'organization_id': test_org.id,
        })
        assert response.status_code in (401, 403)


# =============================================================================
# 2. Manager role — scoped capabilities
# =============================================================================

class TestManagerCapabilities:
    """Role='manager' should manage products but not users or org settings."""

    def test_manager_cannot_invite_user(self, manager_client, test_org):
        """POST /api/users is org_admin-only — manager should be rejected."""
        response = manager_client.post('/api/users', json={
            'username': 'newuser',
            'email': 'new@test.local',
            'password': 'NewPassword!23',
            'role': 'user',
            'organization_id': test_org.id,
        })
        assert response.status_code in (401, 403), (
            "Manager role must NOT be able to invite users"
        )

    def test_manager_cannot_delete_user(self, manager_client):
        """DELETE /api/users/<id> is org_admin-only."""
        response = manager_client.delete('/api/users/999')
        assert response.status_code in (401, 403)

    def test_user_with_can_manage_products_override_can_write(
        self, db_session, client, test_org
    ):
        """
        Documents the capability-override path in @manager_required.

        Even a role='user' account becomes effectively a manager if the
        org_admin flips can_manage_products=True on them. This is the
        intended escape hatch for "give this one user write access
        without promoting them to a full manager role". Removing it
        would break any existing customer who relied on it, so we
        pin the behaviour with this test.
        """
        from app.models import User
        from werkzeug.security import generate_password_hash
        user = User(
            username='overrideuser',
            email='override@test.local',
            password_hash=generate_password_hash('overridepass123'),
            role='user',
            can_manage_products=True,  # explicit override
            organization_id=test_org.id,
            is_active=True,
            auth_type='local',
        )
        db_session.add(user)
        db_session.commit()
        with client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['organization_id'] = test_org.id
            sess['_fresh'] = True

        # The same endpoint that the viewer_client can't hit should now work.
        response = client.post('/api/product-exclusions', json={
            'vendor': 'acme',
            'product_name': 'widget',
            'organization_id': test_org.id,
            'reason': 'capability-override test',
        })
        assert response.status_code == 201, (
            f"can_manage_products=True override must grant write access; "
            f"got {response.status_code}"
        )


# =============================================================================
# 3. Cross-tenant POST — the CRITICAL bug from PR #331
# =============================================================================

class TestCrossTenantProductAssignment:
    """
    An org_admin of Org A must not be able to attach one of their products
    to Org B by passing organization_ids: [B.id] in the POST payload.

    This test exists because we shipped a critical fix for exactly this
    pattern in routes.py::assign_product_organizations. If anyone removes
    the allowed_target_org_ids check, this test will catch it.
    """

    def test_org_admin_cannot_assign_product_to_foreign_org(
        self, org_admin_client, sample_product, second_org
    ):
        """POST /api/products/<id>/organizations with a foreign org_id
        must return 403 (or at minimum not attach the product)."""
        response = org_admin_client.post(
            f'/api/products/{sample_product.id}/organizations',
            json={'organization_ids': [second_org.id]},
        )
        # The fix returns 403 with a clear message. Accept 403 or 404 but
        # NEVER 200 — a 200 means the cross-tenant leak regressed.
        assert response.status_code != 200, (
            f"CRITICAL REGRESSION: cross-tenant product assignment succeeded "
            f"(HTTP {response.status_code}: {response.get_data(as_text=True)[:300]}). "
            f"routes.py::assign_product_organizations must validate that every "
            f"target org_id is in current_user.get_all_organizations()."
        )
        assert response.status_code in (403, 404), (
            f"Expected 403 or 404, got {response.status_code}: "
            f"{response.get_data(as_text=True)[:200]}"
        )

    def test_viewer_cannot_assign_product_to_their_own_org(
        self, viewer_client, sample_product, test_org
    ):
        """Viewer shouldn't even reach the cross-tenant code path — the
        decorator @org_admin_required should reject first."""
        response = viewer_client.post(
            f'/api/products/{sample_product.id}/organizations',
            json={'organization_ids': [test_org.id]},
        )
        assert response.status_code in (401, 403)


# =============================================================================
# 4. Cross-tenant GET product orgs — the MEDIUM leak from the audit
# =============================================================================

class TestProductOrgListLeak:
    """
    GET /api/products/<id>/organizations used to return the full list of
    orgs the product was shared with, even orgs the caller did not belong
    to. The fix filters the response to only the orgs the caller can see.
    """

    def test_second_org_admin_cannot_enumerate_primary_org(
        self, db_session, second_org_client, test_org, second_org, sample_product
    ):
        """Attach sample_product (which belongs to test_org) to second_org
        via the M2M relationship. Then, logged in as second_org_admin,
        GET /api/products/<id>/organizations should NOT return test_org
        in the response — second_org_admin has no right to know about
        test_org's existence, name, or id.
        """
        # Share the product with second_org via the M2M relationship
        sample_product.organizations.append(second_org)
        db_session.commit()

        response = second_org_client.get(
            f'/api/products/{sample_product.id}/organizations'
        )
        assert response.status_code == 200, response.get_data(as_text=True)

        data = response.get_json()
        # The response may use 'organizations' as the wrapping key.
        orgs = data.get('organizations') if isinstance(data, dict) else data
        assert orgs is not None, f"Unexpected response shape: {data}"

        returned_ids = {o.get('id') for o in orgs}
        returned_names = {o.get('name') for o in orgs}

        # The primary org's id and name must NOT leak to a caller that
        # doesn't belong to it.
        assert test_org.id not in returned_ids, (
            f"REGRESSION: primary org id {test_org.id} leaked to "
            f"second_org_admin in response: {orgs}"
        )
        assert test_org.name not in returned_names
        assert test_org.display_name not in {o.get('display_name') for o in orgs}


# =============================================================================
# 5. Remediation assignment — M15 note redaction
# =============================================================================

class TestAssignmentNoteRedaction:
    """
    Notes and resolution_notes may contain sensitive remediation details
    (credentials, ticket numbers, internal rationale) — the list endpoint
    must redact them for any caller whose role is NOT in
    (admin, org_admin, super_admin).
    """

    @pytest.fixture
    def assignment_with_notes(self, db_session, test_org, sample_product):
        from app.models import RemediationAssignment
        a = RemediationAssignment(
            organization_id=test_org.id,
            product_id=sample_product.id,
            cve_id='CVE-2024-1234',
            assigned_to='someone@test.local',
            assigned_by='orgadmin@test.local',
            due_date=date.today(),
            status='open',
            priority='high',
            notes='SECRET: use breakglass cred abc-123',
            resolution_notes='SECRET: internal ticket JIRA-999',
        )
        db_session.add(a)
        db_session.commit()
        return a

    def test_viewer_gets_redacted_notes(self, viewer_client, assignment_with_notes):
        """role='user' must see notes=null in the list response."""
        response = viewer_client.get('/api/remediation/assignments')
        assert response.status_code == 200, response.get_data(as_text=True)
        data = response.get_json()
        items = data.get('assignments', [])
        assert len(items) >= 1, "Viewer should at least see the assignment in their org"
        for a in items:
            assert a.get('notes') is None, (
                f"M15 REGRESSION: viewer saw notes={a.get('notes')!r} "
                "— assignment notes must be redacted for non-admin roles"
            )
            assert a.get('resolution_notes') is None

    def test_manager_gets_redacted_notes(self, manager_client, assignment_with_notes):
        """role='manager' is also not in the privileged set — notes redacted."""
        response = manager_client.get('/api/remediation/assignments')
        assert response.status_code == 200
        for a in response.get_json().get('assignments', []):
            assert a.get('notes') is None
            assert a.get('resolution_notes') is None

    def test_org_admin_sees_notes_plaintext(
        self, org_admin_client, assignment_with_notes
    ):
        """role='org_admin' is in the privileged set — notes returned verbatim."""
        response = org_admin_client.get('/api/remediation/assignments')
        assert response.status_code == 200
        found = None
        for a in response.get_json().get('assignments', []):
            if a.get('id') == assignment_with_notes.id:
                found = a
                break
        assert found is not None, "org_admin should see the assignment in their org"
        assert found.get('notes') == 'SECRET: use breakglass cred abc-123'
        assert found.get('resolution_notes') == 'SECRET: internal ticket JIRA-999'


# =============================================================================
# 6. /api/remediation/assignments never 500s
# =============================================================================

class TestAssignmentListNeverFivexx:
    """The per-row try/except in list_assignments must keep the endpoint
    returning 200 even when a single row is broken (missing product FK,
    orphan match.vulnerability, etc.).
    """

    def test_empty_list_returns_200(self, org_admin_client):
        """No assignments yet — endpoint must return 200, not 500."""
        response = org_admin_client.get('/api/remediation/assignments')
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('assignments') == []
        assert data.get('total') == 0
        assert data.get('overdue') == 0

    def test_broken_row_does_not_500(
        self, db_session, org_admin_client, test_org
    ):
        """Create an assignment that references a product_id that doesn't
        exist. The per-row try/except should swallow the error and still
        return 200 with the broken row skipped.
        """
        from app.models import RemediationAssignment
        # product_id=99999 is an orphan reference. SQLite doesn't enforce
        # FKs by default in tests, so this row will be inserted but the
        # serializer will fail when it tries to dereference a.product.
        a = RemediationAssignment(
            organization_id=test_org.id,
            product_id=99999,  # intentionally orphan
            cve_id='CVE-2024-0001',
            assigned_to='someone@test.local',
            assigned_by='orgadmin@test.local',
            due_date=date.today(),
            status='open',
            priority='low',
            notes='',
        )
        db_session.add(a)
        db_session.commit()

        response = org_admin_client.get('/api/remediation/assignments')
        # The hard constraint: we must NOT 500 no matter how mangled the
        # row is. The row may be included (if serialization happened to
        # succeed) or skipped (if it didn't) — both are acceptable.
        assert response.status_code == 200, (
            f"REGRESSION: /api/remediation/assignments returned "
            f"{response.status_code} with an orphan product_id row present. "
            f"The per-row try/except in list_assignments must catch this. "
            f"Body: {response.get_data(as_text=True)[:300]}"
        )

    def test_unauthenticated_returns_401_not_500(self, client, setup_complete):
        """Rule out the 'unauthenticated call 500s on None org_id' pattern.

        Uses the setup_complete fixture so the check_setup() middleware
        doesn't short-circuit with a 503 before we even reach the auth
        decorator. What we care about here is that the auth layer
        returns 401/403 cleanly instead of falling into a 500 on None
        organization_id.
        """
        response = client.get('/api/remediation/assignments')
        assert response.status_code in (401, 403), (
            f"Expected 401/403 from unauthenticated call, got "
            f"{response.status_code}: {response.get_data(as_text=True)[:200]}"
        )
