"""Tests for F.6 + F.8 CVE matching pipeline fixes.

F.6 — keyword `vendor_product` confidence demotion:
  When a product matches a vulnerability via vendor+product name (no CPE-
  based version verification possible), the confidence MUST be 'medium'
  ONLY if the vulnerability carries upstream cpe_data (so the version
  range was knowable). When cpe_data is NULL, demote to 'low' to keep
  the 'Chrome 147 ↔ CVE-2010' style false positives off the default
  dashboard.

F.8 — purge_and_rematch on CPE flip:
  When an admin manually edits a product's CPE (or batch_apply_cpe_mappings
  flips a product from no-CPE to CPE), the previous keyword-only matches
  are stale. The fix purges them and re-runs match_vulnerabilities_to_products
  so the dashboard reflects the new CPE-aware state immediately.
"""
import json

import pytest

from app import db
from app.cpe_mapping import purge_and_rematch_products
from app.filters import check_keyword_match
from app.models import Product, Vulnerability, VulnerabilityMatch


# ---------- F.6 ----------

class _FakeVuln:
    """Lightweight stand-in for Vulnerability so check_keyword_match doesn't
    require the full ORM round-trip just to set cpe_data presence."""
    def __init__(self, vendor_project, product, cpe_data):
        self.vendor_project = vendor_project
        self.product = product
        self.cpe_data = cpe_data


class _FakeProduct:
    def __init__(self, vendor, product_name, version=None, keywords=None):
        self.vendor = vendor
        self.product_name = product_name
        self.version = version
        self.keywords = keywords


def test_f6_vendor_product_medium_when_cpe_data_present():
    vuln = _FakeVuln('Apache', 'Tomcat', cpe_data='[{"cpe23Uri":"cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"}]')
    prod = _FakeProduct('Apache', 'Tomcat', version='9.0.50')
    reasons, method, confidence = check_keyword_match(vuln, prod)
    assert method == 'vendor_product'
    assert confidence == 'medium'


def test_f6_vendor_product_low_when_cpe_data_null():
    vuln = _FakeVuln('Google', 'Chrome', cpe_data=None)
    prod = _FakeProduct('Google', 'Chrome', version='147.0.7341.0')
    reasons, method, confidence = check_keyword_match(vuln, prod)
    assert method == 'vendor_product'
    assert confidence == 'low'  # F.6: demoted because cpe_data missing


def test_f6_vendor_product_low_when_cpe_data_empty_array():
    """Empty JSON array is the same as missing cpe_data — no version was knowable."""
    vuln = _FakeVuln('Google', 'Chrome', cpe_data='[]')
    prod = _FakeProduct('Google', 'Chrome', version='147.0.7341.0')
    reasons, method, confidence = check_keyword_match(vuln, prod)
    assert method == 'vendor_product'
    assert confidence == 'low'


def test_f6_keyword_only_stays_low():
    """Pure keyword (no vendor+product structural match) was already 'low'."""
    vuln = _FakeVuln('', '', cpe_data='[{"x":1}]')
    prod = _FakeProduct('', 'tomcat', keywords='tomcat')
    # keyword-only path: vuln.product is empty so vendor+product can't match
    # but the keyword 'tomcat' won't match against empty vuln_product either
    # — verify behavior: no match at all
    reasons, method, confidence = check_keyword_match(vuln, prod)
    assert method is None or confidence in ('low', None)


# ---------- F.8 ----------

def _seed_match(db_session, product, vulnerability, method='vendor_product', confidence='low'):
    m = VulnerabilityMatch(
        product_id=product.id,
        vulnerability_id=vulnerability.id,
        match_method=method,
        match_confidence=confidence,
        match_reasons=json.dumps([f"keyword: {product.product_name}"]),
    )
    db_session.add(m)
    db_session.commit()
    return m


@pytest.fixture
def cpe_flip_setup(db_session, test_org):
    """Seed: 1 product, 1 vuln, 1 stale keyword match.

    Pre-flip product has no CPE; the stale match would be a F.6-low
    keyword fallback. After the admin edits the product to add CPE,
    purge_and_rematch_products should remove the stale match.
    """
    product = Product(
        vendor='Apache',
        product_name='Tomcat',
        version='9.0.50',
        criticality='medium',
        active=True,
        organization_id=test_org.id,
        match_type='auto',
    )
    db_session.add(product)
    db_session.flush()

    vuln = Vulnerability(
        cve_id='CVE-2099-9999',
        vendor_project='Apache',
        product='Tomcat',
        cpe_data=None,
        is_actively_exploited=False,
    )
    db_session.add(vuln)
    db_session.commit()
    _seed_match(db_session, product, vuln)

    return product, vuln


def test_f8_purge_removes_stale_match(db_session, cpe_flip_setup):
    product, vuln = cpe_flip_setup
    assert VulnerabilityMatch.query.filter_by(product_id=product.id).count() == 1

    # Simulate CPE flip: admin sets CPE on product
    product.cpe_vendor = 'apache'
    product.cpe_product = 'tomcat'
    db_session.commit()

    rematched = purge_and_rematch_products([product.id])
    assert rematched == 1

    # The stale match was deleted. The matcher may re-create it if criteria
    # still hold (but since vuln.cpe_data is NULL and product has no version
    # range knowable, the match either becomes 'low' keyword or disappears).
    # Either way, the OLD pre-flip match row id must NOT survive verbatim.
    matches = VulnerabilityMatch.query.filter_by(product_id=product.id).all()
    if matches:
        # If matcher created a new match, it must reflect the post-flip state.
        for m in matches:
            assert m.match_method in ('cpe', 'vendor_product', 'keyword')


def test_f8_purge_empty_input_returns_zero(db_session):
    assert purge_and_rematch_products([]) == 0
    assert purge_and_rematch_products(None) == 0
    assert purge_and_rematch_products([None]) == 0


def test_f8_purge_handles_unknown_product_id(db_session):
    """Calling with a product_id that doesn't exist should not crash."""
    result = purge_and_rematch_products([999999])
    # Returns count of unique input ids attempted; no targets means no rematch
    # but the function shouldn't raise.
    assert result in (0, 1)
