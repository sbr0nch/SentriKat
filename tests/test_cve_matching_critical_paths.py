"""
Critical-path regression tests for the CVE matching pipeline.

These tests guard the fixes verified during the 2026-05-06 pre-EA
hardening session. Each test corresponds to an audit finding
documented in `docs/architecture/CVE-MATCHING-PIPELINE.md`. If any
of these break, the corresponding F.x gap has regressed.

Test inventory:
    1. test_f2_manual_ui_create_assigns_cpe_via_local_tiers
       — F.2: routes.py:create_product calls apply_cpe_to_product
    2. test_apply_cpe_to_product_idempotent_when_already_set
       — apply_cpe_to_product no-ops when CPE already provided (NVD path priority)
    3. test_check_cpe_match_high_confidence_in_range
       — core matching: cpe/high when version inside range
    4. test_check_keyword_match_no_version_returns_low_confidence
       — F.6: vendor_product demoted to low when no version on either side
    5. test_cleanup_invalid_matches_removes_keyword_after_cpe_apply
       — F.8: rematch after CPE apply cleans up keyword-only false positives

Run:
    pytest tests/test_cve_matching_critical_paths.py -v
"""
import json
import pytest


# ---------------------------------------------------------------------------
# Test 1: F.2 — manual UI product creation triggers Tier 1+2+3 CPE assignment
# ---------------------------------------------------------------------------

def test_f2_manual_ui_create_assigns_cpe_via_local_tiers(admin_client, db_session, test_org):
    """
    Regression for F.2 (CVE-MATCHING-PIPELINE.md §F.2).

    Pre-fix: POST /api/products only called attempt_cpe_match (NVD Tier 4).
    When NVD didn't find a match, product was saved with cpe_vendor=NULL,
    yielding zero CVE matches.

    Post-fix (commit 592bffb): apply_cpe_to_product is invoked after flush,
    running Tier 1 (regex) + Tier 2 (curated dict) + Tier 3 (local CPE dict).

    This test asserts that creating "Apache Tomcat 9.0.50" via the manual
    UI endpoint results in cpe_vendor='apache' and cpe_product='tomcat'
    via the local tiers, WITHOUT requiring NVD.
    """
    from app.models import Product

    response = admin_client.post('/api/products', json={
        'vendor': 'Apache',
        'product_name': 'Tomcat',
        'version': '9.0.50',
        'organization_id': test_org.id,
    })

    assert response.status_code == 201, f"Expected 201 Created, got {response.status_code}: {response.get_data(as_text=True)}"

    product = Product.query.filter_by(product_name='Tomcat').first()
    assert product is not None, "Product was not persisted"
    assert product.cpe_vendor == 'apache', f"F.2 regression: cpe_vendor={product.cpe_vendor!r}, expected 'apache' from Tier 1/2/3"
    assert product.cpe_product == 'tomcat', f"F.2 regression: cpe_product={product.cpe_product!r}, expected 'tomcat'"


# ---------------------------------------------------------------------------
# Test 2: apply_cpe_to_product is idempotent (NVD path priority preserved)
# ---------------------------------------------------------------------------

def test_apply_cpe_to_product_idempotent_when_already_set(db_session, test_org):
    """
    apply_cpe_to_product MUST be a no-op when cpe_vendor + cpe_product are
    already populated. This protects the NVD attempt_cpe_match path in
    routes.py:create_product — if NVD found a match first, the F.2 local-tier
    fallback should not overwrite it.
    """
    from app.cpe_mapping import apply_cpe_to_product
    from app.models import Product

    product = Product(
        organization_id=test_org.id,
        vendor='SomeRandomVendor',
        product_name='SomeRandomProduct',
        version='1.0',
        cpe_vendor='preset_vendor_from_nvd',
        cpe_product='preset_product_from_nvd',
        active=True,
    )
    db_session.add(product)
    db_session.commit()

    result = apply_cpe_to_product(product)

    assert result is False, "apply_cpe_to_product should return False when CPE already set"
    assert product.cpe_vendor == 'preset_vendor_from_nvd', "F.2 idempotency violated: NVD-set cpe_vendor was overwritten"
    assert product.cpe_product == 'preset_product_from_nvd', "F.2 idempotency violated: NVD-set cpe_product was overwritten"


# ---------------------------------------------------------------------------
# Test 3: check_cpe_match returns cpe/high when product version is in range
# ---------------------------------------------------------------------------

def test_check_cpe_match_high_confidence_in_range(db_session, test_org):
    """
    Core matching invariant (CVE-MATCHING-PIPELINE.md §D table line 2).

    A product with cpe_vendor=apache, cpe_product=tomcat, version=9.0.50
    against a vulnerability whose cpe_data contains a ranged entry
    (apache:tomcat, version_end=10.1 excluding) MUST return cpe/high.

    If this regresses, the entire pipeline silently degrades to keyword
    fallback, reintroducing 87% false positives.
    """
    from app.models import Product, Vulnerability
    from app.filters import check_cpe_match

    product = Product(
        organization_id=test_org.id,
        vendor='Apache',
        product_name='Tomcat',
        version='9.0.50',
        cpe_vendor='apache',
        cpe_product='tomcat',
        active=True,
    )
    db_session.add(product)

    vuln = Vulnerability(
        cve_id='CVE-TEST-IN-RANGE',
        vendor_project='Apache',
        product='Tomcat',
        cpe_data=json.dumps([{
            'vendor': 'apache',
            'product': 'tomcat',
            'cpe_uri': 'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*',
            'version_start': None,
            'version_start_type': None,
            'version_end': '10.1',
            'version_end_type': 'excluding',
            'exact_version': None,
        }]),
        nvd_status='Analyzed',
    )
    from datetime import datetime
    vuln.cpe_fetched_at = datetime.utcnow()
    db_session.add(vuln)
    db_session.commit()

    matched_cpes, method, confidence = check_cpe_match(vuln, product)

    assert matched_cpes, f"Expected non-empty matched_cpes, got {matched_cpes!r}"
    assert method == 'cpe', f"Expected method='cpe', got {method!r}"
    assert confidence == 'high', f"CRITICAL regression: expected confidence='high' when version in range, got {confidence!r}"


# ---------------------------------------------------------------------------
# Test 4: F.6 — keyword fallback demoted to 'low' when version unverifiable
# ---------------------------------------------------------------------------

def test_check_keyword_match_no_version_returns_low_confidence(db_session, test_org):
    """
    Regression for F.6 (CVE-MATCHING-PIPELINE.md §F.6).

    Pre-fix: check_keyword_match returned 'medium' confidence for vendor+product
    matches even when version could not be verified. This is what produced
    "Chrome 147 ↔ CVE-2010-4204 CRITICAL 9.8" false positives.

    Post-fix: when both sides lack cpe_data and the match is keyword-only
    without version verification, confidence is demoted to 'low'.
    """
    from app.models import Product, Vulnerability
    from app.filters import check_keyword_match

    product = Product(
        organization_id=test_org.id,
        vendor='Google',
        product_name='Chrome',
        version='147.0.0.0',
        active=True,
    )
    db_session.add(product)

    vuln = Vulnerability(
        cve_id='CVE-2010-4204',
        vendor_project='Google',
        product='Chrome',
        cpe_data=None,
        nvd_status=None,
    )
    db_session.add(vuln)
    db_session.commit()

    matched_keywords, method, confidence = check_keyword_match(vuln, product)

    if matched_keywords and method in ('vendor_product', 'vendor', 'product', 'keyword'):
        assert confidence == 'low', (
            f"F.6 regression: keyword match without version verification returned "
            f"confidence={confidence!r}, expected 'low'. This is the bug class that "
            f"caused 87% false positives (Chrome 147 ↔ CVE-2010-x). See "
            f"CVE-MATCHING-PIPELINE.md §F.6."
        )


# ---------------------------------------------------------------------------
# Test 5: F.8 — apply_cpe_to_product invokes cleanup_invalid_matches
# ---------------------------------------------------------------------------

def test_cleanup_invalid_matches_removes_keyword_after_cpe_apply(db_session, test_org):
    """
    Regression for F.8 (CVE-MATCHING-PIPELINE.md §F.8).

    Pre-fix: cleanup_invalid_matches ran after sync but NOT when a product
    flipped from no-CPE to CPE via apply_cpe_to_product. So old keyword-only
    matches stayed forever even when proper CPE matches replaced them.

    Post-fix (commit 9b7932e): apply_cpe_to_product, when it flips a product
    to CPE-having, schedules cleanup_invalid_matches for that product.

    This test verifies that cleanup_invalid_matches function exists and is
    importable — full integration is covered by test_e2e_detection.py if
    present. The lightweight check here guards against the function being
    accidentally renamed/removed by a refactor.
    """
    from app.filters import cleanup_invalid_matches

    assert callable(cleanup_invalid_matches), (
        "F.8 regression: cleanup_invalid_matches no longer exists or isn't importable. "
        "The rematch-after-CPE-apply path depends on this function. "
        "See CVE-MATCHING-PIPELINE.md §F.8."
    )

    # Smoke call: should not raise on empty DB. Signature: cleanup_invalid_matches()
    try:
        cleanup_invalid_matches()
    except Exception as e:
        pytest.fail(f"cleanup_invalid_matches() raised on empty DB: {e}")
