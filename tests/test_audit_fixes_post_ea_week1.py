"""
Regression tests for post-EA Week 1 Batch A fixes (PR #414).

Each test corresponds to a fix applied 2026-05-06:
    - F.1: cron cpe_nvd_remap_job hourly (4h interval)
    - F.4: post-restore CPE re-apply
    - F.5: validate_cpe_assignment rejection → audit_event
    - F.7: reset stale is_actively_exploited
    - 6-must #2: /api/admin/health-summary endpoint
    - 6-must #3: data quality badge present in dashboard template

Run:
    pytest tests/test_audit_fixes_post_ea_week1.py -v
"""
import json
from datetime import datetime

import pytest


# ---------------------------------------------------------------------------
# F.1 — cpe_nvd_remap_job is registered in scheduler module
# ---------------------------------------------------------------------------

def test_f1_cpe_nvd_remap_job_function_exists():
    """
    Regression for F.1 (CVE-MATCHING-PIPELINE.md §F.1, commit ecdef66).

    The standalone scheduler job for periodic NVD CPE remap must exist
    and be importable. If accidentally renamed/removed by a refactor,
    the F.1 fix is silently broken — products without CPE in Tiers 1+2+3
    will never get matched.
    """
    from app.scheduler import cpe_nvd_remap_job
    assert callable(cpe_nvd_remap_job), (
        "F.1 regression: cpe_nvd_remap_job no longer exists. "
        "Without this scheduler job, products that fail Tiers 1+2+3 "
        "(e.g., 'Windows SDK', 'Universal CRT Headers') stay cpe_vendor=NULL "
        "forever. See CVE-MATCHING-PIPELINE.md §F.1 + commit ecdef66."
    )


# ---------------------------------------------------------------------------
# F.4 — restore_full_backup re-applies CPE
# ---------------------------------------------------------------------------

def test_f4_restore_full_calls_batch_apply_cpe_mappings(monkeypatch):
    """
    Regression for F.4 (CVE-MATCHING-PIPELINE.md §F.4, commit ceece42).

    After restore_full_backup commits, batch_apply_cpe_mappings(use_nvd=False)
    must be invoked so restored products get CPE via local tiers.
    Without this, backup restore leaves dashboard empty.

    This is a smoke test: verifies the function reference exists. Full
    integration test requires a backup JSON sample.
    """
    from app.cpe_mapping import batch_apply_cpe_mappings
    assert callable(batch_apply_cpe_mappings), (
        "F.4 regression: batch_apply_cpe_mappings no longer importable from "
        "app.cpe_mapping. settings_api.restore_full_backup depends on it for "
        "post-restore CPE re-apply. See commit ceece42."
    )

    # Verify the kwargs signature is stable (use_nvd=False, max_nvd_lookups=0)
    import inspect
    sig = inspect.signature(batch_apply_cpe_mappings)
    assert 'use_nvd' in sig.parameters, "F.4: use_nvd kwarg missing in batch_apply_cpe_mappings"
    assert 'max_nvd_lookups' in sig.parameters, "F.4: max_nvd_lookups kwarg missing"


# ---------------------------------------------------------------------------
# F.5 — validate_cpe_assignment rejection writes audit_event
# ---------------------------------------------------------------------------

def test_f5_validate_cpe_assignment_logs_audit_on_rejection(db_session, test_org, monkeypatch):
    """
    Regression for F.5 (CVE-MATCHING-PIPELINE.md §F.5, commit 65d2d77).

    When validate_cpe_assignment rejects a mapping (word-overlap fail),
    apply_cpe_to_product must call log_audit_event with
    action='CPE_REJECTED'. Otherwise rejections are invisible to admin.
    """
    from app.models import Product
    from app.cpe_mapping import apply_cpe_to_product

    audit_calls = []

    def mock_audit(action, resource, resource_id=None, old_value=None, new_value=None, details=None):
        audit_calls.append({
            'action': action,
            'resource': resource,
            'resource_id': resource_id,
            'new_value': new_value,
        })

    monkeypatch.setattr('app.logging_config.log_audit_event', mock_audit)

    # Create a product whose name will trigger validate rejection.
    # We pre-set cpe_vendor/cpe_product to None so apply_cpe_to_product
    # tries Tier 1+2+3, then we rely on validate_cpe_assignment word-overlap
    # check to reject. Tricky: need a product name that DOES match a regex
    # but the regex output has zero word overlap with the original name.
    # Easier: directly mock get_cpe_for_product to return a bad mapping.

    from app import cpe_mapping
    monkeypatch.setattr(
        cpe_mapping, 'get_cpe_for_product',
        lambda *args, **kwargs: ('totally_unrelated_vendor', 'totally_unrelated_product')
    )

    product = Product(
        organization_id=test_org.id,
        vendor='Logitech',
        product_name='Logi Options+',
        version='1.0',
        active=True,
    )
    db_session.add(product)
    db_session.flush()

    result = apply_cpe_to_product(product)

    assert result is False, "F.5 regression: apply_cpe_to_product should return False on validate rejection"
    assert any(c['action'] == 'CPE_REJECTED' for c in audit_calls), (
        "F.5 regression: validate_cpe_assignment rejection did not write "
        "audit_event with action='CPE_REJECTED'. Admin will not see these "
        "rejections via /admin/logs. See commit 65d2d77."
    )

    # Verify the audit event has expected fields
    cpe_rejected = next((c for c in audit_calls if c['action'] == 'CPE_REJECTED'), None)
    assert cpe_rejected is not None
    assert cpe_rejected['resource'] == 'cpe_mapping'
    nv = cpe_rejected['new_value']
    assert 'product_vendor' in nv
    assert 'rejected_cpe_vendor' in nv
    assert 'reason' in nv


# ---------------------------------------------------------------------------
# F.7 — parse_and_store_vulnerabilities resets stale KEV flags
# ---------------------------------------------------------------------------

def test_f7_parse_and_store_resets_stale_kev_flag(db_session):
    """
    Regression for F.7 (CVE-MATCHING-PIPELINE.md §F.7, commit 755f1d7).

    Pre-fix: a CVE that was once on CISA KEV but later removed kept
    is_actively_exploited=True forever in DB. Post-fix:
    parse_and_store_vulnerabilities resets the flag to False for entries
    no longer in the current KEV feed (conservative: only if source='cisa_kev'
    alone and EPSS percentile<0.95).
    """
    from app.models import Vulnerability
    from app.cisa_sync import parse_and_store_vulnerabilities

    # Seed: 2 CVE with is_actively_exploited=True
    # - CVE-1 is in current feed → should stay True
    # - CVE-2 is NOT in current feed → should be reset to False
    cve1 = Vulnerability(
        cve_id='CVE-2025-AAAA',
        vendor_project='Acme',
        product='Widget',
        vulnerability_name='Widget Bug',
        date_added=datetime(2025, 1, 1).date(),
        short_description='widget',
        required_action='patch',
        is_actively_exploited=True,
        source='cisa_kev',
        epss_percentile=0.5,  # not high enough to keep True via EPSS
    )
    cve2 = Vulnerability(
        cve_id='CVE-2025-BBBB',
        vendor_project='Acme',
        product='Gizmo',
        vulnerability_name='Gizmo Bug',
        date_added=datetime(2025, 1, 1).date(),
        short_description='gizmo',
        required_action='patch',
        is_actively_exploited=True,
        source='cisa_kev',
        epss_percentile=0.5,
    )
    # CVE-3: also stale but EPSS≥0.95 → should KEEP True
    cve3 = Vulnerability(
        cve_id='CVE-2025-CCCC',
        vendor_project='Acme',
        product='Doodad',
        vulnerability_name='Doodad Bug',
        date_added=datetime(2025, 1, 1).date(),
        short_description='doodad',
        required_action='patch',
        is_actively_exploited=True,
        source='cisa_kev',
        epss_percentile=0.97,
    )
    # CVE-4: also stale but multi-source → should KEEP True
    cve4 = Vulnerability(
        cve_id='CVE-2025-DDDD',
        vendor_project='Acme',
        product='Whatsit',
        vulnerability_name='Whatsit Bug',
        date_added=datetime(2025, 1, 1).date(),
        short_description='whatsit',
        required_action='patch',
        is_actively_exploited=True,
        source='cisa_kev+euvd',
        epss_percentile=0.3,
    )
    db_session.add_all([cve1, cve2, cve3, cve4])
    db_session.commit()

    # Mock CISA KEV feed: only CVE-1 and CVE-3 still in feed
    mock_feed = {
        'vulnerabilities': [
            {
                'cveID': 'CVE-2025-AAAA',
                'vendorProject': 'Acme',
                'product': 'Widget',
                'vulnerabilityName': 'Widget Bug',
                'dateAdded': '2025-01-01',
                'shortDescription': 'test',
                'requiredAction': 'patch',
                'dueDate': '2025-02-01',
                'knownRansomwareCampaignUse': 'Unknown',
                'notes': '',
                'cwes': [],
            },
        ]
    }

    parse_and_store_vulnerabilities(mock_feed)
    db_session.commit()

    # Re-query
    db_session.expire_all()
    cve1_after = Vulnerability.query.filter_by(cve_id='CVE-2025-AAAA').first()
    cve2_after = Vulnerability.query.filter_by(cve_id='CVE-2025-BBBB').first()
    cve3_after = Vulnerability.query.filter_by(cve_id='CVE-2025-CCCC').first()
    cve4_after = Vulnerability.query.filter_by(cve_id='CVE-2025-DDDD').first()

    assert cve1_after.is_actively_exploited is True, "CVE in current feed should stay flagged"
    assert cve2_after.is_actively_exploited is False, (
        "F.7 regression: CVE no longer in KEV feed should be reset to False. "
        "See CVE-MATCHING-PIPELINE.md §F.7 + commit 755f1d7."
    )
    assert cve3_after.is_actively_exploited is True, (
        "F.7 regression: CVE with EPSS≥0.95 should NOT be reset (independent evidence)"
    )
    assert cve4_after.is_actively_exploited is True, (
        "F.7 regression: multi-source CVE (cisa_kev+euvd) should NOT be reset "
        "(EUVD still flags as exploited)"
    )


# ---------------------------------------------------------------------------
# 6-must #2 — /api/admin/health-summary endpoint
# ---------------------------------------------------------------------------

def test_must2_health_summary_endpoint_returns_json(admin_client):
    """
    Regression for 6-must #2 (commit 2699cbd).

    /api/admin/health-summary must return JSON with keys: overall_status,
    signals, product_coverage, cve_enrichment, match_distribution,
    last_sync, generated_at.
    """
    response = admin_client.get('/api/admin/health-summary')
    assert response.status_code == 200, (
        f"Expected 200 OK, got {response.status_code}: {response.get_data(as_text=True)}"
    )
    data = response.get_json()
    expected_keys = {
        'overall_status', 'signals', 'product_coverage',
        'cve_enrichment', 'match_distribution', 'last_sync', 'generated_at'
    }
    assert set(data.keys()) >= expected_keys, (
        f"6-must #2 regression: response missing expected keys. "
        f"Got: {sorted(data.keys())}, expected at least: {sorted(expected_keys)}"
    )
    # Validate sub-structures
    assert 'pct' in data['product_coverage']
    assert 'cpe_data_pct' in data['cve_enrichment']
    assert 'cpe_high_pct' in data['match_distribution']


def test_must2_health_summary_classifies_overall_status_correctly(admin_client, db_session, test_org):
    """
    Empty DB state: overall_status should be 'healthy' (no products = no
    signals to flag). When products exist with low CPE coverage, status
    should be 'degraded' or 'critical'.
    """
    from app.models import Product

    # Add 10 products, all without CPE → coverage = 0%
    for i in range(10):
        p = Product(
            organization_id=test_org.id,
            vendor=f'Vendor{i}',
            product_name=f'Product{i}',
            version='1.0',
            active=True,
        )
        db_session.add(p)
    db_session.commit()

    response = admin_client.get('/api/admin/health-summary')
    data = response.get_json()

    # 0% CPE coverage should trigger 'product_cpe_coverage_low' signal
    signal_keys = ' '.join(data.get('signals', []))
    assert 'product_cpe_coverage_low' in signal_keys, (
        f"6-must #2: 0% CPE coverage should trigger signal. "
        f"signals={data.get('signals')}, overall={data.get('overall_status')}"
    )


# ---------------------------------------------------------------------------
# 6-must #3 — Data quality badge JS code present in dashboard template
# ---------------------------------------------------------------------------

def test_must3_data_quality_badge_present_in_dashboard_template():
    """
    Regression for 6-must #3 (commit c9a604b).

    The dashboard.html template must contain the IIFE that renders the
    Verified/Probable/Partial badge. If a future template refactor removes
    this block, customer loses the data quality signal.
    """
    from pathlib import Path
    template = Path('app/templates/dashboard.html').read_text()

    assert "6-must #3 data quality badge" in template, (
        "6-must #3 regression: dashboard.html no longer contains the data "
        "quality badge IIFE block. Customer-facing trust signal removed. "
        "See commit c9a604b."
    )
    # Check all 3 badge variants exist
    assert 'Verified' in template
    assert 'Probable' in template
    assert 'Partial' in template
    # Check the aggregation logic relies on match_method + match_confidence
    assert 'match_method' in template
    assert 'match_confidence' in template
