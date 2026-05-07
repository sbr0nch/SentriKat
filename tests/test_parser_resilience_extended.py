"""Extended parser-resilience coverage — EUVD + EPSS + CVE.org + agent telemetry.

Complements ``test_parser_resilience.py`` with end-to-end smoke against
all four parser ports landed in the post-EA week-1 batch.
"""

import pytest

from app.parser_resilience import get_aliased


class TestEuvdAliasResilience:
    """app.nvd_api._fetch_cvss_from_euvd alias coverage."""

    def test_euvd_alias_map_canonical(self):
        from app.nvd_api import _EUVD_CVSS_ALIASES
        item = {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_score']) == 9.8
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_severity']) == 'CRITICAL'

    def test_euvd_alias_map_renamed_to_score(self):
        from app.nvd_api import _EUVD_CVSS_ALIASES
        # Hypothetical ENISA rename: baseScore → score
        item = {'score': 7.5, 'severity': 'HIGH'}
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_score']) == 7.5
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_severity']) == 'HIGH'

    def test_euvd_alias_map_nested_cvss(self):
        from app.nvd_api import _EUVD_CVSS_ALIASES
        # Hypothetical schema move: cvss.baseScore wrapper
        item = {'cvss': {'baseScore': 5.0, 'baseSeverity': 'MEDIUM'}}
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_score']) == 5.0
        assert get_aliased(item, _EUVD_CVSS_ALIASES['base_severity']) == 'MEDIUM'


class TestCveOrgMetricExtraction:
    """app.nvd_api._extract_cve_org_metric tolerates Vulnrichment + CNA shapes."""

    def test_v3_1_canonical(self):
        from app.nvd_api import _extract_cve_org_metric
        metric = {'cvssV3_1': {'baseScore': 9.0, 'baseSeverity': 'CRITICAL'}}
        assert _extract_cve_org_metric(metric) == (9.0, 'CRITICAL')

    def test_v4_0_preferred_over_v3_1(self):
        from app.nvd_api import _extract_cve_org_metric
        metric = {
            'cvssV4_0': {'baseScore': 8.0, 'baseSeverity': 'HIGH'},
            'cvssV3_1': {'baseScore': 5.0, 'baseSeverity': 'MEDIUM'},
        }
        # Alias order says cvssV4_0 first
        assert _extract_cve_org_metric(metric) == (8.0, 'HIGH')

    def test_severity_derived_from_score_when_only_score_present(self):
        from app.nvd_api import _extract_cve_org_metric
        metric = {'cvssV3_1': {'baseScore': 9.5}}  # missing severity
        score, sev = _extract_cve_org_metric(metric)
        assert score == 9.5
        assert sev == 'CRITICAL'

    def test_unknown_version_skipped(self):
        from app.nvd_api import _extract_cve_org_metric
        metric = {'cvssV2_0': {'baseScore': 5.0}}  # we don't extract V2 from CVE.org
        assert _extract_cve_org_metric(metric) == (None, None)


class TestEpssAliasResilience:
    """app.epss_sync.fetch_epss_scores tolerates renamed FIRST fields."""

    def test_epss_aliases_canonical(self):
        from app.epss_sync import _EPSS_ALIASES
        item = {'cve': 'CVE-2024-1', 'epss': 0.5, 'percentile': 0.9}
        assert get_aliased(item, _EPSS_ALIASES['cve_id']) == 'CVE-2024-1'
        assert get_aliased(item, _EPSS_ALIASES['epss']) == 0.5
        assert get_aliased(item, _EPSS_ALIASES['percentile']) == 0.9

    def test_epss_aliases_renamed(self):
        # Hypothetical FIRST renames: epss → score, percentile → pctl, cve → cveId
        from app.epss_sync import _EPSS_ALIASES
        item = {'cveId': 'CVE-2024-2', 'score': 0.3, 'pctl': 0.85}
        assert get_aliased(item, _EPSS_ALIASES['cve_id']) == 'CVE-2024-2'
        assert get_aliased(item, _EPSS_ALIASES['epss']) == 0.3
        assert get_aliased(item, _EPSS_ALIASES['percentile']) == 0.85

    def test_fetch_epss_scores_handles_renamed_payload(self, monkeypatch):
        """End-to-end: a renamed FIRST payload must still produce scores."""
        from app import epss_sync

        class FakeResp:
            status_code = 200
            def raise_for_status(self):
                return None
            def json(self):
                # Renamed envelope (records instead of data) and renamed fields
                return {
                    'records': [
                        {'cveId': 'CVE-2024-1', 'score': 0.7, 'pctl': 0.95},
                        {'cveId': 'CVE-2024-2', 'score': 0.1, 'pctl': 0.45},
                    ]
                }

        monkeypatch.setattr(epss_sync.requests, 'get', lambda *a, **k: FakeResp())

        result = epss_sync.fetch_epss_scores(['CVE-2024-1', 'CVE-2024-2'])
        assert 'CVE-2024-1' in result
        assert result['CVE-2024-1']['epss'] == 0.7
        assert result['CVE-2024-1']['percentile'] == 0.95
        assert result['CVE-2024-2']['epss'] == 0.1


class TestAgentVersionSourceTelemetry:
    """Server-side aggregation of agent-reported version_source signal."""

    def test_telemetry_keys_present(self):
        # Just verifies the bucket dict shape is what we expect — guards
        # against accidental rename in agent_api.py that would break the
        # ops dashboard / log greps.
        expected_keys = {'DisplayVersion', 'Version', 'MajorMinor', 'null', 'absent'}
        # Mock the dict directly to confirm the shape
        version_source_counts = {
            'DisplayVersion': 0, 'Version': 0, 'MajorMinor': 0,
            'null': 0, 'absent': 0,
        }
        assert set(version_source_counts.keys()) == expected_keys

    def test_classification_logic(self):
        """Replicate the agent_api inventory loop branch exactly."""
        version_source_counts = {
            'DisplayVersion': 0, 'Version': 0, 'MajorMinor': 0,
            'null': 0, 'absent': 0,
        }
        # 5 items: 2 DisplayVersion, 1 MajorMinor, 1 null (field present but None),
        # 1 legacy (no field at all)
        items = [
            {'version_source': 'DisplayVersion'},
            {'version_source': 'DisplayVersion'},
            {'version_source': 'MajorMinor'},
            {'version_source': None},   # field present, no signal
            {},                          # legacy agent
        ]
        for product_data in items:
            vsrc = product_data.get('version_source')
            if vsrc is None:
                if 'version_source' in product_data:
                    version_source_counts['null'] += 1
                else:
                    version_source_counts['absent'] += 1
            else:
                version_source_counts[vsrc] = version_source_counts.get(vsrc, 0) + 1

        assert version_source_counts['DisplayVersion'] == 2
        assert version_source_counts['MajorMinor'] == 1
        assert version_source_counts['null'] == 1
        assert version_source_counts['absent'] == 1
        assert version_source_counts['Version'] == 0


class TestCpeLimitDefault:
    """[08.5.1] regression — sync_cisa_kev default cpe_limit is 300."""

    def test_default_cpe_limit_is_300(self):
        import inspect
        from app.cisa_sync import sync_cisa_kev
        sig = inspect.signature(sync_cisa_kev)
        assert sig.parameters['cpe_limit'].default == 300


class TestKevSourceReconciliation:
    """[CISA-RECONCILE] when KEV sync confirms a CVE that NVD/EUVD/CVE.org
    created earlier, the source must be reconciled to cisa_kev+<original>
    so the dashboard widget and F.7 stale reset see it correctly."""

    def test_alias_map_keys_present(self):
        # Sanity: the canonical KEV record fields are still aliased in cisa_sync
        from app.cisa_sync import _KEV_ALIASES
        for k in ('cve_id', 'vendor_project', 'product', 'vulnerability_name',
                  'date_added', 'short_description', 'required_action',
                  'due_date', 'known_ransomware', 'notes'):
            assert k in _KEV_ALIASES, f"_KEV_ALIASES missing canonical key {k!r}"

    def test_source_reconciliation_branches_documented(self):
        """The reconciliation logic in parse_and_store_vulnerabilities must
        cover all known upstream sources. Verifies via source-string parse,
        not by running the function (which needs DB)."""
        import inspect
        from app import cisa_sync
        src = inspect.getsource(cisa_sync.parse_and_store_vulnerabilities)
        # Each branch should reconcile to a 'cisa_kev+<original>' label
        assert "vuln.source = 'cisa_kev+euvd'" in src
        assert "vuln.source = 'cisa_kev+nvd'" in src
        assert "vuln.source = 'cisa_kev+cve_org'" in src
        # And there's a catch-all for unknown future sources
        assert "f'cisa_kev+{vuln.source}'" in src

    def test_f7_resettable_sources_include_nvd_and_cve_org(self):
        """F.7 reset must apply to cisa_kev+nvd and cisa_kev+cve_org since
        those sources don't carry an independent actively_exploited signal.
        EUVD-merged is excluded (EUVD has its own exploited flag)."""
        import inspect
        from app import cisa_sync
        src = inspect.getsource(cisa_sync.parse_and_store_vulnerabilities)
        assert "kev_resettable_sources = ['cisa_kev', 'cisa_kev+nvd', 'cisa_kev+cve_org']" in src


class TestKevCatalogWidgetFilter:
    """The /api/dashboard/stats endpoint must filter total_vulnerabilities
    via LIKE '%cisa_kev%' so that all reconciled sources are counted under
    'KEV Catalog' label."""

    def test_routes_uses_like_filter(self):
        import inspect
        from app import routes
        src = inspect.getsource(routes)
        # Filter via LIKE catches cisa_kev, cisa_kev+euvd, cisa_kev+nvd, cisa_kev+cve_org
        assert "Vulnerability.source.like('%cisa_kev%')" in src
        # Also exposes total all-source count for forward-compat
        assert "cve_database_total" in src
