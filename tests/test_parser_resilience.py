"""Tests for app.parser_resilience helpers + refactored CISA/NVD parsers.

R-PARSER-RESILIENCE acceptance: a synthetic upstream payload with
renamed/re-nested OPTIONAL fields must still ingest; renamed REQUIRED
fields produce SchemaIncompatibleError without aborting the batch.
"""

import pytest

from app.parser_resilience import (
    SchemaIncompatibleError,
    coerce_bool,
    coerce_float,
    coerce_severity,
    detect_schema_drift,
    get_aliased,
    require_aliased,
    shape_hash,
)


class TestGetAliased:
    def test_first_alias_wins(self):
        payload = {'a': 'first', 'b': 'second'}
        assert get_aliased(payload, ['a', 'b']) == 'first'

    def test_falls_through_to_second_alias(self):
        payload = {'b': 'second'}
        assert get_aliased(payload, ['a', 'b']) == 'second'

    def test_dotted_path_resolves_nested(self):
        payload = {'cve': {'id': 'CVE-2024-1'}}
        assert get_aliased(payload, ['cveId', 'cve.id']) == 'CVE-2024-1'

    def test_array_index_path(self):
        payload = {'metrics': [{'score': 7.5}]}
        assert get_aliased(payload, ['metrics.0.score']) == 7.5

    def test_default_when_no_match(self):
        assert get_aliased({}, ['a', 'b'], default='X') == 'X'

    def test_none_skipped_in_favor_of_next(self):
        payload = {'a': None, 'b': 'second'}
        assert get_aliased(payload, ['a', 'b']) == 'second'


class TestRequireAliased:
    def test_raises_on_missing(self):
        with pytest.raises(SchemaIncompatibleError):
            require_aliased({}, ['cveId', 'cve.id'], 'cve_id')

    def test_raises_on_empty_string(self):
        with pytest.raises(SchemaIncompatibleError):
            require_aliased({'cveId': ''}, ['cveId'], 'cve_id')

    def test_returns_value(self):
        assert require_aliased({'cveId': 'X'}, ['cveId'], 'cve_id') == 'X'

    def test_error_includes_record_id(self):
        try:
            require_aliased({}, ['x'], 'cve_id', record_id='REC-1')
        except SchemaIncompatibleError as e:
            assert 'REC-1' in str(e)


class TestCoerceSeverity:
    @pytest.mark.parametrize("inp,expected", [
        ('HIGH', 'HIGH'),
        ('high', 'HIGH'),
        ('High', 'HIGH'),
        ('moderate', 'MEDIUM'),
        ('CRITICAL', 'CRITICAL'),
        ('low', 'LOW'),
        ('info', 'NONE'),
        (9.5, 'CRITICAL'),
        (7.0, 'HIGH'),
        (4.0, 'MEDIUM'),
        (0.5, 'LOW'),
        (0.0, 'LOW'),  # 0.0 still hits the LOW band per design
        ('7.5', 'HIGH'),
        (None, None),
        ('', None),
        ('garbage', None),
        (True, None),  # bool excluded
    ])
    def test_coerce(self, inp, expected):
        assert coerce_severity(inp) == expected


class TestCoerceFloat:
    @pytest.mark.parametrize("inp,expected", [
        (7.5, 7.5),
        (7, 7.0),
        ('7.5', 7.5),
        ('  3.14  ', 3.14),
        (None, None),
        ('', None),
        ('not-a-number', None),
        (True, None),
    ])
    def test_coerce(self, inp, expected):
        assert coerce_float(inp) == expected


class TestCoerceBool:
    @pytest.mark.parametrize("inp,expected", [
        (True, True),
        (False, False),
        ('Known', True),  # CISA KEV ransomware indicator
        ('Unknown', False),
        ('true', True),
        ('1', True),
        ('yes', True),
        ('no', False),
        (1, True),
        (0, False),
        (None, False),
    ])
    def test_coerce(self, inp, expected):
        assert coerce_bool(inp) == expected


class TestShapeHash:
    def test_same_shape_same_hash(self):
        a = {'cveID': 'CVE-1', 'metrics': [{'score': 9.0}]}
        b = {'cveID': 'CVE-2', 'metrics': [{'score': 4.5}]}
        assert shape_hash(a) == shape_hash(b)

    def test_different_keys_different_hash(self):
        a = {'cveID': 'CVE-1'}
        b = {'cve_id': 'CVE-1'}
        assert shape_hash(a) != shape_hash(b)

    def test_added_key_changes_hash(self):
        a = {'cveID': 'CVE-1'}
        b = {'cveID': 'CVE-1', 'newField': True}
        assert shape_hash(a) != shape_hash(b)

    def test_array_element_shape_sampled(self):
        # Same element shape → same hash regardless of length
        a = {'items': [{'k': 'v'}]}
        b = {'items': [{'k': 'a'}, {'k': 'b'}]}
        assert shape_hash(a) == shape_hash(b)


class TestDetectSchemaDrift:
    def test_first_call_no_drift(self):
        # Fresh feed name — caches but does not report drift
        assert detect_schema_drift('test_feed_first', {'a': 1}) is False

    def test_second_call_same_shape_no_drift(self):
        detect_schema_drift('test_feed_stable', {'a': 1})
        assert detect_schema_drift('test_feed_stable', {'a': 2}) is False

    def test_changed_shape_reports_drift(self):
        detect_schema_drift('test_feed_drift', {'a': 1})
        assert detect_schema_drift('test_feed_drift', {'a': 1, 'b': 2}) is True


class TestNvdParserResilience:
    """Verify NVD CVSS extraction tolerates upstream renames."""

    def test_canonical_nvd_2_payload_extracts_correctly(self):
        from app.nvd_api import _extract_cvss_entry
        entry = {
            'type': 'Primary',
            'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'},
        }
        assert _extract_cvss_entry(entry) == (9.8, 'CRITICAL')

    def test_flattened_payload_still_extracts(self):
        # Hypothetical NVD 3.x flatten — no cvssData wrapper
        from app.nvd_api import _extract_cvss_entry
        entry = {'type': 'Primary', 'baseScore': 7.5, 'baseSeverity': 'HIGH'}
        assert _extract_cvss_entry(entry) == (7.5, 'HIGH')

    def test_severity_coerced_from_score_when_missing(self):
        from app.nvd_api import _extract_cvss_entry
        entry = {'cvssData': {'baseScore': 9.5}}  # no baseSeverity
        score, sev = _extract_cvss_entry(entry)
        assert score == 9.5
        assert sev == 'CRITICAL'

    def test_string_score_coerced_to_float(self):
        from app.nvd_api import _extract_cvss_entry
        entry = {'cvssData': {'baseScore': '7.5', 'baseSeverity': 'high'}}
        score, sev = _extract_cvss_entry(entry)
        assert score == 7.5
        assert sev == 'HIGH'

    def test_lowercase_severity_normalised(self):
        from app.nvd_api import _extract_cvss_entry
        entry = {'cvssData': {'baseScore': 5.0, 'baseSeverity': 'medium'}}
        assert _extract_cvss_entry(entry) == (5.0, 'MEDIUM')


class TestKevAliasMap:
    """Verify CISA KEV record-level aliases match real and renamed payloads."""

    def test_aliases_resolve_canonical(self):
        from app.cisa_sync import _KEV_ALIASES
        record = {
            'cveID': 'CVE-2024-1',
            'vendorProject': 'Acme',
            'product': 'Widget',
            'vulnerabilityName': 'RCE',
            'dateAdded': '2024-01-01',
            'dueDate': '2024-02-01',
            'shortDescription': 'desc',
            'requiredAction': 'patch',
            'knownRansomwareCampaignUse': 'Known',
            'notes': 'n',
        }
        for canonical, aliases in _KEV_ALIASES.items():
            assert get_aliased(record, aliases) is not None, (
                f"Alias chain for {canonical!r} did not resolve in canonical record"
            )

    def test_aliases_resolve_renamed(self):
        # Hypothetical CISA-side rename: vendorProject → vendor, dueDate → due_date
        from app.cisa_sync import _KEV_ALIASES
        record = {
            'cve_id': 'CVE-2024-2',
            'vendor': 'Acme',
            'productName': 'Widget',
            'name': 'RCE',
            'date_added': '2024-01-01',
            'due_date': '2024-02-01',
        }
        assert get_aliased(record, _KEV_ALIASES['cve_id']) == 'CVE-2024-2'
        assert get_aliased(record, _KEV_ALIASES['vendor_project']) == 'Acme'
        assert get_aliased(record, _KEV_ALIASES['product']) == 'Widget'
        assert get_aliased(record, _KEV_ALIASES['vulnerability_name']) == 'RCE'
        assert get_aliased(record, _KEV_ALIASES['date_added']) == '2024-01-01'
        assert get_aliased(record, _KEV_ALIASES['due_date']) == '2024-02-01'

    def test_required_field_missing_raises(self):
        from app.cisa_sync import _KEV_ALIASES
        record = {'vendorProject': 'Acme'}  # no cveID/cve_id
        with pytest.raises(SchemaIncompatibleError):
            require_aliased(record, _KEV_ALIASES['cve_id'], 'cve_id')
