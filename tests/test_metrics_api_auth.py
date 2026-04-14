"""
Tests for the /metrics endpoint auth overhaul (H1, H2) and float
formatting (M16).
"""

import re
import pytest


class TestMetricsAuth:
    def test_no_auth_returns_401(self, client, monkeypatch, setup_complete):
        monkeypatch.setenv('SENTRIKAT_METRICS_KEY', 'shh')
        monkeypatch.delenv('SENTRIKAT_PROVISION_KEY', raising=False)
        resp = client.get('/metrics')
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self, client, monkeypatch, setup_complete):
        monkeypatch.setenv('SENTRIKAT_METRICS_KEY', 'shh')
        resp = client.get('/metrics', headers={'Authorization': 'Bearer nope'})
        assert resp.status_code == 401

    def test_localhost_no_longer_bypasses_auth(self, client, monkeypatch, setup_complete):
        """H1: even 127.0.0.1 must present a bearer token."""
        monkeypatch.setenv('SENTRIKAT_METRICS_KEY', 'shh')
        # Flask's test client puts remote_addr=127.0.0.1 by default.
        resp = client.get('/metrics')
        assert resp.status_code == 401

    def test_valid_token_returns_metrics(self, client, monkeypatch, setup_complete):
        monkeypatch.setenv('SENTRIKAT_METRICS_KEY', 'shh')
        resp = client.get('/metrics', headers={'Authorization': 'Bearer shh'})
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'sentrikat_organizations_active' in body
        assert 'sentrikat_metrics_duration_seconds' in body

    def test_provision_key_fallback_still_works(self, client, monkeypatch, setup_complete):
        """H2: fallback is allowed for now but logs a deprecation warning."""
        monkeypatch.delenv('SENTRIKAT_METRICS_KEY', raising=False)
        monkeypatch.setenv('SENTRIKAT_PROVISION_KEY', 'provkey')
        resp = client.get('/metrics', headers={'Authorization': 'Bearer provkey'})
        assert resp.status_code == 200

    def test_no_keys_configured_denies(self, client, monkeypatch, setup_complete):
        monkeypatch.delenv('SENTRIKAT_METRICS_KEY', raising=False)
        monkeypatch.delenv('SENTRIKAT_PROVISION_KEY', raising=False)
        resp = client.get('/metrics', headers={'Authorization': 'Bearer anything'})
        assert resp.status_code == 401


class TestMetricsFormat:
    def test_no_scientific_notation(self, client, monkeypatch, setup_complete):
        """M16: we must never emit scientific-notation numbers."""
        monkeypatch.setenv('SENTRIKAT_METRICS_KEY', 'shh')
        resp = client.get('/metrics', headers={'Authorization': 'Bearer shh'})
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        sci = re.findall(r'\d+\.?\d*[eE][+-]?\d+', body)
        assert sci == [], f"scientific notation values found: {sci}"
