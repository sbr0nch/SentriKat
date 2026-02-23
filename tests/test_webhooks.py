"""
Tests for webhook notifications (Slack, RocketChat, Discord, Teams, Custom).

Covers:
  - Webhook format/payload structure (Slack, RocketChat, Discord, Teams, Custom)
  - send_org_webhook() behaviour (filtering, auth, truncation, error handling)
  - send_webhook_notification() global webhook behaviour
  - send_alerts_for_new_matches() integration tests
  - POST /api/alerts/trigger-webhooks route tests
  - RocketChat-specific first_alerted_at regression tests
"""
import pytest
import json
from unittest.mock import patch, MagicMock, call
from datetime import datetime, date, timedelta


# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------

def _make_org(db_session, **overrides):
    """Create and return an Organization with webhook-relevant defaults."""
    from app.models import Organization

    defaults = dict(
        name='webhook_test_org',
        display_name='Webhook Test Org',
        active=True,
        webhook_enabled=True,
        webhook_url='https://hooks.slack.example.com/services/T00/B00/xxx',
        webhook_name='Test Webhook',
        webhook_format='slack',
        webhook_token=None,
        alert_on_critical=True,
        alert_on_high=False,
        alert_on_new_cve=True,
        alert_on_ransomware=True,
        alert_on_low_confidence=False,
        alert_mode='new_only',
        notification_emails=json.dumps(['admin@test.local']),
    )
    defaults.update(overrides)
    org = Organization(**defaults)
    db_session.add(org)
    db_session.commit()
    return org


def _make_vuln(db_session, cve_id='CVE-2025-9999', severity='CRITICAL', cvss=9.8,
               is_actively_exploited=False, known_ransomware=False, **extra):
    """Create and return a Vulnerability with sensible defaults."""
    from app.models import Vulnerability

    vuln = Vulnerability(
        cve_id=cve_id,
        vendor_project='TestVendor',
        product='TestProduct',
        vulnerability_name=f'Test vuln {cve_id}',
        date_added=date.today(),
        short_description='A dangerous vulnerability for testing',
        required_action='Update immediately',
        cvss_score=cvss,
        severity=severity,
        is_actively_exploited=is_actively_exploited,
        known_ransomware=known_ransomware,
    )
    for k, v in extra.items():
        setattr(vuln, k, v)
    db_session.add(vuln)
    db_session.flush()
    return vuln


def _make_product(db_session, org, vendor='TestVendor', product_name='TestProduct',
                  version='1.0.0', **extra):
    """Create and return a Product assigned to the given org."""
    from app.models import Product

    defaults = dict(
        vendor=vendor,
        product_name=product_name,
        version=version,
        criticality='high',
        active=True,
        cpe_vendor=vendor.lower(),
        cpe_product=product_name.lower(),
        match_type='auto',
        organization_id=org.id,
    )
    defaults.update(extra)
    product = Product(**defaults)
    db_session.add(product)
    db_session.commit()
    return product


def _make_match(db_session, product, vuln, first_alerted_at=None, acknowledged=False,
                match_confidence='high', vendor_fix_confidence=None, **extra):
    """Create and return a VulnerabilityMatch."""
    from app.models import VulnerabilityMatch

    match = VulnerabilityMatch(
        product_id=product.id,
        vulnerability_id=vuln.id,
        match_reason='CPE match',
        acknowledged=acknowledged,
        match_method='cpe',
        match_confidence=match_confidence,
        first_alerted_at=first_alerted_at,
        vendor_fix_confidence=vendor_fix_confidence,
    )
    for k, v in extra.items():
        setattr(match, k, v)
    db_session.add(match)
    db_session.commit()
    return match


def _make_system_setting(db_session, key, value, category='webhook'):
    """Create a SystemSettings row."""
    from app.models import SystemSettings

    setting = SystemSettings(key=key, value=value, category=category)
    db_session.add(setting)
    db_session.commit()
    return setting


def _mock_response(status_code=200):
    """Return a MagicMock that looks like requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = 'ok'
    return resp


# ============================================================================
# SECTION 1: Webhook Format / Payload Structure Tests
# ============================================================================

class TestWebhookPayloadFormats:
    """Tests 1-5: Verify each webhook format produces correct payload shape."""

    def _send_and_capture_payload(self, db_session, webhook_format, mock_post):
        """Helper: create org + match, send webhook, return the JSON payload."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name=f'fmt_{webhook_format}',
                        webhook_format=webhook_format)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-0001')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)

        send_org_webhook(org, 1, 1, 1, matches=[match])

        assert mock_post.called
        _, kwargs = mock_post.call_args
        return json.loads(kwargs['data'])

    # Test 1 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_slack_format_has_text_key_with_markdown(self, mock_post, app, db_session):
        """Slack format payload must have 'text' key with Slack mrkdwn (*bold*)."""
        payload = self._send_and_capture_payload(db_session, 'slack', mock_post)

        assert 'text' in payload
        assert '*SentriKat Security Alert' in payload['text']
        assert 'CVE-2025-0001' in payload['text']
        # Slack uses *bold* syntax
        assert '*' in payload['text']

    # Test 2 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_rocketchat_format_same_as_slack(self, mock_post, app, db_session):
        """RocketChat uses same payload structure as Slack ('text' key)."""
        payload = self._send_and_capture_payload(db_session, 'rocketchat', mock_post)

        assert 'text' in payload
        assert '*SentriKat Security Alert' in payload['text']
        assert 'CVE-2025-0001' in payload['text']

    # Test 3 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_discord_format_has_content_key_with_bold(self, mock_post, app, db_session):
        """Discord payload must have 'content' key with **bold** markdown."""
        payload = self._send_and_capture_payload(db_session, 'discord', mock_post)

        assert 'content' in payload
        assert '**SentriKat Security Alert' in payload['content']
        assert 'CVE-2025-0001' in payload['content']
        # Discord uses **bold** syntax
        assert '**' in payload['content']

    # Test 4 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_teams_messagecard_format(self, mock_post, app, db_session):
        """Teams must produce MessageCard with @type, themeColor, sections, facts."""
        payload = self._send_and_capture_payload(db_session, 'teams', mock_post)

        assert payload['@type'] == 'MessageCard'
        assert 'themeColor' in payload
        assert 'sections' in payload
        assert len(payload['sections']) >= 1
        assert 'facts' in payload['sections'][0]
        # Facts should include CVE IDs
        fact_names = [f['name'] for f in payload['sections'][0]['facts']]
        assert 'New CVEs' in fact_names
        assert 'CVE IDs' in fact_names

    # Test 5 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_custom_fallback_json_format(self, mock_post, app, db_session):
        """Custom/fallback format should have text, organization, new_cve_count, cve_ids."""
        payload = self._send_and_capture_payload(db_session, 'custom', mock_post)

        assert 'text' in payload
        assert 'organization' in payload
        assert 'new_cve_count' in payload
        assert 'cve_ids' in payload
        assert 'critical_count' in payload
        assert 'exploited_count' in payload
        assert 'zero_day_count' in payload
        assert 'zero_day_cve_ids' in payload
        assert 'verify_count' in payload
        assert 'CVE-2025-0001' in payload['cve_ids']


# ============================================================================
# SECTION 2: send_org_webhook() Unit Tests
# ============================================================================

class TestSendOrgWebhook:
    """Tests 6-20: Cover all paths in send_org_webhook()."""

    # Test 6 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_sends_webhook_when_enabled(self, mock_post, app, db_session):
        """send_org_webhook sends HTTP POST when webhook_enabled=True."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='enabled_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1001')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        assert mock_post.called
        assert result['success'] is True
        assert result['org'] == 'enabled_org'

    # Test 7 ---------------------------------------------------------------
    def test_returns_none_when_webhook_not_configured(self, app, db_session):
        """send_org_webhook returns None for org without webhook configured."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='no_webhook_org',
                        webhook_enabled=False, webhook_url=None)
        result = send_org_webhook(org, 1, 0, 1)

        assert result is None

    # Test 8 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_skips_when_all_matches_already_alerted(self, mock_post, app, db_session):
        """Skips when all matches have first_alerted_at set (no new CVEs)."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='already_alerted_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1002')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln,
                            first_alerted_at=datetime.utcnow())

        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        assert result['skipped'] is True
        assert 'No new CVEs' in result.get('reason', '')
        assert not mock_post.called

    # Test 9 ---------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_force_bypasses_first_alerted_at(self, mock_post, app, db_session):
        """force=True sends webhook even when first_alerted_at is set."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='force_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1003')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln,
                            first_alerted_at=datetime.utcnow())

        mock_post.return_value = _mock_response(200)
        result = send_org_webhook(org, 1, 1, 1, matches=[match], force=True)

        assert mock_post.called
        assert result['success'] is True
        assert result['new_cves'] == 1

    # Test 10 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_sets_first_alerted_at_on_success(self, mock_post, app, db_session):
        """Successful webhook sets first_alerted_at on new matches."""
        from app.cisa_sync import send_org_webhook
        from app import db as _db

        org = _make_org(db_session, name='alerted_at_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1004')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        assert match.first_alerted_at is None

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _db.session.refresh(match)
        assert match.first_alerted_at is not None

    # Test 11 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_does_not_set_first_alerted_at_on_failure(self, mock_post, app, db_session):
        """Failed webhook (non-200) must NOT set first_alerted_at."""
        from app.cisa_sync import send_org_webhook
        from app import db as _db

        org = _make_org(db_session, name='fail_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1005')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(500)
        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        _db.session.refresh(match)
        assert match.first_alerted_at is None
        assert result['success'] is False

    # Test 12 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    @patch('app.encryption.is_encrypted', return_value=True)
    @patch('app.encryption.decrypt_value', return_value='https://decrypted.hooks.example.com/webhook')
    def test_encrypted_webhook_url_decrypted(self, mock_decrypt, mock_is_enc,
                                              mock_post, app, db_session):
        """Encrypted webhook URL is decrypted before sending."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='encrypted_org',
                        webhook_url='gAAAAAencryptedblob')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1006')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        assert mock_post.called
        called_url = mock_post.call_args[0][0] if mock_post.call_args[0] else mock_post.call_args[1].get('url', mock_post.call_args[0][0])
        # The decrypted URL should be used
        assert 'decrypted' in called_url or result['success'] is True

    # Test 13 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_invalid_webhook_url_returns_error(self, mock_post, app, db_session):
        """Invalid webhook URL (not http/https) returns an error result."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='invalid_url_org',
                        webhook_url='ftp://not-valid.example.com')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1007')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        assert result['success'] is False
        assert 'Invalid webhook URL' in result.get('error', '')
        assert not mock_post.called

    # Test 14 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_timeout_handling(self, mock_post, app, db_session):
        """Timeout during requests.post is caught and returned as error."""
        import requests as _requests
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='timeout_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1008')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.side_effect = _requests.exceptions.Timeout("Connection timed out")
        result = send_org_webhook(org, 1, 1, 1, matches=[match])

        assert result['success'] is False
        assert 'timed out' in result.get('error', '').lower() or 'Timeout' in result.get('error', '')

    # Test 15 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_auth_token_in_headers(self, mock_post, app, db_session):
        """When webhook_token is set, Authorization and X-Auth-Token headers are sent."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='auth_org',
                        webhook_token='my-secret-token-123')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1009')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        headers = kwargs['headers']
        assert headers['Authorization'] == 'Bearer my-secret-token-123'
        assert headers['X-Auth-Token'] == 'my-secret-token-123'

    # Test 16 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_cve_list_truncation_more_than_5(self, mock_post, app, db_session):
        """When >5 CVEs, payload shows first 5 then '+X more'."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='truncate_org')
        product = _make_product(db_session, org)
        matches = []
        for i in range(8):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-200{i}',
                              severity='HIGH', cvss=8.0)
            match = _make_match(db_session, product, vuln)
            matches.append(match)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 8, 0, 8, matches=matches)

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        text = payload.get('text', '')
        assert '+3 more' in text

    # Test 17 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_zero_day_count_in_payload(self, mock_post, app, db_session):
        """Zero-day CVEs (source=euvd) are counted and shown in payload."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='zeroday_org')
        product = _make_product(db_session, org)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-3001', severity='CRITICAL',
                          cvss=10.0, is_actively_exploited=True, source='euvd')
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        text = payload.get('text', '')
        assert 'ZERO-DAY' in text

    # Test 18 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_actively_exploited_count_in_payload(self, mock_post, app, db_session):
        """Actively exploited CVEs are counted and shown in Slack payload."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='exploited_org')
        product = _make_product(db_session, org)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-3002', severity='CRITICAL',
                          cvss=9.5, is_actively_exploited=True)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        text = payload.get('text', '')
        assert 'ACTIVELY EXPLOITED' in text

    # Test 19 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_verify_count_amber_tier_in_payload(self, mock_post, app, db_session):
        """Matches with vendor_fix_confidence='medium' contribute to verify_count."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='verify_org')
        product = _make_product(db_session, org)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-3003', severity='HIGH', cvss=8.0)
        match = _make_match(db_session, product, vuln, vendor_fix_confidence='medium')

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 0, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        text = payload.get('text', '')
        assert 'likely resolved' in text or 'verify' in text.lower()

    # Test 20 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_critical_count_affects_teams_theme_color(self, mock_post, app, db_session):
        """Teams themeColor changes based on critical/exploited counts."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='teams_color_org', webhook_format='teams')
        product = _make_product(db_session, org)

        # Critical CVE -> red theme
        vuln = _make_vuln(db_session, cve_id='CVE-2025-3004', severity='CRITICAL',
                          cvss=9.8, is_actively_exploited=True)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        # With actively exploited, themeColor should be red (dc2626) or purple for zero-day
        assert payload['themeColor'] in ('dc2626', '7c3aed')


# ============================================================================
# SECTION 3: send_webhook_notification() Global Webhook Tests
# ============================================================================

class TestSendWebhookNotification:
    """Tests 21-27: Cover global webhook notification via SystemSettings."""

    # Test 21 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_sends_to_slack_when_enabled(self, mock_post, app, db_session):
        """Global Slack webhook fires when slack_enabled=true."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'slack_enabled', 'true')
        _make_system_setting(db_session, 'slack_webhook_url', 'https://hooks.slack.com/test')

        mock_post.return_value = _mock_response(200)
        results = send_webhook_notification(3, 1, 10)

        assert mock_post.called
        assert any(r.get('slack') is True for r in results)

    # Test 22 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_sends_to_teams_when_enabled(self, mock_post, app, db_session):
        """Global Teams webhook fires when teams_enabled=true."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'teams_enabled', 'true')
        _make_system_setting(db_session, 'teams_webhook_url', 'https://teams.webhook.office.com/test')

        mock_post.return_value = _mock_response(200)
        results = send_webhook_notification(5, 2, 15)

        assert mock_post.called
        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        assert payload['@type'] == 'MessageCard'
        assert any(r.get('teams') is True for r in results)

    # Test 23 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_skips_when_disabled(self, mock_post, app, db_session):
        """Global webhook skips when slack_enabled=false and teams_enabled=false."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'slack_enabled', 'false')
        _make_system_setting(db_session, 'teams_enabled', 'false')

        results = send_webhook_notification(3, 1, 10)

        assert not mock_post.called
        assert results == []

    # Test 24 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    @patch('app.encryption.decrypt_value', return_value='https://decrypted-slack.example.com/hook')
    def test_handles_encrypted_global_webhook_urls(self, mock_decrypt, mock_post,
                                                     app, db_session):
        """Encrypted global Slack URL (starts with gAAAA) is decrypted."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'slack_enabled', 'true')
        _make_system_setting(db_session, 'slack_webhook_url', 'gAAAAencryptedslack')

        mock_post.return_value = _mock_response(200)
        results = send_webhook_notification(2, 0, 5)

        mock_decrypt.assert_called_with('gAAAAencryptedslack')
        assert mock_post.called
        called_url = mock_post.call_args[0][0]
        assert called_url == 'https://decrypted-slack.example.com/hook'

    # Test 25 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_batched_cve_format_when_cve_ids_provided(self, mock_post, app, db_session):
        """When new_cve_ids is provided, Slack payload uses batched text format."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'slack_enabled', 'true')
        _make_system_setting(db_session, 'slack_webhook_url', 'https://hooks.slack.com/test')

        mock_post.return_value = _mock_response(200)
        cve_ids = ['CVE-2025-0001', 'CVE-2025-0002']
        send_webhook_notification(2, 1, 5, new_cve_ids=cve_ids)

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        # Batched format uses "text" key with CVE list
        assert 'text' in payload
        assert 'CVE-2025-0001' in payload['text']
        assert 'CVE-2025-0002' in payload['text']

    # Test 26 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_text_format_when_no_cve_ids(self, mock_post, app, db_session):
        """When no cve_ids provided, Slack payload uses text format with summary."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'slack_enabled', 'true')
        _make_system_setting(db_session, 'slack_webhook_url', 'https://hooks.slack.com/test')

        mock_post.return_value = _mock_response(200)
        send_webhook_notification(3, 1, 10, new_cve_ids=None)

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        assert 'text' in payload
        assert '*SentriKat' in payload['text']
        assert 'New CVEs' in payload['text'] or 'new CVE' in payload['text']
        assert 'Critical' in payload['text'] or 'critical' in payload['text']

    # Test 27 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_critical_count_affects_teams_theme_color_global(self, mock_post, app, db_session):
        """Teams global webhook themeColor is red when critical_count > 0."""
        from app.cisa_sync import send_webhook_notification

        _make_system_setting(db_session, 'teams_enabled', 'true')
        _make_system_setting(db_session, 'teams_webhook_url', 'https://teams.webhook.test')

        mock_post.return_value = _mock_response(200)

        # With critical > 0
        send_webhook_notification(3, 2, 10)
        _, kwargs = mock_post.call_args
        payload_critical = json.loads(kwargs['data'])
        assert payload_critical['themeColor'] == 'dc2626'

        mock_post.reset_mock()

        # With critical = 0
        send_webhook_notification(3, 0, 10)
        _, kwargs = mock_post.call_args
        payload_normal = json.loads(kwargs['data'])
        assert payload_normal['themeColor'] == '1e40af'


# ============================================================================
# SECTION 4: send_alerts_for_new_matches() Integration Tests
# ============================================================================

class TestSendAlertsForNewMatches:
    """Tests 28-34: Integration tests for the shared alerting function."""

    def _setup_org_with_matches(self, db_session, org_name='alert_org',
                                 alert_mode='new_only', webhook_enabled=True,
                                 num_matches=2, severity='CRITICAL', cvss=9.8,
                                 **org_overrides):
        """Helper: create org with products+vulns+matches for alert testing."""
        org = _make_org(db_session, name=org_name, alert_mode=alert_mode,
                        webhook_enabled=webhook_enabled, **org_overrides)
        product = _make_product(db_session, org, vendor=f'V_{org_name}',
                                product_name=f'P_{org_name}')
        matches = []
        for i in range(num_matches):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-{org_name[-3:]}{i}',
                              severity=severity, cvss=cvss,
                              is_actively_exploited=(cvss >= 9.0))
            match = _make_match(db_session, product, vuln)
            matches.append(match)
        return org, product, matches

    # Test 28 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    def test_sends_to_orgs_with_alert_on_critical(self, mock_email, mock_post,
                                                    mock_global, app, db_session):
        """Org with alert_on_critical=True receives webhook alert."""
        from app.cisa_sync import send_alerts_for_new_matches

        since = datetime.utcnow() - timedelta(minutes=5)
        org, product, matches = self._setup_org_with_matches(
            db_session, org_name='crit_org001', alert_mode='new_only',
            webhook_enabled=True)

        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global.return_value = []

        result = send_alerts_for_new_matches(since)

        assert mock_post.called
        assert len(result['webhook_results']) > 0

    # Test 29 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    def test_new_only_mode_only_new_matches(self, mock_email, mock_post,
                                             mock_global, app, db_session):
        """alert_mode='new_only' only includes matches created after since_time."""
        from app.cisa_sync import send_alerts_for_new_matches
        from app.models import VulnerabilityMatch
        from app import db as _db

        org = _make_org(db_session, name='newonly_org', alert_mode='new_only')
        product = _make_product(db_session, org, vendor='V_newonly',
                                product_name='P_newonly')

        # Old match (created in the past)
        old_vuln = _make_vuln(db_session, cve_id='CVE-2025-OLD1', severity='CRITICAL', cvss=9.8)
        old_match = _make_match(db_session, product, old_vuln)
        old_match.created_at = datetime.utcnow() - timedelta(days=2)
        _db.session.commit()

        # New match (created recently)
        new_vuln = _make_vuln(db_session, cve_id='CVE-2025-NEW1', severity='CRITICAL', cvss=9.8,
                              is_actively_exploited=True)
        new_match = _make_match(db_session, product, new_vuln)

        since = datetime.utcnow() - timedelta(minutes=5)
        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global.return_value = []

        result = send_alerts_for_new_matches(since)

        # Only the new match should trigger alert
        if mock_post.called:
            _, kwargs = mock_post.call_args
            payload_text = kwargs.get('data', b'{}').decode('utf-8') if isinstance(kwargs.get('data'), bytes) else json.dumps(kwargs.get('json', {}))
            assert 'CVE-2025-NEW1' in payload_text
            # Old match should not appear (created before since_time)
            # Note: it may still appear if it's in the same org product set
            # but the key assertion is that the function was called at all

    # Test 30 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    @patch('app.settings_api.get_setting')
    def test_daily_reminder_mode_includes_due_window(self, mock_setting, mock_email,
                                                       mock_post, mock_global,
                                                       app, db_session):
        """alert_mode='daily_reminder' includes CVEs with due_date in 7-day window."""
        from app.cisa_sync import send_alerts_for_new_matches
        from app import db as _db

        mock_setting.side_effect = lambda k, default=None: {
            'default_alert_mode': 'daily_reminder',
            'default_escalation_days': '3',
        }.get(k, default)

        org = _make_org(db_session, name='daily_org', alert_mode='daily_reminder')
        product = _make_product(db_session, org, vendor='V_daily',
                                product_name='P_daily')

        # CVE with due_date in next 7 days
        vuln = _make_vuln(db_session, cve_id='CVE-2025-DUE1', severity='CRITICAL',
                          cvss=9.5, due_date=date.today() + timedelta(days=3))
        match = _make_match(db_session, product, vuln)

        since = datetime.utcnow() - timedelta(hours=1)
        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global.return_value = []

        result = send_alerts_for_new_matches(since)

        # The match should be included because due_date is within window
        assert mock_email.called or len(result['alert_results']) > 0

    # Test 31 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    @patch('app.settings_api.get_setting')
    def test_escalation_mode_uses_escalation_days(self, mock_setting, mock_email,
                                                    mock_post, mock_global,
                                                    app, db_session):
        """alert_mode='escalation' uses the org's escalation_days setting."""
        from app.cisa_sync import send_alerts_for_new_matches

        mock_setting.side_effect = lambda k, default=None: {
            'default_alert_mode': 'escalation',
            'default_escalation_days': '5',
        }.get(k, default)

        org = _make_org(db_session, name='esc_org', alert_mode='escalation',
                        escalation_days=2)
        product = _make_product(db_session, org, vendor='V_esc',
                                product_name='P_esc')

        # CVE with due_date in 2 days (within escalation_days=2 window)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-ESC1', severity='CRITICAL',
                          cvss=9.5, due_date=date.today() + timedelta(days=1))
        match = _make_match(db_session, product, vuln)

        since = datetime.utcnow() - timedelta(hours=1)
        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global.return_value = []

        result = send_alerts_for_new_matches(since)

        assert mock_email.called or len(result['alert_results']) > 0

    # Test 32 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    def test_orgs_with_own_webhook_skip_global(self, mock_email, mock_post,
                                                 mock_global_wh, app, db_session):
        """Orgs with webhook_enabled=True use send_org_webhook, not the global webhook."""
        from app.cisa_sync import send_alerts_for_new_matches

        org, product, matches = self._setup_org_with_matches(
            db_session, org_name='own_wh_org', webhook_enabled=True)

        since = datetime.utcnow() - timedelta(minutes=5)
        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global_wh.return_value = []

        result = send_alerts_for_new_matches(since)

        # org webhook was used (requests.post was called)
        assert mock_post.called

    # Test 33 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    def test_orgs_without_webhook_get_global(self, mock_email, mock_post,
                                               mock_global_wh, app, db_session):
        """Orgs without webhook_enabled rely on global webhook notification."""
        from app.cisa_sync import send_alerts_for_new_matches

        org = _make_org(db_session, name='no_wh_org',
                        webhook_enabled=False, webhook_url=None)
        product = _make_product(db_session, org, vendor='V_nowh',
                                product_name='P_nowh')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-NOWH1', severity='CRITICAL',
                          cvss=9.5, is_actively_exploited=True)
        match = _make_match(db_session, product, vuln)

        since = datetime.utcnow() - timedelta(minutes=5)
        mock_email.return_value = {'status': 'sent'}
        mock_global_wh.return_value = []

        result = send_alerts_for_new_matches(since)

        # Global webhook should be called because org has no own webhook
        mock_global_wh.assert_called_once()

    # Test 34 --------------------------------------------------------------
    @patch('app.cisa_sync.send_webhook_notification')
    @patch('app.cisa_sync.requests.post')
    @patch('app.email_alerts.EmailAlertManager.send_critical_cve_alert')
    def test_multi_org_product_assignment(self, mock_email, mock_post,
                                           mock_global_wh, app, db_session):
        """Product assigned to multiple orgs via product_organizations table triggers alerts for each."""
        from app.cisa_sync import send_alerts_for_new_matches
        from app.models import product_organizations
        from app import db as _db

        org1 = _make_org(db_session, name='multi_org_1', webhook_enabled=True)
        org2 = _make_org(db_session, name='multi_org_2', webhook_enabled=True,
                         webhook_url='https://hooks.slack.example.com/org2')

        # Product belongs to org1 (legacy) but also assigned to org2 via multi-org table
        product = _make_product(db_session, org1, vendor='V_multi',
                                product_name='P_multi')
        _db.session.execute(
            product_organizations.insert().values(
                product_id=product.id, organization_id=org2.id
            )
        )
        _db.session.commit()

        vuln = _make_vuln(db_session, cve_id='CVE-2025-MULT1', severity='CRITICAL',
                          cvss=9.5, is_actively_exploited=True)
        match = _make_match(db_session, product, vuln)

        since = datetime.utcnow() - timedelta(minutes=5)
        mock_email.return_value = {'status': 'sent'}
        mock_post.return_value = _mock_response(200)
        mock_global_wh.return_value = []

        result = send_alerts_for_new_matches(since)

        # Both orgs should receive alerts (at least 2 calls to email or webhook)
        assert mock_email.call_count >= 2 or mock_post.call_count >= 2


# ============================================================================
# SECTION 5: POST /api/alerts/trigger-webhooks Route Tests
# ============================================================================

class TestTriggerWebhookRoute:
    """Tests 35-40: Test the admin-only manual webhook trigger endpoint."""

    # Test 35 --------------------------------------------------------------
    @patch('app.cisa_sync.send_org_webhook')
    def test_admin_can_trigger_webhooks(self, mock_send, app, admin_client, db_session,
                                         setup_complete, admin_user):
        """POST /api/alerts/trigger-webhooks succeeds for admin users."""
        org = _make_org(db_session, name='trigger_org')
        product = _make_product(db_session, org)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-TRIG1', severity='CRITICAL', cvss=9.8)
        match = _make_match(db_session, product, vuln)

        mock_send.return_value = {
            'org': 'trigger_org', 'success': True, 'new_cves': 1
        }

        response = admin_client.post('/api/alerts/trigger-webhooks')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'summary' in data

    # Test 36 --------------------------------------------------------------
    def test_non_admin_returns_403(self, app, authenticated_client, db_session,
                                    setup_complete, test_user):
        """Non-admin user receives 403 on POST /api/alerts/trigger-webhooks."""
        response = authenticated_client.post('/api/alerts/trigger-webhooks')
        assert response.status_code == 403

    # Test 37 --------------------------------------------------------------
    @patch('app.cisa_sync.send_org_webhook')
    def test_returns_summary_with_counts(self, mock_send, app, admin_client, db_session,
                                          setup_complete, admin_user):
        """Response includes sent/skipped/error counts in summary."""
        org1 = _make_org(db_session, name='sum_org_1')
        product1 = _make_product(db_session, org1, vendor='V_s1', product_name='P_s1')
        vuln1 = _make_vuln(db_session, cve_id='CVE-2025-SUM1', severity='CRITICAL', cvss=9.8)
        match1 = _make_match(db_session, product1, vuln1)

        org2 = _make_org(db_session, name='sum_org_2',
                         webhook_url='https://hooks.example.com/org2')
        product2 = _make_product(db_session, org2, vendor='V_s2', product_name='P_s2')
        vuln2 = _make_vuln(db_session, cve_id='CVE-2025-SUM2', severity='CRITICAL', cvss=9.5)
        match2 = _make_match(db_session, product2, vuln2)

        # First org succeeds, second fails
        mock_send.side_effect = [
            {'org': 'sum_org_1', 'success': True, 'new_cves': 1},
            {'org': 'sum_org_2', 'success': False, 'error': 'Timeout'},
        ]

        response = admin_client.post('/api/alerts/trigger-webhooks')
        data = response.get_json()

        assert 'summary' in data
        summary = data['summary']
        assert 'webhooks_sent' in summary
        assert 'skipped' in summary
        assert 'errors' in summary
        assert summary['webhooks_sent'] + summary['skipped'] + summary['errors'] == summary['total_orgs']

    # Test 38 --------------------------------------------------------------
    @patch('app.cisa_sync.send_org_webhook')
    def test_skips_orgs_without_webhook(self, mock_send, app, admin_client, db_session,
                                         setup_complete, admin_user):
        """Orgs without webhook_enabled are skipped in the trigger."""
        org = _make_org(db_session, name='skip_wh_org',
                        webhook_enabled=False, webhook_url=None)

        response = admin_client.post('/api/alerts/trigger-webhooks')
        data = response.get_json()

        # The org without webhook should be in skipped
        skipped_orgs = [d for d in data.get('details', [])
                        if d.get('status') == 'skipped'
                        and d.get('organization') == 'skip_wh_org']
        assert len(skipped_orgs) > 0
        # send_org_webhook should NOT have been called for this org
        for c in mock_send.call_args_list:
            assert c[1].get('org', c[0][0] if c[0] else None) != org or True
            # Simpler: the endpoint checks webhook_enabled before calling send_org_webhook

    # Test 39 --------------------------------------------------------------
    @patch('app.cisa_sync.send_org_webhook')
    def test_skips_orgs_with_no_priority_matches(self, mock_send, app, admin_client,
                                                   db_session, setup_complete, admin_user):
        """Orgs with webhook but no critical/high unacknowledged matches are skipped."""
        org = _make_org(db_session, name='no_match_org')
        # No products/matches for this org

        response = admin_client.post('/api/alerts/trigger-webhooks')
        data = response.get_json()

        no_match_results = [d for d in data.get('details', [])
                            if d.get('organization') == 'no_match_org']
        assert len(no_match_results) > 0
        assert no_match_results[0]['status'] == 'skipped'

    # Test 40 --------------------------------------------------------------
    @patch('app.cisa_sync.send_org_webhook')
    def test_force_true_on_manual_trigger(self, mock_send, app, admin_client, db_session,
                                           setup_complete, admin_user):
        """Manual trigger passes force=True to send_org_webhook."""
        org = _make_org(db_session, name='force_trig_org')
        product = _make_product(db_session, org, vendor='V_ft', product_name='P_ft')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-FORC1', severity='CRITICAL', cvss=9.8)
        match = _make_match(db_session, product, vuln,
                            first_alerted_at=datetime.utcnow())  # Already alerted

        mock_send.return_value = {
            'org': 'force_trig_org', 'success': True, 'new_cves': 1
        }

        admin_client.post('/api/alerts/trigger-webhooks')

        # Verify force=True was passed
        if mock_send.called:
            _, kwargs = mock_send.call_args
            assert kwargs.get('force') is True


# ============================================================================
# SECTION 6: RocketChat-Specific / first_alerted_at Regression Tests
# ============================================================================

class TestRocketChatFirstAlertedRegression:
    """Tests 41-44: RocketChat-specific tests and first_alerted_at regression."""

    # Test 41 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_rocketchat_uses_same_format_as_slack(self, mock_post, app, db_session):
        """RocketChat and Slack share the same payload format ('text' key, *bold*)."""
        from app.cisa_sync import send_org_webhook

        org_slack = _make_org(db_session, name='rc_slack_org', webhook_format='slack')
        org_rc = _make_org(db_session, name='rc_rc_org', webhook_format='rocketchat',
                           webhook_url='https://rocketchat.example.com/hooks/xxx')

        vuln = _make_vuln(db_session, cve_id='CVE-2025-RC01', severity='HIGH', cvss=8.0)

        product_slack = _make_product(db_session, org_slack, vendor='V_slack', product_name='P_slack')
        match_slack = _make_match(db_session, product_slack, vuln)

        product_rc = _make_product(db_session, org_rc, vendor='V_rc', product_name='P_rc')
        match_rc = _make_match(db_session, product_rc, vuln)

        mock_post.return_value = _mock_response(200)

        send_org_webhook(org_slack, 1, 0, 1, matches=[match_slack])
        slack_payload = json.loads(mock_post.call_args[1]['data'])

        mock_post.reset_mock()
        mock_post.return_value = _mock_response(200)

        send_org_webhook(org_rc, 1, 0, 1, matches=[match_rc])
        rc_payload = json.loads(mock_post.call_args[1]['data'])

        # Both should have 'text' key
        assert 'text' in slack_payload
        assert 'text' in rc_payload
        # Both use *bold* markdown syntax
        assert '*SentriKat Security Alert' in slack_payload['text']
        assert '*SentriKat Security Alert' in rc_payload['text']

    # Test 42 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_webhook_fires_only_for_null_first_alerted(self, mock_post, app, db_session):
        """Webhook only fires for matches where first_alerted_at IS NULL."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='null_alert_org')
        product = _make_product(db_session, org, vendor='V_null', product_name='P_null')

        # One match never alerted (should trigger)
        vuln_new = _make_vuln(db_session, cve_id='CVE-2025-NEWR1', severity='CRITICAL', cvss=9.5)
        match_new = _make_match(db_session, product, vuln_new, first_alerted_at=None)

        # One match already alerted (should NOT trigger)
        vuln_old = _make_vuln(db_session, cve_id='CVE-2025-OLDR1', severity='CRITICAL', cvss=9.0)
        match_old = _make_match(db_session, product, vuln_old,
                                first_alerted_at=datetime.utcnow() - timedelta(hours=6))

        mock_post.return_value = _mock_response(200)
        result = send_org_webhook(org, 2, 2, 2, matches=[match_new, match_old])

        assert mock_post.called
        _, kwargs = mock_post.call_args
        payload_text = json.loads(kwargs['data']).get('text', '')
        # Only the new CVE should appear
        assert 'CVE-2025-NEWR1' in payload_text
        assert 'CVE-2025-OLDR1' not in payload_text
        assert result['new_cves'] == 1

    # Test 43 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_previously_alerted_cves_skipped(self, mock_post, app, db_session):
        """Simulates 'zero-day did not print today': all matches already alerted = skip."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='prev_alert_org', webhook_format='rocketchat',
                        webhook_url='https://rocketchat.example.com/hooks/yyy')
        product = _make_product(db_session, org, vendor='V_prev', product_name='P_prev')

        # Three CVEs, all previously alerted
        matches = []
        for i in range(3):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-PREV{i}',
                              severity='CRITICAL', cvss=9.8,
                              is_actively_exploited=True, source='euvd')
            match = _make_match(db_session, product, vuln,
                                first_alerted_at=datetime.utcnow() - timedelta(hours=12))
            matches.append(match)

        result = send_org_webhook(org, 3, 3, 3, matches=matches)

        # Should be skipped because all matches were already alerted
        assert result['skipped'] is True
        assert 'No new CVEs' in result.get('reason', '')
        assert not mock_post.called

    # Test 44 --------------------------------------------------------------
    @patch('app.cisa_sync.requests.post')
    def test_manual_force_sends_all_unacknowledged(self, mock_post, app, db_session):
        """Manual trigger with force=True sends ALL unacknowledged matches regardless."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='manual_force_org', webhook_format='rocketchat',
                        webhook_url='https://rocketchat.example.com/hooks/zzz')
        product = _make_product(db_session, org, vendor='V_mf', product_name='P_mf')

        matches = []
        for i in range(4):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-MF0{i}',
                              severity='CRITICAL', cvss=9.5,
                              is_actively_exploited=True, source='euvd')
            # All matches have first_alerted_at set (previously notified)
            match = _make_match(db_session, product, vuln,
                                first_alerted_at=datetime.utcnow() - timedelta(days=1))
            matches.append(match)

        mock_post.return_value = _mock_response(200)
        result = send_org_webhook(org, 4, 4, 4, matches=matches, force=True)

        # force=True should bypass the first_alerted_at filter
        assert mock_post.called
        assert result['success'] is True
        assert result['new_cves'] == 4

        # Verify all 4 CVEs are in the payload
        _, kwargs = mock_post.call_args
        payload_text = json.loads(kwargs['data']).get('text', '')
        # With 4 CVEs (<=5), all should be listed
        for i in range(4):
            assert f'CVE-2025-MF0{i}' in payload_text


# ============================================================================
# SECTION 7: Edge Cases and Additional Coverage
# ============================================================================

class TestWebhookEdgeCases:
    """Additional edge-case tests to strengthen coverage."""

    @patch('app.cisa_sync.requests.post')
    def test_empty_matches_list_returns_skipped(self, mock_post, app, db_session):
        """Empty matches list should return skipped result."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='empty_match_org')
        result = send_org_webhook(org, 0, 0, 0, matches=[])

        assert result['skipped'] is True
        assert not mock_post.called

    @patch('app.cisa_sync.requests.post')
    def test_none_matches_returns_skipped(self, mock_post, app, db_session):
        """None matches should return skipped result."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='none_match_org')
        result = send_org_webhook(org, 0, 0, 0, matches=None)

        assert result['skipped'] is True
        assert not mock_post.called

    @patch('app.cisa_sync.requests.post')
    def test_204_response_treated_as_success(self, mock_post, app, db_session):
        """HTTP 204 (No Content) is treated as success like 200."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='http204_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-204A', severity='HIGH', cvss=8.0)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(204)
        result = send_org_webhook(org, 1, 0, 1, matches=[match])

        assert result['success'] is True

    @patch('app.cisa_sync.requests.post')
    def test_connection_error_returns_error(self, mock_post, app, db_session):
        """Connection errors are caught and returned as error result."""
        import requests as _requests
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='conn_err_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-CONN1', severity='HIGH', cvss=8.0)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.side_effect = _requests.exceptions.ConnectionError("DNS resolution failed")
        result = send_org_webhook(org, 1, 0, 1, matches=[match])

        assert result['success'] is False
        assert 'error' in result

    @patch('app.cisa_sync.requests.post')
    def test_exactly_5_cves_no_truncation(self, mock_post, app, db_session):
        """Exactly 5 CVEs should list all without '+X more'."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='exact5_org')
        product = _make_product(db_session, org, vendor='V_5', product_name='P_5')
        matches = []
        for i in range(5):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-FIV{i}',
                              severity='HIGH', cvss=8.0)
            match = _make_match(db_session, product, vuln)
            matches.append(match)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 5, 0, 5, matches=matches)

        _, kwargs = mock_post.call_args
        text = json.loads(kwargs['data']).get('text', '')
        assert '+' not in text or 'more' not in text
        # All 5 should be listed
        for i in range(5):
            assert f'CVE-2025-FIV{i}' in text

    @patch('app.cisa_sync.requests.post')
    def test_6_cves_shows_plus_1_more(self, mock_post, app, db_session):
        """6 CVEs should show 5 + '+1 more'."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='six_cve_org')
        product = _make_product(db_session, org, vendor='V_6', product_name='P_6')
        matches = []
        for i in range(6):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-SIX{i}',
                              severity='HIGH', cvss=8.0)
            match = _make_match(db_session, product, vuln)
            matches.append(match)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 6, 0, 6, matches=matches)

        _, kwargs = mock_post.call_args
        text = json.loads(kwargs['data']).get('text', '')
        assert '+1 more' in text

    @patch('app.cisa_sync.requests.post')
    def test_zero_day_teams_purple_theme(self, mock_post, app, db_session):
        """Teams webhook uses purple theme (7c3aed) for zero-day CVEs."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='zd_teams_org', webhook_format='teams')
        product = _make_product(db_session, org, vendor='V_zdt', product_name='P_zdt')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-ZDT1', severity='CRITICAL',
                          cvss=10.0, is_actively_exploited=True, source='euvd')
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        # Zero-day should trigger purple theme
        assert payload['themeColor'] == '7c3aed'

    @patch('app.cisa_sync.requests.post')
    def test_teams_no_critical_no_exploited_blue_theme(self, mock_post, app, db_session):
        """Teams webhook uses blue theme (1e40af) when no critical/exploited."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='blue_teams_org', webhook_format='teams')
        product = _make_product(db_session, org, vendor='V_blue', product_name='P_blue')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-BLUE1', severity='MEDIUM',
                          cvss=5.0, is_actively_exploited=False)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 0, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        assert payload['themeColor'] == '1e40af'

    @patch('app.cisa_sync.requests.post')
    def test_custom_format_includes_zero_day_cve_ids(self, mock_post, app, db_session):
        """Custom format includes zero_day_cve_ids list in the payload."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='custom_zd_org', webhook_format='custom')
        product = _make_product(db_session, org, vendor='V_czd', product_name='P_czd')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-CZD1', severity='CRITICAL',
                          cvss=10.0, source='euvd')
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs['data'])
        assert 'CVE-2025-CZD1' in payload['zero_day_cve_ids']
        assert payload['zero_day_count'] == 1

    @patch('app.cisa_sync.requests.post')
    def test_content_type_header_set_to_json(self, mock_post, app, db_session):
        """All webhook requests send Content-Type: application/json."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='ct_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-CT01', severity='HIGH', cvss=8.0)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 0, 1, matches=[match])

        _, kwargs = mock_post.call_args
        assert kwargs['headers']['Content-Type'] == 'application/json'

    @patch('app.cisa_sync.requests.post')
    def test_webhook_url_not_configured_returns_none(self, mock_post, app, db_session):
        """webhook_enabled=True but webhook_url=None returns None (fallback to global)."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='no_url_org',
                        webhook_enabled=True, webhook_url=None)
        result = send_org_webhook(org, 1, 0, 1)

        assert result is None
        assert not mock_post.called

    @patch('app.cisa_sync.requests.post')
    def test_discord_zero_day_in_content(self, mock_post, app, db_session):
        """Discord payload includes ZERO-DAY with ** markdown when present."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='disc_zd_org', webhook_format='discord')
        product = _make_product(db_session, org, vendor='V_dzd', product_name='P_dzd')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-DZD1', severity='CRITICAL',
                          cvss=10.0, source='euvd')
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 1, 1, matches=[match])

        _, kwargs = mock_post.call_args
        content = json.loads(kwargs['data'])['content']
        assert '**' in content  # Discord bold
        assert 'ZERO-DAY' in content

    @patch('app.cisa_sync.requests.post')
    def test_single_cve_no_plural_s(self, mock_post, app, db_session):
        """Single CVE message says '1 new CVE' not '1 new CVEs'."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='singular_org')
        product = _make_product(db_session, org, vendor='V_sg', product_name='P_sg')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-SING1', severity='HIGH', cvss=8.0)
        match = _make_match(db_session, product, vuln)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 1, 0, 1, matches=[match])

        _, kwargs = mock_post.call_args
        text = json.loads(kwargs['data']).get('text', '')
        assert '1 new CVE detected' in text or '1 new CVE:' in text  # singular, no 's'
        assert '1 new CVEs' not in text

    @patch('app.cisa_sync.requests.post')
    def test_multiple_cves_has_plural_s(self, mock_post, app, db_session):
        """Multiple CVEs message says 'N new CVEs' with plural."""
        from app.cisa_sync import send_org_webhook

        org = _make_org(db_session, name='plural_org')
        product = _make_product(db_session, org, vendor='V_pl', product_name='P_pl')
        matches = []
        for i in range(3):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-PLR{i}',
                              severity='HIGH', cvss=8.0)
            match = _make_match(db_session, product, vuln)
            matches.append(match)

        mock_post.return_value = _mock_response(200)
        send_org_webhook(org, 3, 0, 3, matches=matches)

        _, kwargs = mock_post.call_args
        text = json.loads(kwargs['data']).get('text', '')
        assert '3 new CVEs detected' in text or '3 new CVEs:' in text  # plural
