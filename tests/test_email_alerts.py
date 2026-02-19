"""
Tests for app/email_alerts.py - Email alert system.

Covers: should_send_alert_now, _send_email, test_smtp_connection,
send_user_invite_email, send_user_status_email, _build_alert_email_html,
send_generic_alert, and error handling paths.
"""
import pytest
import json
import smtplib
from unittest.mock import patch, MagicMock, PropertyMock, call
from datetime import datetime, date, timedelta


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_org(db_session, **overrides):
    """Create and return an Organization with sensible defaults."""
    from app.models import Organization

    defaults = dict(
        name='email_test_org',
        display_name='Email Test Org',
        active=True,
        smtp_host='smtp.example.com',
        smtp_port=587,
        smtp_username='user@example.com',
        smtp_password='secret',
        smtp_use_tls=True,
        smtp_use_ssl=False,
        smtp_from_email='alerts@example.com',
        smtp_from_name='SentriKat Alerts',
        notification_emails=json.dumps(['admin@example.com', 'sec@example.com']),
        alert_on_critical=True,
        alert_on_high=False,
        alert_on_new_cve=True,
        alert_on_ransomware=True,
        alert_on_low_confidence=False,
        alert_time_start='08:00',
        alert_time_end='18:00',
        alert_days='mon,tue,wed,thu,fri',
    )
    defaults.update(overrides)
    org = Organization(**defaults)
    db_session.add(org)
    db_session.commit()
    return org


def _make_vuln(db_session, cve_id='CVE-2025-9999', severity='CRITICAL', cvss=9.8,
               is_actively_exploited=False, known_ransomware=False, **extra):
    """Create and return a Vulnerability with defaults."""
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


def _make_product(db_session, org, vendor='TestVendor', product_name='TestProduct'):
    """Create and return a Product."""
    from app.models import Product

    prod = Product(
        vendor=vendor,
        product_name=product_name,
        version='1.0.0',
        criticality='high',
        active=True,
        organization_id=org.id,
    )
    db_session.add(prod)
    db_session.flush()
    return prod


def _make_match(db_session, product, vuln, acknowledged=False, first_alerted_at=None,
                match_confidence='high'):
    """Create and return a VulnerabilityMatch."""
    from app.models import VulnerabilityMatch

    match = VulnerabilityMatch(
        product_id=product.id,
        vulnerability_id=vuln.id,
        acknowledged=acknowledged,
        first_alerted_at=first_alerted_at,
        match_confidence=match_confidence,
    )
    db_session.add(match)
    db_session.commit()
    return match


# ===================================================================
# should_send_alert_now
# ===================================================================

class TestShouldSendAlertNow:
    """Tests for the time-window / day-of-week filter."""

    def test_returns_true_when_no_time_restriction(self, app, db_session):
        """With no alert_time_start/end, should always return True."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, alert_time_start=None, alert_time_end=None)
        assert EmailAlertManager.should_send_alert_now(org) is True

    @patch('app.email_alerts.datetime')
    def test_returns_true_within_time_window_and_correct_day(self, mock_dt, app, db_session):
        """Should return True when current time is within window on a valid day."""
        from app.email_alerts import EmailAlertManager

        # Simulate Wednesday 10:00 UTC
        fake_now = datetime(2025, 6, 4, 10, 0, 0)  # Wednesday
        mock_dt.utcnow.return_value = fake_now
        mock_dt.strptime = datetime.strptime

        org = _make_org(db_session, alert_time_start='08:00', alert_time_end='18:00',
                        alert_days='mon,tue,wed,thu,fri')
        assert EmailAlertManager.should_send_alert_now(org) is True

    @patch('app.email_alerts.datetime')
    def test_returns_false_outside_time_window(self, mock_dt, app, db_session):
        """Should return False when current time is outside the window."""
        from app.email_alerts import EmailAlertManager

        # Simulate Wednesday 06:00 UTC (before 08:00 start)
        fake_now = datetime(2025, 6, 4, 6, 0, 0)
        mock_dt.utcnow.return_value = fake_now
        mock_dt.strptime = datetime.strptime

        org = _make_org(db_session, alert_time_start='08:00', alert_time_end='18:00',
                        alert_days='mon,tue,wed,thu,fri')
        assert EmailAlertManager.should_send_alert_now(org) is False

    @patch('app.email_alerts.datetime')
    def test_returns_false_on_excluded_day(self, mock_dt, app, db_session):
        """Should return False on a day not in alert_days."""
        from app.email_alerts import EmailAlertManager

        # Simulate Saturday 12:00 UTC
        fake_now = datetime(2025, 6, 7, 12, 0, 0)  # Saturday
        mock_dt.utcnow.return_value = fake_now
        mock_dt.strptime = datetime.strptime

        org = _make_org(db_session, alert_time_start='08:00', alert_time_end='18:00',
                        alert_days='mon,tue,wed,thu,fri')
        assert EmailAlertManager.should_send_alert_now(org) is False

    @patch('app.email_alerts.datetime')
    def test_midnight_crossing_window(self, mock_dt, app, db_session):
        """Window crossing midnight (e.g. 22:00-02:00) should work correctly."""
        from app.email_alerts import EmailAlertManager

        # Simulate Wednesday 23:00 UTC (inside 22:00-02:00 window)
        fake_now = datetime(2025, 6, 4, 23, 0, 0)
        mock_dt.utcnow.return_value = fake_now
        mock_dt.strptime = datetime.strptime

        org = _make_org(db_session, alert_time_start='22:00', alert_time_end='02:00',
                        alert_days='mon,tue,wed,thu,fri')
        assert EmailAlertManager.should_send_alert_now(org) is True


# ===================================================================
# _send_email
# ===================================================================

class TestSendEmail:
    """Tests for _send_email SMTP logic."""

    def _smtp_config(self, **overrides):
        defaults = dict(
            host='smtp.example.com', port=587, username='user', password='pass',
            use_tls=True, use_ssl=False, from_email='alerts@test.com',
            from_name='SentriKat'
        )
        defaults.update(overrides)
        return defaults

    @patch('app.email_alerts.smtplib.SMTP')
    def test_send_email_with_tls(self, MockSMTP, app):
        """When use_tls=True, SMTP + starttls should be used."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSMTP.return_value = mock_server

        EmailAlertManager._send_email(
            self._smtp_config(), ['admin@test.com'], 'Test', '<p>Hello</p>'
        )

        MockSMTP.assert_called_once_with('smtp.example.com', 587, timeout=30)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('user', 'pass')
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch('app.email_alerts.smtplib.SMTP_SSL')
    def test_send_email_with_ssl(self, MockSSL, app):
        """When use_ssl=True, SMTP_SSL should be used (no starttls)."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSSL.return_value = mock_server

        EmailAlertManager._send_email(
            self._smtp_config(use_ssl=True, use_tls=False, port=465),
            ['a@b.com'], 'Subj', '<p>Hi</p>'
        )

        MockSSL.assert_called_once_with('smtp.example.com', 465, timeout=30)
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()

    @patch('app.email_alerts.smtplib.SMTP')
    def test_send_email_no_auth_when_creds_missing(self, MockSMTP, app):
        """When username/password are empty, login should be skipped."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSMTP.return_value = mock_server

        EmailAlertManager._send_email(
            self._smtp_config(username='', password=''),
            ['a@b.com'], 'Subj', '<p>Hi</p>'
        )

        mock_server.login.assert_not_called()
        mock_server.sendmail.assert_called_once()

    @patch('app.email_alerts.time.sleep')
    @patch('app.email_alerts.smtplib.SMTP')
    def test_send_email_retries_on_failure(self, MockSMTP, mock_sleep, app):
        """Transient failures should be retried with exponential backoff."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSMTP.return_value = mock_server
        # Fail twice, succeed on third attempt
        mock_server.sendmail.side_effect = [
            smtplib.SMTPServerDisconnected("gone"),
            smtplib.SMTPServerDisconnected("gone again"),
            None
        ]

        EmailAlertManager._send_email(
            self._smtp_config(), ['a@b.com'], 'Subj', '<p>Hi</p>', max_retries=3
        )

        assert mock_server.sendmail.call_count == 3
        # Backoff: 2s, 4s
        assert mock_sleep.call_args_list == [call(2), call(4)]

    @patch('app.email_alerts.time.sleep')
    @patch('app.email_alerts.smtplib.SMTP')
    def test_send_email_raises_after_max_retries(self, MockSMTP, mock_sleep, app):
        """If all retries fail, the last exception should be raised."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSMTP.return_value = mock_server
        mock_server.sendmail.side_effect = smtplib.SMTPServerDisconnected("gone")

        with pytest.raises(smtplib.SMTPServerDisconnected):
            EmailAlertManager._send_email(
                self._smtp_config(), ['a@b.com'], 'Subj', '<p>Hi</p>', max_retries=2
            )


# ===================================================================
# test_smtp_connection
# ===================================================================

class TestSmtpConnection:
    """Tests for test_smtp_connection."""

    @patch('app.email_alerts.smtplib.SMTP')
    def test_connection_success_with_tls(self, MockSMTP, app):
        """Successful TLS connection returns success=True."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSMTP.return_value = mock_server

        config = dict(host='smtp.test.com', port=587, username='u', password='p',
                      use_tls=True, use_ssl=False)
        result = EmailAlertManager.test_smtp_connection(config)

        assert result['success'] is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch('app.email_alerts.smtplib.SMTP_SSL')
    def test_connection_success_with_ssl(self, MockSSL, app):
        """Successful SSL connection returns success=True."""
        from app.email_alerts import EmailAlertManager

        mock_server = MagicMock()
        MockSSL.return_value = mock_server

        config = dict(host='smtp.test.com', port=465, username='u', password='p',
                      use_tls=False, use_ssl=True)
        result = EmailAlertManager.test_smtp_connection(config)

        assert result['success'] is True

    @patch('app.email_alerts.smtplib.SMTP')
    def test_connection_failure_returns_error(self, MockSMTP, app):
        """SMTP connection failure returns success=False with error."""
        from app.email_alerts import EmailAlertManager

        MockSMTP.side_effect = smtplib.SMTPConnectError(421, 'Service not available')

        config = dict(host='bad.host', port=587, username='u', password='p',
                      use_tls=True, use_ssl=False)
        result = EmailAlertManager.test_smtp_connection(config)

        assert result['success'] is False
        assert 'error' in result


# ===================================================================
# send_user_invite_email
# ===================================================================

class TestSendUserInviteEmail:
    """Tests for send_user_invite_email."""

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_invite_email_sent_with_org_smtp(self, mock_send, app, db_session):
        """Should send invite email using the organization's SMTP config."""
        from app.email_alerts import send_user_invite_email
        from app.models import User

        org = _make_org(db_session)
        user = User(
            username='newuser', email='new@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        success, msg = send_user_invite_email(user)

        assert success is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        assert call_args.kwargs['recipients'] == ['new@example.com']
        assert 'Welcome' in call_args.kwargs['subject']

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_invite_email_falls_back_to_global_smtp(self, mock_send, app, db_session):
        """When org SMTP is not configured, should try global SMTP settings."""
        from app.email_alerts import send_user_invite_email
        from app.models import User

        org = _make_org(db_session, smtp_host=None, smtp_from_email=None)
        user = User(
            username='fallbackuser', email='fb@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        with patch('app.email_alerts.get_setting', return_value=None):
            success, msg = send_user_invite_email(user)

        # Should fail because both org and global SMTP are unconfigured
        assert success is False
        assert 'No SMTP configured' in msg

    def test_invite_email_no_org_returns_failure(self, app, db_session):
        """If user has no organization, should return (False, message)."""
        from app.email_alerts import send_user_invite_email
        from app.models import User

        user = User(
            username='orphan', email='orphan@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=99999,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        success, msg = send_user_invite_email(user)
        assert success is False
        assert 'No organization' in msg

    @patch('app.email_alerts.EmailAlertManager._send_email',
           side_effect=smtplib.SMTPAuthenticationError(535, 'Bad credentials'))
    def test_invite_email_smtp_error_returns_failure(self, mock_send, app, db_session):
        """SMTP authentication failure should return (False, error_detail)."""
        from app.email_alerts import send_user_invite_email
        from app.models import User

        org = _make_org(db_session)
        user = User(
            username='smtpfail', email='fail@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        success, msg = send_user_invite_email(user)
        assert success is False
        assert 'SMTPAuthenticationError' in msg


# ===================================================================
# send_user_status_email
# ===================================================================

class TestSendUserStatusEmail:
    """Tests for send_user_status_email (block/unblock)."""

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_block_email_sent(self, mock_send, app, db_session):
        """Blocking a user should send an email with 'Blocked' in the subject."""
        from app.email_alerts import send_user_status_email
        from app.models import User

        org = _make_org(db_session, name='status_org')
        user = User(
            username='blockme', email='block@example.com', role='user',
            is_active=False, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        success, msg = send_user_status_email(user, is_blocked=True, blocked_by_username='admin')

        assert success is True
        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args.kwargs
        assert 'Blocked' in call_kwargs['subject']

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_unblock_email_sent(self, mock_send, app, db_session):
        """Unblocking a user should send an email with 'Unblocked' in the subject."""
        from app.email_alerts import send_user_status_email
        from app.models import User

        org = _make_org(db_session, name='unblock_org')
        user = User(
            username='unblockme', email='unblock@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        success, msg = send_user_status_email(user, is_blocked=False)

        assert success is True
        call_kwargs = mock_send.call_args.kwargs
        assert 'Unblocked' in call_kwargs['subject']

    def test_status_email_no_smtp_returns_failure(self, app, db_session):
        """With no SMTP configured, should return failure."""
        from app.email_alerts import send_user_status_email
        from app.models import User

        org = _make_org(db_session, name='nosmtp_org', smtp_host=None, smtp_from_email=None)
        user = User(
            username='nosmtp', email='nosmtp@example.com', role='user',
            is_active=True, auth_type='ldap', organization_id=org.id,
            password_hash='x'
        )
        db_session.add(user)
        db_session.commit()

        with patch('app.email_alerts.get_setting', return_value=None):
            success, msg = send_user_status_email(user, is_blocked=True)

        assert success is False
        assert 'No SMTP configured' in msg


# ===================================================================
# _build_alert_email_html
# ===================================================================

class TestBuildAlertEmailHtml:
    """Tests for the HTML email builder."""

    def test_html_contains_organization_name(self, app, db_session):
        """The generated HTML should include the organization display name."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='html_org', display_name='Acme Corp')
        vuln = _make_vuln(db_session)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        html = EmailAlertManager._build_alert_email_html(org, [match], new_count=1)

        assert 'Acme Corp' in html

    def test_html_contains_cve_id(self, app, db_session):
        """The generated HTML should include the CVE identifier."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='cve_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-1234')
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        html = EmailAlertManager._build_alert_email_html(org, [match])

        assert 'CVE-2025-1234' in html

    def test_html_limits_vulnerability_cards_to_10(self, app, db_session):
        """Email should show at most 10 vulnerability detail cards."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='limit_org')
        product = _make_product(db_session, org)

        matches = []
        for i in range(15):
            vuln = _make_vuln(db_session, cve_id=f'CVE-2025-{1000 + i}')
            m = _make_match(db_session, product, vuln)
            matches.append(m)

        html = EmailAlertManager._build_alert_email_html(org, matches)

        # Should mention "+ 5 more vulnerabilities"
        assert '+ 5 more' in html

    def test_html_shows_actively_exploited_badge(self, app, db_session):
        """Actively exploited CVEs should have the ACTIVELY EXPLOITED badge."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='exploited_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-0DAY', is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        html = EmailAlertManager._build_alert_email_html(org, [match])

        assert 'ACTIVELY EXPLOITED' in html


# ===================================================================
# send_critical_cve_alert
# ===================================================================

class TestSendCriticalCveAlert:
    """Tests for the main send_critical_cve_alert flow."""

    def test_skipped_when_no_matches(self, app, db_session):
        """Empty matches list should return skipped status."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='empty_org')
        result = EmailAlertManager.send_critical_cve_alert(org, [])
        assert result['status'] == 'skipped'

    def test_error_when_smtp_not_configured(self, app, db_session):
        """If no SMTP is configured anywhere, should return error."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='nosmtp2_org',
                        smtp_host=None, smtp_from_email=None)
        vuln = _make_vuln(db_session, is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        with patch('app.email_alerts.get_setting', return_value=None):
            result = EmailAlertManager.send_critical_cve_alert(org, [match])

        assert result['status'] == 'error'
        assert 'SMTP not configured' in result['reason']

    def test_error_when_no_recipients(self, app, db_session):
        """If no notification emails are configured, should return error."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='norec_org', notification_emails=None)
        vuln = _make_vuln(db_session, is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        result = EmailAlertManager.send_critical_cve_alert(org, [match])
        assert result['status'] == 'error'
        assert 'No recipients' in result['reason']

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_success_sends_and_logs(self, mock_send, app, db_session):
        """Successful alert should send email, mark first_alerted_at, and log."""
        from app.email_alerts import EmailAlertManager
        from app.models import AlertLog

        org = _make_org(db_session, name='success_org')
        vuln = _make_vuln(db_session, is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln, first_alerted_at=None)

        result = EmailAlertManager.send_critical_cve_alert(org, [match])

        assert result['status'] == 'success'
        assert result['sent_to'] == 2
        assert result['new_count'] == 1
        mock_send.assert_called_once()

        # Verify first_alerted_at was set
        db_session.refresh(match)
        assert match.first_alerted_at is not None

        # Verify alert log was created
        log = AlertLog.query.filter_by(organization_id=org.id).first()
        assert log is not None
        assert log.status == 'success'

    def test_skipped_when_no_matches_meet_criteria(self, app, db_session):
        """If matches exist but none meet alert criteria, should return skipped."""
        from app.email_alerts import EmailAlertManager

        # Org only alerts on critical, but vuln is medium severity
        org = _make_org(db_session, name='nocrit_org',
                        alert_on_critical=True, alert_on_high=False,
                        alert_on_new_cve=False, alert_on_ransomware=False)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-LOW', severity='MEDIUM', cvss=5.0)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln, first_alerted_at=datetime.utcnow())

        result = EmailAlertManager.send_critical_cve_alert(org, [match])
        assert result['status'] == 'skipped'
        assert 'No matches meet alert criteria' in result['reason']

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_low_confidence_matches_skipped_by_default(self, mock_send, app, db_session):
        """LOW confidence matches should be excluded unless org opts in."""
        from app.email_alerts import EmailAlertManager

        org = _make_org(db_session, name='lowconf_org',
                        alert_on_critical=True, alert_on_new_cve=True,
                        alert_on_low_confidence=False)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-LOWCONF', severity='CRITICAL', cvss=9.5)
        product = _make_product(db_session, org)
        # Only match is low confidence
        match = _make_match(db_session, product, vuln, match_confidence='low')

        result = EmailAlertManager.send_critical_cve_alert(org, [match])
        # Should be skipped because the only match is low confidence
        assert result['status'] == 'skipped'

    @patch('app.email_alerts.EmailAlertManager._send_email',
           side_effect=smtplib.SMTPException("Connection refused"))
    def test_smtp_failure_logs_error(self, mock_send, app, db_session):
        """SMTP failure should log error and return error status."""
        from app.email_alerts import EmailAlertManager
        from app.models import AlertLog

        org = _make_org(db_session, name='smtpfail_org')
        vuln = _make_vuln(db_session, cve_id='CVE-2025-FAIL', is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        result = EmailAlertManager.send_critical_cve_alert(org, [match])

        assert result['status'] == 'error'
        log = AlertLog.query.filter_by(organization_id=org.id).first()
        assert log is not None
        assert log.status == 'failed'


# ===================================================================
# send_generic_alert
# ===================================================================

class TestSendGenericAlert:
    """Tests for send_generic_alert."""

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_generic_alert_uses_org_smtp(self, mock_send, app, db_session):
        """Should try Organization SMTP first."""
        from app.email_alerts import EmailAlertManager

        _make_org(db_session, name='generic_org')

        result = EmailAlertManager.send_generic_alert(
            ['ops@example.com'], 'Disk Full', 'Disk usage at 95%'
        )

        assert result['success'] is True
        mock_send.assert_called_once()

    @patch('app.email_alerts.EmailAlertManager._send_email')
    @patch.dict('os.environ', {
        'SMTP_SERVER': 'env.smtp.com', 'SMTP_PORT': '587',
        'SMTP_FROM_EMAIL': 'env@test.com'
    })
    def test_generic_alert_falls_back_to_env_vars(self, mock_send, app, db_session):
        """When no org has SMTP, should fall back to environment variables."""
        from app.email_alerts import EmailAlertManager

        # Patch Organization.query to return org without SMTP
        with patch('app.email_alerts.Organization') as MockOrg:
            mock_org = MagicMock()
            mock_org.get_smtp_config.return_value = {'host': None, 'from_email': None}
            MockOrg.query.first.return_value = mock_org

            result = EmailAlertManager.send_generic_alert(
                ['ops@test.com'], 'Alert', 'Body'
            )

        assert result['success'] is True
        call_kwargs = mock_send.call_args
        smtp_config = call_kwargs[0][0] if call_kwargs[0] else call_kwargs.kwargs.get('smtp_config')
        assert smtp_config['host'] == 'env.smtp.com'

    def test_generic_alert_no_smtp_returns_failure(self, app, db_session):
        """With no SMTP anywhere, should return success=False."""
        from app.email_alerts import EmailAlertManager

        with patch('app.email_alerts.Organization') as MockOrg:
            MockOrg.query.first.return_value = None

            # Clear any env vars
            with patch.dict('os.environ', {}, clear=True):
                result = EmailAlertManager.send_generic_alert(
                    ['ops@test.com'], 'Alert', 'Body'
                )

        assert result['success'] is False


# ===================================================================
# get_app_url
# ===================================================================

class TestGetAppUrl:
    """Test the get_app_url helper."""

    def test_returns_configured_url(self):
        """Should return Config.SENTRIKAT_URL when set."""
        from app.email_alerts import get_app_url

        with patch('app.email_alerts.Config') as MockConfig:
            MockConfig.SENTRIKAT_URL = 'https://sentrikat.acme.com'
            assert get_app_url() == 'https://sentrikat.acme.com'

    def test_returns_fallback_when_not_configured(self):
        """Should return localhost fallback when Config.SENTRIKAT_URL is falsy."""
        from app.email_alerts import get_app_url

        with patch('app.email_alerts.Config') as MockConfig:
            MockConfig.SENTRIKAT_URL = None
            assert get_app_url() == 'http://localhost:5001'


# ===================================================================
# _log_alert
# ===================================================================

class TestLogAlert:
    """Tests for _log_alert database logging."""

    def test_log_alert_creates_record(self, app, db_session):
        """_log_alert should persist an AlertLog row."""
        from app.email_alerts import EmailAlertManager
        from app.models import AlertLog

        org = _make_org(db_session, name='log_org')
        EmailAlertManager._log_alert(org.id, 'critical_cve', 5, 2, 'success', None)

        log = AlertLog.query.filter_by(organization_id=org.id).first()
        assert log is not None
        assert log.alert_type == 'critical_cve'
        assert log.matches_count == 5
        assert log.recipients_count == 2
        assert log.status == 'success'
        assert log.error_message is None

    def test_log_alert_stores_error_message(self, app, db_session):
        """_log_alert should persist error details on failure."""
        from app.email_alerts import EmailAlertManager
        from app.models import AlertLog

        org = _make_org(db_session, name='logerr_org')
        EmailAlertManager._log_alert(org.id, 'critical_cve', 3, 1, 'failed', 'SMTP timeout')

        log = AlertLog.query.filter_by(organization_id=org.id).first()
        assert log.status == 'failed'
        assert log.error_message == 'SMTP timeout'


# ===================================================================
# _role_level helper
# ===================================================================

class TestRoleLevel:
    """Test the _role_level helper function."""

    def test_known_roles(self):
        from app.email_alerts import _role_level
        assert _role_level('user') == 1
        assert _role_level('manager') == 2
        assert _role_level('org_admin') == 3
        assert _role_level('super_admin') == 4

    def test_unknown_role_returns_zero(self):
        from app.email_alerts import _role_level
        assert _role_level('unknown') == 0


# ===================================================================
# Double-encoded notification_emails
# ===================================================================

class TestNotificationEmailsParsing:
    """Test that double-encoded JSON notification_emails are handled."""

    @patch('app.email_alerts.EmailAlertManager._send_email')
    def test_double_encoded_json_recipients(self, mock_send, app, db_session):
        """Double-encoded JSON like '"[\\"a@b.com\\"]"' should be parsed correctly."""
        from app.email_alerts import EmailAlertManager

        # Double-encode: first json.dumps produces list, second wraps in string
        inner = json.dumps(['double@example.com'])
        double_encoded = json.dumps(inner)  # produces a string of the JSON list

        org = _make_org(db_session, name='double_org',
                        notification_emails=double_encoded,
                        alert_on_critical=True)
        vuln = _make_vuln(db_session, cve_id='CVE-2025-DBL', is_actively_exploited=True)
        product = _make_product(db_session, org)
        match = _make_match(db_session, product, vuln)

        result = EmailAlertManager.send_critical_cve_alert(org, [match])

        assert result['status'] == 'success'
        call_kwargs = mock_send.call_args.kwargs
        assert 'double@example.com' in call_kwargs['recipients']
