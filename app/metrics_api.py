"""
Prometheus-compatible metrics endpoint.

Exposes application metrics in Prometheus text format at /metrics.
Protected by API key ONLY — bearer token auth is mandatory on every call.

Security posture:
    * H1 (audit): historically this endpoint allow-listed RFC1918 private
      source addresses and localhost. That bypass has been removed — even
      requests from 127.0.0.1 must now carry a valid bearer token. The
      metrics payload contains tenant-aggregate counts that should not be
      readable by any unauthenticated process co-resident with the app.
    * H2 (audit): the bearer token is read from ``SENTRIKAT_METRICS_KEY``.
      For compatibility with existing deployments we still accept
      ``SENTRIKAT_PROVISION_KEY`` as a fallback, but we emit a deprecation
      warning at WARN level on every successful use of the fallback. The
      provision-key fallback will be REMOVED in Sprint 6.
"""

import hmac
import os
import time
import logging
from flask import Blueprint, request, Response
from app import db
from app.models import (
    Organization, User, Product, Asset, Vulnerability,
    VulnerabilityMatch, AgentApiKey, Subscription
)

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)


def _get_metrics_key_and_source():
    """Return ``(key, source)`` for the metrics bearer token.

    ``source`` is ``'metrics'`` when the dedicated
    ``SENTRIKAT_METRICS_KEY`` env var is set, or ``'provision'`` when we
    fall back to ``SENTRIKAT_PROVISION_KEY``. Returns ``(None, None)``
    when neither is configured.
    """
    metrics_key = (os.environ.get('SENTRIKAT_METRICS_KEY') or '').strip()
    if metrics_key:
        return metrics_key, 'metrics'
    fallback = (os.environ.get('SENTRIKAT_PROVISION_KEY') or '').strip()
    if fallback:
        return fallback, 'provision'
    return None, None


def _is_allowed():
    """Authenticate the metrics request via mandatory bearer token.

    H1: the previous RFC1918 / localhost allowlist has been deleted. Every
    caller — including Prometheus scrapers running on the same host — must
    present an ``Authorization: Bearer <token>`` header. The header value is
    compared with :func:`hmac.compare_digest` to prevent timing side channels.
    """
    metrics_key, source = _get_metrics_key_and_source()
    if not metrics_key:
        # No key configured → deny. We do not fall back to IP-based auth.
        logger.warning(
            "Metrics endpoint hit but neither SENTRIKAT_METRICS_KEY nor "
            "SENTRIKAT_PROVISION_KEY is set — rejecting request"
        )
        return False

    auth_header = request.headers.get('Authorization', '')
    expected = f'Bearer {metrics_key}'
    # hmac.compare_digest is constant-time on equal-length inputs.
    if not hmac.compare_digest(auth_header, expected):
        return False

    if source == 'provision':
        # H2: log a loud deprecation warning — this fallback goes away in
        # Sprint 6 and operators need to rotate to SENTRIKAT_METRICS_KEY.
        logger.warning(
            "DEPRECATION: /metrics authenticated with SENTRIKAT_PROVISION_KEY. "
            "Set SENTRIKAT_METRICS_KEY to a dedicated secret — the provision-key "
            "fallback will be REMOVED in Sprint 6."
        )
    return True


def _fmt_number(value):
    """Format a numeric value for Prometheus text format (M16).

    Prometheus' text exposition format accepts scientific notation but
    several ingesters (and humans reading /metrics) choke on it. We force
    a fixed-point representation: integers as ``"%d"``, floats as
    ``"%.6f"``. Non-numeric values are stringified as-is and the caller is
    expected to have already formatted them.
    """
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, int):
        return f"{value}"
    if isinstance(value, float):
        # Avoid scientific notation for small/large floats.
        return f"{value:.6f}"
    return str(value)


@metrics_bp.route('/metrics')
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint.

    Requires ``Authorization: Bearer <SENTRIKAT_METRICS_KEY>``. Returns
    ``401 Unauthorized`` when the token is missing or wrong (H1).
    """
    if not _is_allowed():
        return Response(
            '# Unauthorized: bearer token required\n',
            status=401,
            headers={'WWW-Authenticate': 'Bearer realm="metrics"'},
            content_type='text/plain; version=0.0.4; charset=utf-8',
        )

    start = time.time()
    lines = []

    def gauge(name, value, help_text, labels=None):
        """Emit a gauge line. ``value`` is formatted via :func:`_fmt_number`
        so we never leak scientific notation into the text exposition (M16)."""
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        formatted = _fmt_number(value)
        if labels:
            label_str = ','.join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f'{name}{{{label_str}}} {formatted}')
        else:
            lines.append(f'{name} {formatted}')

    def _collect(name, fn):
        """Run a metric collector and log+skip on failure (M16).

        A single bad query used to turn the whole /metrics endpoint into a
        500. We now isolate each collector so one broken gauge cannot
        blackhole the scraper.
        """
        try:
            fn()
        except Exception as exc:
            logger.warning(
                f"Metrics collector '{name}' failed, skipping: "
                f"{type(exc).__name__}: {exc}"
            )

    from datetime import datetime, timedelta

    def _orgs():
        org_count = Organization.query.filter_by(active=True).count()
        gauge('sentrikat_organizations_active', org_count, 'Number of active organizations')
    _collect('organizations', _orgs)

    def _users():
        user_count = User.query.filter_by(is_active=True).count()
        gauge('sentrikat_users_active', user_count, 'Number of active users')
    _collect('users', _users)

    def _products():
        product_count = Product.query.filter_by(active=True).count()
        gauge('sentrikat_products_active', product_count, 'Number of active products')
    _collect('products', _products)

    def _agents():
        online_threshold = datetime.utcnow() - timedelta(days=14)
        agents_online = Asset.query.filter(
            Asset.status.in_(['online', 'offline']),
            Asset.last_checkin >= online_threshold
        ).count()
        agents_total = Asset.query.count()
        gauge('sentrikat_agents_online', agents_online, 'Agents checked in within 14 days')
        gauge('sentrikat_agents_total', agents_total, 'Total registered agents')
    _collect('agents', _agents)

    def _vulns():
        vuln_total = Vulnerability.query.count()
        gauge('sentrikat_vulnerabilities_total', vuln_total, 'Total vulnerabilities in database')
        match_total = VulnerabilityMatch.query.count()
        gauge('sentrikat_vulnerability_matches_total', match_total, 'Total vulnerability matches')
    _collect('vulnerabilities', _vulns)

    def _severity():
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = db.session.query(VulnerabilityMatch).join(Vulnerability).filter(
                Vulnerability.severity == severity
            ).count()
            gauge('sentrikat_vulnerability_matches_by_severity', count,
                  'Vulnerability matches by severity', {'severity': severity})
    _collect('severity_breakdown', _severity)

    def _api_keys():
        api_keys_active = AgentApiKey.query.filter_by(active=True).count()
        gauge('sentrikat_api_keys_active', api_keys_active, 'Active agent API keys')
    _collect('api_keys', _api_keys)

    def _sprint4():
        from app.models import RemediationAssignment, RiskException, ProductAlias
        for status in ['open', 'in_progress', 'resolved', 'accepted_risk']:
            count = RemediationAssignment.query.filter_by(status=status).count()
            gauge('sentrikat_assignments', count,
                  'Remediation assignments by status', {'status': status})

        overdue = RemediationAssignment.query.filter(
            RemediationAssignment.due_date < datetime.utcnow().date(),
            RemediationAssignment.status.in_(['open', 'in_progress'])
        ).count()
        gauge('sentrikat_assignments_overdue', overdue, 'Assignments past due date')

        tracker_linked = RemediationAssignment.query.filter(
            RemediationAssignment.tracker_issue_key.isnot(None)
        ).count()
        gauge('sentrikat_assignments_with_tracker_ticket', tracker_linked,
              'Assignments linked to issue tracker tickets')

        for status in ['active', 'expired', 'revoked']:
            count = RiskException.query.filter_by(status=status).count()
            gauge('sentrikat_risk_exceptions', count,
                  'Risk exceptions by status', {'status': status})

        alias_count = ProductAlias.query.count()
        gauge('sentrikat_product_aliases_total', alias_count, 'Total product aliases configured')
    _collect('sprint4', _sprint4)

    def _subs():
        if os.environ.get('SENTRIKAT_MODE', 'onpremise').lower() == 'saas':
            for status in ['active', 'trialing', 'canceled']:
                count = Subscription.query.filter_by(status=status).count()
                gauge('sentrikat_subscriptions', count,
                      'Subscriptions by status', {'status': status})
    _collect('subscriptions', _subs)

    # Request duration — always emitted in fixed-point seconds (M16).
    duration = time.time() - start
    gauge('sentrikat_metrics_duration_seconds', float(duration),
          'Time to generate metrics')

    body = '\n'.join(lines) + '\n'
    return Response(body, content_type='text/plain; version=0.0.4; charset=utf-8')
