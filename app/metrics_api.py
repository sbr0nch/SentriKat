"""
Prometheus-compatible metrics endpoint.

Exposes application metrics in Prometheus text format at /metrics.
Protected by API key or localhost-only access.
"""

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


def _is_allowed():
    """Allow metrics from localhost, Docker networks, or with valid API key."""
    remote = request.remote_addr or ''
    # Allow localhost and Docker internal networks
    if remote in ('127.0.0.1', '::1', 'localhost') or remote.startswith('172.'):
        return True
    # Allow with Bearer token matching SENTRIKAT_PROVISION_KEY (reuse existing key)
    import os
    metrics_key = os.environ.get('SENTRIKAT_METRICS_KEY', os.environ.get('SENTRIKAT_PROVISION_KEY', ''))
    if metrics_key:
        auth = request.headers.get('Authorization', '')
        if auth == f'Bearer {metrics_key}':
            return True
    return False


@metrics_bp.route('/metrics')
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    if not _is_allowed():
        return Response('Forbidden', status=403)

    start = time.time()
    lines = []

    def gauge(name, value, help_text, labels=None):
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        if labels:
            label_str = ','.join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f'{name}{{{label_str}}} {value}')
        else:
            lines.append(f'{name} {value}')

    try:
        # Organization metrics
        org_count = Organization.query.filter_by(active=True).count()
        gauge('sentrikat_organizations_active', org_count, 'Number of active organizations')

        # User metrics
        user_count = User.query.filter_by(is_active=True).count()
        gauge('sentrikat_users_active', user_count, 'Number of active users')

        # Product metrics
        product_count = Product.query.filter_by(active=True).count()
        gauge('sentrikat_products_active', product_count, 'Number of active products')

        # Asset/Agent metrics
        from datetime import datetime, timedelta
        online_threshold = datetime.utcnow() - timedelta(days=14)
        agents_online = Asset.query.filter(
            Asset.status.in_(['online', 'offline']),
            Asset.last_checkin >= online_threshold
        ).count()
        agents_total = Asset.query.count()
        gauge('sentrikat_agents_online', agents_online, 'Agents checked in within 14 days')
        gauge('sentrikat_agents_total', agents_total, 'Total registered agents')

        # Vulnerability metrics
        vuln_total = Vulnerability.query.count()
        gauge('sentrikat_vulnerabilities_total', vuln_total, 'Total vulnerabilities in database')

        match_total = VulnerabilityMatch.query.count()
        gauge('sentrikat_vulnerability_matches_total', match_total, 'Total vulnerability matches')

        # Severity breakdown
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = db.session.query(VulnerabilityMatch).join(Vulnerability).filter(
                Vulnerability.severity == severity
            ).count()
            gauge('sentrikat_vulnerability_matches_by_severity', count,
                  'Vulnerability matches by severity', {'severity': severity})

        # API key metrics
        api_keys_active = AgentApiKey.query.filter_by(active=True).count()
        gauge('sentrikat_api_keys_active', api_keys_active, 'Active agent API keys')

        # Subscription metrics (SaaS only)
        import os
        if os.environ.get('SENTRIKAT_MODE', 'onpremise').lower() == 'saas':
            for status in ['active', 'trialing', 'canceled']:
                count = Subscription.query.filter_by(status=status).count()
                gauge('sentrikat_subscriptions', count,
                      'Subscriptions by status', {'status': status})

        # Request duration
        duration = time.time() - start
        gauge('sentrikat_metrics_duration_seconds', f'{duration:.4f}',
              'Time to generate metrics')

    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return Response(f'# Error generating metrics: {type(e).__name__}\n', status=500,
                        content_type='text/plain; version=0.0.4; charset=utf-8')

    body = '\n'.join(lines) + '\n'
    return Response(body, content_type='text/plain; version=0.0.4; charset=utf-8')
