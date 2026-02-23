"""
Prometheus metrics endpoint for SentriKat.

Exposes application metrics at /metrics for scraping by Prometheus.
Enable with PROMETHEUS_ENABLED=true (default: false).

Metrics exposed:
  - sentrikat_http_requests_total (counter) - HTTP requests by method/endpoint/status
  - sentrikat_http_request_duration_seconds (histogram) - Request latency
  - sentrikat_vulnerabilities_total (gauge) - Total vulnerabilities tracked
  - sentrikat_vulnerability_matches_total (gauge) - Active vulnerability matches
  - sentrikat_products_total (gauge) - Total active products
  - sentrikat_agents_online (gauge) - Online agents
  - sentrikat_sync_last_success_timestamp (gauge) - Last successful sync time
  - sentrikat_import_queue_pending (gauge) - Pending import queue items
  - sentrikat_inventory_jobs_active (gauge) - Active inventory jobs
"""

import os
import time
import logging
from flask import Blueprint, Response, request

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)

# In-memory counters (lightweight, no external dependency required)
_request_counts = {}   # (method, endpoint, status) -> count
_request_durations = {}  # endpoint -> [durations]
_DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]


def _is_enabled():
    return os.environ.get('PROMETHEUS_ENABLED', 'false').lower() == 'true'


def record_request(method, endpoint, status_code, duration):
    """Record a request metric (called from middleware)."""
    if not _is_enabled():
        return
    key = (method, endpoint, str(status_code))
    _request_counts[key] = _request_counts.get(key, 0) + 1

    if endpoint not in _request_durations:
        _request_durations[endpoint] = {'sum': 0.0, 'count': 0, 'buckets': {b: 0 for b in _DURATION_BUCKETS}}
    d = _request_durations[endpoint]
    d['sum'] += duration
    d['count'] += 1
    for b in _DURATION_BUCKETS:
        if duration <= b:
            d['buckets'][b] += 1


def _collect_app_metrics():
    """Collect application-level metrics from database."""
    lines = []
    try:
        from app import db
        from app.models import Vulnerability, VulnerabilityMatch, Product, Asset, InventoryJob

        vuln_count = db.session.query(Vulnerability).count()
        lines.append(f'sentrikat_vulnerabilities_total {vuln_count}')

        match_count = db.session.query(VulnerabilityMatch).filter_by(is_acknowledged=False).count()
        lines.append(f'sentrikat_vulnerability_matches_total {match_count}')

        product_count = db.session.query(Product).filter_by(active=True).count()
        lines.append(f'sentrikat_products_total {product_count}')

        online_agents = db.session.query(Asset).filter_by(agent_status='online').count()
        lines.append(f'sentrikat_agents_online {online_agents}')

        active_jobs = db.session.query(InventoryJob).filter_by(status='processing').count()
        lines.append(f'sentrikat_inventory_jobs_active {active_jobs}')

        try:
            from app.models import ImportQueue
            pending_imports = db.session.query(ImportQueue).filter_by(status='pending').count()
            lines.append(f'sentrikat_import_queue_pending {pending_imports}')
        except Exception:
            pass

        try:
            from app.models import SyncLog
            last_sync = db.session.query(SyncLog).filter_by(status='success').order_by(SyncLog.id.desc()).first()
            if last_sync and last_sync.sync_date:
                ts = last_sync.sync_date.timestamp()
                lines.append(f'sentrikat_sync_last_success_timestamp {ts:.0f}')
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"Error collecting app metrics: {e}")

    return lines


@metrics_bp.route('/metrics')
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    if not _is_enabled():
        return Response('Prometheus metrics not enabled. Set PROMETHEUS_ENABLED=true\n',
                        status=404, mimetype='text/plain')

    lines = []

    # HTTP request counters
    lines.append('# HELP sentrikat_http_requests_total Total HTTP requests')
    lines.append('# TYPE sentrikat_http_requests_total counter')
    for (method, endpoint, status), count in sorted(_request_counts.items()):
        lines.append(f'sentrikat_http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {count}')

    # HTTP request duration histogram
    lines.append('# HELP sentrikat_http_request_duration_seconds HTTP request duration')
    lines.append('# TYPE sentrikat_http_request_duration_seconds histogram')
    for endpoint, d in sorted(_request_durations.items()):
        for bucket_le, count in sorted(d['buckets'].items()):
            lines.append(f'sentrikat_http_request_duration_seconds_bucket{{endpoint="{endpoint}",le="{bucket_le}"}} {count}')
        lines.append(f'sentrikat_http_request_duration_seconds_bucket{{endpoint="{endpoint}",le="+Inf"}} {d["count"]}')
        lines.append(f'sentrikat_http_request_duration_seconds_sum{{endpoint="{endpoint}"}} {d["sum"]:.6f}')
        lines.append(f'sentrikat_http_request_duration_seconds_count{{endpoint="{endpoint}"}} {d["count"]}')

    # Application metrics
    lines.append('# HELP sentrikat_vulnerabilities_total Total vulnerabilities tracked')
    lines.append('# TYPE sentrikat_vulnerabilities_total gauge')
    lines.append('# HELP sentrikat_vulnerability_matches_total Active vulnerability matches')
    lines.append('# TYPE sentrikat_vulnerability_matches_total gauge')
    lines.append('# HELP sentrikat_products_total Total active products')
    lines.append('# TYPE sentrikat_products_total gauge')
    lines.append('# HELP sentrikat_agents_online Currently online agents')
    lines.append('# TYPE sentrikat_agents_online gauge')
    lines.append('# HELP sentrikat_inventory_jobs_active Active inventory jobs')
    lines.append('# TYPE sentrikat_inventory_jobs_active gauge')
    lines.append('# HELP sentrikat_import_queue_pending Pending import queue items')
    lines.append('# TYPE sentrikat_import_queue_pending gauge')
    lines.append('# HELP sentrikat_sync_last_success_timestamp Last successful sync unix timestamp')
    lines.append('# TYPE sentrikat_sync_last_success_timestamp gauge')
    lines.extend(_collect_app_metrics())

    return Response('\n'.join(lines) + '\n', mimetype='text/plain; version=0.0.4; charset=utf-8')


def setup_metrics_middleware(app):
    """Install after_request handler to record metrics."""
    if not _is_enabled():
        return

    @app.after_request
    def _record_metrics(response):
        if request.path == '/metrics' or request.path.startswith('/static'):
            return response
        duration = getattr(request, '_metrics_start_time', None)
        if duration is not None:
            duration = time.time() - duration
            endpoint = request.endpoint or request.path
            record_request(request.method, endpoint, response.status_code, duration)
        return response

    @app.before_request
    def _start_timer():
        request._metrics_start_time = time.time()
