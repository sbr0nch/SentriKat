# SentriKat Logging & Performance Monitoring Guide

This guide explains the comprehensive logging and performance monitoring system implemented in SentriKat.

## Table of Contents
- [Log Files](#log-files)
- [Audit Logging](#audit-logging)
- [Performance Monitoring](#performance-monitoring)
- [Caching System](#caching-system)
- [Usage Examples](#usage-examples)
- [Log Analysis](#log-analysis)

## Log Files

All logs are stored in `/var/log/sentrikat/` (or `./logs/` if permission denied):

### 1. `application.log` - General Application Logs
- **Level**: INFO and above
- **Content**: General application events, startup messages, info logs
- **Rotation**: 10MB per file, 10 backups
- **Format**: `[timestamp] LEVEL in module (function:line): message`

### 2. `error.log` - Error Logs Only
- **Level**: ERROR and CRITICAL only
- **Content**: Application errors, exceptions, critical failures
- **Rotation**: 10MB per file, 10 backups
- **Use**: Quick error diagnosis without sifting through INFO logs

### 3. `access.log` - HTTP Request Logs
- **Level**: INFO
- **Content**: All HTTP requests with timing and user info
- **Rotation**: 20MB per file, 10 backups
- **Format**: `method path status duration_ms user:user_id ip:ip_address`
- **Example**: `GET /api/vulnerabilities 200 245.32ms user:5 ip:192.168.1.100`

### 4. `ldap.log` - LDAP Operations
- **Level**: INFO (success) and ERROR (failures)
- **Content**: All LDAP operations (searches, invites, syncs)
- **Rotation**: 10MB per file, 10 backups
- **Use**: Debugging LDAP/Active Directory integration issues

### 5. `security.log` - Security Events
- **Level**: WARNING and above
- **Content**: Authentication failures, permission errors, security events
- **Rotation**: 10MB per file, 20 backups (kept longer for security audits)
- **Use**: Security auditing, breach detection, compliance

### 6. `audit.log` - Data Modification Audit Trail (NEW)
- **Level**: INFO
- **Content**: All data modifications (CREATE, UPDATE, DELETE, INVITE)
- **Rotation**: 20MB per file, 50 backups (extensive history for compliance)
- **Format**: JSON (structured logging)
- **Use**: Compliance audits, change tracking, forensics

**Example audit log entry:**
```json
{
  "timestamp": "2025-12-19T14:23:45.123Z",
  "level": "INFO",
  "logger": "audit",
  "message": "INVITE users:42 - Invited LDAP user jdoe",
  "action": "INVITE",
  "resource": "users:42",
  "user_id": 15,
  "ip_address": "192.168.1.100",
  "new_value": {
    "username": "jdoe",
    "email": "jdoe@company.com",
    "role": "user",
    "organization_id": 3,
    "auth_type": "ldap"
  }
}
```

### 7. `performance.log` - Performance Profiling (NEW)
- **Level**: INFO (slow) and WARNING (very slow)
- **Content**: Slow endpoints (>1s), slow queries (>500ms)
- **Rotation**: 20MB per file, 10 backups
- **Format**: JSON (structured logging)
- **Use**: Performance optimization, identifying bottlenecks

**Example performance log entry:**
```json
{
  "timestamp": "2025-12-19T14:23:45.123Z",
  "level": "WARNING",
  "logger": "performance",
  "message": "VERY SLOW: POST /api/shared/create took 5234.56ms",
  "endpoint": "POST /api/shared/create",
  "duration_ms": 5234.56,
  "method": "POST",
  "ip_address": "192.168.1.100",
  "query_count": 12
}
```

## Audit Logging

### Usage in Code

```python
from app.logging_config import log_audit_event

# Log user creation
log_audit_event(
    'CREATE',
    'users',
    user.id,
    new_value={
        'username': 'jdoe',
        'email': 'jdoe@example.com',
        'role': 'user'
    }
)

# Log user update
log_audit_event(
    'UPDATE',
    'users',
    user.id,
    old_value={'role': 'user'},
    new_value={'role': 'admin'},
    details='Role escalation approved by super admin'
)

# Log deletion
log_audit_event(
    'DELETE',
    'products',
    product_id,
    old_value={'name': 'Old Product', 'version': '1.0'}
)
```

### Audit Event Types
- **CREATE**: New resource created
- **UPDATE**: Resource modified
- **DELETE**: Resource deleted
- **INVITE**: User invited to system
- **REACTIVATE**: Inactive user reactivated
- **SYNC**: Data synchronized (e.g., LDAP sync)

## Performance Monitoring

### Automatic Monitoring

The performance middleware automatically:
- Tracks all HTTP request durations
- Logs requests slower than 1 second
- Counts database queries per request
- Adds debug headers: `X-Response-Time`, `X-Query-Count`

### Manual Profiling

#### 1. Function Decorator

```python
from app.logging_config import track_performance

@track_performance(threshold_ms=500)
def expensive_operation():
    # Code that might be slow
    ...
```

#### 2. Context Manager

```python
from app.performance_middleware import PerformanceMonitor

def process_data():
    with PerformanceMonitor('data_processing', threshold_ms=1000):
        # Code to monitor
        ...
```

#### 3. Manual Logging

```python
from app.logging_config import log_performance

start_time = time.time()
# ... operation ...
duration_ms = (time.time() - start_time) * 1000

log_performance(
    endpoint='custom_operation',
    duration_ms=duration_ms,
    query_count=5,
    cache_hit=True
)
```

## Caching System

### Simple In-Memory Cache

```python
from app.cache_utils import get_cache, cached

# Get cache instance
cache = get_cache()

# Manual caching
cache.set('stats', data, ttl=600)  # 10 minutes
data = cache.get('stats')
cache.delete('stats')

# Decorator-based caching
@cached(ttl=300)  # 5 minutes
def get_dashboard_stats():
    # Expensive operation
    return expensive_query()

# Cache will be automatically used on subsequent calls
stats = get_dashboard_stats()  # Cached after first call
```

### Query Result Caching

```python
from app.cache_utils import cached_query

@cached_query(ttl=600)
def get_active_vulnerabilities(org_id):
    return Vulnerability.query.filter_by(
        organization_id=org_id
    ).all()
```

### Cache Invalidation

```python
from app.cache_utils import invalidate_cache_pattern

# Invalidate all product caches when products change
invalidate_cache_pattern('products')

# Invalidate specific organization caches
invalidate_cache_pattern(f'org:{org_id}')
```

## Usage Examples

### Example 1: Log User Role Change

```python
@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    user = User.query.get(user_id)
    old_role = user.role
    new_role = request.json['role']

    user.role = new_role
    db.session.commit()

    # Audit the change
    log_audit_event(
        'UPDATE',
        'users',
        user_id,
        old_value={'role': old_role},
        new_value={'role': new_role},
        details=f'Role changed from {old_role} to {new_role}'
    )

    return jsonify({'success': True})
```

### Example 2: Cache Expensive Queries

```python
from app.cache_utils import cached

@cached(ttl=600, key_prefix='vuln_stats')
def get_vulnerability_statistics(org_id):
    """Cache stats for 10 minutes"""
    stats = {
        'total': Vulnerability.query.filter_by(
            organization_id=org_id
        ).count(),
        'critical': Vulnerability.query.filter_by(
            organization_id=org_id,
            priority='critical'
        ).count()
    }
    return stats

# First call: hits database
stats = get_vulnerability_statistics(5)

# Subsequent calls within 10 minutes: served from cache
stats = get_vulnerability_statistics(5)
```

### Example 3: Profile Slow Operations

```python
from app.performance_middleware import PerformanceMonitor

def sync_all_ldap_users(org_id):
    with PerformanceMonitor('ldap_full_sync', threshold_ms=5000):
        # This will be logged if it takes more than 5 seconds
        users = LDAPManager.search_users('*', max_results=1000)

        for user in users:
            # Process users...
            pass
```

## Log Analysis

### Finding Slow Endpoints

```bash
# Show all slow requests (>1 second)
grep "SLOW" /var/log/sentrikat/performance.log | jq '.'

# Show VERY slow requests (>5 seconds)
grep "VERY SLOW" /var/log/sentrikat/performance.log | jq '.'

# Find slowest endpoints
grep "duration_ms" /var/log/sentrikat/performance.log | \
  jq -r '[.endpoint, .duration_ms] | @tsv' | \
  sort -k2 -rn | head -20
```

### Tracking User Actions

```bash
# Find all actions by a specific user
grep '"user_id": 5' /var/log/sentrikat/audit.log | jq '.'

# Find all role changes
grep '"action": "UPDATE"' /var/log/sentrikat/audit.log | \
  grep '"resource": "users:' | jq '.'

# Find all deletions
grep '"action": "DELETE"' /var/log/sentrikat/audit.log | jq '.'
```

### Security Monitoring

```bash
# Failed login attempts
grep "LOGIN_FAILED" /var/log/sentrikat/security.log

# Permission denied errors
grep "PERMISSION_DENIED" /var/log/sentrikat/security.log

# Recent security events
tail -100 /var/log/sentrikat/security.log
```

### Performance Analysis

```bash
# Average response time for an endpoint
grep "/api/vulnerabilities" /var/log/sentrikat/access.log | \
  awk '{print $4}' | sed 's/ms//' | \
  awk '{sum+=$1; count++} END {print sum/count "ms average"}'

# Requests with most database queries
grep "query_count" /var/log/sentrikat/performance.log | \
  jq -r '[.endpoint, .query_count] | @tsv' | \
  sort -k2 -rn | head -10
```

## Log Rotation

All logs use Python's `RotatingFileHandler`:
- **Automatic rotation** when file reaches max size
- **Backup copies** kept for historical analysis
- **Automatic compression** (optional, can be added)

## Best Practices

1. **Audit Critical Operations**: Always log CREATE, UPDATE, DELETE for important resources
2. **Cache Aggressively**: Cache expensive queries with appropriate TTL
3. **Profile New Features**: Use `@track_performance` on new complex functions
4. **Monitor Performance Logs**: Regularly check for slow endpoints and optimize
5. **Review Audit Logs**: Periodic compliance reviews of data modifications
6. **Set Appropriate TTLs**: Balance freshness vs. performance (5-10 minutes typical)
7. **Invalidate on Updates**: Clear cache when underlying data changes

## Troubleshooting

### Logs Not Being Created
- Check directory permissions: `/var/log/sentrikat/` or `./logs/`
- Check user running Flask app has write permissions
- Logs will fallback to `./logs/` if `/var/log/` is not writable

### Performance Log Empty
- Performance log only logs slow operations (>1 second)
- If app is fast, this is normal!
- Lower threshold in `performance_middleware.py` if needed

### Cache Not Working
- Ensure cache TTL hasn't expired
- Check cache stats: `get_cache().get_stats()`
- Clear cache if stale: `get_cache().clear()`

## Integration with Log Management Tools

The JSON-formatted logs (audit.log, performance.log) can be easily integrated with:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **Datadog**
- **Grafana Loki**
- **CloudWatch Logs** (AWS)

Simply configure log shipper to read JSON logs and send to your log aggregation platform.
