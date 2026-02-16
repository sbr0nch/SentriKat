from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
import os

# Read version from VERSION file (single source of truth)
_VERSION_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VERSION')
try:
    with open(_VERSION_FILE, 'r') as _f:
        APP_VERSION = _f.read().strip()
except Exception:
    APP_VERSION = '0.0.0'

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
# Rate limits: Allow reasonable admin operations while preventing abuse
# Exempt admin/manager routes from strict limits via decorator overrides
limiter = Limiter(key_func=get_remote_address, default_limits=["1000 per day", "200 per hour"])


def _apply_schema_migrations(logger, db_uri):
    """Apply schema migrations for new columns (works for SQLite and PostgreSQL)"""
    from sqlalchemy import text, create_engine

    # List of migrations to apply: (table_name, column_name, column_definition_sqlite, column_definition_pg)
    migrations = [
        ('vulnerability_matches', 'first_alerted_at', 'DATETIME', 'TIMESTAMP'),
        ('agent_api_keys', 'auto_approve', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        ('inventory_jobs', 'api_key_id', 'INTEGER', 'INTEGER'),
        ('users', 'totp_required', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        ('vulnerability_matches', 'auto_acknowledged', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        ('vulnerability_matches', 'resolution_reason', 'VARCHAR(50)', 'VARCHAR(50)'),
        ('vulnerability_matches', 'acknowledged_at', 'DATETIME', 'TIMESTAMP'),
        # EPSS (Exploit Prediction Scoring System) columns
        ('vulnerabilities', 'epss_score', 'REAL', 'DOUBLE PRECISION'),
        ('vulnerabilities', 'epss_percentile', 'REAL', 'DOUBLE PRECISION'),
        ('vulnerabilities', 'epss_fetched_at', 'DATETIME', 'TIMESTAMP'),
        # Agent Command & Control columns
        ('assets', 'pending_scan', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        ('assets', 'scan_interval_override', 'INTEGER', 'INTEGER'),
        ('assets', 'pending_scan_requested_at', 'DATETIME', 'TIMESTAMP'),
        ('assets', 'pending_scan_requested_by', 'VARCHAR(100)', 'VARCHAR(100)'),
        # Vendor Fix Override table (auto-created by SQLAlchemy, columns here for safety)
        # Phase 2: Agent distro version and KB reporting
        ('product_installations', 'distro_package_version', 'VARCHAR(200)', 'VARCHAR(200)'),
        ('assets', 'installed_kbs', 'TEXT', 'TEXT'),
        ('vendor_fix_overrides', 'fix_type', "VARCHAR(50) DEFAULT 'backport_patch'", "VARCHAR(50) DEFAULT 'backport_patch'"),
        ('vendor_fix_overrides', 'vendor_advisory_url', 'TEXT', 'TEXT'),
        ('vendor_fix_overrides', 'vendor_advisory_id', 'VARCHAR(100)', 'VARCHAR(100)'),
        ('vendor_fix_overrides', 'patch_identifier', 'VARCHAR(255)', 'VARCHAR(255)'),
        ('vendor_fix_overrides', 'notes', 'TEXT', 'TEXT'),
        ('vendor_fix_overrides', 'approved_by', 'INTEGER', 'INTEGER'),
        ('vendor_fix_overrides', 'approved_at', 'DATETIME', 'TIMESTAMP'),
        ('vendor_fix_overrides', 'status', "VARCHAR(20) DEFAULT 'approved'", "VARCHAR(20) DEFAULT 'approved'"),
        # Three-tier confidence system
        ('vendor_fix_overrides', 'confidence', "VARCHAR(20) DEFAULT 'medium'", "VARCHAR(20) DEFAULT 'medium'"),
        ('vendor_fix_overrides', 'confidence_reason', 'VARCHAR(255)', 'VARCHAR(255)'),
        ('vulnerability_matches', 'vendor_fix_confidence', 'VARCHAR(20)', 'VARCHAR(20)'),
        # Product agent tracking columns (required for agent inventory submission)
        ('products', 'source', "VARCHAR(20) DEFAULT 'manual'", "VARCHAR(20) DEFAULT 'manual'"),
        ('products', 'approval_status', "VARCHAR(20) DEFAULT 'approved'", "VARCHAR(20) DEFAULT 'approved'"),
        ('products', 'pending_since', 'DATETIME', 'TIMESTAMP'),
        ('products', 'reviewed_by', 'INTEGER', 'INTEGER'),
        ('products', 'reviewed_at', 'DATETIME', 'TIMESTAMP'),
        ('products', 'rejection_reason', 'VARCHAR(500)', 'VARCHAR(500)'),
        ('products', 'last_agent_report', 'DATETIME', 'TIMESTAMP'),
        ('products', 'auto_disabled', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        # Agent license server/client breakdown columns
        ('agent_licenses', 'server_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
        ('agent_licenses', 'client_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
        ('agent_licenses', 'peak_servers', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
        ('agent_licenses', 'peak_clients', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
        # Agent remote update push columns
        ('assets', 'pending_update', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
        ('assets', 'pending_update_requested_at', 'DATETIME', 'TIMESTAMP'),
        ('assets', 'pending_update_requested_by', 'VARCHAR(100)', 'VARCHAR(100)'),
        # Inventory job retry tracking
        ('inventory_jobs', 'retry_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
        # Multi-source CVSS provenance tracking
        ('vulnerabilities', 'cvss_source', 'VARCHAR(30)', 'VARCHAR(30)'),
        # Vulnerability source tracking (cisa_kev or euvd)
        ('vulnerabilities', 'source', "VARCHAR(20) DEFAULT 'cisa_kev'", "VARCHAR(20) DEFAULT 'cisa_kev'"),
    ]

    is_sqlite = db_uri.startswith('sqlite')

    # Use a completely isolated engine for migrations
    # Use NullPool to avoid any connection pooling issues
    from sqlalchemy.pool import NullPool
    engine = None
    try:
        engine = create_engine(
            db_uri,
            poolclass=NullPool,  # Don't pool connections - each connect() creates new connection
            isolation_level="AUTOCOMMIT"  # Prevent transaction issues
        )

        for table_name, column_name, col_def_sqlite, col_def_pg in migrations:
            conn = None
            try:
                conn = engine.connect()
                # Check if column exists
                if is_sqlite:
                    result = conn.execute(text(f"PRAGMA table_info({table_name})"))
                    columns = [row[1] for row in result.fetchall()]
                else:
                    result = conn.execute(text(
                        f"SELECT column_name FROM information_schema.columns "
                        f"WHERE table_name = '{table_name}'"
                    ))
                    columns = [row[0] for row in result.fetchall()]

                if column_name not in columns:
                    logger.info(f"Adding column {column_name} to {table_name}")
                    col_def = col_def_sqlite if is_sqlite else col_def_pg
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_def}"))
                    logger.info(f"Successfully added column {column_name} to {table_name}")
                else:
                    logger.debug(f"Column {column_name} already exists in {table_name}")
            except Exception as e:
                logger.warning(f"Could not add column {column_name} to {table_name}: {e}")
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
    except Exception as e:
        logger.warning(f"Migration error: {e}")
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass


def create_app(config_class=Config):
    app = Flask(__name__,
                static_folder='../static',
                template_folder='templates')
    app.config.from_object(config_class)

    # Apply ProxyFix to trust X-Forwarded headers from nginx reverse proxy
    # This is required for correct HTTPS detection when behind a reverse proxy
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    # Security headers via Talisman (only in production)
    # Set FORCE_HTTPS=false in .env if not using HTTPS (e.g., behind reverse proxy)
    if os.environ.get('FLASK_ENV') == 'production':
        from flask_talisman import Talisman
        force_https = os.environ.get('FORCE_HTTPS', 'true').lower() == 'true'
        # For HTTP deployments, session_cookie_secure must be False
        session_cookie_secure = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
        Talisman(app,
            force_https=force_https,
            session_cookie_secure=session_cookie_secure,  # Must be False for HTTP
            strict_transport_security=force_https,  # Only enable HSTS with HTTPS
            strict_transport_security_max_age=31536000 if force_https else 0,
            content_security_policy={
                'default-src': "'self'",
                'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
                'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
                'img-src': ["'self'", "data:"],
                'font-src': ["'self'", "cdn.jsdelivr.net", "fonts.gstatic.com"],
            }
        )

        if force_https:
            # Exempt internal health check paths from HTTPS redirect.
            # Docker/nginx health checks use HTTP internally (curl http://localhost:5000/...)
            # and get stuck in redirect loops when FORCE_HTTPS is enabled.
            _health_paths = frozenset(['/api/health', '/api/sync/status'])

            @app.before_request
            def _skip_https_for_internal_health():
                from flask import request
                remote = request.remote_addr or ''
                is_internal = (remote.startswith('127.') or remote == '::1' or
                               remote.startswith('172.') or remote.startswith('10.') or
                               remote.startswith('192.168.'))
                if request.path in _health_paths and is_internal:
                    # Tell Talisman this request is already secure
                    request.environ['wsgi.url_scheme'] = 'https'

    # Setup comprehensive logging with rotation
    from app.logging_config import setup_logging
    setup_logging(app)

    # Setup performance profiling middleware
    from app.performance_middleware import setup_performance_middleware
    setup_performance_middleware(app)

    from app import routes, models, ldap_models, shared_views, auth, setup, settings_api, ldap_api, ldap_group_api, shared_views_api, licensing, cpe_api, agent_api, integrations_api, saml_api, reports_api, api_docs
    app.register_blueprint(routes.bp)
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(setup.setup_bp)
    app.register_blueprint(settings_api.settings_bp)
    app.register_blueprint(ldap_api.ldap_bp)
    app.register_blueprint(ldap_group_api.ldap_group_bp)
    app.register_blueprint(shared_views_api.shared_views_bp)
    app.register_blueprint(licensing.license_bp)
    app.register_blueprint(cpe_api.bp)
    app.register_blueprint(agent_api.agent_bp)
    app.register_blueprint(integrations_api.bp)
    app.register_blueprint(saml_api.saml_bp)
    app.register_blueprint(reports_api.bp)
    app.register_blueprint(api_docs.api_docs_bp)

    # Error handlers: return JSON for API routes, HTML for browser routes
    @app.errorhandler(404)
    def not_found_error(e):
        from flask import request as _req, jsonify as _jfy
        if _req.path.startswith('/api/'):
            return _jfy({'error': 'Not found'}), 404
        return '<h1>404 - Page Not Found</h1><p>The requested page does not exist.</p>', 404

    @app.errorhandler(500)
    def internal_error(e):
        from flask import request as _req, jsonify as _jfy
        try:
            db.session.rollback()
        except Exception:
            pass
        if _req.path.startswith('/api/'):
            return _jfy({'error': 'Internal server error'}), 500
        return '<h1>500 - Internal Server Error</h1><p>An unexpected error occurred.</p>', 500

    @app.errorhandler(429)
    def rate_limit_error(e):
        from flask import request as _req, jsonify as _jfy
        if _req.path.startswith('/api/'):
            return _jfy({'error': 'Rate limit exceeded'}), 429
        return '<h1>429 - Too Many Requests</h1><p>Please try again later.</p>', 429

    # Make current user and branding available in all templates
    @app.context_processor
    def inject_globals():
        from flask import session
        from app.models import User, SystemSettings
        import os

        current_user = None
        if 'user_id' in session:
            current_user = db.session.get(User, session['user_id'])

        # Match auth.py: AUTH_ENABLED = DISABLE_AUTH != 'true'
        auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

        # Load branding settings
        branding = {
            'app_name': 'SentriKat',
            'login_message': '',
            'support_email': '',
            'show_version': True,
            'logo_url': '/static/images/favicon-128x128.png',  # Default logo
            'report_branding_enabled': True
        }
        try:
            app_name = SystemSettings.query.filter_by(key='app_name').first()
            login_message = SystemSettings.query.filter_by(key='login_message').first()
            support_email = SystemSettings.query.filter_by(key='support_email').first()
            show_version = SystemSettings.query.filter_by(key='show_version').first()
            logo_url = SystemSettings.query.filter_by(key='logo_url').first()
            report_branding = SystemSettings.query.filter_by(key='report_branding_enabled').first()

            if app_name and app_name.value:
                branding['app_name'] = app_name.value
            if login_message and login_message.value:
                branding['login_message'] = login_message.value
            if support_email and support_email.value:
                branding['support_email'] = support_email.value
            if show_version:
                branding['show_version'] = show_version.value != 'false'
            if logo_url and logo_url.value:
                branding['logo_url'] = logo_url.value
            if report_branding:
                branding['report_branding_enabled'] = report_branding.value != 'false'
        except Exception:
            # Rollback to prevent session corruption on DB errors
            try:
                db.session.rollback()
            except Exception:
                pass

        # Load license info
        license_info = None
        try:
            from app.licensing import get_license
            license_info = get_license()
            # Update branding based on license
            if license_info and license_info.is_professional():
                branding['show_powered_by'] = False
            else:
                branding['show_powered_by'] = True
        except Exception:
            # Rollback to prevent session corruption on DB errors
            try:
                db.session.rollback()
            except Exception:
                pass
            branding['show_powered_by'] = True

        # Load session timeout for client-side handling
        session_timeout_minutes = 480  # Default 8 hours
        try:
            timeout_setting = SystemSettings.query.filter_by(key='session_timeout').first()
            if timeout_setting and timeout_setting.value:
                session_timeout_minutes = int(timeout_setting.value)
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

        return dict(
            current_user=current_user,
            auth_enabled=auth_enabled,
            branding=branding,
            license=license_info,
            session_timeout_minutes=session_timeout_minutes,
            app_version=APP_VERSION
        )

    # Setup wizard redirect
    @app.before_request
    def check_setup():
        from flask import request, redirect, url_for, jsonify
        # Skip setup check for static files, setup routes, auth routes, and API status
        if request.endpoint and (
            request.endpoint.startswith('static') or
            request.endpoint.startswith('setup.') or
            request.endpoint.startswith('auth.') or
            request.path == '/api/setup/status' or
            request.path == '/api/auth/status'
        ):
            return None

        # Skip setup check for agent API endpoints (they use their own key-based auth)
        if request.path.startswith('/api/agent/') or request.path == '/api/health':
            return None

        # Check if setup is complete
        if not setup.is_setup_complete():
            # Return JSON error for API paths instead of HTML redirect
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Setup not complete', 'setup_required': True}), 503
            # Redirect to setup wizard for browser requests
            if request.endpoint != 'setup.setup_wizard':
                return redirect(url_for('setup.setup_wizard'))

    # Add API version headers to all API responses
    @app.after_request
    def add_api_version_headers(response):
        from flask import request
        # Only add headers to API responses
        if request.path.startswith('/api/'):
            response.headers['X-API-Version'] = 'v1'
            response.headers['X-App-Version'] = APP_VERSION
        return response

    with app.app_context():
        # Check if database exists before auto-creating
        # This prevents silently creating empty databases in wrong locations
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')

        if db_uri.startswith('sqlite'):
            # Extract path from sqlite URI (sqlite:/// or sqlite:////)
            if db_uri.startswith('sqlite:////'):
                db_path = db_uri[10:]  # Absolute path (4 slashes)
            elif db_uri.startswith('sqlite:///'):
                db_path = db_uri[9:]   # Could be relative
                if not os.path.isabs(db_path):
                    # Make relative paths absolute from app root
                    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), db_path)

            db_exists = os.path.exists(db_path)

            if not db_exists:
                # Create data directory if needed
                db_dir = os.path.dirname(db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)

                # Create tables - this is first run or setup
                import logging
                logging.getLogger(__name__).info(f"Creating new database at: {db_path}")
                db.create_all()
            else:
                # Database exists - run migrations for new columns
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"Using existing database at: {db_path}")

                # Apply schema migrations for new columns (SQLite doesn't auto-add columns)
                _apply_schema_migrations(logger, db_uri)
        else:
            # Non-SQLite database (PostgreSQL, etc.)
            import logging
            logger = logging.getLogger(__name__)

            # First ensure tables exist
            db.create_all()

            # Then apply schema migrations for new columns
            logger.info("Applying schema migrations for PostgreSQL...")
            _apply_schema_migrations(logger, db_uri)

    return app
