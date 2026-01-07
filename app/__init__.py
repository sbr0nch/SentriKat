from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
import os

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

def create_app(config_class=Config):
    app = Flask(__name__,
                static_folder='../static',
                template_folder='templates')
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    # Security headers via Talisman (only in production with HTTPS)
    if os.environ.get('FLASK_ENV') == 'production':
        from flask_talisman import Talisman
        Talisman(app,
            force_https=True,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,
            content_security_policy={
                'default-src': "'self'",
                'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
                'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
                'img-src': ["'self'", "data:"],
                'font-src': ["'self'", "cdn.jsdelivr.net"],
            }
        )

    # Setup comprehensive logging with rotation
    from app.logging_config import setup_logging
    setup_logging(app)

    # Setup performance profiling middleware
    from app.performance_middleware import setup_performance_middleware
    setup_performance_middleware(app)

    from app import routes, models, ldap_models, shared_views, auth, setup, settings_api, ldap_api, ldap_group_api, shared_views_api
    app.register_blueprint(routes.bp)
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(setup.setup_bp)
    app.register_blueprint(settings_api.settings_bp)
    app.register_blueprint(ldap_api.ldap_bp)
    app.register_blueprint(ldap_group_api.ldap_group_bp)
    app.register_blueprint(shared_views_api.shared_views_bp)

    # Make current user and branding available in all templates
    @app.context_processor
    def inject_globals():
        from flask import session
        from app.models import User, SystemSettings
        import os

        current_user = None
        if 'user_id' in session:
            current_user = User.query.get(session['user_id'])

        # Match auth.py: AUTH_ENABLED = DISABLE_AUTH != 'true'
        auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

        # Load branding settings
        branding = {
            'app_name': 'SentriKat',
            'login_message': '',
            'support_email': '',
            'show_version': True
        }
        try:
            app_name = SystemSettings.query.filter_by(key='app_name').first()
            login_message = SystemSettings.query.filter_by(key='login_message').first()
            support_email = SystemSettings.query.filter_by(key='support_email').first()
            show_version = SystemSettings.query.filter_by(key='show_version').first()

            if app_name and app_name.value:
                branding['app_name'] = app_name.value
            if login_message and login_message.value:
                branding['login_message'] = login_message.value
            if support_email and support_email.value:
                branding['support_email'] = support_email.value
            if show_version:
                branding['show_version'] = show_version.value != 'false'
        except:
            pass  # Use defaults if DB not ready

        return dict(
            current_user=current_user,
            auth_enabled=auth_enabled,
            branding=branding
        )

    # Setup wizard redirect
    @app.before_request
    def check_setup():
        from flask import request, redirect, url_for
        # Skip setup check for static files, setup routes, auth routes, and API status
        if request.endpoint and (
            request.endpoint.startswith('static') or
            request.endpoint.startswith('setup.') or
            request.endpoint.startswith('auth.') or
            request.path == '/api/setup/status' or
            request.path == '/api/auth/status'
        ):
            return None

        # Check if setup is complete
        if not setup.is_setup_complete():
            # Redirect to setup wizard
            if request.endpoint != 'setup.setup_wizard':
                return redirect(url_for('setup.setup_wizard'))

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
                # Database exists - DON'T run create_all() to avoid issues
                # Migrations should handle schema changes
                import logging
                logging.getLogger(__name__).info(f"Using existing database at: {db_path}")
        else:
            # Non-SQLite database (PostgreSQL, etc.) - always run create_all for safety
            # In production, migrations should be used instead
            db.create_all()

    return app
