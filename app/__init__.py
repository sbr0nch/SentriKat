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

    # Make current user available in all templates
    @app.context_processor
    def inject_user():
        from flask import session
        from app.models import User
        import os
        current_user = None
        if 'user_id' in session:
            current_user = User.query.get(session['user_id'])
        # Match auth.py: AUTH_ENABLED = DISABLE_AUTH != 'true'
        auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'
        return dict(current_user=current_user, auth_enabled=auth_enabled)

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
        db.create_all()

    return app
