from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config

db = SQLAlchemy()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)

    from app import routes, models, auth, setup
    app.register_blueprint(routes.bp)
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(setup.setup_bp)

    # Setup wizard redirect
    @app.before_request
    def check_setup():
        from flask import request, redirect, url_for
        # Skip setup check for static files, setup routes, and API status
        if request.endpoint and (
            request.endpoint.startswith('static') or
            request.endpoint.startswith('setup.') or
            request.path == '/api/setup/status'
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
