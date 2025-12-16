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

    from app import routes, models, auth
    app.register_blueprint(routes.bp)
    app.register_blueprint(auth.auth_bp)

    with app.app_context():
        db.create_all()

    return app
