import os
from datetime import timedelta

# Determine base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    """Application configuration"""

    # =========================================================================
    # Security Configuration
    # =========================================================================

    # Secret key for session signing - MUST be set in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        import warnings
        if os.environ.get('FLASK_ENV') == 'production':
            raise ValueError("SECRET_KEY environment variable must be set in production!")
        warnings.warn("SECRET_KEY not set - using insecure default for development only")
        SECRET_KEY = 'dev-secret-key-change-in-production'

    # Encryption key for sensitive data (LDAP password, SMTP password, etc.)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

    # =========================================================================
    # Database Configuration - PostgreSQL
    # =========================================================================

    # Database URL (PostgreSQL recommended for production)
    # Format: postgresql://user:password@host:port/database
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL:
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Default PostgreSQL connection for Docker deployment
        SQLALCHEMY_DATABASE_URI = os.environ.get(
            'DATABASE_URL',
            'postgresql://sentrikat:sentrikat@db:5432/sentrikat'
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before use
        'pool_recycle': 300,    # Recycle connections every 5 minutes
    }

    # =========================================================================
    # Application Configuration
    # =========================================================================

    # Application URL (for generating share links, email links, etc.)
    SENTRIKAT_URL = os.environ.get('SENTRIKAT_URL', '').rstrip('/')

    # CISA KEV Feed URL
    CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

    # Sync schedule (daily at 2 AM UTC)
    SYNC_HOUR = int(os.environ.get('SYNC_HOUR', 2))
    SYNC_MINUTE = int(os.environ.get('SYNC_MINUTE', 0))

    # Application settings
    ITEMS_PER_PAGE = 50
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload

    # =========================================================================
    # Network Configuration
    # =========================================================================

    # Proxy configuration (optional)
    HTTP_PROXY = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    HTTPS_PROXY = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    NO_PROXY = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')

    # SSL Certificate Verification
    VERIFY_SSL = os.environ.get('VERIFY_SSL', 'true').lower() != 'false'

    # =========================================================================
    # Session Security
    # =========================================================================

    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    # Use 'Lax' instead of 'Strict' to allow cookie on navigation redirects
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    @staticmethod
    def get_proxies():
        """
        Get proxy configuration for requests library.
        Priority: Database settings > Environment variables
        """
        proxies = {}

        # Try to get from database first (GUI settings)
        try:
            from app.models import SystemSettings
            http_proxy_setting = SystemSettings.query.filter_by(key='http_proxy').first()
            https_proxy_setting = SystemSettings.query.filter_by(key='https_proxy').first()

            if http_proxy_setting and http_proxy_setting.value:
                proxies['http'] = http_proxy_setting.value
            if https_proxy_setting and https_proxy_setting.value:
                proxies['https'] = https_proxy_setting.value

            if proxies:
                return proxies
        except Exception:
            pass

        # Fallback to environment variables
        if Config.HTTP_PROXY:
            proxies['http'] = Config.HTTP_PROXY
        if Config.HTTPS_PROXY:
            proxies['https'] = Config.HTTPS_PROXY

        return proxies if proxies else None

    @staticmethod
    def get_verify_ssl():
        """
        Get SSL verification setting.
        Priority: Database settings > Environment variables
        """
        try:
            from app.models import SystemSettings
            verify_ssl_setting = SystemSettings.query.filter_by(key='verify_ssl').first()
            if verify_ssl_setting:
                return verify_ssl_setting.value.lower() != 'false'
        except Exception:
            pass

        return Config.VERIFY_SSL
