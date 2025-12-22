import os
from datetime import timedelta

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///sentrikat.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Application URL (for generating share links, email links, etc.)
    # If not set, falls back to request.host_url at runtime
    SENTRIKAT_URL = os.environ.get('SENTRIKAT_URL', '').rstrip('/')

    # CISA KEV Feed URL
    CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

    # Proxy configuration (optional)
    # If your company uses a proxy to reach external sites, configure here
    HTTP_PROXY = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    HTTPS_PROXY = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    NO_PROXY = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')

    # Sync schedule (daily at 2 AM)
    SYNC_HOUR = int(os.environ.get('SYNC_HOUR', 2))
    SYNC_MINUTE = int(os.environ.get('SYNC_MINUTE', 0))

    # Application settings
    ITEMS_PER_PAGE = 50
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload

    # Security settings
    # Only use secure cookies if explicitly enabled (for HTTPS deployments)
    # Set SESSION_COOKIE_SECURE=true in .env when using HTTPS
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # SSL Certificate Verification
    # WARNING: Disabling SSL verification is a security risk!
    # Only disable in corporate environments with SSL inspection/interception
    # Set to 'false' to disable SSL verification (not recommended for production)
    VERIFY_SSL = os.environ.get('VERIFY_SSL', 'true').lower() != 'false'

    @staticmethod
    def get_proxies():
        """
        Get proxy configuration as dict for requests library.

        Priority: GUI settings (database) > .env settings

        Returns dict like {'http': 'http://proxy:port', 'https': 'http://proxy:port'}
        """
        proxies = {}

        # Try to get from database first (GUI settings)
        try:
            from app.models import SystemSettings
            http_proxy_setting = SystemSettings.query.filter_by(key='http_proxy').first()
            https_proxy_setting = SystemSettings.query.filter_by(key='https_proxy').first()

            http_proxy = http_proxy_setting.value if http_proxy_setting and http_proxy_setting.value else None
            https_proxy = https_proxy_setting.value if https_proxy_setting and https_proxy_setting.value else None

            # Use database settings if configured
            if http_proxy:
                proxies['http'] = http_proxy
            if https_proxy:
                proxies['https'] = https_proxy

            # If any proxy found in DB, return it
            if proxies:
                return proxies

        except Exception:
            # Database not available (e.g., during app init), use .env
            pass

        # Fallback to .env settings
        if Config.HTTP_PROXY:
            proxies['http'] = Config.HTTP_PROXY
        if Config.HTTPS_PROXY:
            proxies['https'] = Config.HTTPS_PROXY

        return proxies if proxies else None

    @staticmethod
    def get_verify_ssl():
        """
        Get SSL verification setting.

        Priority: GUI settings (database) > .env settings
        """
        try:
            from app.models import SystemSettings
            verify_ssl_setting = SystemSettings.query.filter_by(key='verify_ssl').first()
            if verify_ssl_setting:
                return verify_ssl_setting.value.lower() != 'false'
        except Exception:
            pass

        return Config.VERIFY_SSL
