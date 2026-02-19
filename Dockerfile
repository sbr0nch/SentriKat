FROM python:3.11-slim

WORKDIR /app

# Accept proxy build args (for corporate environments)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# Set proxy for apt-get
ENV http_proxy=${HTTP_PROXY}
ENV https_proxy=${HTTPS_PROXY}
ENV no_proxy=${NO_PROXY}

# Install system dependencies for PostgreSQL, SAML, and other requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    pkg-config \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
# Use --trusted-host for corporate SSL inspection proxies
COPY requirements.txt .
RUN pip install --no-cache-dir \
    --trusted-host pypi.org \
    --trusted-host pypi.python.org \
    --trusted-host files.pythonhosted.org \
    -r requirements.txt

# Clear proxy env after installs
ENV http_proxy=""
ENV https_proxy=""

# Copy application code
COPY . .

# Download vendor assets (Bootstrap, Chart.js, etc.) for offline/on-premise deployment
# Uses CDN during build; falls back gracefully if unavailable
RUN sed -i 's/\r$//' /app/scripts/download_vendor_assets.sh \
    && chmod +x /app/scripts/download_vendor_assets.sh \
    && /app/scripts/download_vendor_assets.sh /app/static/vendor || true

# Create data directory for uploads/backups and custom CA certs directory
RUN mkdir -p /app/data /app/custom-certs

# Copy and prepare entrypoint script
# Strip Windows CRLF line endings (fixes "no such file or directory" on Windows-cloned repos)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh

# Create non-root user for running the application
RUN groupadd -r sentrikat && useradd -r -g sentrikat -d /app -s /sbin/nologin sentrikat \
    && chown -R sentrikat:sentrikat /app/data

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=run.py
ENV PYTHONUNBUFFERED=1

# Use entrypoint script to install custom CA certs before starting app
# Note: entrypoint runs as root to install CA certs, then exec's gunicorn
ENTRYPOINT ["/docker-entrypoint.sh"]

# Run the application with gunicorn using config file
# Config at gunicorn.conf.py: gthread workers, auto-scaling, max-requests recycling
# Override defaults: GUNICORN_WORKERS=4 GUNICORN_THREADS=4 GUNICORN_TIMEOUT=120
CMD ["gunicorn", "--config", "gunicorn.conf.py", "run:app"]
