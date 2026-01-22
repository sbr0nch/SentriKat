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

# Install system dependencies for PostgreSQL and other requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
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

# Create data directory for uploads/backups
RUN mkdir -p /app/data

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=run.py
ENV PYTHONUNBUFFERED=1

# Run the application with gunicorn
# Uses gunicorn_config.py for worker settings and post_fork hook
# to properly manage database connections across forked workers
CMD ["gunicorn", "-c", "gunicorn_config.py", "run:app"]
