"""
Storage abstraction layer for SentriKat.

Provides a unified interface for file storage operations, supporting:
- Local filesystem storage (current on-premise default)
- S3-compatible object storage (for SaaS migration)

Usage:
    from app.storage import get_storage_backend

    storage = get_storage_backend()
    storage.save('uploads/custom_logo.png', file_data)
    data = storage.load('uploads/custom_logo.png')
    url = storage.get_url('uploads/custom_logo.png')

Configuration (environment variables):
    STORAGE_BACKEND=local          (default, on-premise)
    STORAGE_BACKEND=s3             (S3-compatible: AWS S3, DigitalOcean Spaces, MinIO)

    For S3 backend:
    S3_ENDPOINT_URL=https://nyc3.digitaloceanspaces.com  (or AWS S3 URL)
    S3_BUCKET_NAME=sentrikat-files
    S3_ACCESS_KEY=your-access-key
    S3_SECRET_KEY=your-secret-key
    S3_REGION=nyc3                 (optional)
    S3_PUBLIC_URL=https://cdn.example.com  (optional, for CDN)
"""

import logging
import os
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Optional S3 dependencies — imported at module level so tests can patch them.
try:
    import boto3
    from botocore.config import Config as BotoConfig
except ImportError:
    boto3 = None
    BotoConfig = None

# Singleton instance
_storage_backend = None


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def save(self, key, data, content_type=None):
        """
        Save data to storage.

        Args:
            key: Storage path/key (e.g., 'uploads/custom_logo.png')
            data: File data (bytes or file-like object)
            content_type: Optional MIME type
        """
        pass

    @abstractmethod
    def load(self, key):
        """
        Load data from storage.

        Args:
            key: Storage path/key

        Returns:
            bytes or None if not found
        """
        pass

    @abstractmethod
    def delete(self, key):
        """
        Delete a file from storage.

        Args:
            key: Storage path/key

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def exists(self, key):
        """
        Check if a file exists.

        Args:
            key: Storage path/key

        Returns:
            True if exists
        """
        pass

    @abstractmethod
    def get_url(self, key):
        """
        Get a URL for accessing the file.

        For local storage, returns a relative path.
        For S3, returns a presigned URL or public URL.

        Args:
            key: Storage path/key

        Returns:
            URL string
        """
        pass

    @abstractmethod
    def get_local_path(self, key):
        """
        Get the local filesystem path for a file (if applicable).

        For local storage, returns the absolute path.
        For S3, returns None (use load() instead).

        Args:
            key: Storage path/key

        Returns:
            Absolute path string or None
        """
        pass


class LocalStorageBackend(StorageBackend):
    """
    Local filesystem storage backend.

    Stores files under DATA_DIR (default: /app/data).
    This is the default for on-premise installations.
    """

    def __init__(self):
        self.base_dir = os.environ.get('DATA_DIR', '/app/data')
        os.makedirs(self.base_dir, exist_ok=True)
        logger.info(f"Local storage backend initialized: {self.base_dir}")

    def _full_path(self, key):
        """Get full filesystem path, with path traversal protection."""
        safe_key = os.path.normpath(key).lstrip('/')
        if '..' in safe_key.split(os.sep):
            raise ValueError(f"Path traversal detected in key: {key}")
        full = os.path.join(self.base_dir, safe_key)
        # Verify the resolved path is under base_dir
        real_full = os.path.realpath(full)
        real_base = os.path.realpath(self.base_dir)
        if not real_full.startswith(real_base + os.sep) and real_full != real_base:
            raise ValueError(f"Path traversal detected in key: {key}")
        return full

    def save(self, key, data, content_type=None):
        path = self._full_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        if hasattr(data, 'read'):
            # File-like object
            with open(path, 'wb') as f:
                while True:
                    chunk = data.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
        else:
            # Raw bytes
            with open(path, 'wb') as f:
                f.write(data)

        logger.debug(f"Saved file: {key} ({os.path.getsize(path)} bytes)")

    def load(self, key):
        path = self._full_path(key)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

    def delete(self, key):
        path = self._full_path(key)
        if os.path.exists(path):
            os.remove(path)
            logger.debug(f"Deleted file: {key}")
            return True
        return False

    def exists(self, key):
        return os.path.exists(self._full_path(key))

    def get_url(self, key):
        # Return relative URL path for serving via Flask
        safe_key = os.path.normpath(key).lstrip('/')
        return f'/data/{safe_key}'

    def get_local_path(self, key):
        path = self._full_path(key)
        if os.path.exists(path):
            return path
        return None


class S3StorageBackend(StorageBackend):
    """
    S3-compatible object storage backend.

    Works with AWS S3, DigitalOcean Spaces, MinIO, and other S3-compatible services.
    Enable by setting STORAGE_BACKEND=s3 and configuring S3_* environment variables.
    """

    def __init__(self):
        if boto3 is None:
            raise ImportError(
                "S3 storage backend requires boto3. "
                "Install it with: pip install boto3"
            )

        self.bucket_name = os.environ.get('S3_BUCKET_NAME', 'sentrikat-files')
        self.public_url = os.environ.get('S3_PUBLIC_URL', '').rstrip('/')

        endpoint_url = os.environ.get('S3_ENDPOINT_URL')
        region = os.environ.get('S3_REGION', 'us-east-1')

        self.client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=os.environ.get('S3_ACCESS_KEY'),
            aws_secret_access_key=os.environ.get('S3_SECRET_KEY'),
            config=BotoConfig(
                signature_version='s3v4',
                retries={'max_attempts': 3, 'mode': 'adaptive'}
            )
        )

        logger.info(f"S3 storage backend initialized: bucket={self.bucket_name}")

    def save(self, key, data, content_type=None):
        extra_args = {}
        if content_type:
            extra_args['ContentType'] = content_type

        if hasattr(data, 'read'):
            self.client.upload_fileobj(data, self.bucket_name, key, ExtraArgs=extra_args)
        else:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                **extra_args
            )

        logger.debug(f"Saved to S3: {key}")

    def load(self, key):
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=key)
            return response['Body'].read()
        except self.client.exceptions.NoSuchKey:
            return None
        except Exception as e:
            logger.error(f"Failed to load from S3: {key}: {e}")
            return None

    def delete(self, key):
        try:
            self.client.delete_object(Bucket=self.bucket_name, Key=key)
            logger.debug(f"Deleted from S3: {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete from S3: {key}: {e}")
            return False

    def exists(self, key):
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except Exception:
            return False

    def get_url(self, key):
        if self.public_url:
            return f"{self.public_url}/{key}"
        # Generate presigned URL (valid for 1 hour)
        return self.client.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket_name, 'Key': key},
            ExpiresIn=3600
        )

    def get_local_path(self, key):
        # S3 backend has no local paths
        return None


def get_storage_backend():
    """
    Get the configured storage backend (singleton).

    Returns the appropriate backend based on STORAGE_BACKEND env var.
    Default is 'local' for on-premise installations.
    """
    global _storage_backend

    if _storage_backend is None:
        backend_type = os.environ.get('STORAGE_BACKEND', 'local').lower()

        if backend_type == 's3':
            _storage_backend = S3StorageBackend()
        else:
            _storage_backend = LocalStorageBackend()

    return _storage_backend


def reset_storage_backend():
    """Reset the storage backend singleton (for testing)."""
    global _storage_backend
    _storage_backend = None
