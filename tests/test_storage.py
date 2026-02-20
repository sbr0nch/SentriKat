"""
Tests for the storage abstraction layer.

Covers LocalStorageBackend, S3StorageBackend, and the singleton
get_storage_backend() / reset_storage_backend() helpers.
"""

import io
import os
from unittest.mock import MagicMock, patch

import pytest

from app.storage import (
    LocalStorageBackend,
    S3StorageBackend,
    get_storage_backend,
    reset_storage_backend,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def local_backend(tmp_path):
    """Return a LocalStorageBackend whose base_dir points at a temp directory."""
    with patch.dict(os.environ, {"DATA_DIR": str(tmp_path)}):
        backend = LocalStorageBackend()
    return backend


@pytest.fixture()
def mock_boto3():
    """Patch boto3.client and botocore.config.Config used by S3StorageBackend."""
    mock_client = MagicMock()
    with patch.dict(os.environ, {
        "S3_BUCKET_NAME": "test-bucket",
        "S3_ENDPOINT_URL": "https://s3.example.com",
        "S3_ACCESS_KEY": "fake-key",
        "S3_SECRET_KEY": "fake-secret",
        "S3_REGION": "us-east-1",
        "S3_PUBLIC_URL": "",
    }):
        with patch("app.storage.boto3") as mock_boto:
            mock_boto.client.return_value = mock_client
            with patch("app.storage.BotoConfig"):
                yield mock_client, mock_boto.client


# ---------------------------------------------------------------------------
# Helper to build an S3StorageBackend with mocked boto3
# ---------------------------------------------------------------------------

def _make_s3_backend(env_overrides=None):
    """Construct an S3StorageBackend with boto3 fully mocked."""
    env = {
        "S3_BUCKET_NAME": "test-bucket",
        "S3_ENDPOINT_URL": "https://s3.example.com",
        "S3_ACCESS_KEY": "fake-key",
        "S3_SECRET_KEY": "fake-secret",
        "S3_REGION": "us-east-1",
        "S3_PUBLIC_URL": "",
    }
    if env_overrides:
        env.update(env_overrides)

    mock_client = MagicMock()
    with patch.dict(os.environ, env):
        with patch("app.storage.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            with patch("app.storage.BotoConfig"):
                backend = S3StorageBackend()
    return backend, mock_client


# ===================================================================
# 1. LocalStorageBackend tests
# ===================================================================

class TestLocalStorageBackendSave:
    """Tests for LocalStorageBackend.save()."""

    def test_save_raw_bytes(self, local_backend, tmp_path):
        """save() writes raw bytes to disk."""
        local_backend.save("report.txt", b"hello world")
        written = (tmp_path / "report.txt").read_bytes()
        assert written == b"hello world"

    def test_save_file_like_object(self, local_backend, tmp_path):
        """save() reads from a file-like object and writes to disk."""
        fobj = io.BytesIO(b"file-like content")
        local_backend.save("upload.bin", fobj)
        written = (tmp_path / "upload.bin").read_bytes()
        assert written == b"file-like content"

    def test_save_creates_subdirectories(self, local_backend, tmp_path):
        """save() auto-creates intermediate directories."""
        local_backend.save("a/b/c/deep.txt", b"nested")
        written = (tmp_path / "a" / "b" / "c" / "deep.txt").read_bytes()
        assert written == b"nested"

    def test_save_overwrites_existing(self, local_backend, tmp_path):
        """save() overwrites a previously saved file at the same key."""
        local_backend.save("dup.txt", b"first")
        local_backend.save("dup.txt", b"second")
        assert (tmp_path / "dup.txt").read_bytes() == b"second"


class TestLocalStorageBackendLoad:
    """Tests for LocalStorageBackend.load()."""

    def test_load_existing_file(self, local_backend, tmp_path):
        """load() returns the contents of a previously saved file."""
        (tmp_path / "exists.txt").write_bytes(b"data here")
        result = local_backend.load("exists.txt")
        assert result == b"data here"

    def test_load_nonexistent_returns_none(self, local_backend):
        """load() returns None when the key does not exist."""
        assert local_backend.load("ghost.txt") is None


class TestLocalStorageBackendDelete:
    """Tests for LocalStorageBackend.delete()."""

    def test_delete_existing_file(self, local_backend, tmp_path):
        """delete() removes the file and returns True."""
        (tmp_path / "doomed.txt").write_bytes(b"bye")
        assert local_backend.delete("doomed.txt") is True
        assert not (tmp_path / "doomed.txt").exists()

    def test_delete_nonexistent_returns_false(self, local_backend):
        """delete() returns False when the key does not exist."""
        assert local_backend.delete("no_such_file.txt") is False


class TestLocalStorageBackendExists:
    """Tests for LocalStorageBackend.exists()."""

    def test_exists_true(self, local_backend, tmp_path):
        (tmp_path / "here.txt").write_bytes(b"x")
        assert local_backend.exists("here.txt") is True

    def test_exists_false(self, local_backend):
        assert local_backend.exists("nope.txt") is False


class TestLocalStorageBackendGetUrl:
    """Tests for LocalStorageBackend.get_url()."""

    def test_get_url_returns_data_prefixed_path(self, local_backend):
        """get_url() returns /data/<key> for local storage."""
        url = local_backend.get_url("uploads/logo.png")
        assert url == "/data/uploads/logo.png"

    def test_get_url_normalises_slashes(self, local_backend):
        """get_url() normalises redundant separators."""
        url = local_backend.get_url("uploads//extra///slashes.png")
        assert "//" not in url
        assert url.startswith("/data/")


class TestLocalStorageBackendGetLocalPath:
    """Tests for LocalStorageBackend.get_local_path()."""

    def test_get_local_path_existing(self, local_backend, tmp_path):
        """get_local_path() returns absolute path when file exists."""
        (tmp_path / "present.txt").write_bytes(b"x")
        path = local_backend.get_local_path("present.txt")
        assert path is not None
        assert os.path.isabs(path)
        assert path.endswith("present.txt")

    def test_get_local_path_nonexistent(self, local_backend):
        """get_local_path() returns None when file is missing."""
        assert local_backend.get_local_path("missing.txt") is None


class TestLocalStorageBackendPathTraversal:
    """Path traversal protection."""

    def test_dotdot_in_key_raises(self, local_backend):
        """Keys containing '..' components are rejected."""
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            local_backend.save("../../etc/passwd", b"bad")

    def test_dotdot_load_raises(self, local_backend):
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            local_backend.load("../secret")

    def test_dotdot_delete_raises(self, local_backend):
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            local_backend.delete("foo/../../bar")

    def test_dotdot_exists_raises(self, local_backend):
        with pytest.raises(ValueError, match="[Pp]ath traversal"):
            local_backend.exists("../outside")


class TestLocalStorageBackendDirectoryCreation:
    """Verify that the base_dir is created on init."""

    def test_init_creates_base_dir(self, tmp_path):
        target = tmp_path / "brand_new_dir"
        assert not target.exists()
        with patch.dict(os.environ, {"DATA_DIR": str(target)}):
            LocalStorageBackend()
        assert target.is_dir()


# ===================================================================
# 2. S3StorageBackend tests
# ===================================================================

class TestS3StorageBackendSave:
    """Tests for S3StorageBackend.save()."""

    def test_save_raw_bytes(self):
        """save() with bytes calls put_object."""
        backend, mock_client = _make_s3_backend()
        backend.save("reports/file.csv", b"csv,data")
        mock_client.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="reports/file.csv",
            Body=b"csv,data",
        )

    def test_save_file_like_object(self):
        """save() with a file-like object calls upload_fileobj."""
        backend, mock_client = _make_s3_backend()
        fobj = io.BytesIO(b"stream data")
        backend.save("stream.bin", fobj)
        mock_client.upload_fileobj.assert_called_once_with(
            fobj, "test-bucket", "stream.bin", ExtraArgs={}
        )

    def test_save_with_content_type(self):
        """save() passes ContentType when provided."""
        backend, mock_client = _make_s3_backend()
        backend.save("image.png", b"\x89PNG", content_type="image/png")
        mock_client.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="image.png",
            Body=b"\x89PNG",
            ContentType="image/png",
        )

    def test_save_fileobj_with_content_type(self):
        """save() passes ContentType in ExtraArgs for file-like objects."""
        backend, mock_client = _make_s3_backend()
        fobj = io.BytesIO(b"data")
        backend.save("doc.pdf", fobj, content_type="application/pdf")
        mock_client.upload_fileobj.assert_called_once_with(
            fobj,
            "test-bucket",
            "doc.pdf",
            ExtraArgs={"ContentType": "application/pdf"},
        )


class TestS3StorageBackendLoad:
    """Tests for S3StorageBackend.load()."""

    def test_load_existing_key(self):
        """load() returns bytes from the S3 response body."""
        backend, mock_client = _make_s3_backend()
        body_mock = MagicMock()
        body_mock.read.return_value = b"s3 contents"
        mock_client.get_object.return_value = {"Body": body_mock}
        result = backend.load("some/key.txt")
        assert result == b"s3 contents"
        mock_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="some/key.txt"
        )

    def test_load_nosuchkey_returns_none(self):
        """load() returns None when S3 raises NoSuchKey."""
        backend, mock_client = _make_s3_backend()
        error_cls = type("NoSuchKey", (Exception,), {})
        mock_client.exceptions.NoSuchKey = error_cls
        mock_client.get_object.side_effect = error_cls("not found")
        assert backend.load("missing.txt") is None

    def test_load_generic_error_returns_none(self):
        """load() returns None on unexpected S3 errors."""
        backend, mock_client = _make_s3_backend()
        mock_client.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        mock_client.get_object.side_effect = RuntimeError("network error")
        assert backend.load("broken.txt") is None


class TestS3StorageBackendDelete:
    """Tests for S3StorageBackend.delete()."""

    def test_delete_success(self):
        """delete() calls delete_object and returns True."""
        backend, mock_client = _make_s3_backend()
        assert backend.delete("trash.txt") is True
        mock_client.delete_object.assert_called_once_with(
            Bucket="test-bucket", Key="trash.txt"
        )

    def test_delete_error_returns_false(self):
        """delete() returns False when S3 raises."""
        backend, mock_client = _make_s3_backend()
        mock_client.delete_object.side_effect = RuntimeError("boom")
        assert backend.delete("fail.txt") is False


class TestS3StorageBackendExists:
    """Tests for S3StorageBackend.exists()."""

    def test_exists_true(self):
        """exists() returns True when head_object succeeds."""
        backend, mock_client = _make_s3_backend()
        mock_client.head_object.return_value = {"ContentLength": 42}
        assert backend.exists("real.txt") is True
        mock_client.head_object.assert_called_once_with(
            Bucket="test-bucket", Key="real.txt"
        )

    def test_exists_false(self):
        """exists() returns False when head_object raises."""
        backend, mock_client = _make_s3_backend()
        mock_client.head_object.side_effect = Exception("404")
        assert backend.exists("fake.txt") is False


class TestS3StorageBackendGetUrl:
    """Tests for S3StorageBackend.get_url()."""

    def test_get_url_with_public_url(self):
        """get_url() returns <public_url>/<key> when S3_PUBLIC_URL is set."""
        backend, mock_client = _make_s3_backend(
            {"S3_PUBLIC_URL": "https://cdn.example.com"}
        )
        url = backend.get_url("assets/logo.png")
        assert url == "https://cdn.example.com/assets/logo.png"
        mock_client.generate_presigned_url.assert_not_called()

    def test_get_url_presigned_when_no_public_url(self):
        """get_url() generates a presigned URL when no public URL is configured."""
        backend, mock_client = _make_s3_backend({"S3_PUBLIC_URL": ""})
        mock_client.generate_presigned_url.return_value = (
            "https://s3.example.com/test-bucket/key?Signature=abc"
        )
        url = backend.get_url("private/doc.pdf")
        mock_client.generate_presigned_url.assert_called_once_with(
            "get_object",
            Params={"Bucket": "test-bucket", "Key": "private/doc.pdf"},
            ExpiresIn=3600,
        )
        assert "Signature" in url


class TestS3StorageBackendGetLocalPath:
    """Tests for S3StorageBackend.get_local_path()."""

    def test_get_local_path_always_none(self):
        """S3 backend never has local paths."""
        backend, _ = _make_s3_backend()
        assert backend.get_local_path("anything.txt") is None


class TestS3StorageBackendInitImportError:
    """Test S3StorageBackend behaviour when boto3 is missing."""

    def test_init_raises_without_boto3(self):
        """S3StorageBackend raises ImportError when boto3 is not installed."""
        with patch("app.storage.boto3", None):
            with pytest.raises(ImportError, match="boto3"):
                S3StorageBackend()


# ===================================================================
# 3. Singleton helpers: get_storage_backend / reset_storage_backend
# ===================================================================

class TestGetStorageBackend:
    """Tests for the get_storage_backend() singleton factory."""

    def setup_method(self):
        """Ensure we start each test with a clean singleton."""
        reset_storage_backend()

    def teardown_method(self):
        reset_storage_backend()

    def test_returns_local_by_default(self, tmp_path):
        """Default STORAGE_BACKEND returns a LocalStorageBackend."""
        with patch.dict(os.environ, {"DATA_DIR": str(tmp_path)}, clear=False):
            os.environ.pop("STORAGE_BACKEND", None)
            backend = get_storage_backend()
            assert isinstance(backend, LocalStorageBackend)

    def test_returns_s3_when_configured(self):
        """STORAGE_BACKEND=s3 returns an S3StorageBackend."""
        with patch.dict(os.environ, {
            "STORAGE_BACKEND": "s3",
            "S3_BUCKET_NAME": "b",
            "S3_ENDPOINT_URL": "https://s3.example.com",
            "S3_ACCESS_KEY": "k",
            "S3_SECRET_KEY": "s",
        }):
            with patch("app.storage.boto3") as m_boto3:
                m_boto3.client.return_value = MagicMock()
                with patch("app.storage.BotoConfig"):
                    backend = get_storage_backend()
                    assert isinstance(backend, S3StorageBackend)

    def test_singleton_returns_same_instance(self, tmp_path):
        """Repeated calls return the exact same object."""
        with patch.dict(os.environ, {"DATA_DIR": str(tmp_path)}, clear=False):
            os.environ.pop("STORAGE_BACKEND", None)
            first = get_storage_backend()
            second = get_storage_backend()
            assert first is second


class TestResetStorageBackend:
    """Tests for reset_storage_backend()."""

    def teardown_method(self):
        reset_storage_backend()

    def test_reset_clears_singleton(self, tmp_path):
        """After reset, get_storage_backend() creates a new instance."""
        with patch.dict(os.environ, {"DATA_DIR": str(tmp_path)}, clear=False):
            os.environ.pop("STORAGE_BACKEND", None)
            first = get_storage_backend()
            reset_storage_backend()
            second = get_storage_backend()
            assert first is not second
