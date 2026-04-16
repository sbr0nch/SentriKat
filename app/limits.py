"""Centralized input and payload size limits (L-5).

Before this module these constants were scattered across ``agent_api.py``,
``remediation_api.py``, ``sbom_export.py`` etc. Pulling them together
makes it easy to audit the attack surface (how big can an attacker make
a single request?) and to tune limits per deployment without hunting
through the codebase.

Consumers should import from this module and keep per-file aliases only
for backward-compat. New limits go here.
"""
from __future__ import annotations

# --- User-supplied string fields (DB column widths). ---
MAX_HOSTNAME_LENGTH = 255
MAX_VENDOR_LENGTH = 200
MAX_PRODUCT_NAME_LENGTH = 200
MAX_VERSION_LENGTH = 100
MAX_PATH_LENGTH = 500
MAX_ASSIGNED_TO_LEN = 200
MAX_JUSTIFICATION_LEN = 5000
MAX_NOTES_LEN = 10000

# --- Paging and bulk-operation caps. ---
MAX_LIST_PAGE_SIZE = 100
MAX_PRODUCTS_PER_REQUEST = 10000
MAX_IMAGES_PER_REQUEST = 50
MAX_VULNS_PER_IMAGE = 5000
MAX_LOCKFILES_PER_REQUEST = 50
MAX_SBOM_PRODUCTS = 5000
MAX_REPORT_REQUIREMENTS = 200
MAX_EVIDENCE_ITEMS_PER_REQUIREMENT = 50
MAX_DEPS_PER_LOCKFILE = 10000

# --- Payload-size ceilings (bytes). ---
MAX_LOCKFILE_SIZE = 10 * 1024 * 1024
MAX_LOCKFILE_CONTENT_SIZE = 10 * 1024 * 1024
MAX_DECOMPRESSED_AGENT_PAYLOAD = 10 * 1024 * 1024
MAX_COMPRESSED_AGENT_PAYLOAD = 2 * 1024 * 1024
MAX_LOGO_SIZE = 2 * 1024 * 1024

# --- Retry / batching. ---
MAX_JOB_RETRIES = 5
MAX_BATCH_SIZE = 100
MAX_RETRIES = 3
MAX_RESPONSE_SIZE = 5 * 1024 * 1024


__all__ = [name for name in globals() if name.startswith('MAX_')]
