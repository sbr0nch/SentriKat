"""
Centralized webhook delivery module for SentriKat.

Provides retry logic with exponential backoff, HMAC-SHA256 signing,
and SSRF protection for all outbound webhook requests.
"""

import hashlib
import hmac
import json
import logging
import time

import requests

from app.network_security import validate_url_for_request
from config import Config

logger = logging.getLogger(__name__)


def send_webhook(url, payload, format='slack', token=None, webhook_secret=None, max_retries=3):
    """Send webhook with retry and optional HMAC signing.

    Args:
        url: Webhook URL.
        payload: Dict payload to send as JSON.
        format: 'slack', 'teams', 'discord', 'generic' (used for logging context only;
                the caller is responsible for building the correct payload shape).
        token: Optional auth token (added as Bearer and X-Auth-Token headers).
        webhook_secret: Optional HMAC secret for signing the request body.
        max_retries: Max retry attempts (default 3). First attempt is not counted
                     as a retry, so up to *max_retries* additional attempts are made
                     after the first failure.

    Returns:
        Tuple of (success: bool, status_code: int, error: str | None).
        On connection errors where no HTTP response was received, status_code is 0.
    """
    # --- SSRF protection ------------------------------------------------
    is_safe, err_msg = validate_url_for_request(url, context=f"webhook ({format})")
    if not is_safe:
        logger.warning(f"Webhook blocked by SSRF protection: {err_msg} — url={url}")
        return (False, 0, f"SSRF protection: {err_msg}")

    # --- Build headers ---------------------------------------------------
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
        headers['X-Auth-Token'] = token

    body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # --- HMAC signing ----------------------------------------------------
    if webhook_secret:
        timestamp = str(int(time.time()))
        signed_payload = f"{timestamp}.".encode('utf-8') + body_bytes
        signature = hmac.new(
            webhook_secret.encode('utf-8'),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()
        headers['X-Webhook-Signature'] = f"sha256={signature}"
        headers['X-Webhook-Timestamp'] = timestamp

    # --- Proxy / TLS settings -------------------------------------------
    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()

    # --- Send with retries (exponential backoff: 2s, 4s, 8s) -----------
    last_status = 0
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            logger.debug(
                f"Webhook attempt {attempt}/{max_retries} to {url} (format={format})"
            )
            response = requests.post(
                url,
                data=body_bytes,
                headers=headers,
                timeout=10,
                proxies=proxies,
                verify=verify_ssl,
            )
            last_status = response.status_code

            if response.status_code in (200, 201, 202, 204):
                logger.info(
                    f"Webhook delivered successfully to {url} "
                    f"(format={format}, status={response.status_code}, attempt={attempt})"
                )
                return (True, response.status_code, None)

            # 4xx errors — do NOT retry (client error, retrying won't help)
            if 400 <= response.status_code < 500:
                last_error = f"HTTP {response.status_code}"
                logger.warning(
                    f"Webhook failed with client error {response.status_code} "
                    f"to {url} — not retrying"
                )
                return (False, response.status_code, last_error)

            # 5xx errors — retry with backoff
            last_error = f"HTTP {response.status_code}"
            logger.warning(
                f"Webhook attempt {attempt}/{max_retries} returned {response.status_code} "
                f"for {url}"
            )

        except requests.exceptions.RequestException as exc:
            last_status = 0
            last_error = str(exc)
            logger.warning(
                f"Webhook attempt {attempt}/{max_retries} connection error "
                f"for {url}: {exc}"
            )

        # Exponential backoff before next retry (2^attempt seconds: 2, 4, 8)
        if attempt < max_retries:
            backoff = 2 ** attempt
            logger.debug(f"Retrying webhook in {backoff}s …")
            time.sleep(backoff)

    # All retries exhausted
    logger.error(
        f"Webhook delivery failed after {max_retries} attempts to {url} "
        f"(format={format}, last_status={last_status}, error={last_error})"
    )
    return (False, last_status, last_error)
