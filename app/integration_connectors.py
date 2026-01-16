"""
Integration Connectors - Fetch software inventory from external systems.

Each connector implements:
- test_connection(): Verify connectivity
- fetch_software(): Retrieve software list

The Generic REST connector can be configured to work with any REST API
that returns a JSON array of software items.
"""

import requests
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ConnectorError(Exception):
    """Base exception for connector errors."""
    pass


class BaseConnector:
    """Base class for all integration connectors."""

    def __init__(self, integration):
        self.integration = integration
        self.config = integration.get_config()

    def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to the external system."""
        raise NotImplementedError

    def fetch_software(self) -> List[Dict[str, Any]]:
        """Fetch software inventory from the external system."""
        raise NotImplementedError


class GenericRestConnector(BaseConnector):
    """
    Generic REST API connector - works with any REST API.

    Configuration:
    {
        "api_url": "https://inventory.example.com/api/software",
        "api_key": "secret",
        "auth_type": "header",  // "header", "basic", "bearer", "none"
        "auth_header": "X-API-Key",  // Header name for auth_type=header
        "username": "",  // For auth_type=basic
        "password": "",  // For auth_type=basic
        "method": "GET",
        "response_path": "data.software",  // JSON path to software array (dot notation)
        "vendor_field": "vendor",  // Field name for vendor in response
        "product_field": "name",  // Field name for product in response
        "version_field": "version",  // Field name for version in response
        "verify_ssl": true,
        "timeout": 30,
        "custom_headers": {}  // Optional additional headers
    }

    Example configurations for common systems:

    # PDQ Inventory
    {
        "api_url": "https://pdq.example.com/api/v1/applications",
        "api_key": "your-api-key",
        "auth_type": "bearer",
        "response_path": "applications",
        "vendor_field": "publisher",
        "product_field": "name",
        "version_field": "version"
    }

    # Generic inventory system
    {
        "api_url": "https://inventory.example.com/api/software",
        "api_key": "your-api-key",
        "auth_type": "header",
        "auth_header": "X-API-Key",
        "response_path": "data",
        "vendor_field": "vendor",
        "product_field": "product_name",
        "version_field": "version"
    }

    # SentriKat Test Endpoint (for testing)
    {
        "api_url": "http://localhost:5000/api/test/mock-software",
        "auth_type": "none",
        "response_path": "software",
        "vendor_field": "vendor",
        "product_field": "product",
        "version_field": "version"
    }
    """

    def test_connection(self) -> Dict[str, Any]:
        api_url = self.config.get('api_url')
        if not api_url:
            return {'success': False, 'error': 'API URL not configured'}

        try:
            response = self._make_request(api_url)

            # Check if response is valid JSON
            try:
                data = response.json()
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': f'Invalid JSON response (HTTP {response.status_code})'
                }

            return {
                'success': True,
                'message': f'Connected successfully (HTTP {response.status_code})',
                'preview': self._get_preview(data)
            }
        except requests.exceptions.ConnectionError as e:
            return {'success': False, 'error': f'Connection failed: {str(e)}'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Connection timed out'}
        except requests.exceptions.HTTPError as e:
            return {'success': False, 'error': f'HTTP error: {e.response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _get_preview(self, data: Any) -> Dict[str, Any]:
        """Get a preview of the data structure for debugging."""
        response_path = self.config.get('response_path', '')

        # Navigate to the software array
        preview_data = data
        if response_path:
            for key in response_path.split('.'):
                if key and isinstance(preview_data, dict):
                    preview_data = preview_data.get(key, [])

        if isinstance(preview_data, list):
            return {
                'type': 'array',
                'count': len(preview_data),
                'sample': preview_data[0] if preview_data else None
            }
        elif isinstance(preview_data, dict):
            return {
                'type': 'object',
                'keys': list(preview_data.keys())[:10]
            }
        else:
            return {'type': type(preview_data).__name__}

    def fetch_software(self) -> List[Dict[str, Any]]:
        api_url = self.config.get('api_url')
        if not api_url:
            raise ConnectorError('API URL not configured')

        response = self._make_request(api_url)
        response.raise_for_status()

        data = response.json()

        # Navigate to the software array using response_path
        response_path = self.config.get('response_path', '')
        if response_path:
            for key in response_path.split('.'):
                if key and isinstance(data, dict):
                    data = data.get(key, [])

        if not isinstance(data, list):
            raise ConnectorError(
                f'Expected array at response path "{response_path}", '
                f'got {type(data).__name__}. Check your response_path configuration.'
            )

        # Map fields to standard format
        vendor_field = self.config.get('vendor_field', 'vendor')
        product_field = self.config.get('product_field', 'name')
        version_field = self.config.get('version_field', 'version')

        software_list = []
        for item in data:
            if isinstance(item, dict):
                vendor = item.get(vendor_field, '')
                product = item.get(product_field, '')
                version = item.get(version_field, '')

                # Skip items without required fields
                if not vendor or not product:
                    continue

                software_list.append({
                    'vendor': str(vendor).strip(),
                    'product': str(product).strip(),
                    'version': str(version).strip() if version else ''
                })

        logger.info(f"Fetched {len(software_list)} software items from {api_url}")
        return software_list

    def _make_request(self, url: str) -> requests.Response:
        """Make authenticated HTTP request."""
        headers = {'Accept': 'application/json'}
        auth = None

        auth_type = self.config.get('auth_type', 'header')
        verify_ssl = self.config.get('verify_ssl', True)
        method = self.config.get('method', 'GET').upper()
        timeout = self.config.get('timeout', 30)

        # Add custom headers if configured
        custom_headers = self.config.get('custom_headers', {})
        if isinstance(custom_headers, dict):
            headers.update(custom_headers)

        if auth_type == 'header':
            header_name = self.config.get('auth_header', 'X-API-Key')
            api_key = self.config.get('api_key', '')
            if api_key:
                headers[header_name] = api_key

        elif auth_type == 'bearer':
            api_key = self.config.get('api_key', '')
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'

        elif auth_type == 'basic':
            username = self.config.get('username', '')
            password = self.config.get('password', '')
            if username:
                auth = (username, password)

        # auth_type == 'none' - no authentication added

        return requests.request(
            method,
            url,
            headers=headers,
            auth=auth,
            verify=verify_ssl,
            timeout=timeout
        )


# Connector registry - only generic_rest is available
CONNECTORS = {
    'generic_rest': GenericRestConnector,
}


def get_connector(integration) -> Optional[BaseConnector]:
    """Get appropriate connector for an integration."""
    connector_class = CONNECTORS.get(integration.integration_type)
    if connector_class:
        return connector_class(integration)
    return None


def test_connector(integration) -> Dict[str, Any]:
    """Test connection for an integration."""
    connector = get_connector(integration)
    if not connector:
        return {
            'success': False,
            'error': f'No connector available for type: {integration.integration_type}'
        }
    return connector.test_connection()


def sync_integration(integration) -> Dict[str, Any]:
    """
    Sync software from an integration.

    Returns results summary.
    """
    from app import db
    from app.integrations_models import ImportQueue
    from app.integrations_api import attempt_cpe_match, create_product_from_queue
    from app.models import Product

    connector = get_connector(integration)
    if not connector:
        raise ConnectorError(f'No connector available for type: {integration.integration_type}')

    # Fetch software list
    software_list = connector.fetch_software()

    results = {
        'success': True,
        'total_found': len(software_list),
        'queued': 0,
        'auto_approved': 0,
        'duplicates': 0,
        'errors': 0
    }

    for item in software_list:
        vendor = item.get('vendor', '').strip()
        product_name = item.get('product', '').strip()
        version = item.get('version', '').strip() or None

        if not vendor or not product_name:
            results['errors'] += 1
            continue

        # Check for existing product
        existing = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()

        if existing:
            results['duplicates'] += 1
            continue

        # Check for existing queue item
        existing_queue = ImportQueue.query.filter(
            db.func.lower(ImportQueue.vendor) == vendor.lower(),
            db.func.lower(ImportQueue.product_name) == product_name.lower(),
            ImportQueue.status == 'pending'
        ).first()

        if existing_queue:
            results['duplicates'] += 1
            continue

        # Try CPE match
        cpe_vendor, cpe_product, confidence = attempt_cpe_match(vendor, product_name)

        # Create queue item
        queue_item = ImportQueue(
            integration_id=integration.id,
            vendor=vendor,
            product_name=product_name,
            detected_version=version,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            cpe_match_confidence=confidence,
            organization_id=integration.organization_id,
            criticality=integration.default_criticality or 'medium',
            status='pending'
        )

        # Store source metadata
        source_data = {k: v for k, v in item.items() if k not in ['vendor', 'product', 'version']}
        if source_data:
            queue_item.set_source_data(source_data)

        db.session.add(queue_item)

        if integration.auto_approve:
            product = create_product_from_queue(queue_item)
            if product:
                queue_item.status = 'approved'
                queue_item.product_id = product.id
                queue_item.processed_at = datetime.utcnow()
                results['auto_approved'] += 1
            else:
                results['queued'] += 1
        else:
            results['queued'] += 1

    # Update integration status
    integration.last_sync_at = datetime.utcnow()
    integration.last_sync_status = 'success'
    integration.last_sync_count = len(software_list)
    integration.last_sync_message = f"Found {results['total_found']}, queued {results['queued']}, auto-approved {results['auto_approved']}, duplicates {results['duplicates']}"

    db.session.commit()

    return results
