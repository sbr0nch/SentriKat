"""
Integration Connectors - Fetch software inventory from external systems.

Each connector implements:
- test_connection(): Verify connectivity
- fetch_software(): Retrieve software list

Supported systems:
- PDQ Inventory (REST API)
- Generic REST API (configurable)
- CSV Import (file upload)
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
    Generic REST API connector.

    Configuration:
    {
        "api_url": "https://inventory.example.com/api/software",
        "api_key": "secret",
        "auth_type": "header",  // "header", "basic", "bearer"
        "auth_header": "X-API-Key",  // Header name for auth_type=header
        "username": "",  // For auth_type=basic
        "password": "",  // For auth_type=basic
        "method": "GET",
        "response_path": "data.software",  // JSON path to software array
        "vendor_field": "vendor",  // Field name for vendor
        "product_field": "name",  // Field name for product
        "version_field": "version",  // Field name for version
        "verify_ssl": true
    }
    """

    def test_connection(self) -> Dict[str, Any]:
        api_url = self.config.get('api_url')
        if not api_url:
            return {'success': False, 'error': 'API URL not configured'}

        try:
            response = self._make_request(api_url)
            return {
                'success': True,
                'message': f'Connected successfully (HTTP {response.status_code})'
            }
        except requests.exceptions.ConnectionError as e:
            return {'success': False, 'error': f'Connection failed: {str(e)}'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Connection timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

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
            raise ConnectorError(f'Expected array at response path, got {type(data).__name__}')

        # Map fields to standard format
        vendor_field = self.config.get('vendor_field', 'vendor')
        product_field = self.config.get('product_field', 'name')
        version_field = self.config.get('version_field', 'version')

        software_list = []
        for item in data:
            if isinstance(item, dict):
                software_list.append({
                    'vendor': item.get(vendor_field, ''),
                    'product': item.get(product_field, ''),
                    'version': item.get(version_field, '')
                })

        return software_list

    def _make_request(self, url: str) -> requests.Response:
        """Make authenticated HTTP request."""
        headers = {}
        auth = None

        auth_type = self.config.get('auth_type', 'header')
        verify_ssl = self.config.get('verify_ssl', True)
        method = self.config.get('method', 'GET').upper()

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

        return requests.request(
            method,
            url,
            headers=headers,
            auth=auth,
            verify=verify_ssl,
            timeout=30
        )


class PDQConnector(BaseConnector):
    """
    PDQ Inventory connector.

    Configuration:
    {
        "api_url": "https://pdq.example.com",
        "api_key": "secret"
    }

    Note: PDQ Inventory's REST API availability depends on version.
    This connector is a template - adjust based on your PDQ setup.
    """

    def test_connection(self) -> Dict[str, Any]:
        api_url = self.config.get('api_url', '').rstrip('/')
        api_key = self.config.get('api_key', '')

        if not api_url:
            return {'success': False, 'error': 'API URL not configured'}

        try:
            # PDQ API test endpoint (adjust based on your PDQ version)
            response = requests.get(
                f'{api_url}/api/v1/computers',
                headers={'Authorization': f'Bearer {api_key}'},
                verify=self.config.get('verify_ssl', True),
                timeout=10
            )

            if response.status_code == 401:
                return {'success': False, 'error': 'Invalid API key'}
            elif response.status_code == 404:
                return {'success': False, 'error': 'API endpoint not found - check PDQ version'}

            response.raise_for_status()
            return {'success': True, 'message': 'Connected to PDQ Inventory'}

        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Cannot connect to PDQ server'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def fetch_software(self) -> List[Dict[str, Any]]:
        api_url = self.config.get('api_url', '').rstrip('/')
        api_key = self.config.get('api_key', '')

        if not api_url:
            raise ConnectorError('API URL not configured')

        # Fetch software from PDQ
        # Note: Actual endpoint depends on PDQ version
        response = requests.get(
            f'{api_url}/api/v1/applications',
            headers={'Authorization': f'Bearer {api_key}'},
            verify=self.config.get('verify_ssl', True),
            timeout=60
        )
        response.raise_for_status()

        data = response.json()
        applications = data.get('applications', data) if isinstance(data, dict) else data

        software_list = []
        seen = set()

        for app in applications:
            vendor = app.get('publisher', app.get('vendor', 'Unknown'))
            name = app.get('name', app.get('displayName', ''))
            version = app.get('version', '')

            # Deduplicate
            key = (vendor.lower(), name.lower())
            if key in seen or not name:
                continue
            seen.add(key)

            software_list.append({
                'vendor': vendor,
                'product': name,
                'version': version,
                'install_count': app.get('installCount', app.get('computerCount', 0))
            })

        return software_list


class SCCMConnector(BaseConnector):
    """
    Microsoft SCCM/ConfigMgr connector.

    Configuration:
    {
        "api_url": "https://sccm.example.com/AdminService",
        "username": "domain\\user",
        "password": "secret"
    }

    Uses the SCCM AdminService REST API.
    """

    def test_connection(self) -> Dict[str, Any]:
        api_url = self.config.get('api_url', '').rstrip('/')

        if not api_url:
            return {'success': False, 'error': 'API URL not configured'}

        try:
            response = requests.get(
                f'{api_url}/v1.0/Device',
                auth=(self.config.get('username', ''), self.config.get('password', '')),
                verify=self.config.get('verify_ssl', True),
                timeout=10
            )

            if response.status_code == 401:
                return {'success': False, 'error': 'Authentication failed'}

            response.raise_for_status()
            return {'success': True, 'message': 'Connected to SCCM'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def fetch_software(self) -> List[Dict[str, Any]]:
        api_url = self.config.get('api_url', '').rstrip('/')

        if not api_url:
            raise ConnectorError('API URL not configured')

        # Fetch software inventory
        response = requests.get(
            f'{api_url}/v1.0/SoftwareInventory',
            auth=(self.config.get('username', ''), self.config.get('password', '')),
            verify=self.config.get('verify_ssl', True),
            timeout=60
        )
        response.raise_for_status()

        data = response.json()
        items = data.get('value', data) if isinstance(data, dict) else data

        software_list = []
        seen = set()

        for item in items:
            vendor = item.get('Publisher', item.get('CompanyName', 'Unknown'))
            name = item.get('ProductName', item.get('DisplayName', ''))
            version = item.get('ProductVersion', '')

            key = (vendor.lower(), name.lower())
            if key in seen or not name:
                continue
            seen.add(key)

            software_list.append({
                'vendor': vendor,
                'product': name,
                'version': version
            })

        return software_list


class IntuneConnector(BaseConnector):
    """
    Microsoft Intune connector via Graph API.

    Configuration:
    {
        "tenant_id": "xxx-xxx",
        "client_id": "xxx-xxx",
        "client_secret": "secret"
    }
    """

    def _get_token(self) -> str:
        """Get OAuth token from Azure AD."""
        tenant_id = self.config.get('tenant_id')
        client_id = self.config.get('client_id')
        client_secret = self.config.get('client_secret')

        if not all([tenant_id, client_id, client_secret]):
            raise ConnectorError('Missing Azure AD credentials')

        response = requests.post(
            f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
            data={
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            },
            timeout=10
        )
        response.raise_for_status()
        return response.json()['access_token']

    def test_connection(self) -> Dict[str, Any]:
        try:
            token = self._get_token()
            response = requests.get(
                'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices',
                headers={'Authorization': f'Bearer {token}'},
                timeout=10
            )
            response.raise_for_status()
            return {'success': True, 'message': 'Connected to Microsoft Intune'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def fetch_software(self) -> List[Dict[str, Any]]:
        token = self._get_token()

        # Get detected apps
        response = requests.get(
            'https://graph.microsoft.com/v1.0/deviceManagement/detectedApps',
            headers={'Authorization': f'Bearer {token}'},
            timeout=60
        )
        response.raise_for_status()

        data = response.json()
        apps = data.get('value', [])

        software_list = []
        for app in apps:
            name = app.get('displayName', '')
            version = app.get('version', '')

            # Intune doesn't always have vendor info
            # Try to extract from name or use placeholder
            vendor = app.get('publisher', 'Unknown')

            if name:
                software_list.append({
                    'vendor': vendor,
                    'product': name,
                    'version': version,
                    'install_count': app.get('deviceCount', 0)
                })

        return software_list


# Connector registry
CONNECTORS = {
    'pdq': PDQConnector,
    'sccm': SCCMConnector,
    'intune': IntuneConnector,
    'generic_rest': GenericRestConnector,
    'lansweeper': GenericRestConnector,  # Uses generic REST with custom config
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
