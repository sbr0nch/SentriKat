"""
Jira Integration Module

Allows creating Jira issues directly from vulnerability matches.
Supports both Jira Cloud and Jira Server/Data Center.

Configuration via System Settings:
- jira_enabled: Enable/disable Jira integration
- jira_url: Jira instance URL (e.g., https://yourcompany.atlassian.net)
- jira_email: Jira account email (for Cloud) or username (for Server)
- jira_api_token: API token (Cloud) or password (Server)
- jira_project_key: Default project key for new issues
- jira_issue_type: Default issue type (e.g., 'Bug', 'Task', 'Vulnerability')
"""

import requests
import logging
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import base64

logger = logging.getLogger(__name__)


class JiraClient:
    """Client for Jira Cloud and Server REST API v3/v2."""

    def __init__(self, url: str, email: str, api_token: str, is_cloud: bool = True):
        """
        Initialize Jira client.

        Args:
            url: Jira instance URL (e.g., https://yourcompany.atlassian.net)
            email: Email (Cloud) or username (Server)
            api_token: API token (Cloud) or password (Server)
            is_cloud: True for Jira Cloud, False for Server/Data Center
        """
        self.base_url = url.rstrip('/')
        self.email = email
        self.api_token = api_token
        self.is_cloud = is_cloud

        # Auth header differs between Cloud and Server
        if is_cloud:
            # Jira Cloud uses email:token as Basic auth
            auth_str = f"{email}:{api_token}"
            self.auth_header = f"Basic {base64.b64encode(auth_str.encode()).decode()}"
            self.api_version = '3'
        else:
            # Jira Server uses username:password
            auth_str = f"{email}:{api_token}"
            self.auth_header = f"Basic {base64.b64encode(auth_str.encode()).decode()}"
            self.api_version = '2'

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        return {
            'Authorization': self.auth_header,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def _api_url(self, endpoint: str) -> str:
        """Build API URL."""
        return f"{self.base_url}/rest/api/{self.api_version}/{endpoint}"

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test connection to Jira.

        Returns:
            Tuple of (success, message)
        """
        try:
            response = requests.get(
                self._api_url('myself'),
                headers=self._get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                user = response.json()
                display_name = user.get('displayName', user.get('name', 'Unknown'))
                return True, f"Connected as {display_name}"
            elif response.status_code == 401:
                return False, "Authentication failed - check email and API token"
            elif response.status_code == 403:
                return False, "Access forbidden - check API token permissions"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"

        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def get_projects(self) -> List[Dict]:
        """
        Get list of available projects.

        Returns:
            List of project dicts with 'key', 'name', 'id'
        """
        try:
            response = requests.get(
                self._api_url('project'),
                headers=self._get_headers(),
                timeout=15
            )
            response.raise_for_status()

            projects = response.json()
            return [
                {'key': p['key'], 'name': p['name'], 'id': p['id']}
                for p in projects
            ]
        except Exception as e:
            logger.error(f"Failed to get Jira projects: {e}")
            return []

    def get_issue_types(self, project_key: str) -> List[Dict]:
        """
        Get available issue types for a project.

        Returns:
            List of issue type dicts with 'id', 'name', 'description'
        """
        try:
            response = requests.get(
                self._api_url(f'project/{project_key}'),
                headers=self._get_headers(),
                timeout=10
            )
            response.raise_for_status()

            project = response.json()
            issue_types = project.get('issueTypes', [])
            return [
                {
                    'id': it['id'],
                    'name': it['name'],
                    'description': it.get('description', '')
                }
                for it in issue_types
                if not it.get('subtask', False)  # Exclude subtasks
            ]
        except Exception as e:
            logger.error(f"Failed to get issue types for {project_key}: {e}")
            return []

    def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = 'Task',
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        custom_fields: Optional[Dict] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Create a Jira issue.

        Args:
            project_key: Project key (e.g., 'SEC')
            summary: Issue summary/title
            description: Issue description (supports Jira wiki markup)
            issue_type: Issue type name (e.g., 'Bug', 'Task')
            priority: Priority name (e.g., 'High', 'Critical')
            labels: List of labels to add
            custom_fields: Dict of custom field IDs to values

        Returns:
            Tuple of (success, message, issue_key)
        """
        try:
            # Build issue data
            issue_data = {
                'fields': {
                    'project': {'key': project_key},
                    'summary': summary,
                    'issuetype': {'name': issue_type}
                }
            }

            # Description format differs between API versions
            if self.is_cloud:
                # API v3 uses ADF (Atlassian Document Format)
                issue_data['fields']['description'] = {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {
                            'type': 'paragraph',
                            'content': [{'type': 'text', 'text': description}]
                        }
                    ]
                }
            else:
                # API v2 uses plain text/wiki markup
                issue_data['fields']['description'] = description

            if priority:
                issue_data['fields']['priority'] = {'name': priority}

            if labels:
                issue_data['fields']['labels'] = labels

            if custom_fields:
                issue_data['fields'].update(custom_fields)

            response = requests.post(
                self._api_url('issue'),
                headers=self._get_headers(),
                json=issue_data,
                timeout=15
            )

            if response.status_code in (200, 201):
                result = response.json()
                issue_key = result.get('key')
                issue_url = f"{self.base_url}/browse/{issue_key}"
                logger.info(f"Created Jira issue: {issue_key}")
                return True, f"Created issue {issue_key}", issue_key
            else:
                # Try to parse JSON error response, fall back to text
                try:
                    error_data = response.json()
                    error_msgs = error_data.get('errorMessages', [])
                    errors = error_data.get('errors', {})
                    if errors:
                        # Jira Server often returns errors in a dict
                        error_msgs.extend([f"{k}: {v}" for k, v in errors.items()])
                    error_msg = '; '.join(error_msgs) if error_msgs else f"HTTP {response.status_code}"
                except (ValueError, AttributeError):
                    # Response is not JSON (e.g., HTML error page)
                    error_msg = f"HTTP {response.status_code}"
                    if response.status_code == 404:
                        error_msg = "Issue type or project not found. Check that your Jira project key and issue type exist."
                    elif response.status_code == 401:
                        error_msg = "Authentication failed. Check your credentials."
                    elif response.status_code == 403:
                        error_msg = "Permission denied. Check that your account has permission to create issues."
                    elif response.status_code >= 500:
                        error_msg = "Jira server error. Please try again later."

                logger.error(f"Failed to create Jira issue: {error_msg}")
                return False, f"Failed to create issue: {error_msg}", None

        except requests.RequestException as e:
            logger.exception("Jira issue creation failed - network error")
            return False, f"Network error: {str(e)}", None
        except Exception as e:
            logger.exception("Jira issue creation failed")
            return False, f"Error creating issue: {str(e)}", None

    def get_issue(self, issue_key: str) -> Optional[Dict]:
        """Get issue details by key."""
        try:
            response = requests.get(
                self._api_url(f'issue/{issue_key}'),
                headers=self._get_headers(),
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get Jira issue {issue_key}: {e}")
            return None


def get_jira_client() -> Optional[JiraClient]:
    """
    Get configured Jira client from system settings.

    Returns:
        JiraClient instance or None if not configured/disabled
    """
    from app.settings_api import get_setting
    # Note: get_setting() already handles decryption for encrypted settings,
    # so we don't need to call decrypt_value() again here.

    # Check if enabled
    if get_setting('jira_enabled', 'false') != 'true':
        return None

    url = get_setting('jira_url', '')
    email = get_setting('jira_email', '')
    # get_setting() returns decrypted value for encrypted settings
    api_token = get_setting('jira_api_token', '')

    if not all([url, email, api_token]):
        logger.warning("Jira integration enabled but not fully configured")
        return None

    # Detect Cloud vs Server based on URL
    is_cloud = 'atlassian.net' in url.lower()

    return JiraClient(url, email, api_token, is_cloud)


def create_vulnerability_issue(
    vulnerability_id: int,
    product_id: Optional[int] = None,
    custom_summary: Optional[str] = None,
    custom_description: Optional[str] = None
) -> Tuple[bool, str, Optional[str]]:
    """
    Create a Jira issue for a vulnerability.

    Args:
        vulnerability_id: Vulnerability ID
        product_id: Optional product ID for context
        custom_summary: Override default summary
        custom_description: Override default description

    Returns:
        Tuple of (success, message, issue_key)
    """
    from app.models import Vulnerability, Product
    from app.settings_api import get_setting

    client = get_jira_client()
    if not client:
        return False, "Jira integration not configured or disabled", None

    # Get vulnerability details
    vuln = Vulnerability.query.get(vulnerability_id)
    if not vuln:
        return False, "Vulnerability not found", None

    # Get product details if provided
    product = None
    if product_id:
        product = Product.query.get(product_id)

    # Build default summary and description
    if not custom_summary:
        product_info = f" in {product.vendor} {product.product_name}" if product else ""
        custom_summary = f"[{vuln.cve_id}] {vuln.vulnerability_name}{product_info}"

    if not custom_description:
        lines = [
            f"*CVE ID:* {vuln.cve_id}",
            f"*Severity:* {vuln.severity or 'Unknown'}",
            f"*CVSS Score:* {vuln.cvss_score or 'N/A'}",
            "",
            "*Description:*",
            vuln.short_description or "No description available",
            "",
            "*Required Action:*",
            vuln.required_action or "See CVE details",
            "",
            f"*Due Date:* {vuln.due_date.isoformat() if vuln.due_date else 'Not specified'}",
            f"*Known Ransomware Use:* {'Yes' if vuln.known_ransomware else 'No'}",
            "",
            f"*References:*",
            f"- NVD: https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
            f"- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        ]

        if product:
            lines.insert(4, f"*Affected Product:* {product.vendor} {product.product_name} {product.version or ''}")

        if vuln.epss_score is not None:
            lines.insert(3, f"*EPSS Score:* {vuln.epss_score * 100:.1f}% (Percentile: {vuln.epss_percentile * 100:.0f}%)")

        custom_description = "\n".join(lines)

    # Get project settings
    project_key = get_setting('jira_project_key', '')
    issue_type = get_setting('jira_issue_type', 'Task')

    if not project_key:
        return False, "Jira project key not configured", None

    # Map severity to Jira priority
    priority_map = {
        'CRITICAL': 'Highest',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low'
    }
    priority = priority_map.get(vuln.severity, 'Medium')

    # Labels
    labels = ['security', 'vulnerability', vuln.cve_id.replace('-', '_')]
    if vuln.known_ransomware:
        labels.append('ransomware')

    return client.create_issue(
        project_key=project_key,
        summary=custom_summary[:250],  # Jira summary limit
        description=custom_description,
        issue_type=issue_type,
        priority=priority,
        labels=labels
    )
