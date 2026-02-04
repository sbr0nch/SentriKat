"""
Issue Tracker Integration Module

Unified interface for creating issues in various issue tracking systems:
- Jira (Cloud & Server)
- YouTrack (JetBrains)
- GitHub Issues
- GitLab Issues
- Generic Webhook (for any other system)

Configuration via System Settings:
- issue_tracker_type: 'jira', 'youtrack', 'github', 'gitlab', 'webhook', or 'disabled'
- issue_tracker_*: Type-specific settings
"""

import requests
import logging
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime
import base64

logger = logging.getLogger(__name__)


class IssueTrackerBase(ABC):
    """Base class for issue tracker integrations."""

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to the issue tracker."""
        pass

    @abstractmethod
    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """
        Create an issue.

        Returns:
            Tuple of (success, message, issue_key/id, issue_url)
        """
        pass

    @abstractmethod
    def get_tracker_name(self) -> str:
        """Return human-readable tracker name."""
        pass


class JiraTracker(IssueTrackerBase):
    """Jira Cloud and Server integration."""

    def __init__(self, url: str, email: str, api_token: str, verify_ssl: bool = True):
        self.base_url = url.rstrip('/')
        self.email = email
        self.api_token = api_token
        self.is_cloud = 'atlassian.net' in url.lower()
        self.verify_ssl = verify_ssl

        auth_str = f"{email}:{api_token}"
        self.auth_header = f"Basic {base64.b64encode(auth_str.encode()).decode()}"
        self.api_version = '3' if self.is_cloud else '2'

    def get_tracker_name(self) -> str:
        return "Jira Cloud" if self.is_cloud else "Jira Server"

    def _get_headers(self) -> Dict[str, str]:
        return {
            'Authorization': self.auth_header,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def _api_url(self, endpoint: str) -> str:
        return f"{self.base_url}/rest/api/{self.api_version}/{endpoint}"

    def test_connection(self) -> Tuple[bool, str]:
        try:
            response = requests.get(
                self._api_url('myself'),
                headers=self._get_headers(),
                timeout=10,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                user = response.json()
                display_name = user.get('displayName', user.get('name', 'Unknown'))
                return True, f"Connected as {display_name}"
            elif response.status_code == 401:
                return False, "Authentication failed - check email and API token"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"
        except requests.exceptions.SSLError as e:
            return False, f"SSL certificate error: {str(e)}. Try disabling SSL verification in General Settings."
        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        project_key: str = '',
        issue_type: str = 'Task',
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        try:
            issue_data = {
                'fields': {
                    'project': {'key': project_key},
                    'summary': summary[:250],
                    'issuetype': {'name': issue_type}
                }
            }

            if self.is_cloud:
                issue_data['fields']['description'] = {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {'type': 'paragraph', 'content': [{'type': 'text', 'text': description}]}
                    ]
                }
            else:
                issue_data['fields']['description'] = description

            if priority:
                issue_data['fields']['priority'] = {'name': priority}
            if labels:
                issue_data['fields']['labels'] = labels

            response = requests.post(
                self._api_url('issue'),
                headers=self._get_headers(),
                json=issue_data,
                timeout=15,
                verify=self.verify_ssl
            )

            if response.status_code in (200, 201):
                result = response.json()
                issue_key = result.get('key')
                issue_url = f"{self.base_url}/browse/{issue_key}"
                return True, f"Created issue {issue_key}", issue_key, issue_url
            else:
                # Try to parse JSON error response, fall back to text
                try:
                    error_data = response.json()
                    error_msgs = error_data.get('errorMessages', [])
                    errors = error_data.get('errors', {})
                    if errors:
                        error_msgs.extend([f"{k}: {v}" for k, v in errors.items()])
                    error_msg = '; '.join(error_msgs) if error_msgs else f"HTTP {response.status_code}"
                except (ValueError, AttributeError):
                    # Response is not JSON (e.g., HTML error page)
                    error_msg = f"HTTP {response.status_code}"
                    if response.status_code == 404:
                        error_msg = "Issue type or project not found. Check your Jira project key and issue type."
                    elif response.status_code == 401:
                        error_msg = "Authentication failed. Check your credentials."
                    elif response.status_code == 403:
                        error_msg = "Permission denied. Check that your account can create issues."
                    elif response.status_code >= 500:
                        error_msg = "Jira server error. Please try again later."
                return False, f"Failed: {error_msg}", None, None

        except requests.RequestException as e:
            return False, f"Network error: {str(e)}", None, None
        except Exception as e:
            return False, f"Error: {str(e)}", None, None


class YouTrackTracker(IssueTrackerBase):
    """JetBrains YouTrack integration."""

    def __init__(self, url: str, token: str):
        self.base_url = url.rstrip('/')
        self.token = token

    def get_tracker_name(self) -> str:
        return "YouTrack"

    def _get_headers(self) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def test_connection(self) -> Tuple[bool, str]:
        try:
            response = requests.get(
                f"{self.base_url}/api/users/me",
                headers=self._get_headers(),
                timeout=10
            )
            if response.status_code == 200:
                user = response.json()
                display_name = user.get('fullName', user.get('login', 'Unknown'))
                return True, f"Connected as {display_name}"
            elif response.status_code == 401:
                return False, "Authentication failed - check permanent token"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"
        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def get_projects(self) -> List[Dict]:
        """Get list of YouTrack projects."""
        try:
            response = requests.get(
                f"{self.base_url}/api/admin/projects?fields=id,name,shortName",
                headers=self._get_headers(),
                timeout=15
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get YouTrack projects: {e}")
            return []

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        project_id: str = '',
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        try:
            issue_data = {
                'project': {'id': project_id},
                'summary': summary[:250],
                'description': description
            }

            response = requests.post(
                f"{self.base_url}/api/issues?fields=id,idReadable",
                headers=self._get_headers(),
                json=issue_data,
                timeout=15
            )

            if response.status_code in (200, 201):
                result = response.json()
                issue_id = result.get('idReadable', result.get('id'))
                issue_url = f"{self.base_url}/issue/{issue_id}"

                # Apply tags/labels if any
                if labels and issue_id:
                    for label in labels:
                        try:
                            requests.post(
                                f"{self.base_url}/api/issues/{issue_id}/tags?fields=id",
                                headers=self._get_headers(),
                                json={'name': label},
                                timeout=5
                            )
                        except Exception:
                            pass  # Tags are optional

                return True, f"Created issue {issue_id}", issue_id, issue_url
            else:
                return False, f"Failed: HTTP {response.status_code}", None, None

        except Exception as e:
            return False, f"Error: {str(e)}", None, None


class GitHubTracker(IssueTrackerBase):
    """GitHub Issues integration."""

    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.base_url = "https://api.github.com"

    def get_tracker_name(self) -> str:
        return "GitHub Issues"

    def _get_headers(self) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

    def test_connection(self) -> Tuple[bool, str]:
        try:
            response = requests.get(
                f"{self.base_url}/repos/{self.owner}/{self.repo}",
                headers=self._get_headers(),
                timeout=10
            )
            if response.status_code == 200:
                repo = response.json()
                return True, f"Connected to {repo.get('full_name')}"
            elif response.status_code == 401:
                return False, "Authentication failed - check token"
            elif response.status_code == 404:
                return False, f"Repository not found: {self.owner}/{self.repo}"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"
        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        try:
            issue_data = {
                'title': summary[:250],
                'body': description
            }

            if labels:
                issue_data['labels'] = labels

            response = requests.post(
                f"{self.base_url}/repos/{self.owner}/{self.repo}/issues",
                headers=self._get_headers(),
                json=issue_data,
                timeout=15
            )

            if response.status_code in (200, 201):
                result = response.json()
                issue_number = result.get('number')
                issue_url = result.get('html_url')
                return True, f"Created issue #{issue_number}", f"#{issue_number}", issue_url
            else:
                try:
                    error = response.json().get('message', response.text)
                except (ValueError, AttributeError):
                    error = f"HTTP {response.status_code}"
                return False, f"Failed: {error}", None, None

        except requests.RequestException as e:
            return False, f"Network error: {str(e)}", None, None
        except Exception as e:
            return False, f"Error: {str(e)}", None, None


class GitLabTracker(IssueTrackerBase):
    """GitLab Issues integration."""

    def __init__(self, url: str, token: str, project_id: str):
        self.base_url = url.rstrip('/')
        self.token = token
        self.project_id = project_id

    def get_tracker_name(self) -> str:
        return "GitLab Issues"

    def _get_headers(self) -> Dict[str, str]:
        return {
            'PRIVATE-TOKEN': self.token,
            'Content-Type': 'application/json'
        }

    def test_connection(self) -> Tuple[bool, str]:
        try:
            response = requests.get(
                f"{self.base_url}/api/v4/projects/{self.project_id}",
                headers=self._get_headers(),
                timeout=10
            )
            if response.status_code == 200:
                project = response.json()
                return True, f"Connected to {project.get('path_with_namespace')}"
            elif response.status_code == 401:
                return False, "Authentication failed - check access token"
            elif response.status_code == 404:
                return False, f"Project not found: {self.project_id}"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"
        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        try:
            issue_data = {
                'title': summary[:250],
                'description': description
            }

            if labels:
                issue_data['labels'] = ','.join(labels)

            response = requests.post(
                f"{self.base_url}/api/v4/projects/{self.project_id}/issues",
                headers=self._get_headers(),
                json=issue_data,
                timeout=15
            )

            if response.status_code in (200, 201):
                result = response.json()
                issue_iid = result.get('iid')
                issue_url = result.get('web_url')
                return True, f"Created issue #{issue_iid}", f"#{issue_iid}", issue_url
            else:
                try:
                    error = response.json().get('message', response.text)
                except (ValueError, AttributeError):
                    error = f"HTTP {response.status_code}"
                return False, f"Failed: {error}", None, None

        except requests.RequestException as e:
            return False, f"Network error: {str(e)}", None, None
        except Exception as e:
            return False, f"Error: {str(e)}", None, None


class WebhookTracker(IssueTrackerBase):
    """Generic webhook integration for any issue tracker."""

    def __init__(self, url: str, method: str = 'POST', headers: Optional[Dict] = None,
                 auth_type: str = 'none', auth_value: str = ''):
        self.webhook_url = url
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.auth_type = auth_type
        self.auth_value = auth_value

    def get_tracker_name(self) -> str:
        return "Custom Webhook"

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            'Content-Type': 'application/json',
            **self.custom_headers
        }

        if self.auth_type == 'bearer':
            headers['Authorization'] = f'Bearer {self.auth_value}'
        elif self.auth_type == 'basic':
            headers['Authorization'] = f'Basic {base64.b64encode(self.auth_value.encode()).decode()}'
        elif self.auth_type == 'header':
            # Custom header auth (e.g., X-API-Key: value)
            if ':' in self.auth_value:
                header_name, header_val = self.auth_value.split(':', 1)
                headers[header_name.strip()] = header_val.strip()

        return headers

    def test_connection(self) -> Tuple[bool, str]:
        # For webhooks, we just validate the URL format
        try:
            if not self.webhook_url.startswith(('http://', 'https://')):
                return False, "Invalid URL - must start with http:// or https://"
            return True, f"Webhook configured: {self.webhook_url}"
        except Exception as e:
            return False, f"Configuration error: {str(e)}"

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
        **kwargs
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        try:
            payload = {
                'title': summary,
                'summary': summary,
                'description': description,
                'priority': priority,
                'labels': labels or [],
                'tags': labels or [],
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'SentriKat',
                **kwargs  # Include any extra fields
            }

            response = requests.request(
                self.method,
                self.webhook_url,
                headers=self._get_headers(),
                json=payload,
                timeout=30
            )

            if response.status_code in (200, 201, 202, 204):
                # Try to extract issue info from response
                try:
                    result = response.json()
                    issue_id = result.get('id') or result.get('key') or result.get('issue_id')
                    issue_url = result.get('url') or result.get('web_url') or result.get('html_url')
                    return True, "Issue created via webhook", str(issue_id) if issue_id else None, issue_url
                except Exception:
                    return True, "Webhook delivered successfully", None, None
            else:
                return False, f"Webhook failed: HTTP {response.status_code}", None, None

        except Exception as e:
            return False, f"Error: {str(e)}", None, None


# =============================================================================
# Factory and Helper Functions
# =============================================================================

def get_issue_tracker() -> Optional[IssueTrackerBase]:
    """
    Get configured issue tracker from system settings.

    Returns:
        IssueTracker instance or None if disabled/not configured
    """
    from app.settings_api import get_setting
    # Note: get_setting() already handles decryption for encrypted settings,
    # so we don't need to call decrypt_value() again here.

    tracker_type = get_setting('issue_tracker_type', 'disabled')

    if tracker_type == 'disabled':
        return None

    # Get SSL verification setting (used by trackers that support it)
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'

    try:
        if tracker_type == 'jira':
            url = get_setting('jira_url', '')
            email = get_setting('jira_email', '')
            # get_setting() returns decrypted value for encrypted settings
            token = get_setting('jira_api_token', '')
            if not all([url, email, token]):
                return None
            return JiraTracker(url, email, token, verify_ssl=verify_ssl)

        elif tracker_type == 'youtrack':
            url = get_setting('youtrack_url', '')
            # get_setting() returns decrypted value for encrypted settings
            token = get_setting('youtrack_token', '')
            if not all([url, token]):
                return None
            return YouTrackTracker(url, token)

        elif tracker_type == 'github':
            # get_setting() returns decrypted value for encrypted settings
            token = get_setting('github_token', '')
            owner = get_setting('github_owner', '')
            repo = get_setting('github_repo', '')
            if not all([token, owner, repo]):
                return None
            return GitHubTracker(token, owner, repo)

        elif tracker_type == 'gitlab':
            url = get_setting('gitlab_url', 'https://gitlab.com')
            # get_setting() returns decrypted value for encrypted settings
            token = get_setting('gitlab_token', '')
            project_id = get_setting('gitlab_project_id', '')
            if not all([token, project_id]):
                return None
            return GitLabTracker(url, token, project_id)

        elif tracker_type == 'webhook':
            url = get_setting('webhook_url', '')
            method = get_setting('webhook_method', 'POST')
            auth_type = get_setting('webhook_auth_type', 'none')
            # get_setting() returns decrypted value for encrypted settings
            auth_value = get_setting('webhook_auth_value', '')
            if not url:
                return None
            return WebhookTracker(url, method, auth_type=auth_type, auth_value=auth_value)

    except Exception as e:
        logger.error(f"Failed to initialize issue tracker: {e}")

    return None


def get_issue_tracker_config() -> Dict[str, Any]:
    """Get current issue tracker configuration (for UI)."""
    from app.settings_api import get_setting

    tracker_type = get_setting('issue_tracker_type', 'disabled')

    config = {
        'type': tracker_type,
        'enabled': tracker_type != 'disabled'
    }

    if tracker_type == 'jira':
        config.update({
            'url': get_setting('jira_url', ''),
            'email': get_setting('jira_email', ''),
            'project_key': get_setting('jira_project_key', ''),
            'issue_type': get_setting('jira_issue_type', 'Task')
        })
    elif tracker_type == 'youtrack':
        config.update({
            'url': get_setting('youtrack_url', ''),
            'project_id': get_setting('youtrack_project_id', '')
        })
    elif tracker_type == 'github':
        config.update({
            'owner': get_setting('github_owner', ''),
            'repo': get_setting('github_repo', '')
        })
    elif tracker_type == 'gitlab':
        config.update({
            'url': get_setting('gitlab_url', 'https://gitlab.com'),
            'project_id': get_setting('gitlab_project_id', '')
        })
    elif tracker_type == 'webhook':
        config.update({
            'url': get_setting('webhook_url', ''),
            'method': get_setting('webhook_method', 'POST')
        })

    return config


def create_vulnerability_issue(
    vulnerability_id: int,
    product_id: Optional[int] = None,
    custom_summary: Optional[str] = None,
    custom_description: Optional[str] = None
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Create an issue for a vulnerability using the configured tracker.

    Args:
        vulnerability_id: Vulnerability ID
        product_id: Optional product ID for context
        custom_summary: Override default summary
        custom_description: Override default description

    Returns:
        Tuple of (success, message, issue_key/id, issue_url)
    """
    from app.models import Vulnerability, Product
    from app.settings_api import get_setting

    tracker = get_issue_tracker()
    if not tracker:
        return False, "Issue tracker not configured or disabled", None, None

    # Get vulnerability details
    vuln = Vulnerability.query.get(vulnerability_id)
    if not vuln:
        return False, "Vulnerability not found", None, None

    # Get product details if provided
    product = None
    if product_id:
        product = Product.query.get(product_id)

    # Build default summary
    if not custom_summary:
        product_info = f" in {product.vendor} {product.product_name}" if product else ""
        custom_summary = f"[{vuln.cve_id}] {vuln.vulnerability_name}{product_info}"

    # Build default description (Markdown format - works with most trackers)
    if not custom_description:
        lines = [
            f"**CVE ID:** {vuln.cve_id}",
            f"**Severity:** {vuln.severity or 'Unknown'}",
            f"**CVSS Score:** {vuln.cvss_score or 'N/A'}",
        ]

        if vuln.epss_score is not None:
            lines.append(f"**EPSS Score:** {vuln.epss_score * 100:.1f}% (Percentile: {vuln.epss_percentile * 100:.0f}%)")

        if product:
            lines.append(f"**Affected Product:** {product.vendor} {product.product_name} {product.version or ''}")

        lines.extend([
            "",
            "## Description",
            vuln.short_description or "No description available",
            "",
            "## Required Action",
            vuln.required_action or "See CVE details",
            "",
            f"**Due Date:** {vuln.due_date.isoformat() if vuln.due_date else 'Not specified'}",
            f"**Known Ransomware Use:** {'Yes' if vuln.known_ransomware else 'No'}",
            "",
            "## References",
            f"- [NVD](https://nvd.nist.gov/vuln/detail/{vuln.cve_id})",
            f"- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
        ])

        custom_description = "\n".join(lines)

    # Map severity to priority
    priority_map = {
        'CRITICAL': 'Highest',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low'
    }
    priority = priority_map.get(vuln.severity, 'Medium')

    # Labels/tags
    labels = ['security', 'vulnerability', 'cve', vuln.cve_id.lower().replace('-', '_')]
    if vuln.known_ransomware:
        labels.append('ransomware')

    # Tracker-specific parameters
    tracker_type = get_setting('issue_tracker_type', 'disabled')
    extra_params = {}

    if tracker_type == 'jira':
        extra_params['project_key'] = get_setting('jira_project_key', '')
        extra_params['issue_type'] = get_setting('jira_issue_type', 'Task')
    elif tracker_type == 'youtrack':
        extra_params['project_id'] = get_setting('youtrack_project_id', '')
    # GitHub and GitLab don't need extra params
    # Webhook includes everything in the payload

    # Add vulnerability data for webhook
    extra_params['vulnerability'] = {
        'id': vuln.id,
        'cve_id': vuln.cve_id,
        'name': vuln.vulnerability_name,
        'severity': vuln.severity,
        'cvss_score': vuln.cvss_score,
        'epss_score': vuln.epss_score,
        'due_date': vuln.due_date.isoformat() if vuln.due_date else None,
        'known_ransomware': vuln.known_ransomware
    }

    if product:
        extra_params['product'] = {
            'id': product.id,
            'vendor': product.vendor,
            'name': product.product_name,
            'version': product.version
        }

    return tracker.create_issue(
        summary=custom_summary,
        description=custom_description,
        priority=priority,
        labels=labels,
        **extra_params
    )
