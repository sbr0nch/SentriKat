"""
SentriKat API Documentation Module

Provides:
- OpenAPI 3.0 specification at /api/spec.json
- Swagger UI at /api/docs
- Exportable documentation for docu.sentrikat.com
"""

from flask import Blueprint, jsonify, render_template_string
from datetime import datetime

api_docs_bp = Blueprint('api_docs', __name__)

# API Version
API_VERSION = '1.0.0'

# OpenAPI 3.0 Specification
def get_openapi_spec():
    """Generate OpenAPI 3.0 specification for all SentriKat APIs."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SentriKat API",
            "description": """
SentriKat Vulnerability Management Platform API

## Authentication
Most endpoints require authentication. SentriKat supports:
- **Session cookies** - For web UI interactions
- **API Keys** - For agent integrations (push inventory)

## Rate Limiting
Default limits: 1000 requests/day, 200 requests/hour per IP.
Some admin endpoints have higher limits.

## Response Format
All responses are JSON. Errors include an `error` field with a description.
""",
            "version": API_VERSION,
            "contact": {
                "name": "SentriKat Support",
                "url": "https://sentrikat.com/support"
            },
            "license": {
                "name": "Proprietary",
                "url": "https://sentrikat.com/license"
            }
        },
        "servers": [
            {
                "url": "/",
                "description": "Current Server"
            }
        ],
        "tags": [
            {"name": "Authentication", "description": "Login, logout, and session management"},
            {"name": "Dashboard", "description": "Dashboard data and vulnerability overview"},
            {"name": "Products", "description": "Product/software inventory management"},
            {"name": "Vulnerabilities", "description": "CVE vulnerability data"},
            {"name": "Organizations", "description": "Organization management (multi-tenant)"},
            {"name": "Agents", "description": "Push agent API for automated inventory"},
            {"name": "Sync", "description": "NVD/EPSS data synchronization"},
            {"name": "Settings", "description": "System configuration"},
            {"name": "License", "description": "License management"},
            {"name": "Reports", "description": "Compliance and vulnerability reports"},
            {"name": "Integrations", "description": "Issue tracker and notification integrations"},
            {"name": "Health Checks", "description": "System health monitoring and diagnostics"},
            {"name": "Notifications", "description": "In-app system notifications"},
            {"name": "Logs", "description": "System log viewing and download"},
            {"name": "Audit", "description": "Audit trail and compliance logs"}
        ],
        "paths": _get_api_paths(),
        "components": {
            "schemas": _get_schemas(),
            "securitySchemes": {
                "sessionAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session",
                    "description": "Session cookie obtained via /api/auth/login"
                },
                "agentApiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Agent API key for push inventory endpoints"
                }
            }
        },
        "security": [
            {"sessionAuth": []}
        ]
    }


def _get_api_paths():
    """Define all API endpoint paths."""
    return {
        # =====================================================================
        # Authentication
        # =====================================================================
        "/api/auth/login": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Login to SentriKat",
                "description": "Authenticate with username and password. Returns session cookie.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["username", "password"],
                                "properties": {
                                    "username": {"type": "string", "example": "admin"},
                                    "password": {"type": "string", "format": "password"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"}
                            }
                        }
                    },
                    "401": {"description": "Invalid credentials"}
                },
                "security": []
            }
        },
        "/api/auth/logout": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Logout from SentriKat",
                "description": "Invalidate current session.",
                "responses": {
                    "200": {"description": "Logout successful"}
                }
            }
        },
        "/api/auth/status": {
            "get": {
                "tags": ["Authentication"],
                "summary": "Check authentication status",
                "description": "Check if current session is valid and get user info.",
                "responses": {
                    "200": {
                        "description": "Authentication status",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AuthStatus"}
                            }
                        }
                    }
                },
                "security": []
            }
        },

        # =====================================================================
        # Dashboard
        # =====================================================================
        "/api/dashboard/stats": {
            "get": {
                "tags": ["Dashboard"],
                "summary": "Get dashboard statistics",
                "description": "Returns counts of products, vulnerabilities, and criticality breakdown.",
                "parameters": [
                    {"name": "org_id", "in": "query", "schema": {"type": "integer"}, "description": "Organization filter"}
                ],
                "responses": {
                    "200": {
                        "description": "Dashboard statistics",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DashboardStats"}
                            }
                        }
                    }
                }
            }
        },
        "/api/dashboard/vulnerabilities/grouped": {
            "get": {
                "tags": ["Dashboard"],
                "summary": "Get grouped vulnerabilities",
                "description": "Returns vulnerabilities grouped by CVE with affected products.",
                "parameters": [
                    {"name": "org_id", "in": "query", "schema": {"type": "integer"}, "description": "Organization filter"},
                    {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["critical", "high", "medium", "low"]}, "description": "Filter by severity"},
                    {"name": "urgency", "in": "query", "schema": {"type": "string", "enum": ["kev", "high_epss", "high_cvss"]}, "description": "Filter by urgency"},
                    {"name": "age", "in": "query", "schema": {"type": "string", "enum": ["7d", "30d", "90d", "all"]}, "description": "Filter by age"},
                    {"name": "vendor", "in": "query", "schema": {"type": "string"}, "description": "Filter by vendor"},
                    {"name": "product", "in": "query", "schema": {"type": "string"}, "description": "Filter by product name"}
                ],
                "responses": {
                    "200": {
                        "description": "Grouped vulnerabilities list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/GroupedVulnerability"}
                                }
                            }
                        }
                    }
                }
            }
        },

        # =====================================================================
        # Products
        # =====================================================================
        "/api/products": {
            "get": {
                "tags": ["Products"],
                "summary": "List all products",
                "description": "Get all products in the inventory.",
                "parameters": [
                    {"name": "org_id", "in": "query", "schema": {"type": "integer"}, "description": "Organization filter"},
                    {"name": "search", "in": "query", "schema": {"type": "string"}, "description": "Search by name or vendor"}
                ],
                "responses": {
                    "200": {
                        "description": "Product list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Product"}
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "tags": ["Products"],
                "summary": "Add a product",
                "description": "Add a new product to the inventory.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ProductCreate"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Product created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Product"}
                            }
                        }
                    },
                    "400": {"description": "Invalid input"},
                    "403": {"description": "License limit reached"}
                }
            }
        },
        "/api/products/{id}": {
            "get": {
                "tags": ["Products"],
                "summary": "Get product details",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {
                    "200": {
                        "description": "Product details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Product"}
                            }
                        }
                    },
                    "404": {"description": "Product not found"}
                }
            },
            "put": {
                "tags": ["Products"],
                "summary": "Update a product",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ProductCreate"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Product updated"},
                    "404": {"description": "Product not found"}
                }
            },
            "delete": {
                "tags": ["Products"],
                "summary": "Delete a product",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {
                    "200": {"description": "Product deleted"},
                    "404": {"description": "Product not found"}
                }
            }
        },

        # =====================================================================
        # Vulnerabilities
        # =====================================================================
        "/api/vulnerabilities": {
            "get": {
                "tags": ["Vulnerabilities"],
                "summary": "List vulnerabilities",
                "description": "Get all vulnerabilities affecting products in inventory.",
                "parameters": [
                    {"name": "org_id", "in": "query", "schema": {"type": "integer"}},
                    {"name": "severity", "in": "query", "schema": {"type": "string"}},
                    {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "acknowledged", "resolved"]}}
                ],
                "responses": {
                    "200": {
                        "description": "Vulnerability list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Vulnerability"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "/api/vulnerabilities/{cve_id}": {
            "get": {
                "tags": ["Vulnerabilities"],
                "summary": "Get vulnerability details",
                "parameters": [
                    {"name": "cve_id", "in": "path", "required": True, "schema": {"type": "string"}, "example": "CVE-2024-1234"}
                ],
                "responses": {
                    "200": {
                        "description": "Vulnerability details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Vulnerability"}
                            }
                        }
                    }
                }
            }
        },
        "/api/vulnerabilities/{cve_id}/acknowledge": {
            "post": {
                "tags": ["Vulnerabilities"],
                "summary": "Acknowledge a vulnerability",
                "description": "Mark a vulnerability as acknowledged for specific products.",
                "parameters": [
                    {"name": "cve_id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "product_ids": {"type": "array", "items": {"type": "integer"}},
                                    "notes": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Vulnerability acknowledged"}
                }
            }
        },

        # =====================================================================
        # Agent API (Push Inventory)
        # =====================================================================
        "/api/agent/inventory": {
            "post": {
                "tags": ["Agents"],
                "summary": "Push inventory from agent",
                "description": "Submit software inventory collected by an agent. Requires Agent API Key.",
                "security": [{"agentApiKey": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/AgentInventory"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Inventory processed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AgentInventoryResponse"}
                            }
                        }
                    },
                    "401": {"description": "Invalid or missing API key"},
                    "403": {"description": "Agent limit reached (license)"}
                }
            }
        },
        "/api/agent/commands": {
            "get": {
                "tags": ["Agents"],
                "summary": "Poll for agent commands",
                "description": "Agent polls this endpoint to check for pending commands (scan_now, update_config, etc).",
                "security": [{"agentApiKey": []}],
                "parameters": [
                    {"name": "hostname", "in": "query", "required": True, "schema": {"type": "string"}, "description": "Agent hostname"}
                ],
                "responses": {
                    "200": {
                        "description": "Commands for agent",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AgentCommands"}
                            }
                        }
                    }
                }
            }
        },
        "/api/agent/version": {
            "get": {
                "tags": ["Agents"],
                "summary": "Check for agent updates",
                "description": "Get latest agent version and download URLs.",
                "responses": {
                    "200": {
                        "description": "Agent version info",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AgentVersion"}
                            }
                        }
                    }
                }
            }
        },

        # =====================================================================
        # Sync (NVD/EPSS)
        # =====================================================================
        "/api/sync/nvd": {
            "post": {
                "tags": ["Sync"],
                "summary": "Trigger NVD sync",
                "description": "Start synchronization with NVD (National Vulnerability Database).",
                "responses": {
                    "200": {"description": "Sync started"}
                }
            }
        },
        "/api/sync/epss": {
            "post": {
                "tags": ["Sync"],
                "summary": "Trigger EPSS sync",
                "description": "Start synchronization with EPSS (Exploit Prediction Scoring System).",
                "responses": {
                    "200": {"description": "Sync started"}
                }
            }
        },
        "/api/sync/status": {
            "get": {
                "tags": ["Sync"],
                "summary": "Get sync status",
                "description": "Get current synchronization status and last sync times.",
                "responses": {
                    "200": {
                        "description": "Sync status",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SyncStatus"}
                            }
                        }
                    }
                },
                "security": []
            }
        },

        # =====================================================================
        # License
        # =====================================================================
        "/api/license": {
            "get": {
                "tags": ["License"],
                "summary": "Get license info",
                "description": "Get current license status, limits, and usage.",
                "responses": {
                    "200": {
                        "description": "License information",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LicenseInfo"}
                            }
                        }
                    }
                }
            },
            "post": {
                "tags": ["License"],
                "summary": "Activate license",
                "description": "Activate a license key. Requires Super Admin.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["license_key"],
                                "properties": {
                                    "license_key": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "License activated"},
                    "400": {"description": "Invalid license key"}
                }
            }
        },
        "/api/license/installation-id": {
            "get": {
                "tags": ["License"],
                "summary": "Get installation ID",
                "description": "Get this installation's unique ID for license requests.",
                "responses": {
                    "200": {
                        "description": "Installation ID",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "installation_id": {"type": "string"},
                                        "hostname": {"type": "string"},
                                        "is_docker": {"type": "boolean"},
                                        "docker_warning": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        # =====================================================================
        # Reports
        # =====================================================================
        "/api/reports/compliance": {
            "get": {
                "tags": ["Reports"],
                "summary": "Get compliance report",
                "description": "Generate CISA BOD 22-01 compliance report. Requires Professional license.",
                "parameters": [
                    {"name": "org_id", "in": "query", "schema": {"type": "integer"}},
                    {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json", "csv", "pdf"]}}
                ],
                "responses": {
                    "200": {"description": "Compliance report"},
                    "403": {"description": "Professional license required"}
                }
            }
        },

        # =====================================================================
        # Organizations
        # =====================================================================
        "/api/organizations": {
            "get": {
                "tags": ["Organizations"],
                "summary": "List organizations",
                "description": "Get all organizations (multi-tenant support).",
                "responses": {
                    "200": {
                        "description": "Organization list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Organization"}
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "tags": ["Organizations"],
                "summary": "Create organization",
                "description": "Create a new organization. Requires Professional license for multi-org.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "description": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "201": {"description": "Organization created"},
                    "403": {"description": "License limit reached"}
                }
            }
        },

        # =====================================================================
        # Integrations
        # =====================================================================
        "/api/integrations/test": {
            "post": {
                "tags": ["Integrations"],
                "summary": "Test integration connection",
                "description": "Test connection to an issue tracker (Jira, GitHub, GitLab, etc).",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["type", "url"],
                                "properties": {
                                    "type": {"type": "string", "enum": ["jira", "github", "gitlab", "youtrack", "webhook"]},
                                    "url": {"type": "string"},
                                    "api_key": {"type": "string"},
                                    "username": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Connection successful"},
                    "400": {"description": "Connection failed"}
                }
            }
        },
        "/api/integrations/create-ticket/{vuln_id}": {
            "post": {
                "tags": ["Integrations"],
                "summary": "Create issue ticket",
                "description": "Create a ticket in configured issue tracker for a vulnerability.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["cve_id"],
                                "properties": {
                                    "cve_id": {"type": "string"},
                                    "product_ids": {"type": "array", "items": {"type": "integer"}},
                                    "priority": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Ticket created"},
                    "403": {"description": "Professional license required"}
                }
            }
        },

        # =====================================================================
        # Health Checks
        # =====================================================================
        "/api/admin/health-checks": {
            "get": {
                "tags": ["Health Checks"],
                "summary": "Get health check results",
                "description": "Returns the latest results for all health checks including database, disk, agents, sync, license, SMTP, and more.",
                "responses": {
                    "200": {
                        "description": "Health check results",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "results": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/HealthCheckResult"}
                                        },
                                        "overall_status": {"type": "string", "enum": ["ok", "warning", "critical", "error"]}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/api/admin/health-checks/run": {
            "post": {
                "tags": ["Health Checks"],
                "summary": "Run all health checks now",
                "description": "Manually trigger all enabled health checks. Returns results after completion.",
                "responses": {
                    "200": {"description": "Health checks completed"},
                    "500": {"description": "Error running health checks"}
                }
            }
        },
        "/api/admin/health-checks/settings": {
            "get": {
                "tags": ["Health Checks"],
                "summary": "Get health check settings",
                "description": "Returns global enable/disable state, notification email, and per-check enable state.",
                "responses": {
                    "200": {"description": "Health check settings"}
                }
            },
            "post": {
                "tags": ["Health Checks"],
                "summary": "Update health check settings",
                "description": "Update global toggle, notification email, and per-check enable/disable.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "enabled": {"type": "boolean", "description": "Global enable/disable"},
                                    "notify_email": {"type": "string", "description": "Email for health notifications"},
                                    "checks": {"type": "object", "description": "Per-check enable/disable map"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Settings updated"},
                    "500": {"description": "Error updating settings"}
                }
            }
        },

        # =====================================================================
        # System Notifications
        # =====================================================================
        "/api/system/notifications": {
            "get": {
                "tags": ["Notifications"],
                "summary": "Get active system notifications",
                "description": "Returns contextual notifications for the notification banner (stale data, license warnings, health issues, pending imports, etc.). Admins see all; regular users see a subset.",
                "responses": {
                    "200": {
                        "description": "System notifications",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "notifications": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id": {"type": "string"},
                                                    "level": {"type": "string", "enum": ["info", "warning", "danger", "success"]},
                                                    "icon": {"type": "string"},
                                                    "message": {"type": "string"},
                                                    "dismissible": {"type": "boolean"},
                                                    "action": {
                                                        "type": "object",
                                                        "properties": {
                                                            "label": {"type": "string"},
                                                            "url": {"type": "string"}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        # =====================================================================
        # Log Viewer (Admin)
        # =====================================================================
        "/api/admin/logs": {
            "get": {
                "tags": ["Logs"],
                "summary": "List available log files",
                "description": "Returns all available log files with sizes and last modified timestamps.",
                "responses": {
                    "200": {
                        "description": "Log file list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "log_dir": {"type": "string"},
                                        "files": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "key": {"type": "string"},
                                                    "filename": {"type": "string"},
                                                    "size": {"type": "integer"},
                                                    "modified": {"type": "string", "format": "date-time"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/api/admin/logs/{log_name}": {
            "get": {
                "tags": ["Logs"],
                "summary": "View log file contents",
                "description": "Read log file with tail behavior (newest lines first). Supports filtering by search term and log level.",
                "parameters": [
                    {"name": "log_name", "in": "path", "required": True, "schema": {"type": "string", "enum": ["application", "error", "security", "access", "audit", "performance", "ldap"]}},
                    {"name": "lines", "in": "query", "schema": {"type": "integer", "default": 200, "maximum": 5000}, "description": "Number of lines to return (from end of file)"},
                    {"name": "search", "in": "query", "schema": {"type": "string"}, "description": "Filter lines containing this string (case-insensitive)"},
                    {"name": "level", "in": "query", "schema": {"type": "string", "enum": ["ERROR", "WARNING", "INFO", "DEBUG"]}, "description": "Filter by log level"}
                ],
                "responses": {
                    "200": {
                        "description": "Log lines (newest first)",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "lines": {"type": "array", "items": {"type": "string"}},
                                        "total": {"type": "integer"},
                                        "returned": {"type": "integer"},
                                        "file_size": {"type": "integer"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/api/admin/logs/{log_name}/download": {
            "get": {
                "tags": ["Logs"],
                "summary": "Download log file",
                "description": "Download the full log file as an attachment.",
                "parameters": [
                    {"name": "log_name", "in": "path", "required": True, "schema": {"type": "string", "enum": ["application", "error", "security", "access", "audit", "performance", "ldap"]}}
                ],
                "responses": {
                    "200": {"description": "Log file download"},
                    "404": {"description": "Log file not found"}
                }
            }
        },

        # =====================================================================
        # Audit Logs
        # =====================================================================
        "/api/audit-logs": {
            "get": {
                "tags": ["Audit"],
                "summary": "Get audit log entries",
                "description": "Returns paginated audit trail of data modifications. Super admin only.",
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                    {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 50}},
                    {"name": "action", "in": "query", "schema": {"type": "string"}, "description": "Filter by action type"},
                    {"name": "resource", "in": "query", "schema": {"type": "string"}, "description": "Filter by resource type"},
                    {"name": "user_id", "in": "query", "schema": {"type": "integer"}},
                    {"name": "search", "in": "query", "schema": {"type": "string"}, "description": "Search in log messages"},
                    {"name": "start_date", "in": "query", "schema": {"type": "string", "format": "date"}},
                    {"name": "end_date", "in": "query", "schema": {"type": "string", "format": "date"}},
                    {"name": "sort", "in": "query", "schema": {"type": "string", "default": "timestamp"}},
                    {"name": "order", "in": "query", "schema": {"type": "string", "enum": ["asc", "desc"], "default": "desc"}}
                ],
                "responses": {
                    "200": {"description": "Paginated audit log entries"},
                    "403": {"description": "Super admin required"}
                }
            }
        },
        "/api/audit-logs/export": {
            "get": {
                "tags": ["Audit"],
                "summary": "Export audit logs",
                "description": "Export audit logs as CSV or JSON. Professional license required.",
                "parameters": [
                    {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["csv", "json"], "default": "csv"}},
                    {"name": "action", "in": "query", "schema": {"type": "string"}},
                    {"name": "start_date", "in": "query", "schema": {"type": "string", "format": "date"}},
                    {"name": "end_date", "in": "query", "schema": {"type": "string", "format": "date"}}
                ],
                "responses": {
                    "200": {"description": "Exported audit log data"},
                    "403": {"description": "Professional license required"}
                }
            }
        },

        # =====================================================================
        # Version Info
        # =====================================================================
        "/api/version": {
            "get": {
                "tags": ["Settings"],
                "summary": "Get application version",
                "description": "Returns SentriKat version, API version, edition, and system info.",
                "responses": {
                    "200": {"description": "Version information"}
                },
                "security": []
            }
        }
    }


def _get_schemas():
    """Define all data schemas."""
    return {
        "LoginResponse": {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "user": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "username": {"type": "string"},
                        "role": {"type": "string"}
                    }
                }
            }
        },
        "AuthStatus": {
            "type": "object",
            "properties": {
                "authenticated": {"type": "boolean"},
                "user": {"type": "object", "nullable": True},
                "auth_enabled": {"type": "boolean"}
            }
        },
        "DashboardStats": {
            "type": "object",
            "properties": {
                "total_products": {"type": "integer"},
                "total_vulnerabilities": {"type": "integer"},
                "critical_count": {"type": "integer"},
                "high_count": {"type": "integer"},
                "medium_count": {"type": "integer"},
                "low_count": {"type": "integer"},
                "kev_count": {"type": "integer", "description": "Known Exploited Vulnerabilities count"}
            }
        },
        "GroupedVulnerability": {
            "type": "object",
            "properties": {
                "vulnerability": {"$ref": "#/components/schemas/Vulnerability"},
                "affected_products": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/Product"}
                },
                "highest_priority": {"type": "string"},
                "unacknowledged_count": {"type": "integer"}
            }
        },
        "Product": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "vendor": {"type": "string"},
                "version": {"type": "string"},
                "cpe": {"type": "string", "description": "CPE (Common Platform Enumeration) identifier"},
                "organization_id": {"type": "integer"},
                "created_at": {"type": "string", "format": "date-time"}
            }
        },
        "ProductCreate": {
            "type": "object",
            "required": ["name", "vendor", "version"],
            "properties": {
                "name": {"type": "string", "example": "Apache HTTP Server"},
                "vendor": {"type": "string", "example": "Apache"},
                "version": {"type": "string", "example": "2.4.51"},
                "cpe": {"type": "string", "example": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"},
                "organization_id": {"type": "integer"}
            }
        },
        "Vulnerability": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "example": "CVE-2024-1234"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "cvss_score": {"type": "number", "format": "float"},
                "cvss_vector": {"type": "string"},
                "epss_score": {"type": "number", "format": "float", "description": "EPSS probability (0-1)"},
                "epss_percentile": {"type": "number", "format": "float"},
                "is_kev": {"type": "boolean", "description": "Is in CISA KEV catalog"},
                "kev_due_date": {"type": "string", "format": "date"},
                "published_date": {"type": "string", "format": "date-time"},
                "last_modified": {"type": "string", "format": "date-time"},
                "references": {"type": "array", "items": {"type": "string"}}
            }
        },
        "Organization": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "created_at": {"type": "string", "format": "date-time"}
            }
        },
        "AgentInventory": {
            "type": "object",
            "required": ["hostname", "products"],
            "properties": {
                "hostname": {"type": "string", "description": "Agent machine hostname"},
                "os": {"type": "string", "description": "Operating system"},
                "os_version": {"type": "string"},
                "asset_type": {"type": "string", "enum": ["server", "workstation", "container"], "default": "server"},
                "agent_version": {"type": "string"},
                "products": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "version"],
                        "properties": {
                            "name": {"type": "string"},
                            "vendor": {"type": "string"},
                            "version": {"type": "string"}
                        }
                    }
                }
            }
        },
        "AgentInventoryResponse": {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "asset_id": {"type": "integer"},
                "products_processed": {"type": "integer"},
                "vulnerabilities_found": {"type": "integer"}
            }
        },
        "AgentCommands": {
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["scan_now", "update_config", "update_available"]},
                            "payload": {"type": "object"}
                        }
                    }
                }
            }
        },
        "AgentVersion": {
            "type": "object",
            "properties": {
                "latest_version": {"type": "string"},
                "download_urls": {
                    "type": "object",
                    "properties": {
                        "linux": {"type": "string"},
                        "windows": {"type": "string"}
                    }
                },
                "changelog": {"type": "string"}
            }
        },
        "SyncStatus": {
            "type": "object",
            "properties": {
                "nvd": {
                    "type": "object",
                    "properties": {
                        "last_sync": {"type": "string", "format": "date-time"},
                        "total_cves": {"type": "integer"},
                        "is_syncing": {"type": "boolean"}
                    }
                },
                "epss": {
                    "type": "object",
                    "properties": {
                        "last_sync": {"type": "string", "format": "date-time"},
                        "is_syncing": {"type": "boolean"}
                    }
                }
            }
        },
        "LicenseInfo": {
            "type": "object",
            "properties": {
                "edition": {"type": "string", "enum": ["community", "professional"]},
                "effective_edition": {"type": "string"},
                "customer": {"type": "string"},
                "is_valid": {"type": "boolean"},
                "is_expired": {"type": "boolean"},
                "expires_at": {"type": "string", "format": "date"},
                "days_until_expiry": {"type": "integer"},
                "limits": {
                    "type": "object",
                    "properties": {
                        "max_users": {"type": "integer"},
                        "max_organizations": {"type": "integer"},
                        "max_products": {"type": "integer"},
                        "max_agents": {"type": "integer"}
                    }
                },
                "features": {"type": "array", "items": {"type": "string"}},
                "installation_id": {"type": "string"}
            }
        },
        "HealthCheckResult": {
            "type": "object",
            "properties": {
                "check_name": {"type": "string", "example": "database"},
                "category": {"type": "string", "enum": ["system", "data_sync", "agents"]},
                "status": {"type": "string", "enum": ["ok", "warning", "critical", "error"]},
                "message": {"type": "string"},
                "value": {"type": "string", "description": "Short display value (e.g. '42ms', '95%')"},
                "details": {"type": "object", "description": "Additional structured data"},
                "checked_at": {"type": "string", "format": "date-time"}
            }
        }
    }


# Swagger UI HTML template
SWAGGER_UI_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentriKat API Documentation</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { font-size: 2em; }
        .header-bar {
            background: #1a1a2e;
            color: white;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .header-bar img { height: 32px; }
        .header-bar h1 { margin: 0; font-size: 1.3em; font-weight: 500; }
        .header-bar a {
            color: #64b5f6;
            text-decoration: none;
            margin-left: auto;
        }
        .export-btn {
            background: #2196f3;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .export-btn:hover { background: #1976d2; }
    </style>
</head>
<body>
    <div class="header-bar">
        <img src="/static/images/favicon-128x128.png" alt="SentriKat">
        <h1>SentriKat API Documentation</h1>
        <button class="export-btn" onclick="exportSpec()">Export OpenAPI Spec</button>
        <a href="/">← Back to Dashboard</a>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/api/spec.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
                deepLinking: true,
                showExtensions: true,
                showCommonExtensions: true
            });
        };

        function exportSpec() {
            window.open('/api/spec.json', '_blank');
        }
    </script>
</body>
</html>
"""


@api_docs_bp.route('/api/docs')
def swagger_ui():
    """Serve Swagger UI for API documentation."""
    return render_template_string(SWAGGER_UI_TEMPLATE)


@api_docs_bp.route('/api/spec.json')
def openapi_spec():
    """Serve OpenAPI 3.0 specification as JSON."""
    return jsonify(get_openapi_spec())


@api_docs_bp.route('/api/spec.yaml')
def openapi_spec_yaml():
    """Serve OpenAPI 3.0 specification as YAML."""
    import yaml
    spec = get_openapi_spec()
    yaml_content = yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return yaml_content, 200, {'Content-Type': 'text/yaml; charset=utf-8'}
