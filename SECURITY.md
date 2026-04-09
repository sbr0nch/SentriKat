# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest| :x:                |

We recommend always running the latest version of SentriKat.

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in SentriKat, please report it responsibly.

### How to Report

**Email:** security@sentrikat.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment:** Within 48 hours of your report
- **Initial Assessment:** Within 5 business days
- **Resolution Timeline:** Critical vulnerabilities within 7 days, others within 30 days
- **Credit:** We will credit you in the release notes (unless you prefer anonymity)

### Scope

In scope:
- SentriKat application code (this repository)
- Authentication and authorization bypasses
- Cross-tenant data leaks (SaaS mode)
- SQL injection, XSS, CSRF, SSRF
- Agent communication protocol vulnerabilities
- License validation bypasses

Out of scope:
- Vulnerabilities in third-party dependencies (report to the dependency maintainer)
- Social engineering attacks
- Physical security
- Denial of service (unless it affects data integrity)

### Safe Harbor

We will not take legal action against security researchers who:
- Act in good faith
- Avoid accessing or modifying other users' data
- Do not publicly disclose the vulnerability before we have had a chance to fix it
- Do not exploit the vulnerability beyond what is necessary to demonstrate it

## Security Best Practices

### On-Premise Deployment
- Always use HTTPS (TLS 1.2+)
- Change default credentials immediately after installation
- Keep PostgreSQL on an internal network (not exposed to the internet)
- Rotate the `SECRET_KEY` and `ENCRYPTION_KEY` periodically
- Enable and configure firewall rules to restrict access
- Review audit logs regularly

### SaaS Usage
- Enable two-factor authentication (2FA) for all admin accounts
- Use strong, unique passwords
- Review user access lists regularly
- Configure alert notification recipients
- Monitor the audit log for suspicious activity
