# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x | Yes |

## Reporting a Vulnerability

We take security seriously at SentriKat. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email**: sotadenis94@gmail.com

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity

| Severity | Target Resolution |
|----------|-------------------|
| Critical | 24-72 hours |
| High | 7 days |
| Medium | 30 days |
| Low | Next release |

### Responsible Disclosure

- Please do not publicly disclose the vulnerability until we have addressed it
- We will credit you in our release notes (unless you prefer to remain anonymous)
- We do not currently offer a bug bounty program

## Security Best Practices

When deploying SentriKat:

1. **Use HTTPS** in production (set `FORCE_HTTPS=true`)
2. **Generate unique keys** for `SECRET_KEY` and `ENCRYPTION_KEY`
3. **Never commit** `.env` files to version control
4. **Regularly update** to the latest version
5. **Backup your database** regularly using the provided script
6. **Use strong passwords** for admin and LDAP accounts

## Security Features

SentriKat includes:

- Encrypted credential storage (Fernet encryption)
- CSRF protection
- Secure session handling
- Input validation and sanitization
- SQL injection prevention via SQLAlchemy ORM
- Rate limiting on API endpoints

---

*Last updated: January 2026*
