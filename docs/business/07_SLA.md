# SENTRIKAT - SERVICE LEVEL AGREEMENT (SLA)

**Effective Date:** February 1, 2026
**Version:** 1.0

---

## 1. OVERVIEW

This Service Level Agreement ("SLA") is part of the Terms of Service between SentriKat and Customer. It defines the support levels and response times for each subscription tier.

---

## 2. SUPPORT TIERS

### 2.1 Demo Edition (Free)

| Metric | Level |
|--------|-------|
| Support Channel | Community Forum, Documentation |
| Response Time | Best Effort |
| Support Hours | N/A |
| SLA Credits | Not Available |

### 2.2 Professional Edition

| Metric | Level |
|--------|-------|
| Support Channel | Email |
| Response Time | 2 Business Days |
| Support Hours | 9 AM - 6 PM CET, Mon-Fri |
| SLA Credits | Not Available |

### 2.3 Business Edition

| Metric | Level |
|--------|-------|
| Support Channel | Email, Phone |
| Response Time | See Priority Matrix |
| Support Hours | 8 AM - 8 PM CET, Mon-Fri |
| SLA Credits | Available |
| Uptime Target | 99.5% (self-hosted N/A) |

### 2.4 Enterprise Edition

| Metric | Level |
|--------|-------|
| Support Channel | Email, Phone, On-Site |
| Response Time | See Priority Matrix |
| Support Hours | 24/7/365 |
| SLA Credits | Available |
| Uptime Target | 99.9% (self-hosted N/A) |
| Dedicated TAM | Yes |

---

## 3. PRIORITY DEFINITIONS

### P1 - Critical

**Definition:** Complete system outage. Core functionality unavailable. No workaround.

**Examples:**
- Application won't start
- Database corruption
- Authentication completely broken
- All agents unable to report

### P2 - High

**Definition:** Major feature unavailable. Significant impact. Limited workaround.

**Examples:**
- Specific integration failure (Jira, LDAP)
- Email alerts not sending
- Reports not generating
- Agent sync failing for some endpoints

### P3 - Medium

**Definition:** Feature partially impaired. Workaround available.

**Examples:**
- UI display issues
- Slow performance
- Non-critical feature bug
- Documentation errors

### P4 - Low

**Definition:** Minor issue. No business impact. Enhancement request.

**Examples:**
- Feature requests
- Cosmetic issues
- General questions
- Training requests

---

## 4. RESPONSE TIME MATRIX

### Business Edition

| Priority | Initial Response | Update Frequency | Target Resolution |
|----------|------------------|------------------|-------------------|
| P1 | 4 hours | Every 2 hours | 8 hours |
| P2 | 8 hours | Daily | 2 business days |
| P3 | 1 business day | Weekly | 5 business days |
| P4 | 2 business days | As needed | Best effort |

### Enterprise Edition

| Priority | Initial Response | Update Frequency | Target Resolution |
|----------|------------------|------------------|-------------------|
| P1 | 1 hour | Every hour | 4 hours |
| P2 | 4 hours | Every 4 hours | 1 business day |
| P3 | 8 hours | Daily | 3 business days |
| P4 | 1 business day | Weekly | Best effort |

---

## 5. SUPPORT PROCESS

### 5.1 Submitting Tickets

**Email:** support@sentrikat.com
**Subject Format:** [PRIORITY] - Brief Description
**Required Information:**
- Company name
- License ID
- SentriKat version
- Issue description
- Steps to reproduce
- Error logs (if applicable)
- Screenshots (if applicable)

### 5.2 Priority Assignment

- Customer may suggest priority
- SentriKat confirms or adjusts based on definitions
- Priority may be upgraded/downgraded as investigation proceeds

### 5.3 Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | Support Team | Initial triage |
| L2 | Senior Engineer | Complex issues |
| L3 | Development Team | Code changes required |
| Executive | Management | Customer request, major incident |

To escalate, reply to ticket with "ESCALATE" or call support line.

---

## 6. SLA CREDITS (Business & Enterprise)

### 6.1 Eligibility

SLA credits apply when SentriKat fails to meet response time commitments, provided:
- Issue is caused by SentriKat software defect
- Customer submitted ticket with required information
- Customer is not in breach of agreement

### 6.2 Credit Calculation

| Missed SLA | Credit |
|------------|--------|
| Response time exceeded by 100% | 5% of monthly fee |
| Response time exceeded by 200% | 10% of monthly fee |
| Resolution time exceeded by 100% | 5% of monthly fee |
| Resolution time exceeded by 200% | 10% of monthly fee |

**Maximum monthly credit:** 25% of monthly subscription fee

### 6.3 Claiming Credits

- Request credit within 30 days of incident
- Email: billing@sentrikat.com
- Include ticket number and missed SLA details
- Credits applied to next invoice

### 6.4 Exclusions

Credits do NOT apply for:
- Issues caused by customer's infrastructure
- Third-party software/hardware failures
- Customer modifications to the Software
- Force majeure events
- Scheduled maintenance (notified 48+ hours in advance)
- Demo or Professional editions

---

## 7. MAINTENANCE WINDOWS

### 7.1 Scheduled Maintenance

- **Notification:** 48 hours minimum advance notice
- **Preferred Window:** Sundays 02:00-06:00 UTC
- **Maximum Duration:** 4 hours per month

### 7.2 Emergency Maintenance

For critical security patches:
- Best effort notification
- Prioritize security over notification
- Post-incident communication within 24 hours

---

## 8. SELF-HOSTED CONSIDERATIONS

Since SentriKat is self-hosted software:

### 8.1 Customer Responsibilities

- Server availability and uptime
- Database availability and backups
- Network connectivity
- Security hardening
- Software updates

### 8.2 SentriKat Responsibilities

- Software functionality as documented
- Security patches and updates
- Technical support as per this SLA
- Documentation accuracy

### 8.3 Uptime SLA Applicability

- Uptime targets (99.5%, 99.9%) apply to SentriKat's support systems, not customer's installation
- Uptime for managed/hosted offerings (future) will have separate SLA

---

## 9. REPORTING

### 9.1 Business Edition

- Monthly support summary (on request)
- Quarterly review meeting (on request)

### 9.2 Enterprise Edition

- Weekly ticket status report
- Monthly SLA compliance report
- Quarterly business review
- Annual executive review

---

## 10. REVISION HISTORY

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Feb 2026 | Initial release |

---

**BY USING SENTRIKAT SUPPORT SERVICES, YOU ACKNOWLEDGE THAT YOU HAVE READ AND AGREE TO THIS SLA.**

---

*Last Updated: February 2026*
