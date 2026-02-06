# SENTRIKAT - PRODUCT ROADMAP
## 2026-2028 Development Plan

---

**Document Version:** 1.0
**Last Updated:** February 2026
**Status:** Active Development

---

## ROADMAP OVERVIEW

```
2026 Q1    2026 Q2    2026 Q3    2026 Q4    2027 Q1    2027 Q2    2027+
   │          │          │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼          ▼          ▼
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
│ v1.0 │  │ v1.1 │  │ v1.2 │  │ v2.0 │  │ v2.1 │  │ v2.2 │  │ v3.0 │
│      │  │      │  │      │  │      │  │      │  │      │  │      │
│Launch│  │Polish│  │Scale │  │Enter-│  │AI/ML │  │Mobile│  │Plat- │
│ MVP  │  │ UX   │  │ Perf │  │prise │  │      │  │      │  │form  │
└──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘
```

---

## Q1 2026 - v1.0 "FOUNDATION" (Current)

### Status: ✅ COMPLETED

| Feature | Status | Notes |
|---------|--------|-------|
| Core vulnerability management | ✅ Done | CISA KEV, NVD |
| Push agents (Windows/Linux) | ✅ Done | Auto-discovery |
| Multi-tenant architecture | ✅ Done | RBAC |
| LDAP/AD integration | ✅ Done | User sync |
| SAML SSO | ✅ Done | Okta, Azure AD |
| Email alerts | ✅ Done | SMTP, templates |
| Webhooks | ✅ Done | Slack, Teams, Discord |
| Jira integration | ✅ Done | Cloud + Server |
| Licensing system | ✅ Done | RSA signed, hardware-locked |
| CI/CD pipeline | ✅ Done | GitHub Actions |
| Customer portal | ✅ Done | SentriKat-web |

---

## Q2 2026 - v1.1 "POLISH"

### Goals
- Improve user experience based on early feedback
- Add missing "table stakes" features
- Bug fixes and stability improvements

### Planned Features

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| Skip initial sync button | High | 1 day | Allow skipping CISA sync during setup |
| Bulk CVE acknowledgement | High | 2 days | Acknowledge multiple CVEs at once |
| Dashboard customization | Medium | 1 week | Widget-based dashboard |
| Export to Excel | High | 3 days | XLSX export for reports |
| macOS agent | High | 1 week | Homebrew/pkgutil inventory |
| Improved CPE matching | High | 1 week | ML-assisted product matching |
| Dark mode | Medium | 3 days | UI theme toggle |
| Audit log export | Medium | 2 days | CSV/JSON export |
| Multi-language support | Low | 2 weeks | i18n framework |

### Technical Debt
- [ ] Increase Gunicorn timeout for large syncs
- [ ] Add Redis caching for dashboard
- [ ] Optimize N+1 queries in reports
- [ ] Add comprehensive test coverage

---

## Q3 2026 - v1.2 "SCALE"

### Goals
- Handle enterprise workloads (10,000+ agents)
- Improve performance and reliability
- Add features for large organizations

### Planned Features

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| PostgreSQL read replicas | High | 2 weeks | Database scaling |
| Redis caching layer | High | 1 week | Dashboard performance |
| Agent groups/tags | High | 1 week | Organize agents |
| Scheduled maintenance windows | Medium | 1 week | Pause alerts during maintenance |
| Custom CVE rules | Medium | 2 weeks | User-defined matching rules |
| Vulnerability exceptions | High | 1 week | Global exception rules |
| Asset discovery scan | Medium | 2 weeks | Network scanning (optional) |
| Container image scanning | Medium | 3 weeks | Docker/K8s integration |
| SBOM import | Medium | 2 weeks | CycloneDX, SPDX |

### Infrastructure
- [ ] Kubernetes Helm charts
- [ ] AWS/Azure/GCP marketplace listings
- [ ] High-availability documentation
- [ ] Disaster recovery procedures

---

## Q4 2026 - v2.0 "ENTERPRISE"

### Goals
- Enterprise-ready features for large organizations
- Compliance certifications
- Advanced reporting

### Planned Features

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| SOC 2 Type II compliance | High | Ongoing | Certification |
| Custom RBAC roles | High | 2 weeks | Fine-grained permissions |
| Hierarchical organizations | High | 3 weeks | Parent/child orgs |
| SSO enforcement | Medium | 1 week | Require SSO for all users |
| Advanced audit logging | High | 2 weeks | SIEM integration |
| Custom branding (white-label) | Medium | 1 week | Full customization |
| API rate limiting per customer | Medium | 1 week | Fair use policies |
| Vulnerability SLA tracking | High | 2 weeks | Time-to-remediation metrics |
| Executive dashboards | Medium | 2 weeks | C-level reporting |
| Scheduled compliance reports | High | 2 weeks | Auto-generate PDF reports |

### Compliance
- [ ] SOC 2 Type II audit
- [ ] GDPR documentation
- [ ] HIPAA BAA template
- [ ] FedRAMP preparation

---

## Q1 2027 - v2.1 "INTELLIGENCE"

### Goals
- AI/ML-powered features
- Predictive analytics
- Automation

### Planned Features

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| AI-powered risk scoring | High | 4 weeks | Beyond CVSS/EPSS |
| Automated remediation suggestions | High | 3 weeks | Based on environment |
| Exploit likelihood prediction | Medium | 3 weeks | Custom ML model |
| Vulnerability trending | Medium | 2 weeks | Predict future vulns |
| Smart alerting | High | 2 weeks | Reduce alert fatigue |
| Auto-CPE mapping | High | 3 weeks | ML-based product matching |
| Threat intelligence feeds | Medium | 4 weeks | STIX/TAXII integration |
| Attack surface visualization | Medium | 3 weeks | Graph-based view |

---

## Q2 2027 - v2.2 "MOBILE & INTEGRATIONS"

### Goals
- Mobile app for on-the-go access
- Expanded integration ecosystem
- Self-service automation

### Planned Features

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| iOS mobile app | High | 6 weeks | Dashboard, alerts |
| Android mobile app | High | 6 weeks | Dashboard, alerts |
| ServiceNow integration | High | 3 weeks | ITSM tickets |
| Splunk integration | Medium | 2 weeks | Log forwarding |
| PagerDuty integration | Medium | 1 week | Incident management |
| Microsoft Defender sync | Medium | 3 weeks | Vuln import |
| Tenable import | Medium | 2 weeks | Migration path |
| Qualys import | Medium | 2 weeks | Migration path |
| REST API v2 | High | 4 weeks | GraphQL support |
| Webhook templates | Medium | 1 week | Customizable payloads |

---

## 2027+ - v3.0 "PLATFORM"

### Vision
Transform SentriKat from a product to a platform

### Planned Capabilities

| Capability | Description |
|------------|-------------|
| Marketplace | Third-party integrations and plugins |
| SDK | Build custom integrations |
| Multi-cloud management | AWS, Azure, GCP asset discovery |
| IoT/OT support | Industrial device inventory |
| Vulnerability bounty integration | HackerOne, Bugcrowd |
| Compliance frameworks | NIST, CIS, ISO 27001 mapping |
| Automated patching | Integration with patch management |
| Security posture scoring | Overall security health metric |

---

## FEATURE REQUEST BACKLOG

### Community Requested
- [ ] OpenID Connect support
- [ ] Duo 2FA integration
- [ ] Slack bot for queries
- [ ] Terraform provider
- [ ] Ansible collection
- [ ] Prometheus metrics endpoint
- [ ] Custom notification templates
- [ ] Vulnerability exclusion by regex
- [ ] Agent silent install mode
- [ ] Proxy-only agent mode

### Technical Improvements
- [ ] GraphQL API
- [ ] WebSocket real-time updates
- [ ] Full-text search (Elasticsearch)
- [ ] Async task queue (Celery/RQ)
- [ ] Microservices architecture (future)

---

## VERSION SUPPORT POLICY

| Version | Release | End of Support | Notes |
|---------|---------|----------------|-------|
| v1.0.x | Q1 2026 | Q1 2027 | 12 months |
| v1.1.x | Q2 2026 | Q2 2027 | 12 months |
| v1.2.x | Q3 2026 | Q3 2027 | 12 months |
| v2.0.x | Q4 2026 | Q4 2028 | 24 months (LTS) |

- **Standard releases**: 12 months security updates
- **LTS releases**: 24 months security updates
- **Critical patches**: Backported to all supported versions

---

## INVESTMENT IMPACT

### With Funding ($X)

| Area | Impact |
|------|--------|
| Development Speed | 2-3x faster feature delivery |
| Team Size | +2-4 engineers |
| Quality | Dedicated QA, security audit |
| Marketing | Faster customer acquisition |

### Without Funding

| Area | Impact |
|------|--------|
| Timeline | 2x longer for each milestone |
| Features | Prioritize revenue-generating only |
| Quality | Founder-only testing |
| Growth | Organic only, slower |

---

## CHANGE LOG

| Date | Version | Changes |
|------|---------|---------|
| Feb 2026 | 1.0 | Initial roadmap |

---

*This roadmap is subject to change based on customer feedback, market conditions, and resource availability.*
