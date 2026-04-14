# SENTRIKAT - PRODUCT ROADMAP
## 2026-2028 Development Plan

---

**Document Version:** 1.2
**Last Updated:** April 2026 (post Sprint 4 + Sprint 5)
**Status:** Active Development — Sprint 4 + 5 shipped

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

| Feature | Priority | Effort | Status | Description |
|---------|----------|--------|--------|-------------|
| Skip initial sync button | High | 1 day | Planned | Allow skipping CISA sync during setup |
| Bulk CVE acknowledgement | High | 2 days | ✅ Done | Acknowledge multiple CVEs at once |
| Dashboard customization | Medium | 1 week | ✅ Done | Two-column widget layout, dual Y-axis chart, clickable priority cards |
| Export to Excel | High | 3 days | Planned | XLSX export for reports |
| macOS agent | High | 1 week | Planned | Homebrew/pkgutil inventory |
| Improved CPE matching | High | 1 week | ✅ Partial | Assign CPE shortcut, NVD search auto-populate, hint banner |
| Dark mode | Medium | 3 days | ✅ Done | Full dark mode with chart awareness |
| Audit log export | Medium | 2 days | Planned | CSV/JSON export |
| Multi-language support | Low | 2 weeks | Planned | i18n framework |
| Multi-tracker support | High | 3 days | ✅ Done | Multiple issue trackers simultaneously |
| Settings consolidation | Medium | 2 days | ✅ Done | 12→6 grouped tabs with visual separators |
| Software Overview | Medium | 3 days | ✅ Done | Cross-endpoint dedup view, version sprawl detection |
| Security hardening | High | 2 days | ✅ Done | XSS escaping, markdown injection sanitization |

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

| Feature | Priority | Effort | Status | Description |
|---------|----------|--------|--------|-------------|
| PostgreSQL read replicas | High | 2 weeks | Planned | Database scaling |
| Redis caching layer | High | 1 week | Planned | Dashboard performance |
| Agent groups/tags | High | 1 week | Planned | Organize agents |
| Scheduled maintenance windows | Medium | 1 week | Planned | Pause alerts during maintenance |
| Custom CVE rules | Medium | 2 weeks | Planned | User-defined matching rules |
| Vulnerability exceptions | High | 1 week | ✅ Done (Sprint 4) | Risk Exception Management with justification + expiry |
| Asset discovery scan | Medium | 2 weeks | Planned | Network scanning (optional) |
| Container image scanning | Medium | 3 weeks | ✅ Done (Sprint 2) | Docker/Podman + Trivy |
| SBOM import | Medium | 2 weeks | Partial | SBOM **export** shipped (CycloneDX/SPDX/STIX); import still planned |

### Sprint 4 (April 2026) — ✅ SHIPPED

| Feature | Status | Notes |
|---|---|---|
| Remediation Assignments page | ✅ Done | Full CRUD with filters, pagination, inline status change, modal detail/edit |
| Multi-tracker integration | ✅ Done | Jira / YouTrack / GitHub / GitLab / Webhook with `tracker_issue_key/url/type` |
| Email notifications (assignments) | ✅ Done | Throttled (max 1/assignment/hour, only created+resolved, only assignee) |
| SBOM Export CycloneDX 1.5 | ✅ Done | `app/sbom_export.py`, JSON bundle |
| SBOM Export SPDX 2.3 | ✅ Done | JSON bundle |
| Risk Exception Management | ✅ Done | Model + CRUD + UI panel + modal |
| Agent Delta Scan + Gzip | ✅ Done | SHA256 hash detection on Linux/macOS/Windows (~90% bandwidth saving) |
| Agent Store-and-Forward | ✅ Done | Spool dir, max 50 files, chronological replay |
| Product Aliases | ✅ Done | Vendor/product disambiguation CRUD |
| Hardening | ✅ Done | Zip bomb protection, rate limits, licensing gates, composite DB indexes, Prometheus telemetry |

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

| Feature | Priority | Effort | Status | Description |
|---------|----------|--------|--------|-------------|
| SOC 2 Type II compliance | High | Ongoing | Planned | Org certification (separate from the SOC 2 gap analysis report shipped in Sprint 5) |
| Custom RBAC roles | High | 2 weeks | Planned | Fine-grained permissions |
| Hierarchical organizations | High | 3 weeks | Planned | Parent/child orgs |
| SSO enforcement | Medium | 1 week | Planned | Require SSO for all users |
| Advanced audit logging | High | 2 weeks | Planned | SIEM integration |
| Custom branding (white-label) | Medium | 1 week | ✅ Done | Full customization |
| API rate limiting per customer | Medium | 1 week | ✅ Done (Sprint 4) | Per-endpoint rate limits with org scoping |
| Vulnerability SLA tracking | High | 2 weeks | ✅ Done (Sprint 4) | SLA policies + due_date computation + `/api/sla/compliance` |
| Executive dashboards | Medium | 2 weeks | Planned | C-level reporting |
| Scheduled compliance reports | High | 2 weeks | ✅ Done (Sprint 5) | PCI-DSS / ISO 27001 / SOC 2 + existing CISA / NIS2 in JSON & PDF with HMAC integrity |

### Sprint 5 (April 2026) — ✅ SHIPPED

| Feature | Status | Notes |
|---|---|---|
| Vulnerability Trending Dashboard | ✅ Done | Chart.js widget on dashboard, 3 views (total / by severity / open vs resolved) consuming `/api/vulnerabilities/trends` |
| STIX 2.1 Export | ✅ Done | `app/sbom_export.py` — vulnerability SDO + software SCO + relationship SRO |
| Patch Tuesday Automation | ✅ Done | `patch_tuesday_digest_job` scheduled 2nd Wed/month at 09:00, manual trigger via `/api/reports/patch-tuesday/trigger?dry_run=true` |
| PCI-DSS v4.0 Gap Analysis Report | ✅ Done | `app/compliance_reports.py` — Req 6.3, 11.3 mapping with PASS/PARTIAL/FAIL/N-A |
| ISO/IEC 27001:2022 Gap Analysis Report | ✅ Done | Annex A.8.8, A.8.16, A.5.24 |
| SOC 2 Gap Analysis Report | ✅ Done | CC7.1, CC7.2, CC7.4, CC6.6 |
| Compliance integrity block | ✅ Done | SHA256 + HMAC over canonical JSON, embedded in every report |

### Sprint 6 (planned, Q3 2026 — proposed scope)

| Feature | Priority | Effort | Description |
|---|---|---|---|
| Cloud asset discovery (AWS / Azure / GCP) | High | 4 weeks | Native cloud provider integration for cloud-native asset inventory |
| Asset graph view | Medium | 2 weeks | Visualize relationships: Org → Asset → Product → Vulnerability → Assignment |
| Advanced scheduled reports | Medium | 2 weeks | Custom report builder, multi-recipient delivery, branded templates |
| SBOM **import** (close the loop) | Medium | 1 week | Accept CycloneDX/SPDX bundles as inventory source |
| Webhook-based incoming Patch Tuesday | Low | 1 week | Listen to MSRC live feed for real-time digest |

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
| Apr 2026 | 1.2 | Sprint 4 + Sprint 5 marked as shipped (15 features). Added Sprint 6 proposed scope (cloud asset discovery, asset graph, SBOM import). Updated status columns for Q3/Q4 features that landed early. |

---

*This roadmap is subject to change based on customer feedback, market conditions, and resource availability.*
