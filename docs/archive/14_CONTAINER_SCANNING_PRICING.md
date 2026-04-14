# SENTRIKAT - CONTAINER SCANNING BUSINESS MODEL & PRICING

---

## THE KEY QUESTION: How Do We Charge for This?

### Recommendation: INCLUDE IT IN THE EXISTING AGENT LICENSE (No Extra Charge)

**Container scanning should NOT be a separate add-on.** Here's why:

---

## PRICING MODEL: SAME AGENT, SAME LICENSE

### How It Works

1. A customer has an endpoint (server, workstation) with a SentriKat agent
2. That agent already counts as 1 agent in their license
3. If that endpoint also runs Docker, the agent scans those images too
4. **No additional agent slot consumed** — it's the same machine, same agent

### Why This Is the Right Call

| Reason | Detail |
|--------|--------|
| **No friction** | Customer doesn't need to think about it — it just works |
| **Competitive edge** | Tenable/Qualys charge extra for container scanning modules |
| **Adoption driver** | More features at the same price = more reasons to choose SentriKat |
| **Zero incremental cost** | Trivy is free (Apache-2.0), runs locally, no API fees |
| **Retention** | Customers get more value → less likely to churn |
| **Simplicity** | Our pricing stays simple: per-agent, not per-feature |

### What Competitors Charge

| Competitor | Container Scanning Cost |
|-----------|------------------------|
| Tenable Cloud Security | Separate product, $10,000+/year |
| Qualys Container Security | Separate module, custom pricing |
| Rapid7 InsightCloudSec | Separate product, custom pricing |
| Snyk Container | $25/dev/month + per-test limits |
| **SentriKat** | **Included in Professional Edition** |

### The Marketing Message

> "SentriKat Professional includes container image scanning at no extra cost.
> Your agents automatically detect Docker and scan every image for vulnerabilities.
> Competitors charge $10,000+/year for this as an add-on. We include it."

---

## PRICING TIERS (UPDATED)

### Demo Edition (Free)
- 1 user, 1 organization, 50 products, 5 agents
- **Container scanning: YES** (limited to 5 agents = 5 endpoints)
- This lets prospects evaluate the feature without paying

### Professional Edition (EUR 2,499/year)
- Unlimited users, organizations, products
- 25 agent slots included
- **Container scanning: YES, unlimited images per agent**
- LDAP, SAML, webhooks, email alerts, Jira, backup/restore

### Agent Packs (Add-ons)
- +25 agents: EUR 699/year
- +50 agents: EUR 1,199/year
- +100 agents: EUR 1,999/year
- Unlimited agents: EUR 3,499/year
- **Container scanning included with every agent** — no separate SKU

---

## WHAT COUNTS AS AN "AGENT"?

### Current Model (No Change)
An "agent" = one unique endpoint (identified by `agent_id` or `hostname + organization`).

### Container Scanning Impact
- Same endpoint running Docker → **still 1 agent**
- 1 server with 50 Docker images → **still 1 agent** (the images aren't separate agents)
- Agent scans both installed software AND container images

### When It Could Count Extra (Future Consideration)
If a customer submits container scans via the **CI/CD pipeline API** (without a deployed agent), we could:
- Count each unique CI/CD integration as 1 "agent slot"
- Or offer a separate "CI/CD scanning" add-on

This is a future decision — for now, all scanning is agent-based.

---

## REVENUE IMPACT ANALYSIS

### Scenario: 100-Endpoint Customer

**Before container scanning:**
- Value proposition: "Track CISA KEV vulns across 100 endpoints"
- Price: EUR 2,499/year + EUR 1,999/year (100 agents) = EUR 4,498/year
- Competitor alternative: Tenable at ~$25,000/year

**After container scanning:**
- Value proposition: "Track CISA KEV vulns across 100 endpoints AND all their Docker images"
- Price: EUR 4,498/year (SAME)
- Competitor alternative: Tenable + Tenable Cloud Security at ~$35,000+/year

**Delta for SentriKat:** Same revenue, significantly stronger competitive position.
**Delta for customer:** 10x more value at the same price.

### Why Not Charge More?

We could charge for container scanning separately (e.g., +EUR 999/year), but:

1. **Adoption barrier** — customers may skip it, reducing our platform stickiness
2. **Pricing complexity** — our strength is simple, predictable pricing
3. **Market timing** — we're entering this market late; we need to win fast
4. **Incremental cost is $0** — Trivy is free, scans run on the customer's hardware

The right strategy is to use container scanning as a **competitive weapon**, not a revenue line.

---

## FUTURE MONETIZATION OPPORTUNITIES

Once container scanning is established, we can monetize adjacent features:

| Feature | When | Model |
|---------|------|-------|
| **SBOM export** (CycloneDX/SPDX) | Q3 2026 | Included in Professional |
| **CI/CD pipeline scanning** | Q3 2026 | Included or small add-on |
| **Container compliance reports** | Q4 2026 | Included in Professional |
| **Kubernetes cluster scanning** | Q1 2027 | Professional + Enterprise tier |
| **Registry scanning** (scan images in Docker Hub, ECR, etc.) | Q2 2027 | Enterprise tier or add-on |
| **Runtime protection** (real-time container monitoring) | Q3 2027 | Enterprise tier (new product?) |

---

## IMPLEMENTATION NOTES FOR LICENSE SERVER

### No License Changes Needed

The current licensing system (`app/licensing.py`) checks:
- `max_agents` — number of unique agent endpoints
- Container scanning doesn't create new agents; it enriches existing ones
- No new license feature flag needed

### Future: Feature Flag for Enterprise-Only Capabilities

If we later add features like **registry scanning** or **Kubernetes cluster scanning** that go beyond endpoint-based scanning, we'd add:

```python
# In licensing.py
'container_registry_scanning': edition == 'enterprise',
'kubernetes_scanning': edition == 'enterprise',
```

But for now: no changes to the licensing system.

---

*Document Version: 1.0 — February 2026*
