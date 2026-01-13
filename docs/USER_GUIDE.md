# SentriKat User Guide

This guide covers daily operations for SentriKat users, including viewing vulnerabilities, managing products, and generating reports.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Dashboard Overview](#dashboard-overview)
- [Viewing Vulnerabilities](#viewing-vulnerabilities)
- [Managing Products](#managing-products)
- [Acknowledging Vulnerabilities](#acknowledging-vulnerabilities)
- [Generating Reports](#generating-reports)
- [Syncing Vulnerabilities](#syncing-vulnerabilities)
- [User Roles](#user-roles)
- [Tips & Best Practices](#tips--best-practices)

---

## Getting Started

### Logging In

1. Navigate to your SentriKat URL (e.g., `https://sentrikat.company.com`)
2. Enter your credentials:
   - **Local Account**: Username and password
   - **LDAP Account**: Your corporate username and password
3. Click **Login**

### First Login

On your first login:
1. You may be prompted to update your profile
2. Verify your email address is correct
3. Familiarize yourself with the dashboard

### Navigation

The main navigation bar contains:

| Menu Item | Description |
|-----------|-------------|
| **Dashboard** | Main vulnerability overview |
| **Products** | Manage tracked software/services |
| **Vulnerabilities** | Full vulnerability list with advanced filters |
| **Reports** | Generate PDF reports |
| **Sync Now** | Manually trigger CISA KEV sync |
| **Administration** | Admin panel (if authorized) |

---

## Dashboard Overview

The dashboard provides a quick overview of your vulnerability status.

### Statistics Cards

| Card | Description |
|------|-------------|
| **Total KEV** | Total vulnerabilities in CISA KEV catalog |
| **Matching** | Vulnerabilities affecting your products |
| **Unacknowledged** | Vulnerabilities not yet reviewed |
| **Products** | Number of active tracked products |

### Recent Vulnerabilities

Shows the most recent vulnerabilities matching your products:
- CVE ID and name
- Affected vendor/product
- Due date
- Match reason

### Quick Actions

- **View All**: See complete vulnerability list
- **Add Product**: Add new software to track
- **Sync Now**: Update vulnerability data

---

## Viewing Vulnerabilities

### Vulnerability List

Navigate to **Vulnerabilities** to see all matching CVEs.

### Filtering Options

| Filter | Description |
|--------|-------------|
| **Search** | Search by CVE ID, vendor, product, or description |
| **Vendor** | Filter by specific vendor |
| **Product** | Filter by specific product |
| **Severity** | Filter by CVSS severity (Critical, High, Medium, Low) |
| **Ransomware** | Show only ransomware-related vulnerabilities |
| **Status** | Acknowledged / Unacknowledged |
| **Date Range** | Filter by date added or due date |

### Sorting

Click column headers to sort by:
- CVE ID
- Vendor
- Product
- Date Added
- Due Date
- Severity

### Vulnerability Details

Click on a vulnerability to see:

| Field | Description |
|-------|-------------|
| **CVE ID** | Unique vulnerability identifier |
| **Vendor/Product** | Affected software |
| **Description** | Detailed vulnerability description |
| **Required Action** | CISA recommended remediation |
| **Due Date** | Deadline for remediation |
| **Date Added** | When added to CISA KEV |
| **Ransomware** | If used in ransomware campaigns |
| **CVSS Score** | Severity score (if available) |
| **References** | Links to additional information |

### Match Information

Each vulnerability shows why it matched your products:
- **CPE Match** (High Confidence): Product matched via CPE identifier from NVD
- **CPE Inference** (Medium Confidence): CPE-based matching without exact version data
- **Vendor+Product Match** (Medium Confidence): Vendor and product names matched
- **Keyword Match** (Low Confidence): Custom keyword matched
- **Version Match**: Indicates if specific version is affected

**Match Confidence Levels:**
| Level | Description |
|-------|-------------|
| **High** | Exact CPE match with version verification |
| **Medium** | CPE inference or vendor+product name match |
| **Low** | Keyword-based matching only |

---

## Managing Products

### Viewing Products

Navigate to **Products** to see all tracked software.

### Adding a Product

Click **Add Product** to open the product dialog. There are two methods to add products:

#### Method 1: NVD Database Search (Recommended)

The primary and most accurate way to add products is by searching the NIST National Vulnerability Database (NVD), which contains over 800,000 software products with standardized CPE (Common Platform Enumeration) identifiers.

1. Click **Add Product**
2. In the **Search NVD Database** section at the top, type your search query (e.g., "apache tomcat", "microsoft windows")
3. Browse the search results showing matching products
4. Click on a product to select it
5. The vendor and product fields are auto-filled with proper naming
6. Optionally specify a **Version**:
   - **Leave empty**: Matches vulnerabilities for ALL versions
   - **Specify version**: Only matches vulnerabilities affecting that exact version
7. Set the **Criticality Level** (how important this product is to your organization)
8. Click **Save**

**Benefits of NVD Search:**
- Accurate CPE-based vulnerability matching
- Standardized product naming
- Version suggestions from NVD
- Higher matching confidence

#### Method 2: Manual Entry

If you can't find your product in NVD, you can manually enter product details:

1. Click **Add Product**
2. Skip the NVD search and fill in the **Product Details** section:

| Field | Required | Description |
|-------|----------|-------------|
| **Vendor** | Yes | Manufacturer name (e.g., Microsoft, Cisco) |
| **Product Name** | Yes | Software name (e.g., Exchange Server, IOS) |
| **Version** | No | Leave empty for all versions, or specify for exact matching |
| **Criticality** | Yes | How critical this product is to your organization |
| **Active** | Yes | Enable/disable tracking |

3. Optionally expand **Advanced Options** to configure:
   - **Matching Strategy**: Auto (recommended), CPE only, Keyword only, or Both
   - **Additional Keywords**: Extra search terms for better matching
   - **Description**: Internal notes

4. Click **Save**

#### Method 3: Static Catalog (Legacy)

A pre-configured catalog of common software is available:
1. Click **Add Product**
2. Expand **Browse Static Catalog** in the Advanced Options
3. Select from 80+ pre-configured services
4. This method uses older matching logic and is not recommended for new products

### Version Handling

The **Version** field is optional but important for accurate vulnerability matching:

| Version Field | Behavior |
|---------------|----------|
| **Empty** | Matches vulnerabilities for ANY version of the product |
| **Specific version** (e.g., "10.1.18") | Only matches vulnerabilities affecting that exact version |

**Examples:**
- Apache Tomcat (no version): Shows ALL Tomcat vulnerabilities
- Apache Tomcat 10.1.18: Only shows vulnerabilities affecting version 10.1.18

### Product Examples

**Example 1: Microsoft Exchange (using NVD search)**
1. Search: "microsoft exchange"
2. Select: "Microsoft Exchange Server"
3. Version: Leave empty for all versions, or "2019" for specific version
4. Result: Accurate CPE-based matching with high confidence

**Example 2: Cisco Router (using NVD search)**
1. Search: "cisco ios"
2. Select: "Cisco IOS"
3. Version: "15.2" (or empty for all)
4. Result: Matches vulnerabilities with precise CPE identification

**Example 3: Apache Web Server (manual entry)**
```
Vendor: Apache
Product: HTTP Server
Version: (leave empty for all versions)
Keywords: httpd, Apache2
Matching Strategy: Both (CPE and keyword)
```

### Editing a Product

1. Click **Edit** on the product row
2. Modify fields as needed
3. Click **Save**

### Deleting a Product

1. Click **Delete** on the product row
2. Confirm deletion
3. Historical matches are preserved

### Bulk Import

For importing multiple products:
1. Prepare a CSV file with columns: Vendor, Product, Version, Keywords, Description
2. Go to **Products > Import**
3. Upload the CSV file
4. Review and confirm

---

## Acknowledging Vulnerabilities

### What is Acknowledgement?

Acknowledging a vulnerability indicates that:
- Your team has reviewed the CVE
- Appropriate action has been taken or planned
- The item can be removed from the "unacknowledged" list

### Acknowledging a Single Vulnerability

1. Navigate to the vulnerability
2. Click **Acknowledge**
3. Add optional notes
4. Click **Confirm**

### Bulk Acknowledgement

1. Use checkboxes to select multiple vulnerabilities
2. Click **Acknowledge Selected**
3. Add optional notes
4. Click **Confirm**

### Unacknowledging

To reverse an acknowledgement:
1. Navigate to the vulnerability
2. Click **Unacknowledge**
3. Confirm action

### Acknowledgement Best Practices

- Acknowledge after creating a remediation ticket
- Add notes with ticket number or remediation plan
- Review unacknowledged items daily
- Don't acknowledge without taking action

---

## Generating Reports

### Available Reports

| Report | Description |
|--------|-------------|
| **All Vulnerabilities** | Complete list of matching CVEs |
| **Unacknowledged** | CVEs requiring attention |
| **Critical/High** | High-severity vulnerabilities |
| **Ransomware** | Ransomware-related CVEs |
| **By Vendor** | CVEs grouped by vendor |
| **By Product** | CVEs for specific product |

### Creating a Report

1. Navigate to **Reports**
2. Select report type
3. Configure filters:
   - Date range
   - Severity levels
   - Vendors/Products
4. Choose format (PDF)
5. Click **Generate**
6. Download or print the report

### Report Contents

Reports include:
- Executive summary
- Statistics and charts
- Detailed vulnerability list
- Remediation timelines
- Product inventory

### Scheduling Reports

Automatic report delivery (if configured):
1. Go to **Reports > Schedule**
2. Select report type
3. Set frequency (daily, weekly, monthly)
4. Add email recipients
5. Click **Save Schedule**

---

## Syncing Vulnerabilities

### Automatic Sync

SentriKat automatically syncs with CISA KEV:
- Default: Daily at 2:00 AM
- Configurable by administrator

### Manual Sync

To immediately update vulnerabilities:
1. Click **Sync Now** in the navigation bar
2. Wait for sync to complete (usually 30-60 seconds)
3. View new vulnerabilities on dashboard

### Sync Status

Check sync status:
1. Go to **Administration > Sync History** (if authorized)
2. Or view the "Last Sync" timestamp on dashboard

### What Gets Synced

During sync, SentriKat:
1. Downloads latest CISA KEV JSON
2. Adds new vulnerabilities to database
3. Updates existing vulnerability details
4. Re-runs matching against your products
5. Sends alerts for new critical matches (if configured)

---

## User Roles

### Role Permissions

| Permission | User | Manager | Org Admin | Super Admin |
|------------|------|---------|-----------|-------------|
| View Dashboard | ✓ | ✓ | ✓ | ✓ |
| View Vulnerabilities | ✓ | ✓ | ✓ | ✓ |
| View Products | ✓ | ✓ | ✓ | ✓ |
| Acknowledge CVEs | ✓ | ✓ | ✓ | ✓ |
| Generate Reports | ✓ | ✓ | ✓ | ✓ |
| Add/Edit Products | | ✓ | ✓ | ✓ |
| Delete Products | | | ✓ | ✓ |
| Manage Users | | | ✓ | ✓ |
| Manage Organization | | | ✓ | ✓ |
| System Settings | | | | ✓ |
| Manage All Orgs | | | | ✓ |

### Role Descriptions

**User**
- View vulnerabilities and products
- Acknowledge vulnerabilities
- Generate reports
- Cannot modify products or settings

**Manager**
- All User permissions
- Add and edit products
- Manage product inventory

**Organization Admin**
- All Manager permissions
- Delete products
- Manage users in their organization
- Configure organization settings (SMTP, alerts)

**Super Admin**
- Full system access
- Manage all organizations
- Configure global settings (LDAP, sync)
- User management across organizations

---

## Tips & Best Practices

### Product Configuration

1. **Use NVD Search**: Always try NVD search first for accurate CPE-based matching
2. **Version Strategy**: Leave version empty for all vulnerabilities, or specify for precision
3. **Add Keywords**: Include common abbreviations and alternative names for manual entries
4. **Set Criticality**: Properly set criticality levels to prioritize vulnerability review
5. **Regular Review**: Periodically review and update product list

### Vulnerability Management

1. **Daily Review**: Check unacknowledged vulnerabilities daily
2. **Priority Triage**: Focus on Critical and High severity first
3. **Ransomware Alert**: Pay special attention to ransomware-flagged CVEs
4. **Document Actions**: Use acknowledgement notes to track remediation

### Efficient Workflow

1. **Filter First**: Use filters to focus on relevant CVEs
2. **Bulk Actions**: Use bulk acknowledgement for efficiency
3. **Bookmarks**: Save filtered views for quick access
4. **Email Alerts**: Configure alerts for critical vulnerabilities

### Common Issues

**No Matches Found**
- Verify products are marked "Active"
- Try using NVD search instead of manual entry for better CPE matching
- Check vendor/product name spelling
- Add keywords for manual entries
- Sync after adding new products

**Too Many Matches**
- Specify a version to narrow down results
- Use CPE-based matching (via NVD search) for more precision
- Change matching strategy to "CPE Only" in Advanced Options

**Missing CVEs**
- Manually trigger sync
- Verify product configuration
- Check if CVE is in CISA KEV (not all CVEs are included)
- For NVD products, try switching matching strategy to "Both"

**Low Confidence Matches**
- Re-add the product using NVD search for CPE-based matching
- Higher confidence = more accurate vulnerability identification

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `g` then `d` | Go to Dashboard |
| `g` then `v` | Go to Vulnerabilities |
| `g` then `p` | Go to Products |
| `/` | Focus search box |
| `?` | Show keyboard shortcuts |
| `a` | Acknowledge selected |
| `j` / `k` | Navigate up/down in list |

---

## Getting Help

### In-App Help

- Click the **?** icon for contextual help
- Hover over icons for tooltips

### Support

Contact your organization's SentriKat administrator for:
- Account issues
- Permission requests
- Product additions
- Technical problems

### Documentation

- [Configuration Guide](CONFIGURATION.md) - Settings reference
- [Admin Guide](ADMIN_GUIDE.md) - Administrative tasks

---

## Glossary

| Term | Definition |
|------|------------|
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog |
| **CPE** | Common Platform Enumeration - standardized naming scheme for software products |
| **CVE** | Common Vulnerabilities and Exposures identifier |
| **CVSS** | Common Vulnerability Scoring System |
| **NVD** | National Vulnerability Database - NIST database containing CPE and CVE data |
| **Acknowledgement** | Marking a vulnerability as reviewed |
| **Match** | A vulnerability that affects one of your products |
| **Match Confidence** | How certain the system is about a vulnerability match (High, Medium, Low) |
| **Sync** | Process of downloading and processing CISA data |
