# SentriKat Comprehensive Testing Guide

**Version:** 2.0
**Date:** 2025-12-18
**Branch:** claude/continue-previous-tasks-nm378

---

## Table of Contents

1. [Test Environment Setup](#test-environment-setup)
2. [User Account Types](#user-account-types)
3. [GUI Component Testing](#gui-component-testing)
4. [Multi-User Testing Scenarios](#multi-user-testing-scenarios)
5. [Conflict Testing](#conflict-testing)
6. [Performance Testing](#performance-testing)
7. [Security Testing](#security-testing)

---

## Test Environment Setup

### Prerequisites

```bash
# Ensure you're on the correct branch
git checkout claude/continue-previous-tasks-nm378

# Database is set up with admin user
python3 update_admin_roles.py

# Server is running
./start_fresh.sh
```

### Test Database

Location: `/opt/sentrikat/data/sentrikat.db` (or as per your .env)

### Browser Setup

- **Clear cache before each test session**: Ctrl+Shift+Delete
- **Use incognito/private windows for multi-user testing**
- **Tested browsers**: Chrome, Firefox, Edge

---

## User Account Types

We need to test with **5 different account types**:

### 1. Super Admin
- **Username:** `admin`
- **Password:** `admin123`
- **Role:** `super_admin`
- **Permissions:**
  - Can view all organizations
  - Can manage all users
  - Can configure LDAP
  - Can manage LDAP groups
  - Can view system logs
  - Full access to all features

### 2. Organization Admin
- **Username:** `org_admin`
- **Role:** `org_admin`
- **Permissions:**
  - Can view only their organization
  - Can manage users in their organization
  - Can manage products in their organization
  - Cannot configure global LDAP
  - Cannot view other organizations

### 3. Manager
- **Username:** `manager`
- **Role:** `manager`
- **Permissions:**
  - Can view organization data
  - Can manage products
  - Cannot manage users
  - Cannot configure settings

### 4. Regular User
- **Username:** `user`
- **Role:** `user`
- **Permissions:**
  - Can view dashboard
  - Can view vulnerabilities
  - Cannot manage products
  - Cannot access admin panel

### 5. LDAP User
- **Username:** `ldap_user`
- **Auth Type:** `ldap`
- **Permissions:** Varies based on LDAP group mapping
- **Special:** Tests LDAP authentication and group sync

---

## GUI Component Testing

### Test Matrix Format

For each component, test:
- ✅ **Visibility**: Is it visible to the user role?
- ✅ **Functionality**: Does it work correctly?
- ✅ **Data Isolation**: Does it show only authorized data?
- ✅ **Error Handling**: Does it handle errors gracefully?
- ✅ **Conflicts**: No conflicts with other features?

---

### 1. Login Page (`/login`)

**URL:** `http://cve.cti.bonelabs.com:5001/login`

| Test Case | Super Admin | Org Admin | Manager | User | LDAP User | Expected Result |
|-----------|-------------|-----------|---------|------|-----------|-----------------|
| Login with valid credentials | ✅ | ✅ | ✅ | ✅ | ✅ | Redirect to dashboard |
| Login with invalid password | ❌ | ❌ | ❌ | ❌ | ❌ | Error: "Invalid username or password" |
| Login with inactive account | ❌ | ❌ | ❌ | ❌ | ❌ | Error: "Account is inactive" |
| LDAP authentication | N/A | N/A | N/A | N/A | ✅ | Authenticate against AD, sync groups |
| Session persistence | ✅ | ✅ | ✅ | ✅ | ✅ | Stay logged in for 8 hours |

**Test Steps:**
1. Open `/login` in browser
2. Enter credentials
3. Click "Sign In"
4. Verify redirect
5. Check session cookie is set
6. Verify user role in session

**Conflicts to Check:**
- [ ] No JavaScript errors in console
- [ ] No CORS errors
- [ ] Cookie is set correctly (check browser DevTools → Application → Cookies)

---

### 2. Dashboard (`/`)

**URL:** `http://cve.cti.bonelabs.com:5001/`

| Component | Super Admin | Org Admin | Manager | User | LDAP User |
|-----------|-------------|-----------|---------|------|-----------|
| Products Overview | All orgs | Own org only | Own org only | Own org only | Based on org assignment |
| Vulnerability Matches | All orgs | Own org only | Own org only | Own org only | Based on org assignment |
| Critical Alerts | All orgs | Own org only | Own org only | Own org only | Based on org assignment |
| Charts/Graphs | All orgs | Own org only | Own org only | Own org only | Based on org assignment |
| Export CSV | ✅ | ✅ | ✅ | ✅ | ✅ |

**Test Steps:**
1. Login as each user type
2. Navigate to dashboard
3. Verify data displayed matches user's organization
4. Click on each chart/card
5. Test CSV export
6. Verify filters work

**Conflicts to Check:**
- [ ] Charts render correctly (no JavaScript errors)
- [ ] Data refreshes when filters change
- [ ] Export includes only authorized data
- [ ] No memory leaks (check browser memory over time)

---

### 3. Admin Panel (`/admin-panel`)

**URL:** `http://cve.cti.bonelabs.com:5001/admin-panel`

#### 3.1 Users Tab

| Action | Super Admin | Org Admin | Manager | User | LDAP User |
|--------|-------------|-----------|---------|------|-----------|
| View users list | ✅ All users | ✅ Own org users | ❌ | ❌ | ❌ |
| Add new user | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Edit user | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Delete user | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Change user role | ✅ | ✅ (not to super_admin) | ❌ | ❌ | ❌ |
| Deactivate user | ✅ | ✅ Own org | ❌ | ❌ | ❌ |

**Test Steps:**
1. Login as Super Admin
2. Click "Admin Panel" → "Users" tab
3. Test each action:
   - **List Users**: Verify all users shown
   - **Add User**: Click "+", fill form, save
   - **Edit User**: Click edit icon, change email, save
   - **Delete User**: Click delete, confirm
   - **Change Role**: Edit user, change role dropdown
4. Repeat as Org Admin
5. Verify Manager/User cannot access

**Conflicts to Check:**
- [ ] Modal opens/closes properly
- [ ] Form validation works (required fields)
- [ ] Success/error toasts appear
- [ ] User list refreshes after changes
- [ ] No duplicate users created
- [ ] Password fields are secure (not visible)

#### 3.2 Organizations Tab

| Action | Super Admin | Org Admin | Manager | User | LDAP User |
|--------|-------------|-----------|---------|------|-----------|
| View organizations | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Add organization | ✅ | ❌ | ❌ | ❌ | ❌ |
| Edit organization | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Delete organization | ✅ | ❌ | ❌ | ❌ | ❌ |
| Configure SMTP | ✅ | ✅ Own org | ❌ | ❌ | ❌ |
| Test SMTP | ✅ | ✅ Own org | ❌ | ❌ | ❌ |

**Test Steps:**
1. Login as Super Admin
2. Click "Organizations" tab
3. Test:
   - **List**: See all organizations
   - **Add**: Create new org with display name
   - **Edit**: Change org settings, SMTP config
   - **SMTP Test**: Click "Test Email", verify email sent
   - **Delete**: Delete org (after moving users)
4. Repeat as Org Admin (limited to own org)

**Conflicts to Check:**
- [ ] SMTP settings persist correctly
- [ ] Test email actually sends
- [ ] Cannot delete org with active users (proper error)
- [ ] Email list validation (valid email format)

#### 3.3 Settings Tab

| Sub-Section | Super Admin | Org Admin | Manager | User | LDAP User |
|-------------|-------------|-----------|---------|------|-----------|
| **LDAP Configuration** | ✅ | ❌ | ❌ | ❌ | ❌ |
| - LDAP Server | ✅ | ❌ | ❌ | ❌ | ❌ |
| - Base DN | ✅ | ❌ | ❌ | ❌ | ❌ |
| - Bind DN/Password | ✅ | ❌ | ❌ | ❌ | ❌ |
| - Test Connection | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Global SMTP** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Sync Settings** | ✅ | ❌ | ❌ | ❌ | ❌ |

**Test Steps - LDAP Configuration:**
1. Login as Super Admin
2. Navigate to Settings → LDAP Configuration
3. Fill in:
   - LDAP Server: `ldap://dc3.bonelabs.com:389`
   - Base DN: `DC=bonelabs,DC=com`
   - Bind DN: (service account)
   - Bind Password: (password)
   - Search Filter: `(sAMAccountName={username})`
4. Click "Test Connection"
5. Verify: Success message or detailed error
6. Click "Save Settings"
7. Verify: Settings saved to database

**Conflicts to Check:**
- [ ] LDAP test button works (not stuck in loading)
- [ ] Error messages are clear (not generic)
- [ ] Password field is masked
- [ ] Settings persist after save
- [ ] .env settings migrate to database
- [ ] GUI settings override .env

**Test Steps - Global SMTP:**
1. Configure global SMTP server
2. Test email sending
3. Verify vs organization-specific SMTP
4. Check priority: Org SMTP > Global SMTP

#### 3.4 LDAP Groups Tab ⭐ **NEW**

| Action | Super Admin | Org Admin | Manager | User | LDAP User |
|--------|-------------|-----------|---------|------|-----------|
| View LDAP groups | ✅ | ❌ | ❌ | ❌ | ❌ |
| Add group mapping | ✅ | ❌ | ❌ | ❌ | ❌ |
| Edit group mapping | ✅ | ❌ | ❌ | ❌ | ❌ |
| Delete group mapping | ✅ | ❌ | ❌ | ❌ | ❌ |
| Sync users from group | ✅ | ❌ | ❌ | ❌ | ❌ |
| Set role priority | ✅ | ❌ | ❌ | ❌ | ❌ |

**Test Steps:**
1. Login as Super Admin
2. Navigate to "LDAP Groups" tab
3. Click "Add LDAP Group Mapping"
4. Fill form:
   - LDAP Group DN: `CN=SentriKat Admins,OU=Groups,DC=bonelabs,DC=com`
   - Display Name: `SentriKat Admins`
   - Organization: Select from dropdown
   - Role: `org_admin`
   - Auto Provision: ✅
   - Priority: 10
5. Click "Save"
6. Click "Sync Now" to test
7. Verify users from AD group are created/updated

**Conflicts to Check:**
- [ ] Group DN validation (valid LDAP DN format)
- [ ] Priority conflict resolution (higher priority wins)
- [ ] Auto-provision creates users correctly
- [ ] Auto-deprovision deactivates users
- [ ] Sync logs are created
- [ ] No duplicate users created during sync

#### 3.5 System Logs Tab ⭐ **NEW**

| View | Super Admin | Org Admin | Manager | User | LDAP User |
|------|-------------|-----------|---------|------|-----------|
| LDAP sync logs | ✅ | ❌ | ❌ | ❌ | ❌ |
| LDAP audit logs | ✅ | ❌ | ❌ | ❌ | ❌ |
| Filter by date | ✅ | ❌ | ❌ | ❌ | ❌ |
| Filter by status | ✅ | ❌ | ❌ | ❌ | ❌ |
| Export logs | ✅ | ❌ | ❌ | ❌ | ❌ |

**Test Steps:**
1. Login as Super Admin
2. Navigate to "System Logs" tab
3. Select "LDAP Sync Logs"
4. Verify logs show recent syncs
5. Filter by date range
6. Filter by status (success/failed)
7. Click on a log entry to view details
8. Switch to "LDAP Audit Logs"
9. Verify audit trail of all LDAP operations

**Conflicts to Check:**
- [ ] Logs load without timeout
- [ ] Date filters work correctly
- [ ] Pagination works for large log sets
- [ ] Export includes all filtered data
- [ ] No SQL injection in filters

---

### 4. Product Management (`/admin`)

**URL:** `http://cve.cti.bonelabs.com:5001/admin`

| Action | Super Admin | Org Admin | Manager | User | LDAP User |
|--------|-------------|-----------|---------|------|-----------|
| View products | ✅ All orgs | ✅ Own org | ✅ Own org | ✅ Own org | ✅ Based on org |
| Add product | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Edit product | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Delete product | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Browse catalog | ✅ | ✅ | ✅ | ✅ | ✅ |
| Bulk add from catalog | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Set criticality | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Assign to organization | ✅ | ✅ Own org | ✅ Own org | ❌ | Based on permissions |

**Test Steps:**
1. Login as each user type
2. Navigate to `/admin`
3. Test:
   - **List Products**: Verify only authorized products shown
   - **Add Product**: Manual entry, verify org assignment
   - **Browse Catalog**: Open modal, search for "Microsoft"
   - **Add from Catalog**: Select multiple, assign org, add
   - **Edit Product**: Change criticality, save
   - **Delete Product**: Confirm deletion

**Conflicts to Check:**
- [ ] Organization dropdown shows correct orgs for user
- [ ] Cannot assign product to unauthorized org
- [ ] Catalog modal doesn't interfere with product modal
- [ ] Bulk add doesn't create duplicates
- [ ] Product list refreshes after changes

---

### 5. Vulnerability Matches

| View | Super Admin | Org Admin | Manager | User | LDAP User |
|------|-------------|-----------|---------|------|-----------|
| All matches | ✅ All orgs | ✅ Own org | ✅ Own org | ✅ Own org | ✅ Based on org |
| Filter by severity | ✅ | ✅ | ✅ | ✅ | ✅ |
| Filter by product | ✅ | ✅ | ✅ | ✅ | ✅ |
| Acknowledge match | ✅ | ✅ | ✅ | ❌ | Based on permissions |
| Export matches | ✅ | ✅ | ✅ | ✅ | ✅ |

**Test Steps:**
1. Ensure products exist with vulnerability matches
2. Login as each user type
3. View vulnerability matches
4. Apply filters
5. Acknowledge matches (if permitted)
6. Export to CSV
7. Verify exported data matches filters

**Conflicts to Check:**
- [ ] Filters combine correctly (AND logic)
- [ ] Export includes only visible matches
- [ ] Acknowledge updates database immediately
- [ ] No matches from other orgs shown

---

## Multi-User Testing Scenarios

### Scenario 1: Concurrent Editing

**Setup:**
- User A (Super Admin) - Chrome
- User B (Org Admin) - Firefox

**Steps:**
1. Both users login simultaneously
2. Both navigate to Users tab
3. User A edits user "John" - changes email
4. User B edits same user "John" - changes role
5. User A saves first
6. User B saves second

**Expected:**
- User B's save should show conflict warning (if implemented)
- OR: Last write wins, User B's changes applied
- No data corruption

**Verify:**
- Check database: User "John" has correct final state
- Check logs: Both edits recorded in audit log

### Scenario 2: LDAP Sync During User Management

**Setup:**
- User A (Super Admin) - Managing users manually
- System: LDAP sync runs automatically

**Steps:**
1. User A creates new user "Jane" with role "manager"
2. LDAP sync starts (scheduled or manual trigger)
3. LDAP sync finds same user "Jane" in AD
4. LDAP sync tries to update "Jane"

**Expected:**
- LDAP sync should detect existing user
- LDAP sync should update only LDAP-managed fields
- Manual role assignment should be preserved (or overridden based on config)

**Verify:**
- User "Jane" exists with correct attributes
- Audit log shows both operations
- No duplicate users

### Scenario 3: Organization Deletion with Active Users

**Setup:**
- Super Admin deletes organization "Engineering"
- Organization has 10 active users
- Organization has 50 products

**Steps:**
1. Login as Super Admin
2. Try to delete "Engineering" org
3. System should prevent deletion

**Expected:**
- Error message: "Cannot delete organization with active users"
- Suggestion: "Move or deactivate users first"

**Verify:**
- Organization still exists
- No orphaned users or products

### Scenario 4: Permission Escalation Attempt

**Setup:**
- User A (Manager) tries to escalate to Admin

**Steps:**
1. Login as Manager
2. Try to access `/admin-panel` directly
3. Try to POST to `/api/users` to create admin
4. Try to modify own role via API

**Expected:**
- All attempts blocked with 403 Forbidden
- Audit log records unauthorized attempts

**Verify:**
- User still has "manager" role
- Security audit shows blocked attempts

---

## Conflict Testing

### Database Conflicts

| Scenario | Test | Expected Result |
|----------|------|-----------------|
| Duplicate username | Create user with existing username | Error: "Username already exists" |
| Duplicate email | Create user with existing email | Error: "Email already in use" |
| Invalid org assignment | Assign user to non-existent org | Error: "Invalid organization" |
| Circular dependencies | Delete org referenced by users | Prevented with foreign key constraint |
| Orphaned records | Delete user with products | Products remain, assigned to org |

### UI/UX Conflicts

| Component | Conflict | Resolution |
|-----------|----------|------------|
| Modal over modal | Catalog browser + Product edit | Z-index correct, both accessible |
| Long data | Very long organization names | Text truncation with tooltip |
| Many items | 1000+ products in list | Pagination implemented |
| Slow network | Loading states visible | Spinners, skeleton screens |
| Session expiry | 8 hour session timeout | Redirect to login with message |

### Browser Compatibility

Test matrix:

| Feature | Chrome | Firefox | Edge | Safari |
|---------|--------|---------|------|--------|
| Login | ✅ | ✅ | ✅ | ✅ |
| Dashboard charts | ✅ | ✅ | ✅ | ⚠️ Test |
| Admin panel | ✅ | ✅ | ✅ | ⚠️ Test |
| LDAP groups | ✅ | ✅ | ✅ | ⚠️ Test |
| CSV export | ✅ | ✅ | ✅ | ✅ |

---

## Performance Testing

### Load Testing

| Test | Metric | Target | Tool |
|------|--------|--------|------|
| Login | Response time | < 500ms | Browser DevTools |
| Dashboard | Page load | < 2s | Browser DevTools |
| Product list (1000 items) | Render time | < 3s | Browser DevTools |
| LDAP sync (1000 users) | Completion | < 60s | Server logs |
| CSV export (10,000 rows) | Generation | < 10s | Browser DevTools |

### Memory Leaks

1. Open admin panel
2. Navigate through all tabs 50 times
3. Check browser memory (DevTools → Memory)
4. Memory should stabilize, not continuously grow

---

## Security Testing

### Authentication

- [ ] Cannot access `/admin-panel` without login
- [ ] Session cookie is HttpOnly
- [ ] Session cookie is Secure (if HTTPS)
- [ ] Password is hashed (bcrypt/scrypt)
- [ ] LDAP password not stored in plaintext

### Authorization

- [ ] Manager cannot access super admin functions
- [ ] Org admin cannot view other organizations
- [ ] User cannot delete products
- [ ] API endpoints check permissions

### Input Validation

- [ ] XSS: Try `<script>alert('xss')</script>` in org name
- [ ] SQL Injection: Try `'; DROP TABLE users; --` in username
- [ ] Path Traversal: Try `../../etc/passwd` in file uploads
- [ ] LDAP Injection: Try `*)(uid=*))(|(uid=*` in LDAP filters

---

## Test Execution Checklist

### Before Testing

- [ ] Pull latest code: `git pull origin claude/continue-previous-tasks-nm378`
- [ ] Database is fresh: `python3 setup_now.py`
- [ ] Server is running: `./start_fresh.sh`
- [ ] Browser cache cleared: Ctrl+Shift+Delete

### During Testing

- [ ] Document all issues in issue tracker
- [ ] Take screenshots of errors
- [ ] Note browser console errors
- [ ] Check server logs for errors

### After Testing

- [ ] Export test results to CSV
- [ ] Create bug reports for failures
- [ ] Update this document with findings
- [ ] Commit changes to git

---

## Test Result Template

```markdown
### Test Session: [Date]

**Tester:** [Name]
**Browser:** Chrome 120.0.6099.129
**OS:** Windows 11

#### Test Results

| Component | Test Case | Result | Notes |
|-----------|-----------|--------|-------|
| Login | Valid credentials | ✅ PASS | Redirect OK |
| Login | Invalid password | ✅ PASS | Error shown |
| Dashboard | Load time | ⚠️ WARN | 3.2s (target: 2s) |
| Users Tab | Create user | ❌ FAIL | Email validation broken |

#### Issues Found

1. **Email validation not working**
   - Severity: Medium
   - Steps: Create user, enter invalid email, save
   - Expected: Error "Invalid email format"
   - Actual: User created with invalid email
   - Screenshot: attached

#### Recommendations

- Fix email validation regex
- Add loading indicator for LDAP test
- Improve dashboard performance
```

---

## Next Steps

1. **Create Test Users**: Run script to create all 5 user types
2. **Start Testing**: Begin with Login → Dashboard → Admin Panel
3. **Document Issues**: Use template above
4. **Fix and Retest**: Iterate until all tests pass

**Ready to start testing!** 🎯
