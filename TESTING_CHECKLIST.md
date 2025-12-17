# LDAP and RBAC Testing Checklist

This document provides a comprehensive testing guide for the LDAP user management and role-based access control (RBAC) features implemented in SentriKat.

## Prerequisites

Before testing, ensure:
1. LDAP/Active Directory is configured in Settings → LDAP / Active Directory
2. LDAP connection test passes successfully
3. At least one organization exists
4. Test users with different roles are available

## Testing Overview

### Test Users Needed

Create the following test users to verify RBAC:
- **Super Admin** - Full system access
- **Org Admin** (Organization A) - Full access to Organization A
- **Org Admin** (Organization B) - Full access to Organization B
- **Manager** - Product management only
- **Regular User** - View-only access

---

## 1. LDAP Configuration Testing

### 1.1 LDAP Settings Configuration
**Steps:**
1. Log in as Super Admin
2. Navigate to Admin Panel → Settings → LDAP / Active Directory
3. Configure LDAP settings:
   - Server: `ldap://dc3.bonelabs.com:389`
   - Base DN: `DC=bonelabs,DC=com`
   - Bind DN: Service account DN
   - Bind Password: Service account password
4. Click "Test Connection"

**Expected Results:**
- ✅ Connection test shows "LDAP connection successful!"
- ✅ Settings save without errors
- ✅ Password field shows placeholder (••••••••) after save

**Common Issues:**
- ❌ Connection timeout → Check firewall/network access
- ❌ Invalid credentials → Verify service account credentials
- ❌ Invalid DN → Check Base DN and Bind DN format

---

## 2. LDAP Users Tab Visibility

### 2.1 Tab Visibility for Different Roles

**Test Matrix:**

| User Role | Can See LDAP Users Tab? | Expected Behavior |
|-----------|------------------------|-------------------|
| Super Admin | ✅ Yes | Full access to LDAP features |
| Org Admin | ✅ Yes | Can search and invite to their org only |
| Manager | ❌ No | Tab completely hidden |
| User | ❌ No | Tab completely hidden |

**Steps:**
1. Log out and log in as each role
2. Navigate to Admin Panel
3. Check if "LDAP Users" tab is visible

**Expected Results:**
- Super admins and org admins see the LDAP Users tab
- Managers and regular users do not see the tab
- Page loads without JavaScript errors

---

## 3. LDAP User Search

### 3.1 Search Functionality

**Steps:**
1. Log in as Org Admin or Super Admin
2. Navigate to Admin Panel → LDAP Users
3. Click "Search LDAP Directory"
4. Enter search queries:
   - Single character: `j`
   - Full username: `jdoe`
   - Wildcard: `j*`
   - Email pattern: `*@bonelabs.com`

**Expected Results:**
- ✅ Search modal opens
- ✅ Search returns matching users
- ✅ Results show: Username, Full Name, Email, Status
- ✅ Users already in DB show "Already Invited" badge
- ✅ New users show "Not Invited" badge with "Invite" button

**Test Cases:**

| Search Query | Expected Results |
|--------------|-----------------|
| `*` | All users (up to limit) |
| `jdoe` | Specific user "jdoe" |
| `j*` | All users starting with 'j' |
| `xyz123` | "No users found" message |
| Empty string | Warning: "Please enter a search query" |

### 3.2 Search Error Handling

**Steps:**
1. Stop LDAP server or misconfigure settings
2. Attempt LDAP search

**Expected Results:**
- ✅ Error message displayed clearly
- ✅ No JavaScript console errors
- ✅ Modal remains functional

---

## 4. LDAP User Invitation

### 4.1 Invite New LDAP User

**Steps:**
1. Search for LDAP user not yet in system
2. Click "Invite" button
3. In invite modal:
   - Verify username, email, full name are populated (read-only)
   - Check LDAP groups are displayed
   - Select organization
   - Select role
4. Click "Invite User"

**Expected Results:**
- ✅ User added to database with auth_type='ldap'
- ✅ Success message: "LDAP user invited successfully"
- ✅ User appears in Users tab
- ✅ Search results update to show "Already Invited"
- ✅ User cannot log in until LDAP authentication is attempted

### 4.2 LDAP Group Display

**Steps:**
1. Click "Invite" on a user who is member of LDAP groups
2. Check "LDAP Groups" section in invite modal

**Expected Results:**
- ✅ Groups displayed as comma-separated list
- ✅ If no groups: "No groups found" message
- ✅ Groups load without blocking the modal

---

## 5. RBAC Permission Testing

### 5.1 Super Admin Permissions

**Login as:** Super Admin

**Test Cases:**

| Action | Expected Result |
|--------|----------------|
| View Users tab | ✅ See ALL users from ALL organizations |
| View Organizations tab | ✅ See ALL organizations |
| View LDAP Users tab | ✅ Tab visible and functional |
| Search LDAP | ✅ Can search |
| Invite LDAP user to any org | ✅ Can select any organization |
| Create org admin | ✅ Can create org_admin role |
| Create super admin | ✅ Can create super_admin role |
| Edit user in any org | ✅ Can edit any user |
| Delete user in any org | ✅ Can delete any user |

### 5.2 Org Admin Permissions (Organization A)

**Login as:** Org Admin for Organization A

**Test Cases:**

| Action | Expected Result |
|--------|----------------|
| View Users tab | ✅ See ONLY users in Organization A |
| View users from Org B | ❌ Not visible in user list |
| View LDAP Users tab | ✅ Tab visible |
| Search LDAP | ✅ Can search |
| Invite user to Org A | ✅ Can invite |
| Invite user to Org B | ❌ Get error: "Org admins can only invite to their own org" |
| Create super_admin | ❌ Error: "Org admins cannot create admin users" |
| Create org_admin | ❌ Error: "Org admins cannot create admin users" |
| Create manager in own org | ✅ Success |
| Create user in own org | ✅ Success |
| Edit user in own org | ✅ Can edit |
| Edit user in other org | ❌ 403 Forbidden |
| Delete user in own org | ✅ Can delete (soft delete) |
| Delete user in other org | ❌ 403 Forbidden |
| Delete self | ❌ Error: "Cannot delete yourself" |

### 5.3 Manager Permissions

**Login as:** Manager

**Test Cases:**

| Action | Expected Result |
|--------|----------------|
| View Admin Panel | ❌ Redirected or 403 Forbidden |
| View LDAP Users tab | ❌ Tab not visible |
| Access /api/ldap/search | ❌ 403 Forbidden |
| Manage products | ✅ Can add/edit/delete products |

### 5.4 Regular User Permissions

**Login as:** Regular User

**Test Cases:**

| Action | Expected Result |
|--------|----------------|
| View Admin Panel | ❌ Redirected or 403 Forbidden |
| View LDAP Users tab | ❌ Tab not visible |
| Access any /api/users endpoint | ❌ 403 Forbidden |
| View vulnerabilities | ✅ Can view (read-only) |
| Edit products | ❌ Cannot edit |

---

## 6. User Management RBAC Testing

### 6.1 Create User

**Test Matrix:**

| Current User Role | Target Role | Target Org | Expected Result |
|------------------|-------------|------------|----------------|
| Super Admin | super_admin | Any | ✅ Success |
| Super Admin | org_admin | Any | ✅ Success |
| Super Admin | manager | Any | ✅ Success |
| Super Admin | user | Any | ✅ Success |
| Org Admin (A) | user | Org A | ✅ Success |
| Org Admin (A) | manager | Org A | ✅ Success |
| Org Admin (A) | org_admin | Org A | ❌ Forbidden |
| Org Admin (A) | user | Org B | ❌ Forbidden |
| Org Admin (A) | super_admin | Any | ❌ Forbidden |

### 6.2 Edit User

**Test Scenarios:**

1. **Super Admin edits any user:**
   - ✅ Can change username, email, role, organization
   - ✅ Can promote user to super_admin
   - ✅ Can change user's organization

2. **Org Admin edits user in same organization:**
   - ✅ Can change username, email
   - ✅ Can assign manager or user role
   - ❌ Cannot assign org_admin or super_admin role
   - ❌ Cannot change to different organization

3. **Org Admin edits user in different organization:**
   - ❌ 403 Forbidden

### 6.3 Delete User

**Test Scenarios:**

1. **Delete self:**
   - ❌ Error: "Cannot delete yourself" (any role)

2. **Super Admin deletes any user:**
   - ✅ Success (soft delete: is_active=False)
   - ✅ User no longer appears in user list
   - ✅ User cannot log in

3. **Org Admin deletes user in same org:**
   - ✅ Success

4. **Org Admin deletes user in different org:**
   - ❌ 403 Forbidden

5. **Org Admin deletes super admin:**
   - ❌ 403 Forbidden (no permission to manage super admins)

---

## 7. API Endpoint Testing

### 7.1 LDAP API Endpoints

Use curl or Postman to test API endpoints directly:

```bash
# Get current user info (permission check)
curl -X GET http://localhost:5001/api/current-user \
  -H "Cookie: session=YOUR_SESSION_COOKIE"

# Search LDAP (requires org_admin or super_admin)
curl -X POST http://localhost:5001/api/ldap/search \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{"search_query": "j*"}'

# Invite LDAP user
curl -X POST http://localhost:5001/api/ldap/invite \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{
    "username": "jdoe",
    "email": "jdoe@bonelabs.com",
    "full_name": "John Doe",
    "dn": "CN=John Doe,OU=Users,DC=bonelabs,DC=com",
    "organization_id": 1,
    "role": "user"
  }'

# Get user groups
curl -X POST http://localhost:5001/api/ldap/user-groups \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{"username": "jdoe"}'
```

**Expected HTTP Status Codes:**

| Endpoint | Valid User | Invalid Permission | Not Logged In |
|----------|-----------|-------------------|---------------|
| `/api/current-user` | 200 | N/A | 401 |
| `/api/ldap/search` | 200 | 403 | 401 |
| `/api/ldap/invite` | 200 | 403 | 401 |
| `/api/ldap/user-groups` | 200 | 403 | 401 |

---

## 8. Integration Testing

### 8.1 End-to-End LDAP User Workflow

**Complete User Journey:**

1. **Setup** (Super Admin):
   - Configure LDAP settings
   - Create Organization "Acme Corp"
   - Create org_admin user for "Acme Corp"

2. **Discover Users** (Org Admin):
   - Log in as org_admin
   - Navigate to LDAP Users tab
   - Search for `j*`
   - Verify LDAP users appear

3. **Invite User**:
   - Click "Invite" on user "jdoe"
   - Select organization "Acme Corp"
   - Select role "Manager"
   - Click "Invite User"
   - Verify success message

4. **Verify User Created**:
   - Go to Users tab
   - Find "jdoe" in user list
   - Verify:
     - Auth Type: LDAP
     - Organization: Acme Corp
     - Role: Manager
     - Status: Active

5. **Test LDAP Login** (as jdoe):
   - Log out
   - Log in with LDAP credentials
   - Verify successful authentication
   - Check session has correct user context

6. **Permission Verification**:
   - As jdoe (Manager), verify:
     - Can manage products
     - Cannot access Admin Panel
     - Cannot see LDAP Users tab

### 8.2 Multi-Organization Testing

**Scenario:**
- Organization A with Org Admin A
- Organization B with Org Admin B
- Same LDAP user invited to both orgs (should fail)

**Steps:**
1. Org Admin A invites user "jdoe" to Org A
2. Org Admin B attempts to invite same "jdoe" to Org B

**Expected Results:**
- ✅ First invitation succeeds
- ❌ Second invitation fails or updates existing user
- ✅ User belongs to only one organization

---

## 9. Error Handling and Edge Cases

### 9.1 LDAP Connection Errors

**Test Cases:**

| Scenario | Expected Behavior |
|----------|------------------|
| LDAP server down | Clear error message, no crash |
| Invalid credentials | "Authentication failed" error |
| Network timeout | Timeout error with retry suggestion |
| Invalid Base DN | Search returns 0 results |
| Malformed search query | Validation error or empty results |

### 9.2 User Input Validation

**Test Cases:**

| Input | Expected Result |
|-------|----------------|
| Empty search query | Warning: "Please enter a search query" |
| SQL injection attempt in search | Safely escaped, no SQL execution |
| XSS attempt in username | Escaped in HTML output |
| Very long search query (>1000 chars) | Handled gracefully or truncated |

### 9.3 Concurrent Operations

**Test:**
1. Two admins search LDAP simultaneously
2. Two admins invite same user simultaneously

**Expected Results:**
- ✅ Both searches complete successfully
- ✅ Second invite either succeeds with update or shows "user exists" error

---

## 10. Performance Testing

### 10.1 Large LDAP Directory

**Test with:**
- Directory with 10,000+ users
- Search query returning 100+ results

**Expected Results:**
- ✅ Search completes within 5 seconds
- ✅ Results paginated or limited (max 50 users)
- ✅ UI remains responsive
- ✅ No browser memory issues

### 10.2 Response Time Benchmarks

| Operation | Target Time | Acceptable Time |
|-----------|------------|----------------|
| LDAP search | < 2s | < 5s |
| User invite | < 1s | < 3s |
| Load users list | < 1s | < 2s |
| Permission check | < 500ms | < 1s |

---

## 11. Security Testing

### 11.1 Authorization Bypass Attempts

**Test Cases:**

1. **Org Admin tries to access other org's data via API:**
   ```bash
   # Org Admin A (org_id=1) tries to edit user in Org B (user_id=5, org_id=2)
   curl -X PUT http://localhost:5001/api/users/5 \
     -H "Cookie: session=ORG_ADMIN_A_SESSION" \
     -d '{"role": "super_admin"}'
   ```
   **Expected:** 403 Forbidden

2. **Manager tries to access LDAP endpoints:**
   ```bash
   curl -X POST http://localhost:5001/api/ldap/search \
     -H "Cookie: session=MANAGER_SESSION"
   ```
   **Expected:** 403 Forbidden

3. **Unauthenticated access:**
   ```bash
   curl -X POST http://localhost:5001/api/ldap/search
   ```
   **Expected:** 401 Unauthorized

### 11.2 LDAP Injection Testing

**Test Scenarios:**
- Search for: `*)(objectClass=*`
- Search for: `admin*)(|(password=*`

**Expected Results:**
- ✅ Query properly escaped
- ✅ No LDAP injection occurs
- ✅ Either sanitized results or error

---

## 12. Regression Testing

### 12.1 Existing Features Still Work

**Verify:**
- ✅ Local user creation still works
- ✅ Local user login still works
- ✅ Product management unaffected
- ✅ Vulnerability matching unaffected
- ✅ Email alerts still send
- ✅ Organization SMTP settings persist

### 12.2 Backward Compatibility

**Test:**
- Existing users created before LDAP implementation
- Existing organizations
- Existing products and vulnerabilities

**Expected Results:**
- ✅ All existing data intact
- ✅ No migrations broke existing features
- ✅ Local auth users can still log in

---

## Testing Sign-Off

### Checklist Summary

- [ ] LDAP configuration works
- [ ] LDAP tab visibility correct for all roles
- [ ] LDAP search returns correct results
- [ ] User invitation works
- [ ] LDAP groups display correctly
- [ ] Super admin has full access
- [ ] Org admin restricted to their org
- [ ] Managers/users cannot access LDAP
- [ ] Permission checks enforced on backend
- [ ] API endpoints return correct status codes
- [ ] Error handling works properly
- [ ] No XSS or injection vulnerabilities
- [ ] Performance is acceptable
- [ ] Existing features still work

### Test Environment

- **Date Tested:** _____________
- **Tested By:** _____________
- **SentriKat Version:** _____________
- **LDAP Server Type:** ☐ Active Directory ☐ OpenLDAP ☐ Other: _____________
- **Browser(s) Tested:** _____________

### Issues Found

| Issue # | Description | Severity | Status |
|---------|-------------|----------|--------|
| 1 | | | |
| 2 | | | |
| 3 | | | |

### Notes

```
[Additional testing notes here]
```

---

## Quick Smoke Test (5 minutes)

For rapid verification after deployment:

1. **Login as Super Admin** → Admin Panel loads
2. **LDAP Settings** → Test Connection → ✅ Success
3. **LDAP Users Tab** → Visible
4. **Search LDAP** → Enter `*` → Results appear
5. **Login as Org Admin** → LDAP Users tab visible
6. **Login as Manager** → LDAP Users tab hidden
7. **Login as LDAP user** → Authentication works

If all ✅ pass, core functionality is working.
