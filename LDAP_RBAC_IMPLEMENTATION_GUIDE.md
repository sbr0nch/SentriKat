# LDAP User Management & RBAC Implementation Guide

## ✅ Backend Complete

The backend is fully implemented with:
- LDAP user discovery and search
- LDAP group synchronization
- User invitation/approval workflow
- Role-based access control (RBAC)
- Permission checks on all user management endpoints

## 🎨 Frontend Implementation Needed

### 1. Add LDAP User Management Tab to Admin Panel

Add a new tab in the admin panel for LDAP user management.

**Location:** `app/templates/admin_panel.html`

**Add after line 32 (after Settings tab):**

```html
<li class="nav-item" role="presentation">
    <button class="nav-link" id="ldap-users-tab" data-bs-toggle="tab" data-bs-target="#ldap-users" type="button">
        <i class="bi bi-people-fill me-2"></i>LDAP Users
    </button>
</li>
```

**Add tab content after the Settings tab content (around line 400):**

```html
<!-- LDAP Users Tab -->
<div class="tab-pane fade" id="ldap-users" role="tabpanel">
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-people-fill me-2"></i>LDAP User Discovery</span>
            <button class="btn btn-primary btn-sm" onclick="showLdapSearchModal()">
                <i class="bi bi-search me-1"></i>Search LDAP Directory
            </button>
        </div>
        <div class="card-body">
            <div class="alert alert-info">
                <i class="bi bi-info-circle me-2"></i>
                <strong>LDAP User Management:</strong> Search your LDAP/Active Directory to discover users.
                You can then invite them to SentriKat by assigning an organization and role.
            </div>

            <div id="ldapUsersContent">
                <p class="text-muted text-center py-4">
                    Click "Search LDAP Directory" to discover users
                </p>
            </div>
        </div>
    </div>
</div>
```

### 2. Add LDAP Search Modal

**Add before closing body tag in admin_panel.html:**

```html
<!-- LDAP User Search Modal -->
<div class="modal fade" id="ldapSearchModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="bi bi-search me-2"></i>Search LDAP Directory
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <!-- Search Form -->
                <div class="mb-3">
                    <div class="input-group">
                        <input type="text" class="form-control" id="ldapSearchQuery" placeholder="Search by name, username, or email (leave blank for all users)">
                        <button class="btn btn-primary" onclick="searchLdapUsers()">
                            <i class="bi bi-search me-1"></i>Search
                        </button>
                    </div>
                    <small class="form-text text-muted">
                        Searches LDAP for users matching the query. Leave blank to show all users.
                    </small>
                </div>

                <!-- Search Results -->
                <div id="ldapSearchResults">
                    <p class="text-muted text-center py-4">
                        Enter a search term and click Search
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- LDAP User Invite Modal -->
<div class="modal fade" id="ldapInviteModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="ldapInviteModalTitle">
                    <i class="bi bi-person-plus me-2"></i>Invite LDAP User
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="ldapInviteUsername">
                <input type="hidden" id="ldapInviteEmail">
                <input type="hidden" id="ldapInviteFullName">
                <input type="hidden" id="ldapInviteDN">

                <div class="mb-3">
                    <label class="form-label fw-semibold">Username</label>
                    <input type="text" class="form-control" id="ldapInviteUsernameDisplay" readonly>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-semibold">Email</label>
                    <input type="text" class="form-control" id="ldapInviteEmailDisplay" readonly>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-semibold">Organization *</label>
                    <select class="form-select" id="ldapInviteOrganization">
                        <!-- Populated dynamically -->
                    </select>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-semibold">Role *</label>
                    <select class="form-select" id="ldapInviteRole">
                        <option value="user">User (View Only)</option>
                        <option value="manager">Manager (Can Manage Products)</option>
                        <option value="org_admin">Organization Admin</option>
                        <!-- super_admin only shown to super admins -->
                    </select>
                    <div id="ldapInviteRoleDescription" class="alert alert-sm alert-secondary mt-2">
                        Select a role to see description
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="inviteLdapUser()">
                    <i class="bi bi-person-plus me-1"></i>Invite User
                </button>
            </div>
        </div>
    </div>
</div>
```

### 3. Add JavaScript Functions

**Add to `static/js/admin_panel.js` at the end:**

```javascript
// ============================================================================
// LDAP User Management
// ============================================================================

let ldapSearchResults = [];

function showLdapSearchModal() {
    try {
        console.log('showLdapSearchModal called');
        document.getElementById('ldapSearchQuery').value = '';
        document.getElementById('ldapSearchResults').innerHTML = `
            <p class="text-muted text-center py-4">
                Enter a search term and click Search
            </p>
        `;

        const modalElement = document.getElementById('ldapSearchModal');
        if (!modalElement) {
            console.error('ldapSearchModal element not found');
            return;
        }

        const modal = new bootstrap.Modal(modalElement);
        modal.show();
    } catch (error) {
        console.error('Error in showLdapSearchModal:', error);
        alert('Error opening LDAP search modal: ' + error.message);
    }
}

async function searchLdapUsers() {
    const query = document.getElementById('ldapSearchQuery').value.trim();
    const resultsDiv = document.getElementById('ldapSearchResults');

    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary"></div>
            <p class="text-muted mt-2">Searching LDAP directory...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query || '*', max_results: 100 })
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.error || 'Search failed');
        }

        ldapSearchResults = result.users;

        if (ldapSearchResults.length === 0) {
            resultsDiv.innerHTML = `
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    No users found matching "${query || 'all users'}"
                </div>
            `;
            return;
        }

        // Display results in a table
        resultsDiv.innerHTML = `
            <p class="text-muted mb-3">Found ${ldapSearchResults.length} users</p>
            <div class="table-responsive">
                <table class="table table-hover table-sm">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Email</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${ldapSearchResults.map(user => {
                            let statusBadge = '';
                            let actionButton = '';

                            if (user.exists_in_db) {
                                if (user.is_active) {
                                    statusBadge = '<span class="badge bg-success">Active in System</span>';
                                    actionButton = `<span class="text-muted">Already invited</span>`;
                                } else {
                                    statusBadge = '<span class="badge bg-secondary">Inactive</span>';
                                    actionButton = `<button class="btn btn-sm btn-outline-primary" onclick="showInviteLdapUserModal('${escapeHtml(user.username)}')">
                                        <i class="bi bi-arrow-clockwise me-1"></i>Reactivate
                                    </button>`;
                                }
                            } else {
                                statusBadge = '<span class="badge bg-warning">Not in System</span>';
                                actionButton = `<button class="btn btn-sm btn-primary" onclick="showInviteLdapUserModal('${escapeHtml(user.username)}')">
                                    <i class="bi bi-person-plus me-1"></i>Invite
                                </button>`;
                            }

                            return `
                                <tr>
                                    <td>${escapeHtml(user.username)}</td>
                                    <td>${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                                    <td>${escapeHtml(user.email)}</td>
                                    <td>${statusBadge}</td>
                                    <td>${actionButton}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        console.error('LDAP search error:', error);
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>Error:</strong> ${error.message}
            </div>
        `;
    }
}

async function showInviteLdapUserModal(username) {
    const user = ldapSearchResults.find(u => u.username === username);
    if (!user) {
        showToast('User not found in search results', 'danger');
        return;
    }

    // Populate hidden fields
    document.getElementById('ldapInviteUsername').value = user.username;
    document.getElementById('ldapInviteEmail').value = user.email;
    document.getElementById('ldapInviteFullName').value = user.full_name || '';
    document.getElementById('ldapInviteDN').value = user.dn;

    // Populate display fields
    document.getElementById('ldapInviteUsernameDisplay').value = user.username;
    document.getElementById('ldapInviteEmailDisplay').value = user.email;

    // Load organizations for dropdown
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        const select = document.getElementById('ldapInviteOrganization');
        select.innerHTML = orgs.map(org =>
            `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`
        ).join('');
    } catch (error) {
        console.error('Error loading organizations:', error);
    }

    // Set default role
    document.getElementById('ldapInviteRole').value = 'user';
    updateLdapInviteRoleDescription();

    // Close search modal and open invite modal
    bootstrap.Modal.getInstance(document.getElementById('ldapSearchModal')).hide();

    const modalElement = document.getElementById('ldapInviteModal');
    const modal = new bootstrap.Modal(modalElement);
    modal.show();
}

function updateLdapInviteRoleDescription() {
    const role = document.getElementById('ldapInviteRole').value;
    const descDiv = document.getElementById('ldapInviteRoleDescription');

    const descriptions = {
        'user': {
            text: '👁️ View-only access. Can see vulnerabilities but cannot make changes.',
            class: 'alert-secondary'
        },
        'manager': {
            text: '🛠️ Can manage products and vulnerabilities within their organization.',
            class: 'alert-info'
        },
        'org_admin': {
            text: '👑 Full administrative access within their organization. Can manage users, products, and settings.',
            class: 'alert-warning'
        },
        'super_admin': {
            text: '⭐ Full system access. Can manage all organizations, users, and global settings.',
            class: 'alert-danger'
        }
    };

    const desc = descriptions[role];
    descDiv.textContent = desc.text;
    descDiv.className = `alert alert-sm mt-2 ${desc.class}`;
}

async function inviteLdapUser() {
    const username = document.getElementById('ldapInviteUsername').value;
    const email = document.getElementById('ldapInviteEmail').value;
    const full_name = document.getElementById('ldapInviteFullName').value;
    const dn = document.getElementById('ldapInviteDN').value;
    const organization_id = parseInt(document.getElementById('ldapInviteOrganization').value);
    const role = document.getElementById('ldapInviteRole').value;

    if (!organization_id) {
        showToast('Please select an organization', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/ldap/invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                email,
                full_name,
                dn,
                organization_id,
                role
            })
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.error || 'Invitation failed');
        }

        showToast(result.message || `✓ User ${username} invited successfully`, 'success');

        // Close modal
        bootstrap.Modal.getInstance(document.getElementById('ldapInviteModal')).hide();

        // Refresh users list
        loadUsers();

        // Refresh search results to update status
        searchLdapUsers();
    } catch (error) {
        console.error('Error inviting LDAP user:', error);
        showToast(`Error: ${error.message}`, 'danger');
    }
}

// Add event listener for role dropdown
document.addEventListener('DOMContentLoaded', function() {
    const roleSelect = document.getElementById('ldapInviteRole');
    if (roleSelect) {
        roleSelect.addEventListener('change', updateLdapInviteRoleDescription);
    }
});
```

## 🔒 Frontend Permission Checks

Add permission checks to hide/disable features based on user role.

**Add to admin_panel.js after DOMContentLoaded:**

```javascript
// Check if current user can see LDAP tab
function checkLdapPermissions() {
    // Get current user's role from session or API
    fetch('/api/debug/auth-status')
        .then(response => response.json())
        .then(data => {
            const currentUser = data.user;

            // Hide LDAP tab if not admin
            if (!['super_admin', 'org_admin'].includes(currentUser.role)) {
                const ldapTab = document.getElementById('ldap-users-tab');
                if (ldapTab) {
                    ldapTab.style.display = 'none';
                }
            }

            // Hide super_admin option if not super admin
            if (currentUser.role !== 'super_admin') {
                const superAdminOption = document.querySelector('#ldapInviteRole option[value="super_admin"]');
                if (superAdminOption) {
                    superAdminOption.remove();
                }
            }
        })
        .catch(error => console.error('Error checking permissions:', error));
}

// Call on page load
document.addEventListener('DOMContentLoaded', function() {
    checkLdapPermissions();
});
```

## 📋 Testing Guide

### Prerequisites

1. **LDAP Server Must Be Configured and Working**
   ```
   Admin Panel → Settings → LDAP
   - All fields filled in
   - Test Connection shows success
   ```

2. **Test Users in Your Environment**
   - At least 2 users:
     - 1 Super Admin (for full testing)
     - 1 Org Admin (for permission testing)
   - At least 2 organizations

### Test Scenarios

#### 1. LDAP User Discovery (Super Admin)

**Steps:**
1. Log in as Super Admin
2. Go to Admin Panel → LDAP Users tab
3. Click "Search LDAP Directory"
4. Leave search blank, click Search
5. Should see list of all LDAP users

**Expected Results:**
- ✅ All LDAP users displayed in table
- ✅ Shows username, full name, email
- ✅ Status badge shows if user exists in system
- ✅ "Invite" button for users not in system
- ✅ "Already invited" for active users
- ✅ "Reactivate" for inactive users

**Test Edge Cases:**
- Search with specific username
- Search with partial name
- Search with email
- Search with non-existent user

#### 2. LDAP User Invitation (Super Admin)

**Steps:**
1. Find a user not in system
2. Click "Invite"
3. Select an organization
4. Select role (try each: user, manager, org_admin, super_admin)
5. Click "Invite User"

**Expected Results:**
- ✅ Success message appears
- ✅ User appears in Users tab
- ✅ User can log in with LDAP credentials
- ✅ User has correct organization
- ✅ User has correct role/permissions

#### 3. Organization Admin Permissions

**Steps:**
1. Log in as Org Admin
2. Go to Admin Panel → LDAP Users tab
3. Search for LDAP users
4. Try to invite to their own organization
5. Try to invite to another organization
6. Try to create super_admin role

**Expected Results:**
- ✅ Can see LDAP Users tab
- ✅ Can search LDAP
- ✅ Can invite to own organization
- ❌ Cannot select other organizations
- ❌ Cannot see super_admin role option
- ❌ Gets error if trying to create org_admin

#### 4. Manager/User Permissions

**Steps:**
1. Log in as Manager or User
2. Check Admin Panel

**Expected Results:**
- ❌ Cannot see LDAP Users tab
- ❌ Cannot see Users tab
- ❌ Cannot access /api/ldap/* endpoints

#### 5. User Management Permissions

**Test Matrix:**

| Action | Super Admin | Org Admin (Same Org) | Org Admin (Other Org) | Manager | User |
|--------|-------------|----------------------|-----------------------|---------|------|
| View all users | ✅ | ✅ (own org only) | ❌ | ❌ | ❌ |
| Create user | ✅ | ✅ (own org only) | ❌ | ❌ | ❌ |
| Edit user | ✅ | ✅ (own org, not super admin) | ❌ | ❌ | ❌ |
| Delete user | ✅ | ✅ (own org, not super admin) | ❌ | ❌ | ❌ |
| Create super_admin | ✅ | ❌ | ❌ | ❌ | ❌ |
| Edit super_admin | ✅ | ❌ | ❌ | ❌ | ❌ |

#### 6. LDAP Group Sync

**Steps:**
1. Find a user who is in LDAP groups
2. Invite them to system
3. Call `/api/ldap/user/<username>/groups`

**Expected Results:**
- ✅ Returns list of LDAP groups user belongs to
- ✅ Groups are in DN format

#### 7. Bulk Invite

**Steps:**
1. Search LDAP for multiple users
2. Select 3-5 users not in system
3. Use `/api/ldap/bulk-invite` endpoint

**Expected Results:**
- ✅ All users invited successfully
- ✅ Returns summary: invited, failed, already_exists
- ✅ All users appear in system

### API Testing with curl

```bash
# Search LDAP users
curl -X POST http://localhost:5001/api/ldap/search \
  -H "Content-Type: application/json" \
  -d '{"query": "*", "max_results": 50}'

# Get user groups
curl http://localhost:5001/api/ldap/user/jdoe/groups

# Invite LDAP user
curl -X POST http://localhost:5001/api/ldap/invite \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jdoe",
    "email": "jdoe@company.com",
    "full_name": "John Doe",
    "dn": "CN=John Doe,OU=Users,DC=company,DC=com",
    "organization_id": 1,
    "role": "user"
  }'

# Bulk invite
curl -X POST http://localhost:5001/api/ldap/bulk-invite \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"username": "user1", "email": "user1@company.com", "full_name": "User 1", "dn": "CN=User 1,OU=Users,DC=company,DC=com"},
      {"username": "user2", "email": "user2@company.com", "full_name": "User 2", "dn": "CN=User 2,OU=Users,DC=company,DC=com"}
    ],
    "organization_id": 1,
    "role": "user"
  }'
```

### Integration Testing Checklist

- [ ] LDAP connection test successful
- [ ] Can search LDAP directory
- [ ] Can view LDAP user details
- [ ] Can invite LDAP user
- [ ] Invited user can log in with LDAP credentials
- [ ] User assigned to correct organization
- [ ] User has correct role and permissions
- [ ] Super admin can manage all users
- [ ] Org admin can only manage own org users
- [ ] Org admin cannot create super admins
- [ ] Managers/users cannot access admin features
- [ ] LDAP tab hidden for non-admins
- [ ] Cannot delete yourself
- [ ] Soft delete (deactivate) works correctly
- [ ] Reactivating inactive users works

## 🚀 Deployment Steps

1. **Pull latest code**
   ```bash
   cd /opt/sentrikat
   git pull origin claude/continue-previous-tasks-nm378
   ```

2. **Install dependencies** (if ldap3 not installed)
   ```bash
   source venv/bin/activate
   pip install ldap3
   ```

3. **Restart server**
   ```bash
   pkill -f "flask run"
   pkill -f "python.*run.py"
   ./start_fresh.sh
   ```

4. **Verify LDAP configuration**
   - Go to Admin Panel → Settings → LDAP
   - Click "Test Connection"
   - Should show success

5. **Test LDAP search**
   - Go to Admin Panel → LDAP Users
   - Click "Search LDAP Directory"
   - Should see your LDAP users

## 🐛 Troubleshooting

### "LDAP Users tab not showing"
- Check if you're logged in as admin (super_admin or org_admin)
- Check browser console for JavaScript errors
- Verify you're on the latest code

### "Search returns no users"
- Verify LDAP connection test passes
- Check LDAP Base DN is correct
- Verify service account has search permissions
- Check search filter in LDAP settings

### "Cannot invite user"
- Check if you have permission (org admin or super admin)
- Verify organization is selected
- Check if user already exists
- Look at server logs for detailed error

### "Invited user cannot log in"
- Verify LDAP authentication is enabled
- Check user is active in database
- Verify LDAP credentials are correct
- Check LDAP search filter matches username format

## 📊 Success Criteria

All features working when:
- ✅ Super admin can search and invite LDAP users to any organization
- ✅ Org admin can search and invite LDAP users to their organization only
- ✅ Invited LDAP users can log in with their LDAP credentials
- ✅ Users have correct permissions based on assigned role
- ✅ Org admins cannot access or modify users from other organizations
- ✅ Super admins can manage all users and organizations
- ✅ Regular users cannot access admin features
- ✅ LDAP groups are discoverable for users

## 📞 Support

If you encounter issues during testing:
1. Check server logs: `tail -f /opt/sentrikat/logs/flask.log` (if logging configured)
2. Check browser console for JavaScript errors
3. Verify LDAP connectivity with `ldapsearch` command
4. Test LDAP credentials with test script
