/**
 * Admin Panel JavaScript
 * Handles user management, organization management, and settings
 */

let currentUserId = null;
let currentOrgId = null;
let organizations = [];

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin Panel: DOMContentLoaded fired');

    // Check if Bootstrap is loaded
    if (typeof bootstrap === 'undefined') {
        console.error('Bootstrap is not loaded! Modals will not work.');
        showToast('Error: Bootstrap JavaScript library is not loaded. Please refresh the page.', 'danger');
        return;
    }

    try {
        loadUsers();
        loadOrganizations();
        loadOrganizationsDropdown();
        checkLdapPermissions();  // Check if user can access LDAP features

        // Tab change handlers
        const orgTab = document.getElementById('organizations-tab');
        if (orgTab) {
            orgTab.addEventListener('shown.bs.tab', function() {
                loadOrganizations();
            });
        } else {
            console.warn('organizations-tab element not found');
        }

        // Settings tab handler
        const settingsTab = document.getElementById('settings-tab');
        if (settingsTab) {
            settingsTab.addEventListener('shown.bs.tab', function() {
                loadAllSettings();
            });
        } else {
            console.warn('settings-tab element not found');
        }

        // LDAP Users tab handler - auto-load users when tab is shown
        const ldapUsersTab = document.getElementById('ldap-users-tab');
        if (ldapUsersTab) {
            ldapUsersTab.addEventListener('shown.bs.tab', function() {
                loadLDAPUsersDefault();
            });
        }

        // LDAP Groups tab handler
        const ldapGroupsTab = document.getElementById('ldap-groups-tab');
        if (ldapGroupsTab) {
            ldapGroupsTab.addEventListener('shown.bs.tab', function() {
                loadGroupMappings();
                loadSyncStats();
                loadSyncHistory();
            });
        }

        // LDAP Groups sub-tab handlers
        const groupMappingsTab = document.getElementById('group-mappings-tab');
        if (groupMappingsTab) {
            groupMappingsTab.addEventListener('shown.bs.pill', function() {
                loadGroupMappings();
            });
        }

        const syncDashboardTab = document.getElementById('sync-dashboard-tab');
        if (syncDashboardTab) {
            syncDashboardTab.addEventListener('shown.bs.pill', function() {
                loadSyncStats();
                loadSyncHistory();
            });
        }

        // Load sync status immediately (doesn't require settings to be configured)
        loadSyncStatus();

        console.log('Admin Panel: Initialization complete');
    } catch (error) {
        console.error('Error during admin panel initialization:', error);
    }
});

// ============================================================================
// User Management
// ============================================================================

async function loadUsers() {
    const tbody = document.getElementById('usersTable');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    try {
        const response = await fetch('/api/users');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const users = await response.json();

        if (users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-5">
                        <i class="bi bi-people text-muted" style="font-size: 3rem;"></i>
                        <h5 class="mt-3 text-muted">No users yet</h5>
                        <p class="text-muted">Click "Create User" to add your first user.</p>
                    </td>
                </tr>
            `;
        } else {
            tbody.innerHTML = users.map(user => {
                // Role badge - professional style
                const roleMap = {
                    'super_admin': { badge: 'badge-role-super', text: 'Super Admin' },
                    'org_admin': { badge: 'badge-role-admin', text: 'Org Admin' },
                    'manager': { badge: 'badge-role-manager', text: 'Manager' },
                    'user': { badge: 'badge-role-user', text: 'User' }
                };

                const role = roleMap[user.role] || roleMap['user'];
                const roleBadge = `<span class="badge ${role.badge}">${role.text}</span>`;

                const statusBadge = user.is_active
                    ? '<span class="badge badge-status-active">Active</span>'
                    : '<span class="badge badge-status-inactive">Inactive</span>';

                const authBadge = user.auth_type === 'ldap'
                    ? '<span class="badge badge-auth-ldap">LDAP</span>'
                    : '<span class="badge badge-auth-local">Local</span>';

                // Find organization display name from organizations array
                let orgDisplay = '<span class="text-muted">-</span>';
                if (user.organization_id && organizations.length > 0) {
                    const org = organizations.find(o => o.id === user.organization_id);
                    if (org) {
                        orgDisplay = escapeHtml(org.display_name);
                    } else {
                        orgDisplay = `Org ${user.organization_id}`;
                    }
                } else if (user.organization_id) {
                    orgDisplay = `Org ${user.organization_id}`;
                }

                return `
                    <tr>
                        <td class="fw-semibold">${escapeHtml(user.username)}</td>
                        <td>${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                        <td>${escapeHtml(user.email)}</td>
                        <td>${orgDisplay}</td>
                        <td>${authBadge}</td>
                        <td>${roleBadge}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="d-flex gap-1">
                                <button class="btn-action btn-action-edit" onclick="editUser(${user.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn-action ${user.is_active ? 'btn-action-block' : 'btn-action-success'}"
                                        onclick="toggleUserActive(${user.id}, '${escapeHtml(user.username)}', ${user.is_active})"
                                        title="${user.is_active ? 'Block' : 'Unblock'}">
                                    <i class="bi bi-${user.is_active ? 'slash-circle' : 'check-circle'}"></i>
                                </button>
                                <button class="btn-action btn-action-delete" onclick="deleteUser(${user.id}, '${escapeHtml(user.username)}')" title="Delete">
                                    <i class="bi bi-trash3"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center text-danger py-4">
                    <i class="bi bi-exclamation-triangle"></i> Error loading users: ${error.message}
                </td>
            </tr>
        `;
    }
}

function showCreateUserModal() {
    try {
        console.log('showCreateUserModal called');
        currentUserId = null;
        document.getElementById('userModalTitle').innerHTML = '<i class="bi bi-person-plus me-2"></i>Create User';
        document.getElementById('userForm').reset();

        // Reset to local auth and completely hide LDAP option for creation
        document.getElementById('authLocal').checked = true;
        document.getElementById('authLdap').style.display = 'none';
        document.getElementById('authLdapLabel').style.display = 'none';
        document.getElementById('isActive').checked = true;
        document.getElementById('userRole').value = 'user';
        document.getElementById('canManageProducts').checked = true;

        // Hide org memberships section (only shown when editing)
        document.getElementById('orgMembershipsSection').style.display = 'none';

        toggleAuthFields();
        updateRoleDescription();

        const modalElement = document.getElementById('userModal');
        if (!modalElement) {
            console.error('userModal element not found');
            return;
        }

        const modal = new bootstrap.Modal(modalElement);
        console.log('Modal created, showing...');
        modal.show();
    } catch (error) {
        console.error('Error in showCreateUserModal:', error);
        showToast('Error opening user modal: ' + error.message, 'danger');
    }
}

async function editUser(userId) {
    currentUserId = userId;
    document.getElementById('userModalTitle').innerHTML = '<i class="bi bi-pencil me-2"></i>Edit User';

    try {
        const response = await fetch(`/api/users/${userId}`);
        const user = await response.json();

        document.getElementById('username').value = user.username;
        document.getElementById('email').value = user.email;
        document.getElementById('fullName').value = user.full_name || '';
        document.getElementById('organization').value = user.organization_id || '';
        document.getElementById('userRole').value = user.role || 'user';
        document.getElementById('canManageProducts').checked = user.can_manage_products;
        document.getElementById('canViewAllOrgs').checked = user.can_view_all_orgs;
        document.getElementById('isActive').checked = user.is_active;

        // Set auth type and show/hide LDAP option for editing
        if (user.auth_type === 'ldap') {
            document.getElementById('authLdap').checked = true;
            // Show LDAP option for existing LDAP users (read-only display)
            document.getElementById('authLdap').style.display = '';
            document.getElementById('authLdapLabel').style.display = '';
            document.getElementById('authLdap').disabled = false;
            document.getElementById('authLocal').disabled = true;  // Can't change LDAP user to local
        } else {
            document.getElementById('authLocal').checked = true;
            // Hide LDAP option (can't convert local to LDAP)
            document.getElementById('authLdap').style.display = 'none';
            document.getElementById('authLdapLabel').style.display = 'none';
            document.getElementById('authLocal').disabled = false;
        }

        toggleAuthFields();
        updateRoleDescription();

        // For edit mode, password is optional
        document.getElementById('password').required = false;
        document.getElementById('passwordConfirm').required = false;

        // Show organization memberships section and load memberships
        document.getElementById('orgMembershipsSection').style.display = 'block';
        loadUserOrgMemberships(userId);

        new bootstrap.Modal(document.getElementById('userModal')).show();
    } catch (error) {
        showToast(`Error loading user: ${error.message}`, 'danger');
    }
}

// =============================================================================
// Organization Memberships Functions
// =============================================================================

async function loadUserOrgMemberships(userId) {
    const tbody = document.getElementById('orgMembershipsTable');
    tbody.innerHTML = '<tr><td colspan="4" class="text-center py-3"><div class="spinner-border spinner-border-sm"></div> Loading...</td></tr>';

    try {
        const response = await fetch(`/api/users/${userId}/organizations`);
        if (!response.ok) throw new Error('Failed to load memberships');

        const memberships = await response.json();

        if (memberships.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">No organization memberships</td></tr>';
            return;
        }

        const roleLabels = {
            'super_admin': '<span class="badge badge-role-super">Super Admin</span>',
            'org_admin': '<span class="badge badge-role-admin">Org Admin</span>',
            'manager': '<span class="badge badge-role-manager">Manager</span>',
            'user': '<span class="badge badge-role-user">User</span>'
        };

        tbody.innerHTML = memberships.map(m => `
            <tr>
                <td>
                    <i class="bi bi-building me-1"></i>
                    <strong>${escapeHtml(m.organization_name)}</strong>
                </td>
                <td>
                    ${roleLabels[m.role] || m.role}
                    <select class="form-select form-select-sm d-inline-block ms-2" style="width: auto;"
                            onchange="updateOrgMembershipRole(${userId}, ${m.organization_id}, this.value, ${m.is_primary})">
                        <option value="user" ${m.role === 'user' ? 'selected' : ''}>User</option>
                        <option value="manager" ${m.role === 'manager' ? 'selected' : ''}>Manager</option>
                        <option value="org_admin" ${m.role === 'org_admin' ? 'selected' : ''}>Org Admin</option>
                    </select>
                </td>
                <td>
                    ${m.is_primary ?
                        '<span class="badge bg-primary"><i class="bi bi-star-fill me-1"></i>Primary</span>' :
                        '<span class="badge bg-secondary">Additional</span>'}
                </td>
                <td>
                    ${!m.is_primary ? `
                        <button class="btn btn-sm btn-outline-danger" onclick="removeOrgMembership(${userId}, ${m.organization_id}, '${escapeHtml(m.organization_name)}')" title="Remove from organization">
                            <i class="bi bi-trash3"></i>
                        </button>
                    ` : '<span class="text-muted small">Cannot remove primary</span>'}
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-3">Error: ${error.message}</td></tr>`;
    }
}

async function showAddOrgMembershipModal() {
    if (!currentUserId) {
        showToast('Please save the user first before adding organization memberships', 'warning');
        return;
    }

    document.getElementById('addOrgMembershipUserId').value = currentUserId;

    // Load available organizations
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        // Get current memberships to exclude
        const membershipsResponse = await fetch(`/api/users/${currentUserId}/organizations`);
        const memberships = await membershipsResponse.json();
        const memberOrgIds = new Set(memberships.map(m => m.organization_id));

        const select = document.getElementById('addOrgMembershipOrg');
        select.innerHTML = '<option value="">Select organization...</option>';

        orgs.filter(org => !memberOrgIds.has(org.id)).forEach(org => {
            select.innerHTML += `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`;
        });

        if (select.options.length <= 1) {
            select.innerHTML = '<option value="">No available organizations</option>';
        }

        new bootstrap.Modal(document.getElementById('addOrgMembershipModal')).show();
    } catch (error) {
        showToast('Error loading organizations: ' + error.message, 'danger');
    }
}

async function addOrgMembership() {
    const userId = document.getElementById('addOrgMembershipUserId').value;
    const orgId = document.getElementById('addOrgMembershipOrg').value;
    const role = document.getElementById('addOrgMembershipRole').value;

    if (!orgId) {
        showToast('Please select an organization', 'warning');
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/organizations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ organization_id: parseInt(orgId), role: role })
        });

        const result = await response.json();

        if (response.ok) {
            showToast(result.message || 'Organization added successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('addOrgMembershipModal')).hide();
            loadUserOrgMemberships(userId);
        } else {
            showToast(result.error || 'Failed to add organization', 'danger');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function updateOrgMembershipRole(userId, orgId, newRole, isPrimary) {
    try {
        const response = await fetch(`/api/users/${userId}/organizations/${orgId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: newRole })
        });

        const result = await response.json();

        if (response.ok) {
            showToast(result.message || 'Role updated successfully', 'success');
            // If this is the primary org, also update the role dropdown in the main form
            if (isPrimary) {
                document.getElementById('userRole').value = newRole;
            }
            loadUserOrgMemberships(userId);
        } else {
            showToast(result.error || 'Failed to update role', 'danger');
            loadUserOrgMemberships(userId); // Reload to revert the select
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
        loadUserOrgMemberships(userId);
    }
}

async function removeOrgMembership(userId, orgId, orgName) {
    if (!confirm(`Remove user from "${orgName}"?`)) return;

    try {
        const response = await fetch(`/api/users/${userId}/organizations/${orgId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (response.ok) {
            showToast(result.message || 'Removed from organization', 'success');
            loadUserOrgMemberships(userId);
        } else {
            showToast(result.error || 'Failed to remove from organization', 'danger');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

function toggleAuthFields() {
    const isLocal = document.getElementById('authLocal').checked;
    const passwordField = document.getElementById('passwordField');
    const passwordConfirmField = document.getElementById('passwordConfirmField');
    const usernameHelp = document.getElementById('usernameHelp');

    if (isLocal) {
        passwordField.style.display = 'block';
        passwordConfirmField.style.display = 'block';
        document.getElementById('password').required = currentUserId === null; // Required for new users
        document.getElementById('passwordConfirm').required = currentUserId === null;
        usernameHelp.textContent = 'Unique username for login';
    } else {
        passwordField.style.display = 'none';
        passwordConfirmField.style.display = 'none';
        document.getElementById('password').required = false;
        document.getElementById('passwordConfirm').required = false;
        usernameHelp.textContent = 'For LDAP: Use AD sAMAccountName (e.g., jdoe)';
    }
}

async function saveUser() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const passwordConfirm = document.getElementById('passwordConfirm').value;
    const authType = document.querySelector('input[name="authType"]:checked').value;

    // Validation
    if (!username || !email) {
        showToast('Username and email are required', 'warning');
        return;
    }

    if (authType === 'local' && currentUserId === null) {
        if (!password) {
            showToast('Password is required for local users', 'warning');
            return;
        }
        if (password.length < 8) {
            showToast('Password must be at least 8 characters', 'warning');
            return;
        }
        if (password !== passwordConfirm) {
            showToast('Passwords do not match', 'warning');
            return;
        }
    }

    const userData = {
        username: username,
        email: email,
        full_name: document.getElementById('fullName').value.trim(),
        organization_id: parseInt(document.getElementById('organization').value) || null,
        auth_type: authType,
        role: document.getElementById('userRole').value,
        is_admin: document.getElementById('userRole').value !== 'user' && document.getElementById('userRole').value !== 'manager',
        can_manage_products: document.getElementById('canManageProducts').checked,
        can_view_all_orgs: document.getElementById('canViewAllOrgs').checked,
        is_active: document.getElementById('isActive').checked
    };

    // Only include password for local auth and if provided
    if (authType === 'local' && password) {
        userData.password = password;
    }

    try {
        let response;
        if (currentUserId) {
            response = await fetch(`/api/users/${currentUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        } else {
            response = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        }

        if (response.ok) {
            showToast(
                currentUserId ? '✓ User updated successfully' : '✓ User created successfully',
                'success'
            );
            bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving user: ${error.message}`, 'danger');
    }
}

async function deleteUser(userId, username) {
    const confirmed = await showConfirm(
        `Are you sure you want to delete user "<strong>${username}</strong>"?<br><br>This action cannot be undone.`,
        'Delete User',
        'Delete',
        'btn-danger'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('✓ User deleted successfully', 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error deleting user: ${error.message}`, 'danger');
    }
}

async function toggleUserActive(userId, username, isCurrentlyActive) {
    const action = isCurrentlyActive ? 'block' : 'unblock';
    const actionVerb = isCurrentlyActive ? 'blocked' : 'unblocked';

    const confirmed = await showConfirm(
        `Are you sure you want to ${action} user "<strong>${username}</strong>"?<br><br>` +
        (isCurrentlyActive
            ? 'The user will not be able to log in until unblocked.'
            : 'The user will be able to log in again.'),
        `${action.charAt(0).toUpperCase() + action.slice(1)} User`,
        action.charAt(0).toUpperCase() + action.slice(1),
        isCurrentlyActive ? 'btn-warning' : 'btn-success'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/toggle-active`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            showToast(`✓ User ${username} has been ${actionVerb}`, 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error toggling user status: ${error.message}`, 'danger');
    }
}

// ============================================================================
// Organization Management
// ============================================================================

async function loadOrganizations() {
    const tbody = document.getElementById('orgsTable');
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    try {
        const response = await fetch('/api/organizations');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        organizations = await response.json();

        if (organizations.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-5">
                        <i class="bi bi-building text-muted" style="font-size: 3rem;"></i>
                        <h5 class="mt-3 text-muted">No organizations yet</h5>
                        <p class="text-muted">Click "Create Organization" to add your first organization.</p>
                    </td>
                </tr>
            `;
        } else {
            tbody.innerHTML = organizations.map(org => {
                const smtpBadge = org.smtp_host
                    ? '<span class="badge badge-status-active">Configured</span>'
                    : '<span class="badge badge-status-inactive">Not Set</span>';

                const statusBadge = org.active
                    ? '<span class="badge badge-status-active">Active</span>'
                    : '<span class="badge badge-status-inactive">Inactive</span>';

                return `
                    <tr>
                        <td class="fw-semibold">${escapeHtml(org.name)}</td>
                        <td>${escapeHtml(org.display_name)}</td>
                        <td><span class="badge badge-role-manager">${org.user_count || 0}</span></td>
                        <td>${smtpBadge}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="d-flex gap-1">
                                <button class="btn-action btn-action-edit" onclick="editOrganization(${org.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                ${org.name !== 'default' ? `
                                <button class="btn-action btn-action-delete" onclick="deleteOrganization(${org.id}, '${escapeHtml(org.display_name)}')" title="Delete">
                                    <i class="bi bi-trash3"></i>
                                </button>
                                ` : ''}
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
        console.error('Error loading organizations:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-danger py-4">
                    <i class="bi bi-exclamation-triangle"></i> Error loading organizations: ${error.message}
                </td>
            </tr>
        `;
    }
}

async function loadOrganizationsDropdown() {
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        const select = document.getElementById('organization');
        select.innerHTML = orgs.map(org =>
            `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`
        ).join('');
    } catch (error) {
        console.error('Error loading organizations dropdown:', error);
    }
}

function showCreateOrgModal() {
    try {
        console.log('showCreateOrgModal called');
        currentOrgId = null;
        document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-building me-2"></i>Create Organization';
        document.getElementById('orgForm').reset();
        document.getElementById('orgActive').checked = true;
        document.getElementById('alertCritical').checked = true;
        document.getElementById('alertNewCVE').checked = true;
        document.getElementById('alertRansomware').checked = true;
        document.getElementById('smtpUseTls').checked = true;
        document.getElementById('smtpPort').value = 587;

        const modalElement = document.getElementById('orgModal');
        if (!modalElement) {
            console.error('orgModal element not found');
            return;
        }

        const modal = new bootstrap.Modal(modalElement);
        console.log('Modal created, showing...');
        modal.show();
    } catch (error) {
        console.error('Error in showCreateOrgModal:', error);
        showToast('Error opening organization modal: ' + error.message, 'danger');
    }
}

async function editOrganization(orgId) {
    currentOrgId = orgId;
    document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-pencil me-2"></i>Edit Organization';

    try {
        const response = await fetch(`/api/organizations/${orgId}`);
        const org = await response.json();

        // Basic info
        document.getElementById('orgName').value = org.name;
        document.getElementById('orgDisplayName').value = org.display_name;
        document.getElementById('orgDescription').value = org.description || '';

        // Parse emails
        let emails = [];
        try {
            emails = JSON.parse(org.notification_emails || '[]');
        } catch (e) {
            emails = [];
        }
        document.getElementById('orgEmails').value = emails.join(', ');
        document.getElementById('orgActive').checked = org.active;

        // SMTP settings
        document.getElementById('smtpHost').value = org.smtp_host || '';
        document.getElementById('smtpPort').value = org.smtp_port || 587;
        document.getElementById('smtpUsername').value = org.smtp_username || '';
        // Don't pre-fill masked password - leave blank so user can enter new one if needed
        document.getElementById('smtpPassword').value = '';
        document.getElementById('smtpPassword').placeholder = org.smtp_password ? '(password saved - leave blank to keep)' : 'Password';
        document.getElementById('smtpFromEmail').value = org.smtp_from_email || '';
        document.getElementById('smtpFromName').value = org.smtp_from_name || 'SentriKat Alerts';
        document.getElementById('smtpUseTls').checked = org.smtp_use_tls !== false;

        // Alert settings
        document.getElementById('alertCritical').checked = org.alert_on_critical;
        document.getElementById('alertHigh').checked = org.alert_on_high;
        document.getElementById('alertNewCVE').checked = org.alert_on_new_cve;
        document.getElementById('alertRansomware').checked = org.alert_on_ransomware;

        // Disable name field for existing orgs
        document.getElementById('orgName').readOnly = true;

        new bootstrap.Modal(document.getElementById('orgModal')).show();
    } catch (error) {
        showToast(`Error loading organization: ${error.message}`, 'danger');
    }
}

async function saveOrganization() {
    const name = document.getElementById('orgName').value.trim();
    const displayName = document.getElementById('orgDisplayName').value.trim();

    if (!name || !displayName) {
        showToast('Organization name and display name are required', 'warning');
        return;
    }

    // Parse emails
    const emailsText = document.getElementById('orgEmails').value;
    const emails = emailsText ? emailsText.split(',').map(e => e.trim()).filter(e => e) : [];

    const orgData = {
        name: name.toLowerCase().replace(/\s+/g, '_'),
        display_name: displayName,
        description: document.getElementById('orgDescription').value.trim(),
        notification_emails: JSON.stringify(emails),
        active: document.getElementById('orgActive').checked,

        // SMTP settings
        smtp_host: document.getElementById('smtpHost').value.trim() || null,
        smtp_port: parseInt(document.getElementById('smtpPort').value) || 587,
        smtp_username: document.getElementById('smtpUsername').value.trim() || null,
        smtp_password: document.getElementById('smtpPassword').value.trim() || null,
        smtp_from_email: document.getElementById('smtpFromEmail').value.trim() || null,
        smtp_from_name: document.getElementById('smtpFromName').value.trim() || 'SentriKat Alerts',
        smtp_use_tls: document.getElementById('smtpUseTls').checked,

        // Alert settings
        alert_on_critical: document.getElementById('alertCritical').checked,
        alert_on_high: document.getElementById('alertHigh').checked,
        alert_on_new_cve: document.getElementById('alertNewCVE').checked,
        alert_on_ransomware: document.getElementById('alertRansomware').checked
    };

    try {
        let response;
        if (currentOrgId) {
            response = await fetch(`/api/organizations/${currentOrgId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(orgData)
            });
        } else {
            response = await fetch('/api/organizations', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(orgData)
            });
        }

        if (response.ok) {
            showToast(
                currentOrgId ? '✓ Organization updated successfully' : '✓ Organization created successfully',
                'success'
            );
            bootstrap.Modal.getInstance(document.getElementById('orgModal')).hide();
            loadOrganizations();
            loadOrganizationsDropdown();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving organization: ${error.message}`, 'danger');
    }
}

async function testSMTP() {
    if (!currentOrgId) {
        showToast('Please save the organization first before testing SMTP', 'warning');
        return;
    }

    try {
        const response = await fetch(`/api/organizations/${currentOrgId}/smtp/test`, {
            method: 'POST'
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message || '✓ SMTP connection successful!', 'success');
        } else {
            showToast(`✗ SMTP test failed: ${result.error || result.message || 'Unknown error'}`, 'danger');
        }
    } catch (error) {
        showToast(`Error testing SMTP: ${error.message}`, 'danger');
    }
}

async function deleteOrganization(orgId, displayName) {
    const confirmed = await showConfirm(
        `Are you sure you want to delete organization "<strong>${displayName}</strong>"?<br><br>This will also delete all users and products associated with this organization.<br><br>This action cannot be undone.`,
        'Delete Organization',
        'Delete',
        'btn-danger'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/organizations/${orgId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('✓ Organization deleted successfully', 'success');
            loadOrganizations();
            loadOrganizationsDropdown();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error deleting organization: ${error.message}`, 'danger');
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

function showToast(message, type = 'info') {
    /**
     * Display a Bootstrap toast notification
     * @param {string} message - The message to display
     * @param {string} type - Type of toast: 'success', 'danger', 'warning', 'info'
     */
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }

    // Map type to Bootstrap classes
    const typeClasses = {
        'success': 'bg-success text-white',
        'danger': 'bg-danger text-white',
        'warning': 'bg-warning text-dark',
        'info': 'bg-info text-white'
    };

    const toastClass = typeClasses[type] || typeClasses['info'];

    // Create toast element
    const toastId = `toast-${Date.now()}`;
    const toastHtml = `
        <div id="${toastId}" class="toast ${toastClass}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-body d-flex justify-content-between align-items-center">
                <span>${message}</span>
                <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHtml);

    // Show the toast
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: 3000
    });

    toast.show();

    // Remove toast from DOM after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function () {
        toastElement.remove();
    });
}

function updateRoleDescription() {
    const role = document.getElementById('userRole').value;
    const descDiv = document.getElementById('roleDescription');
    const viewAllOrgsCheck = document.getElementById('viewAllOrgsCheck');
    const canManageProducts = document.getElementById('canManageProducts');

    const descriptions = {
        'user': {
            text: '👁️ View-only access. Can see vulnerabilities but cannot make changes.',
            class: 'alert-secondary',
            canManageProducts: false,
            showViewAllOrgs: false
        },
        'manager': {
            text: '🛠️ Can manage products and vulnerabilities within their organization.',
            class: 'alert-info',
            canManageProducts: true,
            showViewAllOrgs: false
        },
        'org_admin': {
            text: '👑 Full administrative access within their organization. Can manage users, products, and settings.',
            class: 'alert-warning',
            canManageProducts: true,
            showViewAllOrgs: false
        },
        'super_admin': {
            text: '⭐ Full system access. Can manage all organizations, users, and global settings.',
            class: 'alert-danger',
            canManageProducts: true,
            showViewAllOrgs: true
        }
    };

    const desc = descriptions[role];
    descDiv.textContent = desc.text;
    descDiv.className = `alert alert-sm mt-2 ${desc.class}`;
    canManageProducts.checked = desc.canManageProducts;
    viewAllOrgsCheck.style.display = desc.showViewAllOrgs ? 'block' : 'none';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function autoConfigureSmtpSecurity() {
    const port = parseInt(document.getElementById('smtpPort').value);
    const tlsCheckbox = document.getElementById('smtpUseTls');

    // Auto-configure based on common SMTP ports
    switch(port) {
        case 25:
            // Plain SMTP - no TLS/SSL
            tlsCheckbox.checked = false;
            showToast('ℹ️ Port 25 configured: Plain SMTP (no encryption)', 'info');
            break;
        case 587:
            // STARTTLS
            tlsCheckbox.checked = true;
            showToast('ℹ️ Port 587 configured: TLS/STARTTLS enabled', 'info');
            break;
        case 465:
            // SSL (note: we use TLS checkbox for SSL too in this implementation)
            tlsCheckbox.checked = true;
            showToast('ℹ️ Port 465 configured: SSL enabled', 'info');
            break;
        default:
            // Unknown port, don't change settings
            break;
    }
}

// ============================================================================
// Settings Management
// ============================================================================

// LDAP Settings
async function saveLDAPSettings() {
    const settings = {
        ldap_enabled: document.getElementById('ldapEnabled').checked,
        ldap_server: document.getElementById('ldapServer').value,
        ldap_port: document.getElementById('ldapPort').value,
        ldap_base_dn: document.getElementById('ldapBaseDN').value,
        ldap_bind_dn: document.getElementById('ldapBindDN').value,
        ldap_bind_password: document.getElementById('ldapBindPassword').value,
        ldap_search_filter: document.getElementById('ldapSearchFilter').value,
        ldap_username_attr: document.getElementById('ldapUsernameAttr').value,
        ldap_email_attr: document.getElementById('ldapEmailAttr').value,
        ldap_use_tls: document.getElementById('ldapUseTLS').checked,
        ldap_sync_enabled: document.getElementById('ldapSyncEnabled').checked,
        ldap_sync_interval_hours: document.getElementById('ldapSyncInterval').value
    };

    try {
        const response = await fetch('/api/settings/ldap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('✓ LDAP settings saved successfully. Server restart required for scheduled sync changes.', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving LDAP settings: ${error.message}`, 'danger');
    }
}

async function testLDAPConnection() {
    const btn = event.target;
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Testing...';

    try {
        const response = await fetch('/api/settings/ldap/test', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message || '✓ LDAP connection successful!', 'success');
        } else {
            showToast(`✗ LDAP test failed: ${result.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error testing LDAP:', error);
        showToast(`Error testing LDAP: ${error.message}`, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

// Global SMTP Settings
async function saveGlobalSMTPSettings() {
    const settings = {
        smtp_host: document.getElementById('globalSmtpHost').value,
        smtp_port: document.getElementById('globalSmtpPort').value,
        smtp_username: document.getElementById('globalSmtpUsername').value,
        smtp_password: document.getElementById('globalSmtpPassword').value,
        smtp_from_email: document.getElementById('globalSmtpFromEmail').value,
        smtp_from_name: document.getElementById('globalSmtpFromName').value,
        smtp_use_tls: document.getElementById('globalSmtpUseTLS').checked
    };

    try {
        const response = await fetch('/api/settings/smtp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('✓ Global SMTP settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving SMTP settings: ${error.message}`, 'danger');
    }
}

async function testGlobalSMTP() {
    const btn = event.target;
    const originalText = btn.innerHTML;

    // Check if required fields are filled
    const host = document.getElementById('globalSmtpHost').value;
    const fromEmail = document.getElementById('globalSmtpFromEmail').value;

    if (!host || !fromEmail) {
        showToast('⚠️ Please fill in SMTP Host and From Email fields before testing', 'warning');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Sending test email...';

    try {
        const response = await fetch('/api/settings/smtp/test', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message || '✓ Test email sent successfully!', 'success');
        } else {
            showToast(`✗ SMTP test failed: ${result.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error testing SMTP:', error);
        showToast(`Error testing SMTP: ${error.message}`, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

// Sync Settings
async function saveSyncSettings() {
    const settings = {
        auto_sync_enabled: document.getElementById('autoSyncEnabled').checked,
        sync_interval: document.getElementById('syncInterval').value,
        sync_time: document.getElementById('syncTime').value,
        nvd_api_key: document.getElementById('nvdApiKey').value,
        cisa_kev_url: document.getElementById('cisaKevUrl').value
    };

    try {
        const response = await fetch('/api/settings/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('✓ Sync settings saved successfully', 'success');
            loadSyncStatus();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving sync settings: ${error.message}`, 'danger');
    }
}

async function loadSyncStatus() {
    try {
        const response = await fetch('/api/settings/sync/status');
        const status = await response.json();

        document.getElementById('lastSyncTime').textContent = status.last_sync || 'Never';
        document.getElementById('nextSyncTime').textContent = status.next_sync || 'Not scheduled';
        document.getElementById('totalVulns').textContent = status.total_vulnerabilities || '0';
    } catch (error) {
        console.error('Error loading sync status:', error);
    }
}

// General Settings
async function saveGeneralSettings() {
    const settings = {
        verify_ssl: document.getElementById('verifySSL').checked,
        http_proxy: document.getElementById('httpProxy').value,
        https_proxy: document.getElementById('httpsProxy').value,
        no_proxy: document.getElementById('noProxy').value,
        session_timeout: document.getElementById('sessionTimeout').value
    };

    try {
        const response = await fetch('/api/settings/general', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('✓ General settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving general settings: ${error.message}`, 'danger');
    }
}

// ============================================================================
// Audit Logs
// ============================================================================

async function loadAuditLogs() {
    const tbody = document.getElementById('auditLogsTable');
    const statsDiv = document.getElementById('auditLogsStats');
    const countSpan = document.getElementById('auditLogsCount');

    // Show loading
    tbody.innerHTML = `
        <tr>
            <td colspan="6" class="text-center py-5">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="text-muted mt-2">Loading audit logs...</p>
            </td>
        </tr>
    `;

    // Get filter values
    const action = document.getElementById('auditActionFilter')?.value || '';
    const resource = document.getElementById('auditResourceFilter')?.value || '';
    const limit = document.getElementById('auditLimitFilter')?.value || '100';

    // Build query string
    const params = new URLSearchParams();
    if (action) params.append('action', action);
    if (resource) params.append('resource', resource);
    params.append('limit', limit);

    try {
        const response = await fetch(`/api/audit-logs?${params.toString()}`);

        if (!response.ok) {
            if (response.status === 403) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="text-center py-5">
                            <i class="bi bi-shield-lock text-warning" style="font-size: 3rem;"></i>
                            <h5 class="mt-3 text-muted">Access Denied</h5>
                            <p class="text-muted">Only super administrators can view audit logs.</p>
                        </td>
                    </tr>
                `;
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-5">
                        <i class="bi bi-journal-text text-muted" style="font-size: 3rem;"></i>
                        <h5 class="mt-3 text-muted">No audit logs found</h5>
                        <p class="text-muted">Audit events will appear here as actions are performed.</p>
                    </td>
                </tr>
            `;
            statsDiv.style.display = 'none';
            return;
        }

        // Render audit logs
        tbody.innerHTML = data.logs.map(log => {
            // Format timestamp
            const timestamp = log.timestamp
                ? new Date(log.timestamp).toLocaleString()
                : '-';

            // Action badge color
            const actionColors = {
                'CREATE': 'bg-success',
                'UPDATE': 'bg-primary',
                'DELETE': 'bg-danger',
                'INVITE': 'bg-info',
                'BLOCK': 'bg-warning',
                'UNBLOCK': 'bg-success',
                'LOGIN': 'bg-secondary',
                'SYNC': 'bg-info'
            };
            const actionBadge = `<span class="badge ${actionColors[log.action] || 'bg-secondary'}">${escapeHtml(log.action || '-')}</span>`;

            // Format resource
            const resource = log.resource || '-';

            // Format details
            let details = log.message || '';
            if (log.old_value || log.new_value) {
                if (log.old_value && log.new_value) {
                    details += ` (${JSON.stringify(log.old_value)} → ${JSON.stringify(log.new_value)})`;
                } else if (log.new_value) {
                    details += ` (${JSON.stringify(log.new_value)})`;
                }
            }
            // Truncate long details
            if (details.length > 100) {
                details = details.substring(0, 100) + '...';
            }

            return `
                <tr>
                    <td><small>${timestamp}</small></td>
                    <td>${actionBadge}</td>
                    <td><code>${escapeHtml(resource)}</code></td>
                    <td>${log.user_id || '-'}</td>
                    <td><small>${escapeHtml(details)}</small></td>
                    <td><small class="text-muted">${escapeHtml(log.ip_address || '-')}</small></td>
                </tr>
            `;
        }).join('');

        // Update stats
        countSpan.textContent = data.logs.length;
        statsDiv.style.display = 'block';

    } catch (error) {
        console.error('Error loading audit logs:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-5">
                    <i class="bi bi-exclamation-triangle text-danger" style="font-size: 3rem;"></i>
                    <h5 class="mt-3 text-muted">Error loading audit logs</h5>
                    <p class="text-muted">${escapeHtml(error.message)}</p>
                </td>
            </tr>
        `;
    }
}

async function loadAllSettings() {
    try {
        // Load LDAP settings
        const ldapResponse = await fetch('/api/settings/ldap');
        if (ldapResponse.ok) {
            const ldap = await ldapResponse.json();
            document.getElementById('ldapEnabled').checked = ldap.ldap_enabled || false;
            document.getElementById('ldapServer').value = ldap.ldap_server || '';
            document.getElementById('ldapPort').value = ldap.ldap_port || 389;
            document.getElementById('ldapBaseDN').value = ldap.ldap_base_dn || '';
            document.getElementById('ldapBindDN').value = ldap.ldap_bind_dn || '';
            document.getElementById('ldapSearchFilter').value = ldap.ldap_search_filter || '(sAMAccountName={username})';
            document.getElementById('ldapUsernameAttr').value = ldap.ldap_username_attr || 'sAMAccountName';
            document.getElementById('ldapEmailAttr').value = ldap.ldap_email_attr || 'mail';
            document.getElementById('ldapUseTLS').checked = ldap.ldap_use_tls || false;
            document.getElementById('ldapSyncEnabled').checked = ldap.ldap_sync_enabled || false;
            document.getElementById('ldapSyncInterval').value = ldap.ldap_sync_interval_hours || '24';

            // Load last scheduled sync time
            loadLastScheduledSync();
        }

        // Load Global SMTP settings
        const smtpResponse = await fetch('/api/settings/smtp');
        if (smtpResponse.ok) {
            const smtp = await smtpResponse.json();
            document.getElementById('globalSmtpHost').value = smtp.smtp_host || '';
            document.getElementById('globalSmtpPort').value = smtp.smtp_port || 587;
            document.getElementById('globalSmtpUsername').value = smtp.smtp_username || '';
            document.getElementById('globalSmtpFromEmail').value = smtp.smtp_from_email || '';
            document.getElementById('globalSmtpFromName').value = smtp.smtp_from_name || 'SentriKat Alerts';
            document.getElementById('globalSmtpUseTLS').checked = smtp.smtp_use_tls !== false;
        }

        // Load Sync settings
        const syncResponse = await fetch('/api/settings/sync');
        if (syncResponse.ok) {
            const sync = await syncResponse.json();
            document.getElementById('autoSyncEnabled').checked = sync.auto_sync_enabled || false;
            document.getElementById('syncInterval').value = sync.sync_interval || 'daily';
            document.getElementById('syncTime').value = sync.sync_time || '02:00';
            document.getElementById('cisaKevUrl').value = sync.cisa_kev_url || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
        }
        loadSyncStatus();

        // Load General settings
        const generalResponse = await fetch('/api/settings/general');
        if (generalResponse.ok) {
            const general = await generalResponse.json();
            document.getElementById('verifySSL').checked = general.verify_ssl !== false;
            document.getElementById('httpProxy').value = general.http_proxy || '';
            document.getElementById('httpsProxy').value = general.https_proxy || '';
            document.getElementById('noProxy').value = general.no_proxy || '';
            document.getElementById('sessionTimeout').value = general.session_timeout || 480;
        }
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

// ============================================================================
// LDAP User Management
// ============================================================================

/**
 * Load LDAP users by default when tab is shown (uses wildcard search)
 */
async function loadLDAPUsersDefault() {
    const resultsDiv = document.getElementById('ldapSearchResultsTable');
    const statsDiv = document.getElementById('ldapSearchStats');
    const searchInput = document.getElementById('ldapUserSearchQuery');

    // Set default search to wildcard if empty
    if (searchInput && !searchInput.value.trim()) {
        searchInput.value = '*';
    }

    // Show loading
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="text-muted mt-2">Loading LDAP users...</p>
            </div>
        `;
    }
    if (statsDiv) {
        statsDiv.style.display = 'none';
    }

    try {
        const response = await fetch('/api/ldap/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: '*', max_results: 1000 })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to load users');
        }

        const results = await response.json();
        ldapSearchCache.results = results.users;
        ldapSearchCache.query = '*';
        ldapSearchCache.currentPage = 1;

        // Display first page of results
        displayLDAPUserResults(1);

    } catch (error) {
        console.error('Error loading LDAP users:', error);
        if (resultsDiv) {
            resultsDiv.innerHTML = `
                <div class="alert alert-warning">
                    <i class="bi bi-info-circle me-2"></i>
                    <strong>Could not load LDAP users:</strong> ${escapeHtml(error.message)}
                    <hr>
                    <small>Make sure LDAP is configured in Settings. Use the search box above to find specific users.</small>
                </div>
            `;
        }
    }
}

/**
 * Display paginated LDAP user results from cache
 */
function displayLDAPUserResults(page = 1) {
    const resultsDiv = document.getElementById('ldapSearchResultsTable');
    const statsDiv = document.getElementById('ldapSearchStats');
    const pageSize = parseInt(document.getElementById('ldapSearchPageSize')?.value) || 25;

    const allResults = ldapSearchCache.results || [];
    ldapSearchCache.currentPage = page;
    ldapSearchCache.pageSize = pageSize;

    if (allResults.length === 0) {
        resultsDiv.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="bi bi-inbox" style="font-size: 3rem;"></i>
                <p class="mt-3">No LDAP users found</p>
                <p class="text-muted">Check your LDAP configuration in Settings</p>
            </div>
        `;
        return;
    }

    // Calculate pagination
    const totalPages = Math.ceil(allResults.length / pageSize);
    const startIdx = (page - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, allResults.length);
    const pageResults = allResults.slice(startIdx, endIdx);

    // Update stats
    if (document.getElementById('ldapResultCount')) {
        document.getElementById('ldapResultCount').textContent =
            `${startIdx + 1}-${endIdx} of ${allResults.length}`;
    }
    if (statsDiv) {
        statsDiv.style.display = 'block';
    }

    // Build pagination controls
    const paginationHtml = buildLdapPagination(page, totalPages);
    if (document.getElementById('ldapPagination')) {
        document.getElementById('ldapPagination').innerHTML = paginationHtml;
    }

    // Display results in table
    resultsDiv.innerHTML = `
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead class="table-light">
                    <tr>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email</th>
                        <th>DN</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${pageResults.map(user => {
                        // Determine status badge based on exists_in_db and is_active
                        let statusBadge, actionButton;
                        if (user.exists_in_db && user.is_active) {
                            statusBadge = '<span class="badge bg-success"><i class="bi bi-check-circle-fill me-1"></i>Active</span>';
                            actionButton = '<button class="btn btn-sm btn-outline-secondary" disabled title="User is already active in SentriKat"><i class="bi bi-check2-circle me-1"></i>Active</button>';
                        } else if (user.exists_in_db && !user.is_active) {
                            statusBadge = '<span class="badge bg-warning text-dark"><i class="bi bi-person-dash-fill me-1"></i>Blocked</span>';
                            actionButton = `<button class="btn btn-sm btn-success" onclick='showInviteLdapUserModalInline(${JSON.stringify(user).replace(/'/g, "&#39;")})' title="Reactivate this user">
                                   <i class="bi bi-person-check me-1"></i>Reactivate
                               </button>`;
                        } else {
                            statusBadge = '<span class="badge bg-secondary"><i class="bi bi-person-x me-1"></i>Not Invited</span>';
                            actionButton = `<button class="btn btn-sm btn-primary" onclick='showInviteLdapUserModalInline(${JSON.stringify(user).replace(/'/g, "&#39;")})' title="Invite this user to SentriKat">
                                   <i class="bi bi-person-plus-fill me-1"></i>Invite
                               </button>`;
                        }

                        return `
                            <tr>
                                <td class="fw-semibold">${escapeHtml(user.username)}</td>
                                <td>${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                                <td>${escapeHtml(user.email)}</td>
                                <td><small class="text-muted">${escapeHtml(user.dn).substring(0, 60)}${user.dn.length > 60 ? '...' : ''}</small></td>
                                <td>${statusBadge}</td>
                                <td>${actionButton}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

async function checkLdapPermissions() {
    try {
        const response = await fetch('/api/current-user');
        if (response.ok) {
            const user = await response.json();
            // Show LDAP tabs for org_admin, super_admin, or legacy is_admin users
            const canAccessLdap = user.role === 'org_admin' ||
                                  user.role === 'super_admin' ||
                                  user.is_admin === true;

            if (canAccessLdap) {
                const ldapUsersTab = document.getElementById('ldap-users-tab-item');
                const ldapGroupsTab = document.getElementById('ldap-groups-tab-item');

                if (ldapUsersTab) {
                    ldapUsersTab.style.display = 'block';
                }
                if (ldapGroupsTab) {
                    ldapGroupsTab.style.display = 'block';
                }
            }
        }
    } catch (error) {
        console.error('Error checking LDAP permissions:', error);
    }
}

// Store LDAP search results for pagination
let ldapSearchCache = {
    results: [],
    currentPage: 1,
    pageSize: 25,
    query: ''
};

/**
 * Inline LDAP user search with pagination
 */
async function searchLdapUsersInline(page = 1) {
    const query = document.getElementById('ldapUserSearchQuery').value.trim();
    const pageSize = parseInt(document.getElementById('ldapSearchPageSize').value) || 25;

    if (!query) {
        showToast('Please enter a search query', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('ldapSearchResultsTable');
    const statsDiv = document.getElementById('ldapSearchStats');

    // Show loading
    resultsDiv.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="text-muted mt-2">Searching LDAP directory for "${escapeHtml(query)}"...</p>
        </div>
    `;
    statsDiv.style.display = 'none';

    try {
        // Only fetch if query changed or cache is empty
        if (query !== ldapSearchCache.query || ldapSearchCache.results.length === 0) {
            const response = await fetch('/api/ldap/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query, max_results: 1000 })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Search failed');
            }

            const results = await response.json();
            ldapSearchCache.results = results.users;
            ldapSearchCache.query = query;
        }

        ldapSearchCache.pageSize = pageSize;
        ldapSearchCache.currentPage = page;

        const allResults = ldapSearchCache.results;

        if (allResults.length === 0) {
            resultsDiv.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-inbox" style="font-size: 3rem;"></i>
                    <p class="mt-3">No users found matching "${escapeHtml(query)}"</p>
                    <p class="text-muted">Try a different search term or wildcard pattern (e.g., "*${escapeHtml(query)}*")</p>
                </div>
            `;
            return;
        }

        // Calculate pagination
        const totalPages = Math.ceil(allResults.length / pageSize);
        const startIdx = (page - 1) * pageSize;
        const endIdx = Math.min(startIdx + pageSize, allResults.length);
        const pageResults = allResults.slice(startIdx, endIdx);

        // Update stats
        document.getElementById('ldapResultCount').textContent =
            `${startIdx + 1}-${endIdx} of ${allResults.length}`;
        statsDiv.style.display = 'block';

        // Build pagination controls
        const paginationHtml = buildLdapPagination(page, totalPages);
        document.getElementById('ldapPagination').innerHTML = paginationHtml;

        // Display results in table
        const tableHtml = `
            <div class="table-responsive">
                <table class="table table-hover table-sm">
                    <thead class="table-light">
                        <tr>
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Email</th>
                            <th>DN</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pageResults.map(user => {
                            // Determine status badge based on exists_in_db and is_active
                            let statusBadge, actionButton;
                            if (user.exists_in_db && user.is_active) {
                                statusBadge = '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Active</span>';
                                actionButton = '<button class="btn btn-sm btn-outline-secondary" disabled>Already Active</button>';
                            } else if (user.exists_in_db && !user.is_active) {
                                statusBadge = '<span class="badge bg-warning"><i class="bi bi-pause-circle"></i> Blocked</span>';
                                actionButton = `<button class="btn btn-sm btn-success" onclick='showInviteLdapUserModalInline(${JSON.stringify(user).replace(/'/g, "&#39;")})'>
                                       <i class="bi bi-arrow-clockwise me-1"></i>Reactivate
                                   </button>`;
                            } else {
                                statusBadge = '<span class="badge bg-secondary">Not Invited</span>';
                                actionButton = `<button class="btn btn-sm btn-primary" onclick='showInviteLdapUserModalInline(${JSON.stringify(user).replace(/'/g, "&#39;")})'>
                                       <i class="bi bi-person-plus me-1"></i>Invite
                                   </button>`;
                            }

                            return `
                                <tr>
                                    <td class="fw-semibold">${escapeHtml(user.username)}</td>
                                    <td>${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                                    <td>${escapeHtml(user.email)}</td>
                                    <td><small class="text-muted">${escapeHtml(user.dn).substring(0, 60)}${user.dn.length > 60 ? '...' : ''}</small></td>
                                    <td>${statusBadge}</td>
                                    <td>${actionButton}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;

        resultsDiv.innerHTML = tableHtml;

    } catch (error) {
        console.error('LDAP search error:', error);
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>Search Error:</strong> ${escapeHtml(error.message)}
            </div>
        `;
    }
}

/**
 * Build pagination controls for LDAP search
 */
function buildLdapPagination(currentPage, totalPages) {
    if (totalPages <= 1) return '';

    let html = '';

    // Previous button
    html += `
        <button class="btn btn-outline-secondary ${currentPage === 1 ? 'disabled' : ''}"
                onclick="searchLdapUsersInline(${currentPage - 1})"
                ${currentPage === 1 ? 'disabled' : ''}>
            <i class="bi bi-chevron-left"></i>
        </button>
    `;

    // Page numbers (show max 5 pages)
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        html += `<button class="btn btn-outline-secondary" onclick="searchLdapUsersInline(1)">1</button>`;
        if (startPage > 2) {
            html += `<button class="btn btn-outline-secondary" disabled>...</button>`;
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `
            <button class="btn ${i === currentPage ? 'btn-primary' : 'btn-outline-secondary'}"
                    onclick="searchLdapUsersInline(${i})">
                ${i}
            </button>
        `;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += `<button class="btn btn-outline-secondary" disabled>...</button>`;
        }
        html += `<button class="btn btn-outline-secondary" onclick="searchLdapUsersInline(${totalPages})">${totalPages}</button>`;
    }

    // Next button
    html += `
        <button class="btn btn-outline-secondary ${currentPage === totalPages ? 'disabled' : ''}"
                onclick="searchLdapUsersInline(${currentPage + 1})"
                ${currentPage === totalPages ? 'disabled' : ''}>
            <i class="bi bi-chevron-right"></i>
        </button>
    `;

    return html;
}

/**
 * Show invite modal for inline search
 */
async function showInviteLdapUserModalInline(user) {
    // Use correct field IDs matching the modal
    document.getElementById('ldapInviteUsername').value = user.username;
    document.getElementById('ldapInviteEmail').value = user.email;
    document.getElementById('ldapInviteFullName').value = user.full_name || '';
    document.getElementById('ldapUserDN').value = user.dn;

    // Set groups loading state
    const groupsSpan = document.getElementById('ldapGroupsList');
    if (groupsSpan) {
        groupsSpan.textContent = 'Loading...';
    }

    // Load organizations dropdown
    try {
        const response = await fetch('/api/organizations');
        if (response.ok) {
            const orgs = await response.json();
            const select = document.getElementById('ldapInviteOrganization');
            if (select) {
                select.innerHTML = '<option value="">Select organization...</option>' +
                    orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name || org.name)}</option>`).join('');
            }
        }
    } catch (error) {
        console.error('Error loading organizations:', error);
    }

    // Load LDAP groups for this user
    try {
        // First check if user object has groups from search
        if (user.groups && user.groups.length > 0) {
            // Extract CN from DN format (e.g., "cn=GroupName,ou=Groups,..." -> "GroupName")
            const groupNames = user.groups.map(g => {
                const match = g.match(/^cn=([^,]+)/i);
                return match ? match[1] : g;
            });
            if (groupsSpan) {
                groupsSpan.textContent = groupNames.join(', ');
            }
        } else {
            // Fetch groups from API
            const groupsResponse = await fetch('/api/ldap/user-groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user.username })
            });

            if (groupsResponse.ok) {
                const groupsData = await groupsResponse.json();
                if (groupsSpan) {
                    if (groupsData.groups && groupsData.groups.length > 0) {
                        // Extract CN from DN format
                        const groupNames = groupsData.groups.map(g => {
                            const match = g.match(/^cn=([^,]+)/i);
                            return match ? match[1] : g;
                        });
                        groupsSpan.textContent = groupNames.join(', ');
                    } else {
                        groupsSpan.textContent = 'No groups found';
                    }
                }
            } else {
                if (groupsSpan) {
                    groupsSpan.textContent = 'Could not load groups';
                }
            }
        }
    } catch (error) {
        console.error('Error loading LDAP groups:', error);
        if (groupsSpan) {
            groupsSpan.textContent = 'Error loading groups';
        }
    }

    const modal = new bootstrap.Modal(document.getElementById('ldapInviteModal'));
    modal.show();
}

// Keep old function for backward compatibility
function showLdapSearchModal() {
    // Deprecated - now using inline search
    showToast('Please use the search box above', 'info');
}

async function searchLdapUsers() {
    const query = document.getElementById('ldapSearchQuery').value.trim();
    if (!query) {
        showToast('Please enter a search query', 'warning');
        return;
    }

    const resultsDiv = document.getElementById('ldapSearchResultsTable');
    resultsDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="text-muted mt-2">Searching LDAP directory...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query, max_results: 1000 })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Search failed');
        }

        const results = await response.json();

        if (results.users.length === 0) {
            resultsDiv.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="bi bi-inbox" style="font-size: 2rem;"></i>
                    <p class="mt-2">No users found matching "${escapeHtml(query)}"</p>
                </div>
            `;
            return;
        }

        // Display results in a table
        const tableHtml = `
            <div class="table-responsive">
                <table class="table table-hover">
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
                        ${results.users.map(user => {
                            // Determine status badge based on exists_in_db and is_active
                            let statusBadge, actionButton;
                            if (user.exists_in_db && user.is_active) {
                                statusBadge = '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Active</span>';
                                actionButton = '<button class="btn btn-sm btn-secondary" disabled>Already Active</button>';
                            } else if (user.exists_in_db && !user.is_active) {
                                statusBadge = '<span class="badge bg-warning"><i class="bi bi-pause-circle"></i> Blocked</span>';
                                actionButton = `<button class="btn btn-sm btn-success" onclick='showInviteLdapUserModal(${JSON.stringify(user)})'>
                                       <i class="bi bi-arrow-clockwise me-1"></i>Reactivate
                                   </button>`;
                            } else {
                                statusBadge = '<span class="badge bg-secondary">Not Invited</span>';
                                actionButton = `<button class="btn btn-sm btn-primary" onclick='showInviteLdapUserModal(${JSON.stringify(user)})'>
                                       <i class="bi bi-person-plus me-1"></i>Invite
                                   </button>`;
                            }

                            return `
                                <tr>
                                    <td class="fw-semibold">${escapeHtml(user.username)}</td>
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

        resultsDiv.innerHTML = tableHtml;
        showToast(`Found ${results.users.length} user(s)`, 'success');

    } catch (error) {
        console.error('Error searching LDAP:', error);
        resultsDiv.innerHTML = `
            <div class="text-center text-danger py-4">
                <i class="bi bi-exclamation-triangle" style="font-size: 2rem;"></i>
                <p class="mt-2">Error: ${escapeHtml(error.message)}</p>
            </div>
        `;
        showToast(`Search failed: ${error.message}`, 'danger');
    }
}

async function showInviteLdapUserModal(userData) {
    try {
        // Populate form with user data
        document.getElementById('ldapUserDN').value = userData.dn;
        document.getElementById('ldapInviteUsername').value = userData.username;
        document.getElementById('ldapInviteEmail').value = userData.email;
        document.getElementById('ldapInviteFullName').value = userData.full_name || '';

        // Load organizations into dropdown
        const orgResponse = await fetch('/api/organizations');
        const orgs = await orgResponse.json();
        const orgSelect = document.getElementById('ldapInviteOrganization');
        orgSelect.innerHTML = '<option value="">Select organization...</option>' +
            orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`).join('');

        // Load user's LDAP groups
        document.getElementById('ldapGroupsList').textContent = 'Loading...';

        const groupsResponse = await fetch('/api/ldap/user-groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: userData.username })
        });

        if (groupsResponse.ok) {
            const groupsData = await groupsResponse.json();
            const groupsList = groupsData.groups.length > 0
                ? groupsData.groups.join(', ')
                : 'No groups found';
            document.getElementById('ldapGroupsList').textContent = groupsList;
        } else {
            document.getElementById('ldapGroupsList').textContent = 'Could not load groups';
        }

        // Show the modal
        const modalElement = document.getElementById('ldapInviteModal');
        const modal = new bootstrap.Modal(modalElement);
        modal.show();

    } catch (error) {
        console.error('Error showing invite modal:', error);
        showToast('Error opening invite modal: ' + error.message, 'danger');
    }
}

async function inviteLdapUser() {
    const username = document.getElementById('ldapInviteUsername').value;
    const email = document.getElementById('ldapInviteEmail').value;
    const fullName = document.getElementById('ldapInviteFullName').value;
    const dn = document.getElementById('ldapUserDN').value;
    const organizationId = parseInt(document.getElementById('ldapInviteOrganization').value);
    const role = document.getElementById('ldapInviteRole').value;

    if (!organizationId) {
        showToast('Please select an organization', 'warning');
        return;
    }

    if (!username || !email) {
        showToast('Username and email are required', 'warning');
        return;
    }

    // Get the invite button using querySelector (more reliable than event.target)
    const inviteBtn = document.querySelector('#ldapInviteModal .btn-primary');
    const originalHtml = inviteBtn ? inviteBtn.innerHTML : '';
    if (inviteBtn) {
        inviteBtn.disabled = true;
        inviteBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Inviting...';
    }

    try {
        const response = await fetch('/api/ldap/invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                email: email,
                full_name: fullName,
                dn: dn,
                organization_id: organizationId,
                role: role
            })
        });

        if (response.ok) {
            const result = await response.json();

            // Show success state
            if (inviteBtn) {
                inviteBtn.innerHTML = '<i class="bi bi-check-circle me-1"></i>Invited!';
                inviteBtn.classList.remove('btn-primary');
                inviteBtn.classList.add('btn-success');
            }

            showToast(`✓ User "${username}" invited successfully!`, 'success');

            // Close the invite modal after a brief delay
            setTimeout(() => {
                const inviteModal = bootstrap.Modal.getInstance(document.getElementById('ldapInviteModal'));
                if (inviteModal) inviteModal.hide();

                // Reset button state
                if (inviteBtn) {
                    inviteBtn.disabled = false;
                    inviteBtn.innerHTML = originalHtml;
                    inviteBtn.classList.remove('btn-success');
                    inviteBtn.classList.add('btn-primary');
                }
            }, 1500);

            // Refresh user list
            loadUsers();

            // Refresh search results if search is active
            const searchQuery = document.getElementById('ldapUserSearchQuery')?.value;
            if (searchQuery) {
                // Clear cache to force refresh and show updated status
                ldapSearchCache.query = '';
                searchLdapUsersInline();
            }
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error || 'Failed to invite user'}`, 'danger');

            // Reset button state on error
            if (inviteBtn) {
                inviteBtn.disabled = false;
                inviteBtn.innerHTML = originalHtml;
            }
        }
    } catch (error) {
        console.error('Error inviting LDAP user:', error);
        showToast(`Error inviting user: ${error.message}`, 'danger');

        // Reset button state on error
        if (inviteBtn) {
            inviteBtn.disabled = false;
            inviteBtn.innerHTML = originalHtml;
        }
    }
}

// ============================================================================
// LDAP Group Management
// ============================================================================

/**
 * Load all LDAP group mappings
 */
async function loadGroupMappings() {
    const tableBody = document.getElementById('groupMappingsTable');
    if (!tableBody) return;

    tableBody.innerHTML = `
        <tr>
            <td colspan="9" class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="text-muted mt-2">Loading group mappings...</p>
            </td>
        </tr>
    `;

    try {
        const response = await fetch('/api/ldap/groups/mappings');
        if (response.ok) {
            const mappings = await response.json();

            if (mappings.length === 0) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="9" class="text-center py-4">
                            <i class="bi bi-inbox text-muted" style="font-size: 3rem;"></i>
                            <p class="text-muted mt-3">No LDAP group mappings configured.</p>
                            <p class="text-muted">Click "Discover Groups" to find LDAP groups or "Create Mapping" to add one manually.</p>
                        </td>
                    </tr>
                `;
                return;
            }

            tableBody.innerHTML = mappings.map(mapping => {
                const statusBadge = mapping.is_active ?
                    '<span class="badge badge-status-active">Active</span>' :
                    '<span class="badge badge-status-inactive">Inactive</span>';

                const roleBadge = {
                    'super_admin': '<span class="badge badge-role-super">Super Admin</span>',
                    'org_admin': '<span class="badge badge-role-admin">Org Admin</span>',
                    'manager': '<span class="badge badge-role-manager">Manager</span>',
                    'user': '<span class="badge badge-role-user">User</span>'
                }[mapping.role] || mapping.role;

                const autoProvisionIcon = mapping.auto_provision ?
                    '<span class="badge badge-status-active">Yes</span>' :
                    '<span class="badge badge-status-inactive">No</span>';

                const lastSync = mapping.last_sync ?
                    new Date(mapping.last_sync).toLocaleString() :
                    'Never';

                const orgName = mapping.organization_name || 'All Organizations';

                return `
                    <tr>
                        <td>
                            <strong>${escapeHtml(mapping.ldap_group_cn)}</strong><br>
                            <small class="text-muted">${escapeHtml(mapping.ldap_group_dn)}</small>
                        </td>
                        <td>${escapeHtml(orgName)}</td>
                        <td>${roleBadge}</td>
                        <td><span class="badge bg-primary">${mapping.priority}</span></td>
                        <td class="text-center">${autoProvisionIcon}</td>
                        <td>${mapping.member_count || 0}</td>
                        <td><small>${lastSync}</small></td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="d-flex gap-1">
                                <button class="btn-action btn-action-edit" onclick="editGroupMapping(${mapping.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn-action btn-action-delete" onclick="deleteGroupMapping(${mapping.id})" title="Delete">
                                    <i class="bi bi-trash3"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        } else {
            const error = await response.json();
            tableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center py-4 text-danger">
                        <i class="bi bi-exclamation-triangle" style="font-size: 3rem;"></i>
                        <p class="mt-3">Error loading mappings: ${escapeHtml(error.error)}</p>
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading group mappings:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4 text-danger">
                    <p>Error loading group mappings</p>
                </td>
            </tr>
        `;
    }
}

/**
 * Show modal to create a new group mapping
 */
function showCreateMappingModal() {
    // Reset form
    document.getElementById('groupMappingForm').reset();
    document.getElementById('mappingId').value = '';
    document.getElementById('groupMappingModalTitle').textContent = 'Create Group Mapping';

    // Load organizations dropdown
    loadOrganizationsForMapping();

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('groupMappingModal'));
    modal.show();
}

/**
 * Edit an existing group mapping
 */
async function editGroupMapping(mappingId) {
    try {
        const response = await fetch('/api/ldap/groups/mappings');
        if (response.ok) {
            const mappings = await response.json();
            const mapping = mappings.find(m => m.id === mappingId);

            if (!mapping) {
                showToast('Mapping not found', 'danger');
                return;
            }

            // Populate form
            document.getElementById('mappingId').value = mapping.id;
            document.getElementById('ldapGroupDn').value = mapping.ldap_group_dn;
            document.getElementById('ldapGroupCn').value = mapping.ldap_group_cn;
            document.getElementById('ldapGroupDescription').value = mapping.ldap_group_description || '';
            document.getElementById('mappingRole').value = mapping.role;
            document.getElementById('mappingPriority').value = mapping.priority;
            document.getElementById('autoProvision').checked = mapping.auto_provision;
            document.getElementById('autoDeprovision').checked = mapping.auto_deprovision;
            document.getElementById('syncEnabled').checked = mapping.sync_enabled;

            // Load organizations and set selected
            await loadOrganizationsForMapping();
            document.getElementById('mappingOrganization').value = mapping.organization_id || '';

            document.getElementById('groupMappingModalTitle').textContent = 'Edit Group Mapping';

            const modal = new bootstrap.Modal(document.getElementById('groupMappingModal'));
            modal.show();
        }
    } catch (error) {
        console.error('Error loading mapping:', error);
        showToast('Error loading mapping', 'danger');
    }
}

/**
 * Save group mapping (create or update)
 */
async function saveGroupMapping() {
    const mappingId = document.getElementById('mappingId').value;
    const data = {
        ldap_group_dn: document.getElementById('ldapGroupDn').value.trim(),
        ldap_group_cn: document.getElementById('ldapGroupCn').value.trim(),
        ldap_group_description: document.getElementById('ldapGroupDescription').value.trim(),
        organization_id: document.getElementById('mappingOrganization').value || null,
        role: document.getElementById('mappingRole').value,
        priority: parseInt(document.getElementById('mappingPriority').value),
        auto_provision: document.getElementById('autoProvision').checked,
        auto_deprovision: document.getElementById('autoDeprovision').checked,
        sync_enabled: document.getElementById('syncEnabled').checked
    };

    // Validation
    if (!data.ldap_group_dn || !data.ldap_group_cn || !data.role) {
        showToast('Please fill in all required fields', 'warning');
        return;
    }

    try {
        const url = mappingId ?
            `/api/ldap/groups/mappings/${mappingId}` :
            '/api/ldap/groups/mappings';
        const method = mappingId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            showToast(`Group mapping ${mappingId ? 'updated' : 'created'} successfully`, 'success');

            const modal = bootstrap.Modal.getInstance(document.getElementById('groupMappingModal'));
            modal.hide();

            loadGroupMappings();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error saving mapping:', error);
        showToast('Error saving mapping', 'danger');
    }
}

/**
 * Delete a group mapping
 */
async function deleteGroupMapping(mappingId) {
    const confirmed = await showConfirm(
        'Are you sure you want to delete this group mapping?<br><br>This action cannot be undone.',
        'Delete Group Mapping',
        'Delete',
        'btn-danger'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/ldap/groups/mappings/${mappingId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('Group mapping deleted successfully', 'success');
            loadGroupMappings();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error deleting mapping:', error);
        showToast('Error deleting mapping', 'danger');
    }
}

/**
 * Load organizations for the mapping dropdown
 */
async function loadOrganizationsForMapping() {
    const select = document.getElementById('mappingOrganization');
    if (!select) return;

    try {
        const response = await fetch('/api/organizations');
        if (response.ok) {
            const orgs = await response.json();
            select.innerHTML = '<option value="">All Organizations</option>' +
                orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name || org.name)}</option>`).join('');
        }
    } catch (error) {
        console.error('Error loading organizations:', error);
    }
}

/**
 * Discover LDAP groups
 */
/**
 * Toggle group discovery panel visibility
 */
function toggleGroupDiscovery() {
    const panel = document.getElementById('groupDiscoveryPanel');
    const icon = document.getElementById('discoveryToggleIcon');

    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        icon.className = 'bi bi-chevron-up';
    } else {
        panel.style.display = 'none';
        icon.className = 'bi bi-chevron-down';
    }
}

/**
 * Inline LDAP group discovery (replaces modal)
 */
async function performGroupDiscoveryInline() {
    const searchBase = document.getElementById('groupSearchBaseInline').value.trim();
    const container = document.getElementById('discoveredGroupsContainerInline');

    if (!searchBase) {
        showToast('Please enter a search base DN', 'warning');
        return;
    }

    container.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="text-muted mt-3">Discovering LDAP groups in ${escapeHtml(searchBase)}...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/groups/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ search_base: searchBase })
        });

        if (response.ok) {
            const result = await response.json();
            const groups = result.groups || [];

            if (groups.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i>
                        <strong>No groups found</strong> in the specified search base DN.
                        <hr>
                        <small>Try a different search base or verify your LDAP configuration.</small>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="alert alert-success mb-3">
                    <i class="bi bi-check-circle me-2"></i>
                    <strong>Found ${groups.length} LDAP group(s)</strong> - Click "Create Mapping" to configure role assignments
                </div>
                <div class="table-responsive">
                    <table class="table table-hover table-sm">
                        <thead class="table-light">
                            <tr>
                                <th>Group Name</th>
                                <th>Distinguished Name</th>
                                <th>Members</th>
                                <th>Description</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${groups.map(group => `
                                <tr>
                                    <td class="fw-semibold">${escapeHtml(group.cn)}</td>
                                    <td><small class="text-muted">${escapeHtml(group.dn)}</small></td>
                                    <td>
                                        <span class="badge bg-info">${group.member_count || 0} members</span>
                                    </td>
                                    <td><small>${escapeHtml(group.description || '-')}</small></td>
                                    <td>
                                        <button class="btn btn-sm btn-primary"
                                                onclick="createMappingFromDiscoveryInline('${escapeHtml(group.dn)}', '${escapeHtml(group.cn)}', '${escapeHtml(group.description || '')}')">
                                            <i class="bi bi-plus-circle me-1"></i>Create Mapping
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else {
            const error = await response.json();
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    <strong>Discovery Error:</strong> ${escapeHtml(error.error)}
                </div>
            `;
        }
    } catch (error) {
        console.error('Error discovering groups:', error);
        container.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>Error:</strong> Failed to discover groups. Please check your LDAP configuration.
            </div>
        `;
    }
}

/**
 * Create mapping from inline discovery results
 */
function createMappingFromDiscoveryInline(dn, cn, description) {
    // Pre-fill the create mapping modal with discovered group info
    document.getElementById('groupDN').value = dn;
    document.getElementById('groupName').value = cn;
    if (description) {
        document.getElementById('mappingDescription').value = description;
    }

    // Show the create mapping modal
    showCreateMappingModal();

    // Optionally collapse the discovery panel
    const panel = document.getElementById('groupDiscoveryPanel');
    const icon = document.getElementById('discoveryToggleIcon');
    panel.style.display = 'none';
    icon.className = 'bi bi-chevron-down';
}

// Keep old function for backward compatibility
function discoverLdapGroups() {
    // Deprecated - now using inline discovery
    toggleGroupDiscovery();
}

/**
 * Perform LDAP group discovery
 */
async function performGroupDiscovery() {
    const searchBase = document.getElementById('groupSearchBase').value.trim();
    const container = document.getElementById('discoveredGroupsContainer');

    if (!searchBase) {
        showToast('Please enter a search base DN', 'warning');
        return;
    }

    container.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="text-muted mt-3">Discovering LDAP groups...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/groups/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ search_base: searchBase })
        });

        if (response.ok) {
            const result = await response.json();
            const groups = result.groups || [];

            if (groups.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i>
                        No groups found in the specified search base.
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="alert alert-success mb-3">
                    <i class="bi bi-check-circle me-2"></i>
                    Found ${groups.length} LDAP group(s)
                </div>
                <div class="table-responsive">
                    <table class="table table-hover table-sm">
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Distinguished Name</th>
                                <th>Members</th>
                                <th>Description</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${groups.map(group => `
                                <tr>
                                    <td><strong>${escapeHtml(group.cn)}</strong></td>
                                    <td><small>${escapeHtml(group.dn)}</small></td>
                                    <td>${group.member_count || 0}</td>
                                    <td><small>${escapeHtml(group.description || '-')}</small></td>
                                    <td>
                                        <button class="btn btn-sm btn-primary" onclick="createMappingFromDiscovery('${escapeHtml(group.dn)}', '${escapeHtml(group.cn)}', '${escapeHtml(group.description || '')}')">
                                            <i class="bi bi-plus-circle me-1"></i>Create Mapping
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else {
            const error = await response.json();
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Error: ${escapeHtml(error.error)}
                </div>
            `;
        }
    } catch (error) {
        console.error('Error discovering groups:', error);
        container.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Error discovering groups. Please check your LDAP configuration.
            </div>
        `;
    }
}

/**
 * Create a mapping from discovered group
 */
function createMappingFromDiscovery(dn, cn, description) {
    // Close discovery modal
    const discoveryModal = bootstrap.Modal.getInstance(document.getElementById('ldapDiscoveryModal'));
    if (discoveryModal) {
        discoveryModal.hide();
    }

    // Pre-fill mapping form
    document.getElementById('groupMappingForm').reset();
    document.getElementById('mappingId').value = '';
    document.getElementById('ldapGroupDn').value = dn;
    document.getElementById('ldapGroupCn').value = cn;
    document.getElementById('ldapGroupDescription').value = description;
    document.getElementById('groupMappingModalTitle').textContent = 'Create Group Mapping';

    // Load organizations
    loadOrganizationsForMapping();

    // Show mapping modal
    const modal = new bootstrap.Modal(document.getElementById('groupMappingModal'));
    modal.show();
}

/**
 * Trigger manual LDAP sync
 */
async function triggerManualSync() {
    const button = document.getElementById('syncButton');
    const statusDiv = document.getElementById('syncStatus');

    if (!button || !statusDiv) return;

    const originalButtonHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Syncing...';

    statusDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary mb-3" role="status"></div>
            <h5>Synchronization in Progress</h5>
            <p class="text-muted">Please wait while we synchronize all LDAP users...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/groups/sync/manual', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        if (response.ok) {
            const result = await response.json();
            const stats = result.stats;

            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <h5 class="alert-heading"><i class="bi bi-check-circle me-2"></i>Synchronization Complete!</h5>
                    <hr>
                    <div class="row text-center">
                        <div class="col-md-3">
                            <h4>${stats.users_processed || 0}</h4>
                            <small>Users Processed</small>
                        </div>
                        <div class="col-md-3">
                            <h4 class="text-success">${stats.roles_changed || 0}</h4>
                            <small>Roles Updated</small>
                        </div>
                        <div class="col-md-3">
                            <h4 class="text-info">${stats.organizations_changed || 0}</h4>
                            <small>Org Changes</small>
                        </div>
                        <div class="col-md-3">
                            <h4 class="text-danger">${typeof stats.errors === 'number' ? stats.errors : (Array.isArray(stats.errors) ? stats.errors.length : 0)}</h4>
                            <small>Errors</small>
                        </div>
                    </div>
                    <hr>
                    <p class="mb-0"><small>Sync ID: ${result.sync_id} | Duration: ${result.duration.toFixed(2)}s</small></p>
                </div>
            `;

            showToast('LDAP synchronization completed successfully', 'success');

            // Reload sync stats and history
            loadSyncStats();
            loadSyncHistory();
        } else {
            const error = await response.json();
            statusDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    <strong>Synchronization Failed:</strong> ${escapeHtml(error.error)}
                </div>
            `;
            showToast(`Sync failed: ${error.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error triggering sync:', error);
        statusDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>Error:</strong> Failed to trigger synchronization
            </div>
        `;
        showToast('Error triggering sync', 'danger');
    } finally {
        button.disabled = false;
        button.innerHTML = originalButtonHtml;
    }
}

/**
 * Load sync statistics
 */
async function loadSyncStats() {
    try {
        const response = await fetch('/api/ldap/groups/sync/history?limit=1');
        if (response.ok) {
            const history = await response.json();
            const latestSync = history.length > 0 ? history[0] : null;

            // Update stats displays
            if (latestSync) {
                document.getElementById('syncStatsLastSync').textContent =
                    new Date(latestSync.started_at).toLocaleString();
            }

            // Count total LDAP users
            const usersResponse = await fetch('/api/users');
            if (usersResponse.ok) {
                const users = await usersResponse.json();
                const ldapUsers = users.filter(u => u.auth_type === 'ldap');
                document.getElementById('syncStatsTotal').textContent = ldapUsers.length;
            }

            // Count successful syncs and errors from history
            const historyResponse = await fetch('/api/ldap/groups/sync/history?limit=100');
            if (historyResponse.ok) {
                const result = await historyResponse.json();
                const allHistory = result.logs || [];
                const successCount = allHistory.filter(s => s.status === 'completed').length;
                const errorCount = allHistory.filter(s => s.status === 'failed').length;

                document.getElementById('syncStatsSuccess').textContent = successCount;
                document.getElementById('syncStatsErrors').textContent = errorCount;
            }
        }
    } catch (error) {
        console.error('Error loading sync stats:', error);
    }
}

/**
 * Load sync history
 */
async function loadSyncHistory() {
    const tableBody = document.getElementById('syncHistoryTable');
    if (!tableBody) return;

    try {
        const response = await fetch('/api/ldap/groups/sync/history?limit=20');
        if (response.ok) {
            const result = await response.json();
            const history = result.logs || [];

            if (history.length === 0) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="9" class="text-center py-4 text-muted">
                            No synchronization history available
                        </td>
                    </tr>
                `;
                return;
            }

            tableBody.innerHTML = history.map(sync => {
                const statusBadge = sync.status === 'completed' ?
                    '<span class="badge bg-success">Completed</span>' :
                    sync.status === 'failed' ?
                    '<span class="badge bg-danger">Failed</span>' :
                    '<span class="badge bg-warning">In Progress</span>';

                const duration = sync.duration ? `${sync.duration.toFixed(2)}s` : '-';
                const startedAt = new Date(sync.started_at).toLocaleString();

                return `
                    <tr>
                        <td><small>${escapeHtml(sync.sync_id)}</small></td>
                        <td>${escapeHtml(sync.sync_type)}</td>
                        <td><small>${startedAt}</small></td>
                        <td>${duration}</td>
                        <td>${statusBadge}</td>
                        <td>${sync.users_added || 0}</td>
                        <td>${sync.users_updated || 0}</td>
                        <td>${sync.users_deactivated || 0}</td>
                        <td>${sync.error_count || 0}</td>
                    </tr>
                `;
            }).join('');
        } else {
            // Handle API errors (403, 500, etc.)
            tableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center py-4 text-danger">
                        Error loading sync history: ${response.status} ${response.statusText}
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading sync history:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4 text-danger">
                    Error loading sync history: ${error.message}
                </td>
            </tr>
        `;
    }
}

/**
 * Load audit logs
 */
async function loadAuditLogs(page = 1, search = '') {
    const tableBody = document.getElementById('auditLogTable');
    if (!tableBody) return;

    tableBody.innerHTML = `
        <tr>
            <td colspan="7" class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="text-muted mt-2">Loading audit logs...</p>
            </td>
        </tr>
    `;

    try {
        const params = new URLSearchParams({
            page: page,
            limit: 50
        });
        if (search) {
            params.append('search', search);
        }

        const response = await fetch(`/api/ldap/groups/audit?${params}`);
        if (response.ok) {
            const result = await response.json();
            const logs = result.logs || [];

            if (logs.length === 0) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="7" class="text-center py-4 text-muted">
                            No audit logs found
                        </td>
                    </tr>
                `;
                return;
            }

            tableBody.innerHTML = logs.map(log => {
                const eventTypeColors = {
                    'user_sync': 'info',
                    'role_change': 'warning',
                    'org_change': 'primary',
                    'user_provision': 'success',
                    'user_deprovision': 'danger',
                    'manual_sync': 'secondary'
                };

                const badgeColor = eventTypeColors[log.event_type] || 'secondary';
                const eventBadge = `<span class="badge bg-${badgeColor}">${escapeHtml(log.event_type)}</span>`;

                const timestamp = new Date(log.timestamp).toLocaleString();
                const change = log.field_changed ?
                    `${escapeHtml(log.field_changed)}: ${escapeHtml(log.old_value || '-')} → ${escapeHtml(log.new_value || '-')}` :
                    '-';

                return `
                    <tr>
                        <td><small>${timestamp}</small></td>
                        <td>${eventBadge}</td>
                        <td>${escapeHtml(log.user_username || '-')}</td>
                        <td>${escapeHtml(log.target_user_username || '-')}</td>
                        <td><small>${escapeHtml(log.ldap_dn || '-')}</small></td>
                        <td><small>${change}</small></td>
                        <td><small>${escapeHtml(log.ip_address || '-')}</small></td>
                    </tr>
                `;
            }).join('');

            // Update pagination
            updateAuditPagination(result.page, result.total_pages);
        } else {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-4 text-danger">
                        Error loading audit logs: ${response.status} ${response.statusText}
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading audit logs:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-danger">
                    Error loading audit logs: ${error.message}
                </td>
            </tr>
        `;
    }
}

/**
 * Update audit log pagination
 */
function updateAuditPagination(currentPage, totalPages) {
    const pagination = document.getElementById('auditPagination');
    if (!pagination) return;

    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }

    let html = '';
    for (let i = 1; i <= totalPages; i++) {
        const active = i === currentPage ? 'active' : '';
        html += `
            <li class="page-item ${active}">
                <a class="page-link" href="#" onclick="loadAuditLogs(${i}); return false;">${i}</a>
            </li>
        `;
    }

    pagination.innerHTML = html;
}

/**
 * Search audit logs
 */
function searchAuditLogs() {
    const searchInput = document.getElementById('auditSearchInput');
    if (searchInput) {
        loadAuditLogs(1, searchInput.value);
    }
}

/**
 * Load last scheduled sync time
 */
async function loadLastScheduledSync() {
    try {
        const response = await fetch('/api/ldap/groups/sync/history?limit=1');
        if (response.ok) {
            const history = await response.json();
            const displayElement = document.getElementById('ldapLastScheduledSync');

            if (displayElement) {
                if (history.length > 0) {
                    const lastSync = history[0];
                    // Check if this was a scheduled sync (not manual)
                    if (lastSync.sync_type === 'scheduled_sync') {
                        const syncDate = new Date(lastSync.started_at);
                        displayElement.textContent = syncDate.toLocaleString();
                        displayElement.classList.add('text-success');
                    } else {
                        displayElement.textContent = 'Never';
                        displayElement.classList.remove('text-success');
                    }
                } else {
                    displayElement.textContent = 'Never';
                    displayElement.classList.remove('text-success');
                }
            }
        }
    } catch (error) {
        console.error('Error loading last scheduled sync:', error);
    }
}

/**
 * Helper function to escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
