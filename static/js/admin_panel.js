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
    loadUsers();
    loadOrganizations();
    loadOrganizationsDropdown();

    // Tab change handlers
    document.getElementById('organizations-tab').addEventListener('shown.bs.tab', function() {
        loadOrganizations();
    });
});

// ============================================================================
// User Management
// ============================================================================

async function loadUsers() {
    const tbody = document.getElementById('usersTable');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    try {
        const response = await fetch('/api/users');
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
                const roleBadge = user.is_admin
                    ? '<span class="badge bg-danger"><i class="bi bi-shield-check"></i> Admin</span>'
                    : user.can_manage_products
                    ? '<span class="badge bg-info">Manager</span>'
                    : '<span class="badge bg-secondary">Viewer</span>';

                const statusBadge = user.is_active
                    ? '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Active</span>'
                    : '<span class="badge bg-secondary"><i class="bi bi-pause-circle"></i> Inactive</span>';

                const authBadge = user.auth_type === 'ldap'
                    ? '<span class="badge bg-primary"><i class="bi bi-diagram-3"></i> LDAP</span>'
                    : '<span class="badge bg-secondary"><i class="bi bi-key"></i> Local</span>';

                return `
                    <tr>
                        <td class="fw-semibold">${escapeHtml(user.username)}</td>
                        <td>${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                        <td>${escapeHtml(user.email)}</td>
                        <td>${user.organization_id ? `Org ${user.organization_id}` : '<span class="text-muted">-</span>'}</td>
                        <td>${authBadge}</td>
                        <td>${roleBadge}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-primary" onclick="editUser(${user.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn btn-outline-danger" onclick="deleteUser(${user.id}, '${escapeHtml(user.username)}')" title="Delete">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
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
    currentUserId = null;
    document.getElementById('userModalTitle').innerHTML = '<i class="bi bi-person-plus me-2"></i>Create User';
    document.getElementById('userForm').reset();

    // Reset to local auth by default
    document.getElementById('authLocal').checked = true;
    document.getElementById('isActive').checked = true;
    document.getElementById('canManageProducts').checked = true;

    toggleAuthFields();

    new bootstrap.Modal(document.getElementById('userModal')).show();
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
        document.getElementById('isAdmin').checked = user.is_admin;
        document.getElementById('canManageProducts').checked = user.can_manage_products;
        document.getElementById('canViewAllOrgs').checked = user.can_view_all_orgs;
        document.getElementById('isActive').checked = user.is_active;

        // Set auth type
        if (user.auth_type === 'ldap') {
            document.getElementById('authLdap').checked = true;
        } else {
            document.getElementById('authLocal').checked = true;
        }

        toggleAuthFields();

        // For edit mode, password is optional
        document.getElementById('password').required = false;
        document.getElementById('passwordConfirm').required = false;

        new bootstrap.Modal(document.getElementById('userModal')).show();
    } catch (error) {
        showToast(`Error loading user: ${error.message}`, 'danger');
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
        is_admin: document.getElementById('isAdmin').checked,
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
    if (!confirm(`Are you sure you want to delete user "${username}"?\n\nThis action cannot be undone.`)) {
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

// ============================================================================
// Organization Management
// ============================================================================

async function loadOrganizations() {
    const tbody = document.getElementById('orgsTable');
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    try {
        const response = await fetch('/api/organizations');
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
                    ? '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Yes</span>'
                    : '<span class="badge bg-secondary">No</span>';

                const statusBadge = org.active
                    ? '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Active</span>'
                    : '<span class="badge bg-secondary"><i class="bi bi-pause-circle"></i> Inactive</span>';

                return `
                    <tr>
                        <td class="fw-semibold">${escapeHtml(org.name)}</td>
                        <td>${escapeHtml(org.display_name)}</td>
                        <td><span class="badge bg-info">${org.user_count || 0}</span></td>
                        <td>${smtpBadge}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-outline-primary" onclick="editOrganization(${org.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                ${org.name !== 'default' ? `
                                <button class="btn btn-outline-danger" onclick="deleteOrganization(${org.id}, '${escapeHtml(org.display_name)}')" title="Delete">
                                    <i class="bi bi-trash"></i>
                                </button>
                                ` : ''}
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (error) {
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
    currentOrgId = null;
    document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-building me-2"></i>Create Organization';
    document.getElementById('orgForm').reset();
    document.getElementById('orgActive').checked = true;
    document.getElementById('alertCritical').checked = true;
    document.getElementById('alertNewCVE').checked = true;
    document.getElementById('alertRansomware').checked = true;
    document.getElementById('smtpUseTls').checked = true;
    document.getElementById('smtpPort').value = 587;

    new bootstrap.Modal(document.getElementById('orgModal')).show();
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
        document.getElementById('smtpPassword').value = org.smtp_password || '';
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
            showToast('✓ SMTP connection successful!', 'success');
        } else {
            showToast(`✗ SMTP test failed: ${result.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error testing SMTP: ${error.message}`, 'danger');
    }
}

async function deleteOrganization(orgId, displayName) {
    if (!confirm(`Are you sure you want to delete organization "${displayName}"?\n\nThis will also delete all users and products associated with this organization.\n\nThis action cannot be undone.`)) {
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

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
