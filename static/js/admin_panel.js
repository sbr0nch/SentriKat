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
        alert('Error: Bootstrap JavaScript library is not loaded. Please refresh the page.');
        return;
    }

    try {
        loadUsers();
        loadOrganizations();
        loadOrganizationsDropdown();

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
                // Role badge based on new role system
                const roleMap = {
                    'super_admin': { badge: 'bg-danger', icon: 'star-fill', text: 'Super Admin' },
                    'org_admin': { badge: 'bg-warning', icon: 'shield-check', text: 'Org Admin' },
                    'manager': { badge: 'bg-info', icon: 'gear', text: 'Manager' },
                    'user': { badge: 'bg-secondary', icon: 'person', text: 'User' }
                };

                const role = roleMap[user.role] || roleMap['user'];
                const roleBadge = `<span class="badge ${role.badge}"><i class="bi bi-${role.icon}"></i> ${role.text}</span>`;

                const statusBadge = user.is_active
                    ? '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Active</span>'
                    : '<span class="badge bg-secondary"><i class="bi bi-pause-circle"></i> Inactive</span>';

                const authBadge = user.auth_type === 'ldap'
                    ? '<span class="badge bg-primary"><i class="bi bi-diagram-3"></i> LDAP</span>'
                    : '<span class="badge bg-secondary"><i class="bi bi-key"></i> Local</span>';

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
        alert('Error opening user modal: ' + error.message);
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
        alert('Error opening organization modal: ' + error.message);
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
            showToast(result.message || '✓ SMTP connection successful!', 'success');
        } else {
            showToast(`✗ SMTP test failed: ${result.error || result.message || 'Unknown error'}`, 'danger');
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
        ldap_use_tls: document.getElementById('ldapUseTLS').checked
    };

    try {
        const response = await fetch('/api/settings/ldap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('✓ LDAP settings saved successfully', 'success');
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
