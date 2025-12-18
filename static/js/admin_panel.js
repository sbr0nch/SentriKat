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

        const auditLogTab = document.getElementById('audit-log-tab');
        if (auditLogTab) {
            auditLogTab.addEventListener('shown.bs.pill', function() {
                loadAuditLogs();
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

// ============================================================================
// LDAP User Management
// ============================================================================

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

function showLdapSearchModal() {
    try {
        document.getElementById('ldapSearchQuery').value = '';
        document.getElementById('ldapSearchResultsTable').innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="bi bi-search" style="font-size: 2rem;"></i>
                <p class="mt-2">Enter a search query and click Search</p>
            </div>
        `;

        const modalElement = document.getElementById('ldapSearchModal');
        const modal = new bootstrap.Modal(modalElement);
        modal.show();
    } catch (error) {
        console.error('Error showing LDAP search modal:', error);
        showToast('Error opening search modal: ' + error.message, 'danger');
    }
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
            body: JSON.stringify({ search_query: query })
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
                            const statusBadge = user.exists_in_db
                                ? '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Already Invited</span>'
                                : '<span class="badge bg-secondary">Not Invited</span>';

                            const actionButton = user.exists_in_db
                                ? '<button class="btn btn-sm btn-secondary" disabled>Already Exists</button>'
                                : `<button class="btn btn-sm btn-primary" onclick='showInviteLdapUserModal(${JSON.stringify(user)})'>
                                       <i class="bi bi-person-plus me-1"></i>Invite
                                   </button>`;

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
            showToast('✓ LDAP user invited successfully', 'success');

            // Close the invite modal
            const inviteModal = bootstrap.Modal.getInstance(document.getElementById('ldapInviteModal'));
            inviteModal.hide();

            // Refresh user list
            loadUsers();

            // Refresh search results if search modal is still open
            const searchQuery = document.getElementById('ldapSearchQuery').value;
            if (searchQuery) {
                searchLdapUsers();
            }
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        console.error('Error inviting LDAP user:', error);
        showToast(`Error inviting user: ${error.message}`, 'danger');
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
                    '<span class="badge bg-success">Active</span>' :
                    '<span class="badge bg-secondary">Inactive</span>';

                const roleBadge = {
                    'super_admin': '<span class="badge bg-danger">Super Admin</span>',
                    'org_admin': '<span class="badge bg-warning">Org Admin</span>',
                    'manager': '<span class="badge bg-info">Manager</span>',
                    'user': '<span class="badge bg-secondary">User</span>'
                }[mapping.role] || mapping.role;

                const autoProvisionIcon = mapping.auto_provision ?
                    '<i class="bi bi-check-circle-fill text-success" title="Auto-provision enabled"></i>' :
                    '<i class="bi bi-x-circle-fill text-muted" title="Auto-provision disabled"></i>';

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
                            <button class="btn btn-sm btn-outline-primary me-1" onclick="editGroupMapping(${mapping.id})" title="Edit">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteGroupMapping(${mapping.id})" title="Delete">
                                <i class="bi bi-trash"></i>
                            </button>
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
    if (!confirm('Are you sure you want to delete this group mapping? This action cannot be undone.')) {
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
function discoverLdapGroups() {
    const modal = new bootstrap.Modal(document.getElementById('ldapDiscoveryModal'));
    modal.show();
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
                            <h4 class="text-danger">${stats.errors || 0}</h4>
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
                const allHistory = await historyResponse.json();
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
            const history = await response.json();

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
        }
    } catch (error) {
        console.error('Error loading sync history:', error);
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
                        Error loading audit logs
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading audit logs:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-danger">
                    Error loading audit logs
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
 * Helper function to escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
