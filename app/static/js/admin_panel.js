/**
 * SentriKat Admin Panel JavaScript
 * Handles user management, organization management, and LDAP functionality
 */

let currentUserId = null;
let currentOrgId = null;

// ============================================================================
// USER MANAGEMENT
// ============================================================================

async function saveUser() {
    const userId = document.getElementById('userId').value;
    const isEdit = !!userId;

    // Collect form data
    const userData = {
        username: document.getElementById('username').value.trim(),
        email: document.getElementById('email').value.trim(),
        full_name: document.getElementById('fullName').value.trim(),
        organization_id: parseInt(document.getElementById('organization').value),
        role: document.getElementById('userRole').value,
        is_active: document.getElementById('isActive').checked
    };

    // Add password if provided (required for new local users)
    const authType = document.querySelector('input[name="authType"]:checked').value;
    const password = document.getElementById('password').value;
    const passwordConfirm = document.getElementById('passwordConfirm').value;

    if (authType === 'local' && (!isEdit || password)) {
        if (!password || password.length < 8) {
            showToast('Password must be at least 8 characters', 'danger');
            return;
        }
        if (password !== passwordConfirm) {
            showToast('Passwords do not match', 'danger');
            return;
        }
        userData.password = password;
    }

    // Validate required fields
    if (!userData.email || !userData.organization_id) {
        showToast('Please fill in all required fields', 'warning');
        return;
    }

    try {
        const url = isEdit ? `/api/users/${userId}` : '/api/users';
        const method = isEdit ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });

        if (response.ok) {
            showToast(`✓ User ${isEdit ? 'updated' : 'created'} successfully`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
            loadUsers();  // Reload user list
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error || 'Failed to save user'}`, 'danger');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    }
}

async function loadUsers() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();

        const tbody = document.getElementById('usersTable');
        if (!tbody) return;

        tbody.innerHTML = users.map(user => `
            <tr>
                <td>${escapeHtml(user.username)}</td>
                <td>${escapeHtml(user.email || '')}</td>
                <td>${escapeHtml(user.full_name || '')}</td>
                <td><span class="badge bg-${user.is_active ? 'success' : 'secondary'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
                <td><span class="badge bg-info">${user.role}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="editUser(${user.id})">
                        <i class="bi bi-pencil"></i> Edit
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteUser(${user.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading users:', error);
        showToast('Failed to load users', 'danger');
    }
}

async function editUser(userId) {
    try {
        const response = await fetch(`/api/users/${userId}`);
        const user = await response.json();

        // Populate form
        document.getElementById('userId').value = user.id;
        document.getElementById('username').value = user.username || '';
        document.getElementById('email').value = user.email || '';
        document.getElementById('fullName').value = user.full_name || '';
        document.getElementById('organization').value = user.organization_id || '';
        document.getElementById('userRole').value = user.role || 'user';
        document.getElementById('isActive').checked = user.is_active;

        // Clear password fields for edit
        document.getElementById('password').value = '';
        document.getElementById('passwordConfirm').value = '';

        // Update modal title
        document.getElementById('userModalTitle').innerHTML = '<i class="bi bi-pencil me-2"></i>Edit User';

        // Show modal
        new bootstrap.Modal(document.getElementById('userModal')).show();
    } catch (error) {
        showToast('Error loading user data', 'danger');
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
        const response = await fetch(`/api/users/${userId}`, { method: 'DELETE' });

        if (response.ok) {
            showToast('✓ User deleted successfully', 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    }
}

// ============================================================================
// ORGANIZATION MANAGEMENT
// ============================================================================

function showCreateOrgModal() {
    // Clear the form for new organization
    document.getElementById('orgId').value = '';
    document.getElementById('orgName').value = '';
    document.getElementById('orgDescription').value = '';
    document.getElementById('orgEmails').value = '';
    document.getElementById('orgActive').checked = true;

    // Clear SMTP fields if they exist
    const smtpFields = ['smtpHost', 'smtpPort', 'smtpUsername', 'smtpPassword', 'smtpFromEmail', 'smtpFromName'];
    smtpFields.forEach(field => {
        const el = document.getElementById(field);
        if (el) el.value = field === 'smtpPort' ? '587' : '';
    });

    // Update modal title
    document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-building me-2"></i>Create Organization';

    // Show modal
    new bootstrap.Modal(document.getElementById('orgModal')).show();
}

async function saveOrganization() {
    const orgId = document.getElementById('orgId').value;
    const isEdit = !!orgId;

    // Parse notification emails from comma-separated input
    const emailsInput = document.getElementById('orgEmails').value.trim();
    const notificationEmails = emailsInput
        ? emailsInput.split(',').map(e => e.trim()).filter(e => e.length > 0)
        : [];

    const orgData = {
        name: document.getElementById('orgName').value.trim(),
        description: document.getElementById('orgDescription').value.trim(),
        active: document.getElementById('orgActive').checked,
        notification_emails: notificationEmails
    };

    if (!orgData.name) {
        showToast('Organization name is required', 'warning');
        return;
    }

    try {
        const url = isEdit ? `/api/organizations/${orgId}` : '/api/organizations';
        const method = isEdit ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orgData)
        });

        if (response.ok) {
            showToast(`✓ Organization ${isEdit ? 'updated' : 'created'} successfully`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('orgModal')).hide();
            loadOrganizations();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    }
}

async function deleteOrganization(orgId) {
    if (!confirm('Are you sure you want to delete this organization? This will also delete all associated users and products.')) {
        return;
    }

    try {
        const response = await fetch(`/api/organizations/${orgId}`, { method: 'DELETE' });

        if (response.ok) {
            showToast('✓ Organization deleted successfully', 'success');
            loadOrganizations();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    }
}

async function loadOrganizations() {
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        const tbody = document.getElementById('organizationsTable');
        if (!tbody) return;

        tbody.innerHTML = orgs.map(org => `
            <tr>
                <td>${escapeHtml(org.name)}</td>
                <td>${escapeHtml(org.description || '')}</td>
                <td><span class="badge bg-${org.active ? 'success' : 'secondary'}">${org.active ? 'Active' : 'Inactive'}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="editOrganization(${org.id})">
                        <i class="bi bi-pencil"></i> Edit
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteOrganization(${org.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading organizations:', error);
        showToast('Failed to load organizations', 'danger');
    }
}

async function editOrganization(orgId) {
    try {
        const response = await fetch(`/api/organizations/${orgId}`);
        const org = await response.json();

        // Populate form
        document.getElementById('orgId').value = org.id;
        document.getElementById('orgName').value = org.name || '';
        document.getElementById('orgDescription').value = org.description || '';
        document.getElementById('orgActive').checked = org.active;

        // Populate notification emails (array to comma-separated string)
        const emails = org.notification_emails || [];
        document.getElementById('orgEmails').value = Array.isArray(emails) ? emails.join(', ') : '';

        // Update modal title
        document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-pencil me-2"></i>Edit Organization';

        // Show modal
        new bootstrap.Modal(document.getElementById('orgModal')).show();
    } catch (error) {
        showToast('Error loading organization data', 'danger');
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    // Create toast HTML
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    // Add to container or create one
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'position-fixed top-0 end-0 p-3';
        container.style.zIndex = '11';
        document.body.appendChild(container);
    }

    container.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    // Remove after hidden
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

// ============================================================================
// LDAP USER MANAGEMENT
// ============================================================================

let ldapSearchResults = [];
let currentLdapUserIndex = null;

async function searchLdapUsersInline() {
    const query = document.getElementById('ldapUserSearchQuery').value.trim() || '*';
    const maxResults = parseInt(document.getElementById('ldapSearchPageSize').value);

    const resultsDiv = document.getElementById('ldapSearchResultsTable');
    const statsDiv = document.getElementById('ldapSearchStats');

    // Show loading
    resultsDiv.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="mt-3">Searching LDAP directory...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/ldap/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query, max_results: maxResults })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            resultsDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Search Error: ${data.error || 'Unknown error'}
                </div>
            `;
            statsDiv.style.display = 'none';
            return;
        }

        ldapSearchResults = data.users || [];

        if (ldapSearchResults.length === 0) {
            resultsDiv.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-search" style="font-size: 3rem;"></i>
                    <p class="mt-3">No users found matching "${query}"</p>
                    <p class="text-muted">Try a different search term</p>
                </div>
            `;
            statsDiv.style.display = 'none';
            return;
        }

        // Show results count
        document.getElementById('ldapResultCount').textContent = ldapSearchResults.length;
        statsDiv.style.display = 'block';

        // Build results table
        let tableHTML = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Email</th>
                            <th>Groups</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        ldapSearchResults.forEach((user, index) => {
            const statusBadge = user.exists_in_db
                ? `<span class="badge bg-success">In SentriKat</span>`
                : `<span class="badge bg-secondary">Not Invited</span>`;

            const groupNames = user.groups.map(g => {
                const parts = g.split(',');
                const cn = parts[0].replace('cn=', '').replace('CN=', '');
                return cn;
            }).slice(0, 3).join(', ');

            const groupsDisplay = user.groups.length > 0
                ? `<small class="text-muted">${groupNames}${user.groups.length > 3 ? '...' : ''}</small>`
                : `<small class="text-muted">None</small>`;

            const actionButton = user.exists_in_db
                ? `<button class="btn btn-sm btn-outline-secondary" onclick="manageLdapUser(${index})">
                       <i class="bi bi-gear me-1"></i>Manage
                   </button>`
                : `<button class="btn btn-sm btn-primary" onclick="showInviteLdapUserModal(${index})">
                       <i class="bi bi-envelope-plus me-1"></i>Invite
                   </button>`;

            tableHTML += `
                <tr>
                    <td><strong>${user.username}</strong></td>
                    <td>${user.full_name || '<span class="text-muted">N/A</span>'}</td>
                    <td>${user.email}</td>
                    <td>${groupsDisplay}</td>
                    <td>${statusBadge}</td>
                    <td>${actionButton}</td>
                </tr>
            `;
        });

        tableHTML += `
                    </tbody>
                </table>
            </div>
        `;

        resultsDiv.innerHTML = tableHTML;

    } catch (error) {
        console.error('LDAP search error:', error);
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Connection error. Please check your LDAP configuration.
            </div>
        `;
        statsDiv.style.display = 'none';
    }
}

async function showInviteLdapUserModal(userIndex) {
    const user = ldapSearchResults[userIndex];
    if (!user) {
        console.error('User not found at index:', userIndex);
        return;
    }

    // Store index for invite function
    currentLdapUserIndex = userIndex;

    // Create modal HTML
    const modalHTML = `
        <div class="modal fade" id="inviteLdapUserModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="bi bi-envelope-plus me-2"></i>Invite LDAP User
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            Inviting <strong>${user.username}</strong> (${user.email})
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Assign to Organization *</label>
                            <select class="form-select" id="inviteOrgSelect">
                                <option value="">Loading organizations...</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Role *</label>
                            <select class="form-select" id="inviteRoleSelect">
                                <option value="user">User</option>
                                <option value="manager">Manager</option>
                                <option value="org_admin">Organization Admin</option>
                                <option value="super_admin">Super Admin</option>
                            </select>
                            <small class="text-muted">
                                User role determines permissions within the organization
                            </small>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">LDAP Groups</label>
                            <div class="border rounded p-2" style="max-height: 150px; overflow-y: auto;">
                                ${user.groups.length > 0
                                    ? user.groups.map(g => `<div class="small text-muted">${g}</div>`).join('')
                                    : '<span class="text-muted small">No LDAP groups</span>'}
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="inviteLdapUser()">
                            <i class="bi bi-envelope-plus me-1"></i>Send Invitation
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Remove existing modal if any
    const existingModal = document.getElementById('inviteLdapUserModal');
    if (existingModal) existingModal.remove();

    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Load organizations
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        const select = document.getElementById('inviteOrgSelect');
        select.innerHTML = '<option value="">-- Select Organization --</option>' +
            orgs.map(org => `<option value="${org.id}">${org.display_name}</option>`).join('');
    } catch (error) {
        console.error('Error loading organizations:', error);
    }

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('inviteLdapUserModal'));
    modal.show();
}

async function inviteLdapUser() {
    const user = ldapSearchResults[currentLdapUserIndex];
    if (!user) {
        showToast('Error: User data not found', 'danger');
        return;
    }

    const orgId = parseInt(document.getElementById('inviteOrgSelect').value);
    const role = document.getElementById('inviteRoleSelect').value;

    if (!orgId) {
        showToast('Please select an organization', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/ldap/invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user.username,
                email: user.email,
                full_name: user.full_name,
                dn: user.dn,
                organization_id: orgId,
                role: role
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            showToast(`Invitation failed: ${data.error || 'Unknown error'}`, 'danger');
            return;
        }

        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('inviteLdapUserModal'));
        if (modal) modal.hide();

        // Show success message
        showToast(
            `✓ Invitation sent to ${user.email}! User can now log in with LDAP credentials.`,
            'success',
            5000
        );

        // Refresh search results
        await searchLdapUsersInline();

    } catch (error) {
        console.error('Invitation error:', error);
        showToast('Network error. Please try again.', 'danger');
    }
}

function manageLdapUser(userIndex) {
    const user = ldapSearchResults[userIndex];
    if (!user) return;

    // TODO: Open user management modal for existing LDAP users
    showToast('User management coming soon!', 'info');
}

function showToast(message, type = 'info', duration = 3000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }

    // Map type to Bootstrap color
    const bgClass = {
        'success': 'bg-success',
        'danger': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-info';

    // Create toast
    const toastId = 'toast-' + Date.now();
    const toastHTML = `
        <div id="${toastId}" class="toast align-items-center text-white ${bgClass} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHTML);

    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: duration });
    toast.show();

    // Remove toast after it's hidden
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Function to activate tab based on URL hash
function activateTabFromHash() {
    const hash = window.location.hash;
    console.log('Hash detected:', hash);

    if (hash) {
        const tabId = hash.substring(1); // Remove the # symbol
        const tabButtonId = tabId + '-tab';
        console.log('Looking for tab button:', tabButtonId);

        const tabButton = document.getElementById(tabButtonId);
        if (tabButton) {
            console.log('Tab button found, activating tab');
            // Activate the tab
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
        } else {
            console.warn('Tab button not found:', tabButtonId);
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Load initial data if on admin panel page
    if (document.getElementById('usersTable')) {
        loadUsers();
    }
    if (document.getElementById('organizationsTable')) {
        loadOrganizations();
    }

    // Auto-load LDAP users when tab is shown
    const ldapUsersTab = document.getElementById('ldap-users-tab');
    if (ldapUsersTab) {
        ldapUsersTab.addEventListener('shown.bs.tab', function() {
            // Only search if we haven't searched yet
            if (ldapSearchResults.length === 0) {
                searchLdapUsersInline();
            }
        });

        // If LDAP tab is active on page load, search immediately
        if (ldapUsersTab.classList.contains('active')) {
            searchLdapUsersInline();
        }
    }

    // Handle hash-based tab activation on page load
    activateTabFromHash();

    // Listen for hash changes (when clicking dropdown links while already on page)
    window.addEventListener('hashchange', activateTabFromHash);
});
