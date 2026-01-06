/**
 * SentriKat Admin Panel JavaScript
 * Handles user management, organization management, and LDAP functionality
 */

let currentUserId = null;
let currentOrgId = null;

// Selection state for bulk actions
let selectedUsers = new Map(); // Map of userId -> { id, username, is_active }
let selectedOrgs = new Map();  // Map of orgId -> { id, name, active }
let selectedLdapUsers = new Map(); // Map of index -> user data

// ============================================================================
// BULK ACTIONS - USERS
// ============================================================================

function toggleUserSelect(userId, checkbox) {
    if (checkbox.checked) {
        const row = checkbox.closest('tr');
        const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
        const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
        const username = row.querySelector('td[data-column="username"]')?.textContent || '';
        selectedUsers.set(userId, { id: userId, username, is_active: isActive });
    } else {
        selectedUsers.delete(userId);
    }
    updateUsersBulkToolbar();
}

function toggleSelectAllUsers() {
    const selectAll = document.getElementById('selectAllUsers');
    const checkboxes = document.querySelectorAll('.user-checkbox');

    checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
        const userId = parseInt(cb.dataset.userId);
        if (selectAll.checked) {
            const row = cb.closest('tr');
            const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
            const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
            const username = row.querySelector('td[data-column="username"]')?.textContent || '';
            selectedUsers.set(userId, { id: userId, username, is_active: isActive });
        } else {
            selectedUsers.delete(userId);
        }
    });
    updateUsersBulkToolbar();
}

function clearUserSelection() {
    selectedUsers.clear();
    document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = false);
    document.getElementById('selectAllUsers').checked = false;
    updateUsersBulkToolbar();
}

function updateUsersBulkToolbar() {
    const toolbar = document.getElementById('usersBulkActions');
    const count = selectedUsers.size;
    document.getElementById('usersSelectedCount').textContent = count;
    toolbar.style.display = count > 0 ? 'block' : 'none';
}

async function bulkActivateUsers() {
    if (selectedUsers.size === 0) return;

    const toActivate = Array.from(selectedUsers.values()).filter(u => !u.is_active);
    if (toActivate.length === 0) {
        showToast('All selected users are already active', 'info');
        return;
    }

    if (!confirm(`Activate ${toActivate.length} user(s)?`)) return;

    showLoading();
    try {
        for (const user of toActivate) {
            await fetch(`/api/users/${user.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: true })
            });
        }
        showToast(`${toActivate.length} user(s) activated`, 'success');
        clearUserSelection();
        loadUsers();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeactivateUsers() {
    if (selectedUsers.size === 0) return;

    const toDeactivate = Array.from(selectedUsers.values()).filter(u => u.is_active);
    if (toDeactivate.length === 0) {
        showToast('All selected users are already inactive', 'info');
        return;
    }

    if (!confirm(`Deactivate ${toDeactivate.length} user(s)?`)) return;

    showLoading();
    try {
        for (const user of toDeactivate) {
            await fetch(`/api/users/${user.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: false })
            });
        }
        showToast(`${toDeactivate.length} user(s) deactivated`, 'success');
        clearUserSelection();
        loadUsers();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeleteUsers() {
    if (selectedUsers.size === 0) return;

    const userList = Array.from(selectedUsers.values()).map(u => u.username).slice(0, 5).join(', ');
    const more = selectedUsers.size > 5 ? ` and ${selectedUsers.size - 5} more` : '';

    if (!confirm(`DELETE ${selectedUsers.size} user(s)?\n\n${userList}${more}\n\nThis cannot be undone!`)) return;

    showLoading();
    try {
        for (const user of selectedUsers.values()) {
            await fetch(`/api/users/${user.id}`, { method: 'DELETE' });
        }
        showToast(`${selectedUsers.size} user(s) deleted`, 'success');
        clearUserSelection();
        loadUsers();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// BULK ACTIONS - ORGANIZATIONS
// ============================================================================

function toggleOrgSelect(orgId, checkbox) {
    if (checkbox.checked) {
        const row = checkbox.closest('tr');
        const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
        const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
        const name = row.querySelector('td[data-column="name"]')?.textContent || '';
        selectedOrgs.set(orgId, { id: orgId, name, active: isActive });
    } else {
        selectedOrgs.delete(orgId);
    }
    updateOrgsBulkToolbar();
}

function toggleSelectAllOrgs() {
    const selectAll = document.getElementById('selectAllOrgs');
    const checkboxes = document.querySelectorAll('.org-checkbox');

    checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
        const orgId = parseInt(cb.dataset.orgId);
        if (selectAll.checked) {
            const row = cb.closest('tr');
            const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
            const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
            const name = row.querySelector('td[data-column="name"]')?.textContent || '';
            selectedOrgs.set(orgId, { id: orgId, name, active: isActive });
        } else {
            selectedOrgs.delete(orgId);
        }
    });
    updateOrgsBulkToolbar();
}

function clearOrgSelection() {
    selectedOrgs.clear();
    document.querySelectorAll('.org-checkbox').forEach(cb => cb.checked = false);
    document.getElementById('selectAllOrgs').checked = false;
    updateOrgsBulkToolbar();
}

function updateOrgsBulkToolbar() {
    const toolbar = document.getElementById('orgsBulkActions');
    const count = selectedOrgs.size;
    document.getElementById('orgsSelectedCount').textContent = count;
    toolbar.style.display = count > 0 ? 'block' : 'none';
}

async function bulkActivateOrgs() {
    if (selectedOrgs.size === 0) return;

    const toActivate = Array.from(selectedOrgs.values()).filter(o => !o.active);
    if (toActivate.length === 0) {
        showToast('All selected organizations are already active', 'info');
        return;
    }

    if (!confirm(`Activate ${toActivate.length} organization(s)?`)) return;

    showLoading();
    try {
        for (const org of toActivate) {
            await fetch(`/api/organizations/${org.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ active: true })
            });
        }
        showToast(`${toActivate.length} organization(s) activated`, 'success');
        clearOrgSelection();
        loadOrganizations();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeactivateOrgs() {
    if (selectedOrgs.size === 0) return;

    const toDeactivate = Array.from(selectedOrgs.values()).filter(o => o.active);
    if (toDeactivate.length === 0) {
        showToast('All selected organizations are already inactive', 'info');
        return;
    }

    if (!confirm(`Deactivate ${toDeactivate.length} organization(s)?`)) return;

    showLoading();
    try {
        for (const org of toDeactivate) {
            await fetch(`/api/organizations/${org.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ active: false })
            });
        }
        showToast(`${toDeactivate.length} organization(s) deactivated`, 'success');
        clearOrgSelection();
        loadOrganizations();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeleteOrgs() {
    if (selectedOrgs.size === 0) return;

    const orgList = Array.from(selectedOrgs.values()).map(o => o.name).slice(0, 5).join(', ');
    const more = selectedOrgs.size > 5 ? ` and ${selectedOrgs.size - 5} more` : '';

    if (!confirm(`DELETE ${selectedOrgs.size} organization(s)?\n\n${orgList}${more}\n\nThis will also affect users and products!\nThis cannot be undone!`)) return;

    showLoading();
    try {
        for (const org of selectedOrgs.values()) {
            await fetch(`/api/organizations/${org.id}`, { method: 'DELETE' });
        }
        showToast(`${selectedOrgs.size} organization(s) deleted`, 'success');
        clearOrgSelection();
        loadOrganizations();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

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

        // Clear selection state
        selectedUsers.clear();
        updateUsersBulkToolbar();

        tbody.innerHTML = users.map(user => {
            const authBadge = user.auth_type === 'ldap'
                ? '<span class="badge badge-auth-ldap">LDAP</span>'
                : '<span class="badge badge-auth-local">Local</span>';
            const roleBadge = {
                'super_admin': '<span class="badge badge-role-super">Super Admin</span>',
                'org_admin': '<span class="badge badge-role-admin">Org Admin</span>',
                'manager': '<span class="badge badge-role-manager">Manager</span>',
                'user': '<span class="badge badge-role-user">User</span>'
            }[user.role] || `<span class="badge bg-secondary">${user.role}</span>`;
            const statusBadge = user.is_active
                ? '<span class="badge badge-status-active">Active</span>'
                : '<span class="badge badge-status-inactive">Inactive</span>';

            return `
                <tr>
                    <td>
                        <input type="checkbox" class="form-check-input user-checkbox"
                               data-user-id="${user.id}" onchange="toggleUserSelect(${user.id}, this)">
                    </td>
                    <td data-column="username">${escapeHtml(user.username)}</td>
                    <td data-column="fullname">${escapeHtml(user.full_name || '')}</td>
                    <td data-column="email">${escapeHtml(user.email || '')}</td>
                    <td data-column="organization">${escapeHtml(user.organization_name || '-')}</td>
                    <td data-column="authtype">${authBadge}</td>
                    <td data-column="role">${roleBadge}</td>
                    <td data-column="status">${statusBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="editUser(${user.id})">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteUser(${user.id})">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Reset select all checkbox
        const selectAllUsers = document.getElementById('selectAllUsers');
        if (selectAllUsers) selectAllUsers.checked = false;

        // Initialize sortable table after rendering
        if (typeof SortableTable !== 'undefined') {
            SortableTable.init('usersTableContainer');
        }
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

        const tbody = document.getElementById('orgsTable');
        if (!tbody) return;

        // Clear selection state
        selectedOrgs.clear();
        updateOrgsBulkToolbar();

        tbody.innerHTML = orgs.map(org => {
            const smtpBadge = org.smtp_host
                ? '<span class="badge badge-status-active">Configured</span>'
                : '<span class="badge badge-status-inactive">Not Set</span>';
            const statusBadge = org.active
                ? '<span class="badge badge-status-active">Active</span>'
                : '<span class="badge badge-status-inactive">Inactive</span>';

            return `
                <tr>
                    <td>
                        <input type="checkbox" class="form-check-input org-checkbox"
                               data-org-id="${org.id}" onchange="toggleOrgSelect(${org.id}, this)">
                    </td>
                    <td data-column="name">${escapeHtml(org.name)}</td>
                    <td data-column="displayname">${escapeHtml(org.display_name || org.name)}</td>
                    <td data-column="users">${org.user_count || 0}</td>
                    <td data-column="smtp">${smtpBadge}</td>
                    <td data-column="status">${statusBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="editOrganization(${org.id})">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteOrganization(${org.id})">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Reset select all checkbox
        const selectAllOrgs = document.getElementById('selectAllOrgs');
        if (selectAllOrgs) selectAllOrgs.checked = false;

        // Initialize sortable table after rendering
        if (typeof SortableTable !== 'undefined') {
            SortableTable.init('orgsTableContainer');
        }
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
                <table class="table table-hover" id="ldapResultsTableContainer" data-sortable="true">
                    <thead>
                        <tr>
                            <th data-sort-key="username" data-sort-type="string">Username</th>
                            <th data-sort-key="fullname" data-sort-type="string">Full Name</th>
                            <th data-sort-key="email" data-sort-type="string">Email</th>
                            <th data-sort-key="groups" data-sort-type="string">Groups</th>
                            <th data-sort-key="status" data-sort-type="boolean">Status</th>
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
                    <td data-column="username"><strong>${user.username}</strong></td>
                    <td data-column="fullname">${user.full_name || '<span class="text-muted">N/A</span>'}</td>
                    <td data-column="email">${user.email}</td>
                    <td data-column="groups">${groupsDisplay}</td>
                    <td data-column="status">${statusBadge}</td>
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

        // Initialize sortable table after rendering
        if (typeof SortableTable !== 'undefined') {
            SortableTable.init('ldapResultsTableContainer');
        }

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
