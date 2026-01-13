/**
 * Admin Panel JavaScript
 * Handles user management, organization management, and settings
 */

let currentUserId = null;
let currentOrgId = null;
let organizations = [];

// Global license info - loaded at page init
window.licenseInfo = null;

// Selection state for bulk actions
let selectedUsers = new Map(); // Map of userId -> { id, username, is_active }
let selectedOrgs = new Map();  // Map of orgId -> { id, name, active }
let selectedMappings = new Map(); // Map of mappingId -> { id, group_cn, is_active }

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
    const selectAllUsers = document.getElementById('selectAllUsers');
    if (selectAllUsers) selectAllUsers.checked = false;
    updateUsersBulkToolbar();
}

function updateUsersBulkToolbar() {
    const toolbar = document.getElementById('usersBulkActions');
    if (!toolbar) return;
    const count = selectedUsers.size;
    const countEl = document.getElementById('usersSelectedCount');
    if (countEl) countEl.textContent = count;
    toolbar.style.display = count > 0 ? 'block' : 'none';
}

async function bulkActivateUsers() {
    if (selectedUsers.size === 0) return;

    const toActivate = Array.from(selectedUsers.values()).filter(u => !u.is_active);
    if (toActivate.length === 0) {
        showToast('All selected users are already active', 'info');
        return;
    }

    const confirmed = await showConfirm(`Activate ${toActivate.length} user(s)?`, 'Activate Users', 'Activate', 'btn-success');
    if (!confirmed) return;

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

    const confirmed = await showConfirm(`Deactivate ${toDeactivate.length} user(s)?`, 'Deactivate Users', 'Deactivate', 'btn-warning');
    if (!confirmed) return;

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

    const confirmed = await showConfirm(`<strong>DELETE ${selectedUsers.size} user(s)?</strong><br><br>${userList}${more}<br><br><span class="text-danger">This cannot be undone!</span>`, 'Delete Users', 'Delete', 'btn-danger');
    if (!confirmed) return;

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
    const selectAllOrgs = document.getElementById('selectAllOrgs');
    if (selectAllOrgs) selectAllOrgs.checked = false;
    updateOrgsBulkToolbar();
}

function updateOrgsBulkToolbar() {
    const toolbar = document.getElementById('orgsBulkActions');
    if (!toolbar) return;
    const count = selectedOrgs.size;
    const countEl = document.getElementById('orgsSelectedCount');
    if (countEl) countEl.textContent = count;
    toolbar.style.display = count > 0 ? 'block' : 'none';
}

async function bulkActivateOrgs() {
    if (selectedOrgs.size === 0) return;

    const toActivate = Array.from(selectedOrgs.values()).filter(o => !o.active);
    if (toActivate.length === 0) {
        showToast('All selected organizations are already active', 'info');
        return;
    }

    const confirmed = await showConfirm(`Activate ${toActivate.length} organization(s)?`, 'Activate Organizations', 'Activate', 'btn-success');
    if (!confirmed) return;

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

    const confirmed = await showConfirm(`Deactivate ${toDeactivate.length} organization(s)?<br><br><span class="text-warning">Users in these organizations will be blocked from logging in.</span>`, 'Deactivate Organizations', 'Deactivate', 'btn-warning');
    if (!confirmed) return;

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

    const confirmed = await showConfirm(`<strong>DELETE ${selectedOrgs.size} organization(s)?</strong><br><br>${orgList}${more}<br><br><span class="text-warning">This will also affect users and products!</span><br><span class="text-danger">This cannot be undone!</span>`, 'Delete Organizations', 'Delete', 'btn-danger');
    if (!confirmed) return;

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
// BULK ACTIONS - LDAP GROUP MAPPINGS
// ============================================================================

function toggleMappingSelect(mappingId, checkbox) {
    if (checkbox.checked) {
        const row = checkbox.closest('tr');
        const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
        const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
        const groupCn = row.querySelector('td[data-column="group"] strong')?.textContent || '';
        selectedMappings.set(mappingId, { id: mappingId, group_cn: groupCn, is_active: isActive });
    } else {
        selectedMappings.delete(mappingId);
    }
    updateMappingsBulkToolbar();
}

function toggleSelectAllMappings() {
    const selectAll = document.getElementById('selectAllMappings');
    const checkboxes = document.querySelectorAll('.mapping-checkbox');

    checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
        const mappingId = parseInt(cb.dataset.mappingId);
        if (selectAll.checked) {
            const row = cb.closest('tr');
            const statusBadge = row.querySelector('.badge-status-active, .badge-status-inactive');
            const isActive = statusBadge ? statusBadge.classList.contains('badge-status-active') : true;
            const groupCn = row.querySelector('td[data-column="group"] strong')?.textContent || '';
            selectedMappings.set(mappingId, { id: mappingId, group_cn: groupCn, is_active: isActive });
        } else {
            selectedMappings.delete(mappingId);
        }
    });
    updateMappingsBulkToolbar();
}

function updateMappingsBulkToolbar() {
    const toolbar = document.getElementById('mappingsBulkActions');
    const count = document.getElementById('mappingsSelectedCount');
    if (toolbar && count) {
        count.textContent = selectedMappings.size;
        toolbar.style.display = selectedMappings.size > 0 ? 'block' : 'none';
    }
}

function clearMappingSelection() {
    selectedMappings.clear();
    document.querySelectorAll('.mapping-checkbox').forEach(cb => cb.checked = false);
    const selectAllMappings = document.getElementById('selectAllMappings');
    if (selectAllMappings) selectAllMappings.checked = false;
    updateMappingsBulkToolbar();
}

async function bulkActivateMappings() {
    if (selectedMappings.size === 0) return;
    showLoading();
    try {
        for (const [mappingId, mapping] of selectedMappings) {
            const response = await fetch(`/api/ldap/groups/mappings/${mappingId}/activate`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error(`Failed to activate mapping ${mappingId}`);
        }
        showToast(`${selectedMappings.size} mapping(s) activated`, 'success');
        clearMappingSelection();
        loadGroupMappings();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeactivateMappings() {
    if (selectedMappings.size === 0) return;
    showLoading();
    try {
        for (const [mappingId, mapping] of selectedMappings) {
            const response = await fetch(`/api/ldap/groups/mappings/${mappingId}/deactivate`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error(`Failed to deactivate mapping ${mappingId}`);
        }
        showToast(`${selectedMappings.size} mapping(s) deactivated`, 'success');
        clearMappingSelection();
        loadGroupMappings();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function bulkDeleteMappings() {
    if (selectedMappings.size === 0) return;

    const confirmed = await showConfirm(
        `Are you sure you want to delete <strong>${selectedMappings.size}</strong> mapping(s)?<br><br>This action cannot be undone.`,
        'Delete Mappings',
        'Delete',
        'btn-danger'
    );

    if (!confirmed) return;

    showLoading();
    try {
        for (const [mappingId, mapping] of selectedMappings) {
            const response = await fetch(`/api/ldap/groups/mappings/${mappingId}`, {
                method: 'DELETE'
            });
            if (!response.ok) throw new Error(`Failed to delete mapping ${mappingId}`);
        }
        showToast(`${selectedMappings.size} mapping(s) deleted`, 'success');
        clearMappingSelection();
        loadGroupMappings();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', async function() {
    console.log('Admin Panel: DOMContentLoaded fired');

    // Check if Bootstrap is loaded
    if (typeof bootstrap === 'undefined') {
        console.error('Bootstrap is not loaded! Modals will not work.');
        showToast('Error: Bootstrap JavaScript library is not loaded. Please refresh the page.', 'danger');
        return;
    }

    try {
        // Load license info first and apply UI restrictions (await to ensure restrictions apply before showing tabs)
        await loadLicenseAndApplyRestrictions();

        loadUsers();
        loadOrganizations();
        loadOrganizationsDropdown();
        checkLdapPermissions();  // Check if user can access LDAP features (also checks license)

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
    tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    // Clear selection state
    selectedUsers.clear();
    updateUsersBulkToolbar();

    try {
        const response = await fetch('/api/users');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const users = await response.json();

        if (users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="text-center py-5">
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

                let statusBadge = user.is_active
                    ? '<span class="badge badge-status-active">Active</span>'
                    : '<span class="badge badge-status-inactive">Inactive</span>';

                // Add locked indicator if user is locked
                if (user.is_locked) {
                    statusBadge += ' <span class="badge bg-danger" title="Account locked due to failed logins"><i class="bi bi-lock-fill"></i> Locked</span>';
                }

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
                        <td>
                            <input type="checkbox" class="form-check-input user-checkbox"
                                   data-user-id="${user.id}" onchange="toggleUserSelect(${user.id}, this)">
                        </td>
                        <td data-column="username" class="fw-semibold">${escapeHtml(user.username)}</td>
                        <td data-column="fullname">${user.full_name ? escapeHtml(user.full_name) : '<span class="text-muted">-</span>'}</td>
                        <td data-column="email">${escapeHtml(user.email)}</td>
                        <td data-column="organization">${orgDisplay}</td>
                        <td data-column="authtype">${authBadge}</td>
                        <td data-column="role">${roleBadge}</td>
                        <td data-column="status">${statusBadge}</td>
                        <td data-column="actions">
                            <div class="d-flex gap-1">
                                <button class="btn-action btn-action-edit" onclick="editUser(${user.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                ${user.is_locked ? `
                                <button class="btn-action btn-action-warning" onclick="unlockUser(${user.id}, '${escapeHtml(user.username)}')" title="Unlock Account">
                                    <i class="bi bi-unlock-fill"></i>
                                </button>
                                ` : ''}
                                ${user.totp_enabled ? `
                                <button class="btn-action btn-action-warning" onclick="reset2FA(${user.id}, '${escapeHtml(user.username)}')" title="Reset 2FA">
                                    <i class="bi bi-phone-flip"></i>
                                </button>
                                ` : ''}
                                ${user.auth_type === 'local' ? `
                                <button class="btn-action" onclick="forcePasswordChange(${user.id}, '${escapeHtml(user.username)}')" title="Force Password Change" style="color: #7c3aed;">
                                    <i class="bi bi-key-fill"></i>
                                </button>
                                ` : ''}
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

        // Reset select all checkbox
        const selectAllUsers = document.getElementById('selectAllUsers');
        if (selectAllUsers) selectAllUsers.checked = false;

        // Initialize sortable table after rendering
        if (typeof SortableTable !== 'undefined') {
            SortableTable.init('usersTableContainer');
        }
        // Restore table enhancements (column visibility, widths)
        if (typeof TableEnhancements !== 'undefined') {
            TableEnhancements.refresh('usersTableContainer');
        }
    } catch (error) {
        console.error('Error loading users:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center text-danger py-4">
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

        // Show primary org field (for new users)
        document.getElementById('primaryOrgField').style.display = 'block';
        document.getElementById('organization').required = true;

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

        // Hide primary org field (managed via memberships when editing)
        document.getElementById('primaryOrgField').style.display = 'none';
        document.getElementById('organization').required = false;

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
    const confirmed = await showConfirm(`Remove user from "${orgName}"?`, 'Remove Membership', 'Remove', 'btn-warning');
    if (!confirmed) return;

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
        // Basic client-side validation - server will enforce full policy
        if (password.length < 8) {
            showToast('Password must be at least 8 characters. Additional requirements may apply based on security policy.', 'warning');
            return;
        }
        // Check for basic complexity (hint to user about requirements)
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        if (!hasUpper || !hasLower || !hasNumber) {
            showToast('Password should contain uppercase, lowercase, and numbers. Check your organization\'s password policy.', 'info');
            // Don't block - let server validate against actual policy
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
        `<strong>⚠️ PERMANENT DELETION</strong><br><br>` +
        `Are you sure you want to permanently delete user "<strong>${username}</strong>"?<br><br>` +
        `<span class="text-danger">This will remove the user from the database entirely and cannot be undone.</span><br><br>` +
        `<small class="text-muted">Tip: Use the block button (🚫) to temporarily disable a user without deleting them.</small>`,
        'Permanently Delete User',
        'Delete Permanently',
        'btn-danger'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (response.ok) {
            showToast(result.message || '✓ User permanently deleted', 'success');
            loadUsers();
        } else {
            showToast(`Error: ${result.error}`, 'danger');
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

async function unlockUser(userId, username) {
    const confirmed = await showConfirm(
        `Are you sure you want to unlock the account for "<strong>${username}</strong>"?<br><br>` +
        'This will reset failed login attempts and allow the user to log in immediately.',
        'Unlock User Account',
        'Unlock',
        'btn-warning'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/unlock`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            showToast(result.message || `✓ User ${username} has been unlocked`, 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error unlocking user: ${error.message}`, 'danger');
    }
}

async function reset2FA(userId, username) {
    const confirmed = await showConfirm(
        `Are you sure you want to reset 2FA for "<strong>${username}</strong>"?<br><br>` +
        'This will disable their two-factor authentication. They will need to set it up again.',
        'Reset Two-Factor Authentication',
        'Reset 2FA',
        'btn-warning'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/reset-2fa`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            showToast(result.message || `✓ 2FA has been reset for ${username}`, 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error resetting 2FA: ${error.message}`, 'danger');
    }
}

async function forcePasswordChange(userId, username) {
    const confirmed = await showConfirm(
        `Force "<strong>${username}</strong>" to change their password on next login?`,
        'Force Password Change',
        'Force Change',
        'btn-primary'
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/force-password-change`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            showToast(result.message || `✓ ${username} will be required to change password`, 'success');
            loadUsers();
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error forcing password change: ${error.message}`, 'danger');
    }
}

// ============================================================================
// Organization Management
// ============================================================================

async function loadOrganizations() {
    const tbody = document.getElementById('orgsTable');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    // Clear selection state
    selectedOrgs.clear();
    updateOrgsBulkToolbar();

    try {
        const response = await fetch('/api/organizations');

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        organizations = await response.json();

        if (organizations.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-5">
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
                        <td>
                            <input type="checkbox" class="form-check-input org-checkbox"
                                   data-org-id="${org.id}" onchange="toggleOrgSelect(${org.id}, this)">
                        </td>
                        <td data-column="name" class="fw-semibold">${escapeHtml(org.name)}</td>
                        <td data-column="displayname">${escapeHtml(org.display_name)}</td>
                        <td data-column="users"><span class="badge badge-role-manager">${org.user_count || 0}</span></td>
                        <td data-column="smtp">${smtpBadge}</td>
                        <td data-column="status">${statusBadge}</td>
                        <td data-column="actions">
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

        // Reset select all checkbox
        const selectAllOrgs = document.getElementById('selectAllOrgs');
        if (selectAllOrgs) selectAllOrgs.checked = false;

        // Initialize sortable table after rendering
        if (typeof SortableTable !== 'undefined') {
            SortableTable.init('orgsTableContainer');
        }
        // Restore table enhancements
        if (typeof TableEnhancements !== 'undefined') {
            TableEnhancements.refresh('orgsTableContainer');
        }
    } catch (error) {
        console.error('loadOrganizations: Error:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-danger py-4">
                    <i class="bi bi-exclamation-triangle"></i> Error loading organizations: ${error.message}
                </td>
            </tr>
        `;
    }
}

async function loadOrganizationsDropdown() {
    const select = document.getElementById('organization');
    if (!select) {
        console.warn('Organization select element not found');
        return;
    }

    try {
        const response = await fetch('/api/organizations');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const orgs = await response.json();

        if (orgs.length === 0) {
            select.innerHTML = '<option value="">No organizations available</option>';
        } else {
            select.innerHTML = '<option value="">Select organization...</option>' +
                orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`).join('');
        }
    } catch (error) {
        console.error('Error loading organizations dropdown:', error);
        select.innerHTML = '<option value="">Error loading organizations</option>';
    }
}

function showCreateOrgModal() {
    try {
        console.log('showCreateOrgModal called');
        currentOrgId = null;
        document.getElementById('orgModalTitle').innerHTML = '<i class="bi bi-building me-2"></i>Create Organization';
        document.getElementById('orgForm').reset();

        // Make sure orgName is enabled and editable for new organizations
        const orgNameField = document.getElementById('orgName');
        orgNameField.disabled = false;
        orgNameField.readOnly = false;
        orgNameField.value = '';

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
        document.getElementById('smtpUseSsl').checked = org.smtp_use_ssl === true;

        // Alert settings
        document.getElementById('alertCritical').checked = org.alert_on_critical;
        document.getElementById('alertHigh').checked = org.alert_on_high;
        document.getElementById('alertNewCVE').checked = org.alert_on_new_cve;
        document.getElementById('alertRansomware').checked = org.alert_on_ransomware;

        // Alert mode settings (org.alert_settings contains nested values)
        const alertMode = org.alert_settings?.mode || '';
        const escalationDays = org.alert_settings?.escalation_days || '';
        document.getElementById('orgAlertMode').value = alertMode;
        document.getElementById('orgEscalationDays').value = escalationDays;

        // Webhook settings
        document.getElementById('orgWebhookEnabled').checked = org.webhook_enabled || false;
        document.getElementById('orgWebhookUrl').value = org.webhook_url || '';
        document.getElementById('orgWebhookFormat').value = org.webhook_format || 'slack';
        document.getElementById('orgWebhookName').value = org.webhook_name || '';
        document.getElementById('orgWebhookToken').value = '';
        document.getElementById('orgWebhookToken').placeholder = org.webhook_token ? '(token saved - leave blank to keep)' : 'Leave empty if not needed';

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
        smtp_use_ssl: document.getElementById('smtpUseSsl').checked,

        // Alert settings
        alert_on_critical: document.getElementById('alertCritical').checked,
        alert_on_high: document.getElementById('alertHigh').checked,
        alert_on_new_cve: document.getElementById('alertNewCVE').checked,
        alert_on_ransomware: document.getElementById('alertRansomware').checked,

        // Alert mode settings (empty = use global default)
        alert_mode: document.getElementById('orgAlertMode').value || null,
        escalation_days: document.getElementById('orgEscalationDays').value ? parseInt(document.getElementById('orgEscalationDays').value) : null,

        // Webhook settings
        webhook_enabled: document.getElementById('orgWebhookEnabled').checked,
        webhook_url: document.getElementById('orgWebhookUrl').value.trim() || null,
        webhook_format: document.getElementById('orgWebhookFormat').value,
        webhook_name: document.getElementById('orgWebhookName').value.trim() || null,
        webhook_token: document.getElementById('orgWebhookToken').value.trim() || null
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

async function testOrgWebhook() {
    const webhookUrl = document.getElementById('orgWebhookUrl').value.trim();

    if (!webhookUrl) {
        showToast('Please enter a webhook URL first', 'warning');
        return;
    }

    showToast('Testing webhook...', 'info');

    try {
        const response = await fetch('/api/settings/test-webhook', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: 'org',
                webhook_url: webhookUrl,
                webhook_format: document.getElementById('orgWebhookFormat').value,
                webhook_name: document.getElementById('orgWebhookName').value || 'Organization Webhook',
                webhook_token: document.getElementById('orgWebhookToken').value || null
            })
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message || '✓ Webhook test successful!', 'success');
        } else {
            showToast(`✗ Webhook test failed: ${result.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error testing webhook: ${error.message}`, 'danger');
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

    // Truncate very long messages to prevent layout issues
    let displayMessage = message;
    if (message.length > 300) {
        displayMessage = message.substring(0, 300) + '...';
    }

    // Create toast element with proper styling for long messages
    const toastId = `toast-${Date.now()}`;
    const toastHtml = `
        <div id="${toastId}" class="toast ${toastClass}" role="alert" aria-live="assertive" aria-atomic="true" style="max-width: 450px;">
            <div class="toast-body d-flex justify-content-between align-items-start">
                <span style="word-break: break-word; overflow-wrap: break-word;">${displayMessage}</span>
                <button type="button" class="btn-close btn-close-white ms-2 flex-shrink-0" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;

    toastContainer.insertAdjacentHTML('beforeend', toastHtml);

    // Show the toast with longer delay for errors
    const toastElement = document.getElementById(toastId);
    const delay = (type === 'danger' || type === 'warning') ? 8000 : 3000;
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: delay
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
        smtp_use_tls: document.getElementById('globalSmtpUseTLS').checked,
        smtp_use_ssl: document.getElementById('globalSmtpUseSSL').checked
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

        // Build last sync text with status icon
        let lastSyncHtml = 'Never';
        if (status.last_sync) {
            const statusIcon = status.last_sync_status === 'success'
                ? '<i class="bi bi-check-circle-fill text-success me-1"></i>'
                : '<i class="bi bi-exclamation-triangle-fill text-warning me-1"></i>';
            const statsText = (status.last_sync_added > 0 || status.last_sync_updated > 0)
                ? ` (+${status.last_sync_added} new, ${status.last_sync_updated} updated)`
                : '';
            lastSyncHtml = `${statusIcon}${status.last_sync}${statsText}`;
        }

        document.getElementById('lastSyncTime').innerHTML = lastSyncHtml;
        document.getElementById('nextSyncTime').textContent = status.next_sync || 'Not scheduled';
        document.getElementById('totalVulns').textContent = status.total_vulnerabilities || '0';
    } catch (error) {
        console.error('Error loading sync status:', error);
    }
}

// Manual Critical CVE Alert Trigger
async function triggerCriticalCVEAlerts() {
    const confirmed = await showConfirm(
        'This will send email alerts for all unacknowledged critical and high priority CVEs to all configured organizations.\n\nAre you sure you want to proceed?',
        'Send Critical CVE Alerts',
        'Send Alerts',
        'btn-danger'
    );

    if (!confirmed) return;

    showLoading();

    try {
        const response = await fetch('/api/alerts/trigger-critical', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const result = await response.json();

        hideLoading();

        if (result.status === 'success') {
            const summary = result.summary;
            let html = `
                <div class="mb-2">
                    <strong>Summary:</strong><br>
                    Organizations processed: ${summary.total_orgs}<br>
                    Emails sent: <span class="text-success">${summary.emails_sent}</span><br>
                    Skipped: <span class="text-muted">${summary.skipped}</span><br>
                    Errors: <span class="text-danger">${summary.errors}</span>
                </div>
                <hr>
                <strong>Details by Organization:</strong>
                <ul class="mb-0 mt-2">
            `;

            for (const detail of result.details) {
                let statusIcon = '';
                let statusClass = '';

                if (detail.status === 'success') {
                    statusIcon = '<i class="bi bi-check-circle text-success"></i>';
                    statusClass = 'text-success';
                } else if (detail.status === 'skipped') {
                    statusIcon = '<i class="bi bi-dash-circle text-muted"></i>';
                    statusClass = 'text-muted';
                } else {
                    statusIcon = '<i class="bi bi-x-circle text-danger"></i>';
                    statusClass = 'text-danger';
                }

                html += `<li class="${statusClass}">${statusIcon} <strong>${detail.organization}</strong>: `;
                if (detail.status === 'success') {
                    html += `Sent ${detail.matches_count} CVEs to ${detail.sent_to} recipients`;
                } else {
                    html += detail.reason || detail.status;
                }
                html += '</li>';
            }

            html += '</ul>';

            document.getElementById('alertResultsContent').innerHTML = html;
            document.getElementById('alertResultsContainer').style.display = 'block';

            showToast(`Critical CVE alerts processed: ${summary.emails_sent} emails sent`, 'success');
        } else {
            showToast(`Error: ${result.error}`, 'danger');
        }
    } catch (error) {
        hideLoading();
        showToast(`Error triggering alerts: ${error.message}`, 'danger');
    }
}

// Proxy Settings
async function saveProxySettings() {
    const settings = {
        verify_ssl: document.getElementById('verifySSL').checked,
        http_proxy: document.getElementById('httpProxy').value,
        https_proxy: document.getElementById('httpsProxy').value,
        no_proxy: document.getElementById('noProxy').value
    };

    try {
        const response = await fetch('/api/settings/general', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('Proxy settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving proxy settings: ${error.message}`, 'danger');
    }
}

// Test Proxy Connection
async function testProxyConnection() {
    showLoading();
    try {
        // Test by making a request to the CISA KEV endpoint through proxy
        const response = await fetch('/api/sync/test-connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast('Connection test successful! External API is reachable.', 'success');
        } else {
            showToast(`Connection test failed: ${data.error || 'Unknown error'}`, 'danger');
        }
    } catch (error) {
        showToast(`Connection test failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// Security Settings
// ============================================================================

async function saveSecuritySettings() {
    const settings = {
        session_timeout: parseInt(document.getElementById('sessionTimeout').value) || 480,
        max_failed_logins: parseInt(document.getElementById('maxFailedLogins').value) || 5,
        lockout_duration: parseInt(document.getElementById('lockoutDuration').value) || 30,
        password_min_length: parseInt(document.getElementById('passwordMinLength').value) || 8,
        password_require_uppercase: document.getElementById('passwordRequireUppercase').checked,
        password_require_lowercase: document.getElementById('passwordRequireLowercase').checked,
        password_require_numbers: document.getElementById('passwordRequireNumbers').checked,
        password_require_special: document.getElementById('passwordRequireSpecial').checked,
        password_expiry_days: parseInt(document.getElementById('passwordExpiryDays').value) || 0,
        require_2fa: document.getElementById('require2FA').checked
    };

    try {
        const response = await fetch('/api/settings/security', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('Security settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving security settings: ${error.message}`, 'danger');
    }
}

async function loadSecuritySettings() {
    try {
        const response = await fetch('/api/settings/security');
        if (response.ok) {
            const settings = await response.json();
            const sessionTimeout = document.getElementById('sessionTimeout');
            const maxFailedLogins = document.getElementById('maxFailedLogins');
            const lockoutDuration = document.getElementById('lockoutDuration');
            const passwordMinLength = document.getElementById('passwordMinLength');
            const passwordRequireUppercase = document.getElementById('passwordRequireUppercase');
            const passwordRequireLowercase = document.getElementById('passwordRequireLowercase');
            const passwordRequireNumbers = document.getElementById('passwordRequireNumbers');
            const passwordRequireSpecial = document.getElementById('passwordRequireSpecial');

            if (sessionTimeout) sessionTimeout.value = settings.session_timeout || 480;
            if (maxFailedLogins) maxFailedLogins.value = settings.max_failed_logins || 5;
            if (lockoutDuration) lockoutDuration.value = settings.lockout_duration || 30;
            if (passwordMinLength) passwordMinLength.value = settings.password_min_length || 8;
            if (passwordRequireUppercase) passwordRequireUppercase.checked = settings.password_require_uppercase !== false;
            if (passwordRequireLowercase) passwordRequireLowercase.checked = settings.password_require_lowercase !== false;
            if (passwordRequireNumbers) passwordRequireNumbers.checked = settings.password_require_numbers !== false;
            if (passwordRequireSpecial) passwordRequireSpecial.checked = settings.password_require_special === true;

            // Password expiration and 2FA settings
            const passwordExpiryDays = document.getElementById('passwordExpiryDays');
            const require2FA = document.getElementById('require2FA');
            if (passwordExpiryDays) passwordExpiryDays.value = settings.password_expiry_days || 0;
            if (require2FA) require2FA.checked = settings.require_2fa === true;
        }
    } catch (error) {
        console.error('Error loading security settings:', error);
    }
}

// ============================================================================
// Backup & Restore
// ============================================================================

async function downloadBackup() {
    try {
        const response = await fetch('/api/settings/backup');
        if (response.ok) {
            const data = await response.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `sentrikat-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Backup downloaded successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error downloading backup: ${error.message}`, 'danger');
    }
}

async function restoreBackup(file) {
    const confirmed = await showConfirm('Are you sure you want to restore from this backup?<br><br>This will overwrite current settings.', 'Restore Backup', 'Restore', 'btn-warning');
    if (!confirmed) return;

    try {
        const formData = new FormData();
        formData.append('backup', file);

        const response = await fetch('/api/settings/restore', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            showToast('Backup restored successfully. Reloading settings...', 'success');
            setTimeout(() => location.reload(), 1500);
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error restoring backup: ${error.message}`, 'danger');
    }
}

// Full restore function - restores everything including orgs, users, products
async function restoreFullBackup(file) {
    try {
        const formData = new FormData();
        formData.append('backup', file);

        showToast('Performing full restore...', 'info');

        const response = await fetch('/api/settings/restore-full', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            const stats = result.stats || {};
            showToast(
                `Full restore complete: ${stats.organizations || 0} orgs, ${stats.users || 0} users, ${stats.products || 0} products, ${stats.settings || 0} settings`,
                'success'
            );
            setTimeout(() => location.reload(), 2000);
        } else {
            showToast(`Error: ${result.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error restoring backup: ${error.message}`, 'danger');
    }
}

// Confirm and trigger full restore
async function confirmFullRestore() {
    const confirmed = await showConfirm(
        '<strong class="text-danger">⚠️ FULL RESTORE WARNING</strong><br><br>' +
        'This will import all organizations, users, and products from the backup.<br><br>' +
        '• Existing data with the same names will be skipped<br>' +
        '• Local users will need to reset their passwords<br><br>' +
        'Continue?',
        'Full Restore',
        'Restore All Data',
        'btn-danger'
    );
    if (!confirmed) return;
    document.getElementById('restoreFullFile').click();
}

// Setup restore file input listeners
document.addEventListener('DOMContentLoaded', function() {
    const restoreFile = document.getElementById('restoreFile');
    if (restoreFile) {
        restoreFile.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                restoreBackup(e.target.files[0]);
                e.target.value = '';
            }
        });
    }

    const restoreFullFile = document.getElementById('restoreFullFile');
    if (restoreFullFile) {
        restoreFullFile.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                restoreFullBackup(e.target.files[0]);
                e.target.value = '';
            }
        });
    }
});

// ============================================================================
// Branding Settings
// ============================================================================

async function saveBrandingSettings() {
    const settings = {
        app_name: document.getElementById('appName').value || 'SentriKat',
        login_message: document.getElementById('loginMessage').value || '',
        support_email: document.getElementById('supportEmail').value || '',
        show_version: document.getElementById('showVersion').checked
    };

    try {
        const response = await fetch('/api/settings/branding', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('Branding settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving branding settings: ${error.message}`, 'danger');
    }
}

async function loadBrandingSettings() {
    try {
        const response = await fetch('/api/settings/branding');
        if (response.ok) {
            const settings = await response.json();
            const appName = document.getElementById('appName');
            const loginMessage = document.getElementById('loginMessage');
            const supportEmail = document.getElementById('supportEmail');
            const showVersion = document.getElementById('showVersion');
            const logoPreview = document.getElementById('currentLogoPreview');
            const deleteLogoBtn = document.getElementById('deleteLogoBtn');

            if (appName) appName.value = settings.app_name || 'SentriKat';
            if (loginMessage) loginMessage.value = settings.login_message || '';
            if (supportEmail) supportEmail.value = settings.support_email || '';
            if (showVersion) showVersion.checked = settings.show_version !== false;

            // Show custom logo if set
            if (settings.logo_url && logoPreview) {
                logoPreview.src = settings.logo_url;
                if (deleteLogoBtn && settings.logo_url.includes('/uploads/')) {
                    deleteLogoBtn.style.display = 'inline-block';
                }
            }
        }
    } catch (error) {
        console.error('Error loading branding settings:', error);
    }
}

async function uploadLogo() {
    const fileInput = document.getElementById('logoUpload');
    if (!fileInput.files || fileInput.files.length === 0) {
        showToast('Please select a file to upload', 'warning');
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('logo', file);

    showLoading();
    try {
        const response = await fetch('/api/settings/branding/logo', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast('Logo uploaded successfully', 'success');
            // Update preview
            const logoPreview = document.getElementById('currentLogoPreview');
            const deleteLogoBtn = document.getElementById('deleteLogoBtn');
            if (logoPreview) logoPreview.src = data.logo_url + '?t=' + Date.now();
            if (deleteLogoBtn) deleteLogoBtn.style.display = 'inline-block';
            // Clear input
            fileInput.value = '';
        } else {
            showToast(`Error: ${data.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Upload failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function deleteLogo() {
    const confirmed = await showConfirm('Remove custom logo and revert to default?', 'Remove Logo', 'Remove', 'btn-warning');
    if (!confirmed) return;

    showLoading();
    try {
        const response = await fetch('/api/settings/branding/logo', {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast('Logo removed, reverted to default', 'success');
            // Reset preview
            const logoPreview = document.getElementById('currentLogoPreview');
            const deleteLogoBtn = document.getElementById('deleteLogoBtn');
            if (logoPreview) logoPreview.src = '/static/images/favicon-128x128.png';
            if (deleteLogoBtn) deleteLogoBtn.style.display = 'none';
        } else {
            showToast(`Error: ${data.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// Notification Settings
// ============================================================================

async function saveNotificationSettings() {
    const settings = {
        slack_enabled: document.getElementById('slackEnabled').checked,
        slack_webhook_url: document.getElementById('slackWebhookUrl').value || '',
        teams_enabled: document.getElementById('teamsEnabled').checked,
        teams_webhook_url: document.getElementById('teamsWebhookUrl').value || '',
        // Generic webhook settings
        generic_webhook_enabled: document.getElementById('genericWebhookEnabled').checked,
        generic_webhook_url: document.getElementById('genericWebhookUrl').value || '',
        generic_webhook_name: document.getElementById('genericWebhookName').value || 'Custom Webhook',
        generic_webhook_format: document.getElementById('genericWebhookFormat').value || 'slack',
        generic_webhook_custom_template: document.getElementById('genericWebhookTemplate').value || '',
        generic_webhook_token: document.getElementById('genericWebhookToken').value || '',
        // Email settings
        critical_email_enabled: document.getElementById('criticalEmailEnabled').checked,
        critical_email_time: document.getElementById('criticalEmailTime').value || '09:00',
        critical_email_max_age_days: parseInt(document.getElementById('criticalEmailMaxAge').value) || 30,
        // Alert mode defaults
        default_alert_mode: document.getElementById('defaultAlertMode').value || 'daily_reminder',
        default_escalation_days: parseInt(document.getElementById('defaultEscalationDays').value) || 3
    };

    try {
        const response = await fetch('/api/settings/notifications', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('Notification settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving notification settings: ${error.message}`, 'danger');
    }
}

async function loadNotificationSettings() {
    try {
        const response = await fetch('/api/settings/notifications');
        if (response.ok) {
            const settings = await response.json();
            const slackEnabled = document.getElementById('slackEnabled');
            const slackWebhookUrl = document.getElementById('slackWebhookUrl');
            const teamsEnabled = document.getElementById('teamsEnabled');
            const teamsWebhookUrl = document.getElementById('teamsWebhookUrl');
            const genericWebhookEnabled = document.getElementById('genericWebhookEnabled');
            const genericWebhookUrl = document.getElementById('genericWebhookUrl');
            const genericWebhookName = document.getElementById('genericWebhookName');
            const genericWebhookFormat = document.getElementById('genericWebhookFormat');
            const genericWebhookTemplate = document.getElementById('genericWebhookTemplate');
            const genericWebhookToken = document.getElementById('genericWebhookToken');
            const customTemplateContainer = document.getElementById('customTemplateContainer');
            const criticalEmailEnabled = document.getElementById('criticalEmailEnabled');
            const criticalEmailTime = document.getElementById('criticalEmailTime');
            const criticalEmailMaxAge = document.getElementById('criticalEmailMaxAge');

            if (slackEnabled) slackEnabled.checked = settings.slack_enabled === true;
            if (slackWebhookUrl) slackWebhookUrl.value = settings.slack_webhook_url || '';
            if (teamsEnabled) teamsEnabled.checked = settings.teams_enabled === true;
            if (teamsWebhookUrl) teamsWebhookUrl.value = settings.teams_webhook_url || '';

            // Generic webhook settings
            if (genericWebhookEnabled) genericWebhookEnabled.checked = settings.generic_webhook_enabled === true;
            if (genericWebhookUrl) genericWebhookUrl.value = settings.generic_webhook_url || '';
            if (genericWebhookName) genericWebhookName.value = settings.generic_webhook_name || 'Custom Webhook';
            if (genericWebhookFormat) {
                genericWebhookFormat.value = settings.generic_webhook_format || 'slack';
                // Show/hide custom template field
                if (customTemplateContainer) {
                    customTemplateContainer.style.display = genericWebhookFormat.value === 'custom' ? 'block' : 'none';
                }
            }
            if (genericWebhookTemplate) genericWebhookTemplate.value = settings.generic_webhook_custom_template || '';
            if (genericWebhookToken) genericWebhookToken.value = settings.generic_webhook_token || '';

            if (criticalEmailEnabled) criticalEmailEnabled.checked = settings.critical_email_enabled !== false;
            if (criticalEmailTime) criticalEmailTime.value = settings.critical_email_time || '09:00';
            if (criticalEmailMaxAge) criticalEmailMaxAge.value = settings.critical_email_max_age_days || 30;

            // Alert mode defaults
            const defaultAlertMode = document.getElementById('defaultAlertMode');
            const defaultEscalationDays = document.getElementById('defaultEscalationDays');
            if (defaultAlertMode) defaultAlertMode.value = settings.default_alert_mode || 'daily_reminder';
            if (defaultEscalationDays) defaultEscalationDays.value = settings.default_escalation_days || 3;

            // Setup event listener for format change
            if (genericWebhookFormat) {
                genericWebhookFormat.addEventListener('change', function() {
                    if (customTemplateContainer) {
                        customTemplateContainer.style.display = this.value === 'custom' ? 'block' : 'none';
                    }
                });
            }
        }
    } catch (error) {
        console.error('Error loading notification settings:', error);
    }
}

async function testWebhook(type) {
    showLoading();
    try {
        const response = await fetch('/api/settings/notifications/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });

        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
        } else {
            showToast(`Test failed: ${data.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Test failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// Data Retention Settings
// ============================================================================

async function saveRetentionSettings() {
    const settings = {
        audit_log_retention_days: parseInt(document.getElementById('auditLogRetention').value) || 365,
        sync_history_retention_days: parseInt(document.getElementById('syncHistoryRetention').value) || 90,
        session_log_retention_days: parseInt(document.getElementById('sessionLogRetention').value) || 30
    };

    try {
        const response = await fetch('/api/settings/retention', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });

        if (response.ok) {
            showToast('Retention settings saved successfully', 'success');
        } else {
            const error = await response.json();
            showToast(`Error: ${error.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error saving retention settings: ${error.message}`, 'danger');
    }
}

async function loadRetentionSettings() {
    try {
        const response = await fetch('/api/settings/retention');
        if (response.ok) {
            const settings = await response.json();
            const auditLogRetention = document.getElementById('auditLogRetention');
            const syncHistoryRetention = document.getElementById('syncHistoryRetention');
            const sessionLogRetention = document.getElementById('sessionLogRetention');

            if (auditLogRetention) auditLogRetention.value = settings.audit_log_retention_days || 365;
            if (syncHistoryRetention) syncHistoryRetention.value = settings.sync_history_retention_days || 90;
            if (sessionLogRetention) sessionLogRetention.value = settings.session_log_retention_days || 30;
        }
    } catch (error) {
        console.error('Error loading retention settings:', error);
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
            document.getElementById('globalSmtpUseSSL').checked = smtp.smtp_use_ssl === true;
        }

        // Load Sync settings
        const syncResponse = await fetch('/api/settings/sync');
        if (syncResponse.ok) {
            const sync = await syncResponse.json();
            document.getElementById('autoSyncEnabled').checked = sync.auto_sync_enabled || false;
            document.getElementById('syncInterval').value = sync.sync_interval || 'daily';
            document.getElementById('syncTime').value = sync.sync_time || '02:00';
            document.getElementById('cisaKevUrl').value = sync.cisa_kev_url || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
            // NVD API Key - show placeholder if configured
            const nvdKeyInput = document.getElementById('nvdApiKey');
            if (nvdKeyInput) {
                nvdKeyInput.value = '';
                nvdKeyInput.placeholder = sync.nvd_api_key_configured
                    ? '(API key saved - leave blank to keep)'
                    : 'Enter your NVD API key (optional)';
            }
        }
        loadSyncStatus();

        // Load Proxy settings
        const generalResponse = await fetch('/api/settings/general');
        if (generalResponse.ok) {
            const general = await generalResponse.json();
            const verifySSL = document.getElementById('verifySSL');
            const httpProxy = document.getElementById('httpProxy');
            const httpsProxy = document.getElementById('httpsProxy');
            const noProxy = document.getElementById('noProxy');
            if (verifySSL) verifySSL.checked = general.verify_ssl !== false;
            if (httpProxy) httpProxy.value = general.http_proxy || '';
            if (httpsProxy) httpsProxy.value = general.https_proxy || '';
            if (noProxy) noProxy.value = general.no_proxy || '';
        }

        // Load additional settings (security, branding, notifications, retention)
        loadSecuritySettings();
        loadBrandingSettings();
        loadNotificationSettings();
        loadRetentionSettings();
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

            // First check if LDAP feature is licensed
            const ldapLicensed = isFeatureLicensed('ldap');
            if (!ldapLicensed) {
                // LDAP not licensed - tabs stay hidden (handled by applyLicenseRestrictions)
                return;
            }

            // LDAP Users tab: visible to org_admin, super_admin, or legacy is_admin
            const canAccessLdapUsers = user.role === 'org_admin' ||
                                       user.role === 'super_admin' ||
                                       user.is_admin === true;

            // LDAP Groups tab: only visible to super_admin (system-level config)
            const canAccessLdapGroups = user.role === 'super_admin' || user.is_admin === true;

            const ldapUsersTab = document.getElementById('ldap-users-tab-item');
            const ldapGroupsTab = document.getElementById('ldap-groups-tab-item');

            if (ldapUsersTab && canAccessLdapUsers) {
                ldapUsersTab.style.display = 'block';
            }
            if (ldapGroupsTab && canAccessLdapGroups) {
                ldapGroupsTab.style.display = 'block';
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
                        <td colspan="10" class="text-center py-4">
                            <i class="bi bi-inbox text-muted" style="font-size: 3rem;"></i>
                            <p class="text-muted mt-3">No LDAP group mappings configured.</p>
                            <p class="text-muted">Use "Discover LDAP Groups" above to find and map groups from your directory.</p>
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
                            <input type="checkbox" class="form-check-input mapping-checkbox"
                                   data-mapping-id="${mapping.id}" onchange="toggleMappingSelect(${mapping.id}, this)">
                        </td>
                        <td data-column="group">
                            <strong>${escapeHtml(mapping.ldap_group_cn)}</strong><br>
                            <small class="text-muted">${escapeHtml(mapping.ldap_group_dn)}</small>
                        </td>
                        <td data-column="organization">${escapeHtml(orgName)}</td>
                        <td data-column="role">${roleBadge}</td>
                        <td data-column="priority"><span class="badge bg-primary">${mapping.priority}</span></td>
                        <td data-column="autoprovision" class="text-center">${autoProvisionIcon}</td>
                        <td data-column="members">${mapping.member_count || 0}</td>
                        <td data-column="lastsync"><small>${lastSync}</small></td>
                        <td data-column="status">${statusBadge}</td>
                        <td data-column="actions">
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

            // Reset select all checkbox
            const selectAllMappings = document.getElementById('selectAllMappings');
            if (selectAllMappings) selectAllMappings.checked = false;

            // Clear selection state
            selectedMappings.clear();
            updateMappingsBulkToolbar();

            // Initialize table enhancements
            if (typeof SortableTable !== 'undefined') {
                SortableTable.init('groupMappingsTableContainer');
            }
            if (typeof TableEnhancements !== 'undefined') {
                TableEnhancements.refresh('groupMappingsTableContainer');
            }
        } else {
            const error = await response.json();
            tableBody.innerHTML = `
                <tr>
                    <td colspan="10" class="text-center py-4 text-danger">
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
async function showCreateMappingModal() {
    try {
        // Reset form
        const form = document.getElementById('groupMappingForm');
        if (form) {
            form.reset();
            // Clear member count data attribute
            delete form.dataset.memberCount;
        }

        const mappingIdEl = document.getElementById('mappingId');
        if (mappingIdEl) mappingIdEl.value = '';

        const titleEl = document.getElementById('groupMappingModalTitle');
        if (titleEl) titleEl.textContent = 'Create Group Mapping';

        // Load organizations dropdown
        await loadOrganizationsForMapping();

        // Show modal
        const modalEl = document.getElementById('groupMappingModal');
        if (!modalEl) {
            console.error('groupMappingModal element not found');
            showToast('Error: Modal not found', 'danger');
            return;
        }
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    } catch (error) {
        console.error('Error showing create mapping modal:', error);
        showToast('Error opening modal: ' + error.message, 'danger');
    }
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
    const form = document.getElementById('groupMappingForm');
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

    // Include member_count if creating a new mapping (from discovered groups)
    if (!mappingId && form && form.dataset.memberCount) {
        data.member_count = parseInt(form.dataset.memberCount) || 0;
    }

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
                            ${groups.map((group, index) => `
                                <tr>
                                    <td class="fw-semibold">${escapeHtml(group.cn)}</td>
                                    <td><small class="text-muted">${escapeHtml(group.dn)}</small></td>
                                    <td>
                                        <span class="badge bg-success">${group.member_count || 0} members</span>
                                    </td>
                                    <td><small>${escapeHtml(group.description || '-')}</small></td>
                                    <td>
                                        <button class="btn btn-outline-primary btn-sm create-mapping-btn"
                                                data-group-index="${index}"
                                                title="Create mapping for ${escapeHtml(group.cn)}">
                                            <i class="bi bi-plus-circle"></i> Map
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;

            // Store groups data and attach click handlers
            container.discoveredGroups = groups;
            container.querySelectorAll('.create-mapping-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const index = parseInt(this.dataset.groupIndex);
                    const group = container.discoveredGroups[index];
                    createMappingFromDiscoveryInline(group.dn, group.cn, group.description || '', group.member_count || 0);
                });
            });
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
async function createMappingFromDiscoveryInline(dn, cn, description, memberCount) {
    // Show the create mapping modal first
    await showCreateMappingModal();

    // Pre-fill the form with discovered group info
    const form = document.getElementById('groupMappingForm');
    const dnField = document.getElementById('ldapGroupDn');
    const cnField = document.getElementById('ldapGroupCn');
    const descField = document.getElementById('ldapGroupDescription');

    if (dnField) dnField.value = dn;
    if (cnField) cnField.value = cn;
    if (descField && description) descField.value = description;

    // Store member count in data attribute for submission
    if (form) form.dataset.memberCount = memberCount || 0;

    // Update modal title
    const titleEl = document.getElementById('groupMappingModalTitle');
    if (titleEl) titleEl.textContent = 'Create Group Mapping';

    // Optionally collapse the discovery panel
    const panel = document.getElementById('groupDiscoveryPanel');
    const icon = document.getElementById('discoveryToggleIcon');
    if (panel) panel.style.display = 'none';
    if (icon) icon.className = 'bi bi-chevron-down';
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
                            ${groups.map((group, index) => `
                                <tr>
                                    <td><strong>${escapeHtml(group.cn)}</strong></td>
                                    <td><small>${escapeHtml(group.dn)}</small></td>
                                    <td><span class="badge bg-success">${group.member_count || 0}</span></td>
                                    <td><small>${escapeHtml(group.description || '-')}</small></td>
                                    <td>
                                        <button class="btn btn-outline-primary btn-sm create-mapping-btn2"
                                                data-group-index="${index}"
                                                title="Create mapping for ${escapeHtml(group.cn)}">
                                            <i class="bi bi-plus-circle"></i> Map
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;

            // Store groups data and attach click handlers
            container.discoveredGroups = groups;
            container.querySelectorAll('.create-mapping-btn2').forEach(btn => {
                btn.addEventListener('click', function() {
                    const index = parseInt(this.dataset.groupIndex);
                    const group = container.discoveredGroups[index];
                    createMappingFromDiscovery(group.dn, group.cn, group.description || '', group.member_count || 0);
                });
            });
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
function createMappingFromDiscovery(dn, cn, description, memberCount) {
    // Close discovery modal
    const discoveryModal = bootstrap.Modal.getInstance(document.getElementById('ldapDiscoveryModal'));
    if (discoveryModal) {
        discoveryModal.hide();
    }

    // Pre-fill mapping form
    const form = document.getElementById('groupMappingForm');
    form.reset();
    document.getElementById('mappingId').value = '';
    document.getElementById('ldapGroupDn').value = dn;
    document.getElementById('ldapGroupCn').value = cn;
    document.getElementById('ldapGroupDescription').value = description;
    // Store member count in data attribute for submission
    form.dataset.memberCount = memberCount || 0;
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
            const result = await response.json();
            const logs = result.logs || [];
            const latestSync = logs.length > 0 ? logs[0] : null;

            // Update stats displays - use 'timestamp' field from backend
            if (latestSync && latestSync.timestamp) {
                document.getElementById('syncStatsLastSync').textContent =
                    new Date(latestSync.timestamp).toLocaleString();
            }

            // Count total LDAP users
            const usersResponse = await fetch('/api/users');
            if (usersResponse.ok) {
                const users = await usersResponse.json();
                const ldapUsers = users.filter(u => u.auth_type === 'ldap');
                document.getElementById('syncStatsTotal').textContent = ldapUsers.length;
            }

            // Count successful syncs and errors from history
            // Backend uses 'success' not 'completed' for status
            const historyResponse = await fetch('/api/ldap/groups/sync/history?limit=100');
            if (historyResponse.ok) {
                const historyResult = await historyResponse.json();
                const allHistory = historyResult.logs || [];
                const successCount = allHistory.filter(s => s.status === 'success').length;
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
                // Map backend status values to display badges
                let statusBadge;
                if (sync.status === 'success') {
                    statusBadge = '<span class="badge bg-success">Completed</span>';
                } else if (sync.status === 'partial') {
                    statusBadge = '<span class="badge bg-warning">Partial</span>';
                } else if (sync.status === 'failed') {
                    statusBadge = '<span class="badge bg-danger">Failed</span>';
                } else {
                    statusBadge = '<span class="badge bg-secondary">Unknown</span>';
                }

                // Use correct field names from backend (duration_seconds, timestamp)
                const duration = sync.duration_seconds ? `${sync.duration_seconds.toFixed(2)}s` : '-';
                const startedAt = sync.timestamp ? new Date(sync.timestamp).toLocaleString() : '-';
                const errorCount = Array.isArray(sync.errors) ? sync.errors.length : 0;

                return `
                    <tr>
                        <td data-column="syncid"><small>${escapeHtml(sync.sync_id)}</small></td>
                        <td data-column="type">${escapeHtml(sync.sync_type)}</td>
                        <td data-column="started"><small>${startedAt}</small></td>
                        <td data-column="duration">${duration}</td>
                        <td data-column="status">${statusBadge}</td>
                        <td data-column="added">${sync.users_added || 0}</td>
                        <td data-column="updated">${sync.users_updated || 0}</td>
                        <td data-column="deactivated">${sync.users_deactivated || 0}</td>
                        <td data-column="errors">${errorCount}</td>
                    </tr>
                `;
            }).join('');

            // Initialize table enhancements
            if (typeof SortableTable !== 'undefined') {
                SortableTable.init('syncHistoryTableContainer');
            }
            if (typeof TableEnhancements !== 'undefined') {
                TableEnhancements.refresh('syncHistoryTableContainer');
            }
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

// ============================================================================
// AUDIT LOGS
// ============================================================================

let currentAuditPage = 1;

async function loadAuditLogs(page = 1) {
    const tbody = document.getElementById('auditLogsTable');
    if (!tbody) return;

    currentAuditPage = page;

    // Get filter values
    const action = document.getElementById('auditActionFilter')?.value || '';
    const resource = document.getElementById('auditResourceFilter')?.value || '';
    const search = document.getElementById('auditSearchInput')?.value || '';
    const startDate = document.getElementById('auditStartDate')?.value || '';
    const endDate = document.getElementById('auditEndDate')?.value || '';
    const perPage = document.getElementById('auditPerPage')?.value || '50';
    const sortField = document.getElementById('auditSortField')?.value || 'timestamp';
    const sortOrder = document.getElementById('auditSortOrder')?.value || 'desc';

    tbody.innerHTML = `
        <tr>
            <td colspan="6" class="text-center text-muted py-4">
                <div class="spinner-border spinner-border-sm text-primary me-2"></div>Loading audit logs...
            </td>
        </tr>
    `;

    try {
        // Build URL with all parameters
        const params = new URLSearchParams({
            page: page,
            per_page: perPage,
            sort: sortField,
            order: sortOrder
        });
        if (action) params.append('action', action);
        if (resource) params.append('resource', resource);
        if (search) params.append('search', search);
        if (startDate) params.append('start_date', startDate);
        if (endDate) params.append('end_date', endDate);

        const response = await fetch(`/api/audit-logs?${params}`);

        if (!response.ok) {
            const error = await response.json();
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-danger py-4">
                        <i class="bi bi-exclamation-triangle me-2"></i>${error.error || 'Failed to load audit logs'}
                    </td>
                </tr>
            `;
            updateAuditPagination(0, 0, 0);
            return;
        }

        const data = await response.json();

        // Update info display
        const infoEl = document.getElementById('auditPaginationInfo');
        if (infoEl) {
            const start = (data.page - 1) * data.per_page + 1;
            const end = Math.min(data.page * data.per_page, data.total);
            infoEl.textContent = data.total > 0
                ? `Showing ${start}-${end} of ${data.total} entries`
                : 'No entries';
        }

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">
                        <i class="bi bi-journal-text me-2"></i>No audit logs found matching your criteria
                    </td>
                </tr>
            `;
            updateAuditPagination(0, 0, 0);
            return;
        }

        tbody.innerHTML = data.logs.map(log => {
            const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString() : '-';
            const actionBadge = getActionBadge(log.action);

            // Build details from message and/or structured data
            let details = '';
            if (log.message) {
                details = log.message;
            }
            if (log.old_value || log.new_value) {
                const changes = [];
                if (log.old_value) changes.push(`From: ${JSON.stringify(log.old_value)}`);
                if (log.new_value) changes.push(`To: ${JSON.stringify(log.new_value)}`);
                if (details) details += ' | ';
                details += changes.join(' ');
            }
            if (!details) details = '-';

            const truncatedDetails = details.length > 100 ? details.substring(0, 100) + '...' : details;

            // Parse resource to get type and ID
            const resourceParts = (log.resource || '').split(':');
            const resourceType = resourceParts[0] || '-';
            const resourceId = resourceParts[1] || '';

            return `
                <tr>
                    <td class="text-nowrap"><small>${timestamp}</small></td>
                    <td>${actionBadge}</td>
                    <td><small>${escapeHtml(resourceType)}${resourceId ? `:<strong>${resourceId}</strong>` : ''}</small></td>
                    <td><small>${escapeHtml(log.user_id || '-')}</small></td>
                    <td><small class="text-muted">${escapeHtml(log.ip_address || '-')}</small></td>
                    <td><small class="text-muted" title="${escapeHtml(details)}" style="cursor: help;">${escapeHtml(truncatedDetails)}</small></td>
                </tr>
            `;
        }).join('');

        // Update pagination
        updateAuditPagination(data.page, data.total_pages, data.total);

    } catch (error) {
        console.error('Error loading audit logs:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-danger py-4">
                    <i class="bi bi-exclamation-triangle me-2"></i>Error loading audit logs: ${error.message}
                </td>
            </tr>
        `;
        updateAuditPagination(0, 0, 0);
    }
}

function updateAuditPagination(currentPage, totalPages, total) {
    const pagination = document.getElementById('auditPagination');
    if (!pagination) return;

    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }

    let html = '';

    // Previous button
    html += `
        <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="loadAuditLogs(${currentPage - 1}); return false;">&laquo;</a>
        </li>
    `;

    // Page numbers (show max 7 pages)
    const maxPages = 7;
    let startPage = Math.max(1, currentPage - Math.floor(maxPages / 2));
    let endPage = Math.min(totalPages, startPage + maxPages - 1);

    if (endPage - startPage < maxPages - 1) {
        startPage = Math.max(1, endPage - maxPages + 1);
    }

    if (startPage > 1) {
        html += `<li class="page-item"><a class="page-link" href="#" onclick="loadAuditLogs(1); return false;">1</a></li>`;
        if (startPage > 2) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `
            <li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" onclick="loadAuditLogs(${i}); return false;">${i}</a>
            </li>
        `;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
        html += `<li class="page-item"><a class="page-link" href="#" onclick="loadAuditLogs(${totalPages}); return false;">${totalPages}</a></li>`;
    }

    // Next button
    html += `
        <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="loadAuditLogs(${currentPage + 1}); return false;">&raquo;</a>
        </li>
    `;

    pagination.innerHTML = html;
}

function sortAuditLogs(field) {
    const sortFieldEl = document.getElementById('auditSortField');
    const sortOrderEl = document.getElementById('auditSortOrder');

    if (sortFieldEl.value === field) {
        // Toggle order if same field
        sortOrderEl.value = sortOrderEl.value === 'desc' ? 'asc' : 'desc';
    } else {
        sortFieldEl.value = field;
        sortOrderEl.value = 'desc';
    }

    loadAuditLogs(1);
}

function clearAuditFilters() {
    document.getElementById('auditSearchInput').value = '';
    document.getElementById('auditActionFilter').value = '';
    document.getElementById('auditResourceFilter').value = '';
    document.getElementById('auditStartDate').value = '';
    document.getElementById('auditEndDate').value = '';
    document.getElementById('auditPerPage').value = '50';
    document.getElementById('auditSortField').value = 'timestamp';
    document.getElementById('auditSortOrder').value = 'desc';
    loadAuditLogs(1);
}

function getActionBadge(action) {
    const badges = {
        'CREATE': '<span class="badge bg-success">CREATE</span>',
        'UPDATE': '<span class="badge bg-primary">UPDATE</span>',
        'DELETE': '<span class="badge bg-danger">DELETE</span>',
        'LOGIN': '<span class="badge bg-info">LOGIN</span>',
        'LOGOUT': '<span class="badge bg-secondary">LOGOUT</span>',
        'LOGIN_FAILED': '<span class="badge bg-danger">LOGIN FAILED</span>',
        'BLOCK': '<span class="badge bg-warning text-dark">BLOCK</span>',
        'UNBLOCK': '<span class="badge bg-success">UNBLOCK</span>',
        'UNLOCK': '<span class="badge bg-warning text-dark">UNLOCK</span>',
        'RESET_2FA': '<span class="badge bg-purple text-white" style="background-color: #7c3aed;">RESET 2FA</span>',
        'FORCE_PASSWORD_CHANGE': '<span class="badge bg-purple text-white" style="background-color: #7c3aed;">FORCE PWD</span>',
        'SYNC': '<span class="badge bg-info">SYNC</span>',
        'BACKUP': '<span class="badge bg-secondary">BACKUP</span>',
        'RESTORE': '<span class="badge bg-warning text-dark">RESTORE</span>'
    };
    return badges[action] || `<span class="badge bg-secondary">${escapeHtml(action || 'UNKNOWN')}</span>`;
}

function exportAuditLogs(format, days) {
    const action = document.getElementById('auditActionFilter')?.value || '';
    const resource = document.getElementById('auditResourceFilter')?.value || '';
    const search = document.getElementById('auditSearchInput')?.value || '';

    let url = `/api/audit-logs/export?format=${format}&days=${days}`;
    if (action) url += `&action=${encodeURIComponent(action)}`;
    if (resource) url += `&resource=${encodeURIComponent(resource)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    // Trigger download
    window.location.href = url;
    showToast(`Downloading audit logs (${format.toUpperCase()}, last ${days} days)...`, 'info');
}

// Load audit logs when the tab is shown
document.addEventListener('DOMContentLoaded', function() {
    const auditLogsTab = document.getElementById('audit-logs-tab');
    if (auditLogsTab) {
        auditLogsTab.addEventListener('shown.bs.tab', function() {
            loadAuditLogs(1);
        });
    }

    // Load license info when tab is shown
    const licenseTab = document.getElementById('license-tab');
    if (licenseTab) {
        licenseTab.addEventListener('shown.bs.tab', function() {
            loadLicenseInfo();
        });
    }
});

// ============================================================================
// LICENSE MANAGEMENT
// ============================================================================

/**
 * Load license info and apply UI restrictions for premium features
 * This is called early during page initialization
 */
async function loadLicenseAndApplyRestrictions() {
    try {
        const response = await fetch('/api/license');
        if (!response.ok) {
            console.warn('Failed to load license info');
            window.licenseInfo = { is_professional: false, features: [] };
            return;
        }

        window.licenseInfo = await response.json();
        applyLicenseRestrictions();

    } catch (error) {
        console.error('Error loading license for restrictions:', error);
        window.licenseInfo = { is_professional: false, features: [] };
    }
}

/**
 * Apply UI restrictions based on license status
 * Hides premium features and shows upgrade notices for Community users
 */
function applyLicenseRestrictions() {
    const license = window.licenseInfo;
    if (!license) return;

    const isProfessional = license.is_professional;
    const features = license.features || [];

    // Helper to check if a feature is licensed
    const hasFeature = (feature) => isProfessional || features.includes(feature);

    // ========================================
    // LDAP Features - requires 'ldap' license
    // ========================================
    if (!hasFeature('ldap')) {
        // Hide LDAP tabs completely for Community
        const ldapUsersTab = document.getElementById('ldap-users-tab-item');
        const ldapGroupsTab = document.getElementById('ldap-groups-tab-item');
        if (ldapUsersTab) ldapUsersTab.style.display = 'none';
        if (ldapGroupsTab) ldapGroupsTab.style.display = 'none';

        // Add upgrade notice to LDAP settings section
        const ldapSettingsPane = document.getElementById('ldapSettings');
        if (ldapSettingsPane) {
            ldapSettingsPane.innerHTML = createPremiumUpgradeNotice('LDAP Authentication', 'ldap');
        }
    }

    // ========================================
    // Backup & Restore - requires 'backup_restore' license
    // ========================================
    if (!hasFeature('backup_restore')) {
        // Find and replace the Backup & Restore card content
        const backupCard = document.getElementById('backupRestoreCard');
        if (backupCard) {
            backupCard.innerHTML = `
                <div class="card-header">
                    <i class="bi bi-cloud-download me-2"></i>Backup & Restore
                    <span class="badge bg-warning text-dark ms-1" style="font-size: 0.7em;">PRO</span>
                </div>
                ${createPremiumUpgradeNotice('Backup & Restore', 'backup_restore')}
            `;
        }
    }

    // ========================================
    // Email Alerts / Webhooks - requires 'email_alerts' license
    // ========================================
    if (!hasFeature('email_alerts')) {
        const notificationsPane = document.getElementById('notificationsSettings');
        if (notificationsPane) {
            // Replace notifications settings with upgrade notice
            notificationsPane.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <i class="bi bi-bell me-2"></i>Notification Integrations
                        <span class="badge bg-warning text-dark ms-1" style="font-size: 0.7em;">PRO</span>
                    </div>
                    ${createPremiumUpgradeNotice('Email Alerts & Webhooks', 'email_alerts')}
                </div>
            `;
        }

        // Also hide the org webhook tab in organization modal
        const orgWebhookTab = document.getElementById('webhook-tab');
        if (orgWebhookTab) {
            orgWebhookTab.closest('li')?.style.setProperty('display', 'none');
        }
    }

    // ========================================
    // White Label / Branding - requires 'white_label' license
    // ========================================
    if (!hasFeature('white_label')) {
        const brandingPane = document.getElementById('brandingSettings');
        if (brandingPane) {
            // Replace branding settings with upgrade notice
            brandingPane.innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <i class="bi bi-palette me-2"></i>Branding & White Label
                        <span class="badge bg-warning text-dark ms-1" style="font-size: 0.7em;">PRO</span>
                    </div>
                    ${createPremiumUpgradeNotice('Branding & White Label', 'white_label')}
                </div>
            `;
        }
    }

    console.log('License restrictions applied:', {
        isProfessional,
        features,
        ldapEnabled: hasFeature('ldap'),
        backupEnabled: hasFeature('backup_restore'),
        emailAlertsEnabled: hasFeature('email_alerts'),
        whiteLabelEnabled: hasFeature('white_label')
    });
}

/**
 * Create a premium upgrade notice HTML for a locked feature
 */
function createPremiumUpgradeNotice(featureName, featureKey) {
    return `
        <div class="card-body">
            <div class="text-center py-4">
                <i class="bi bi-lock-fill display-3 text-muted mb-3"></i>
                <h5 class="text-muted">${featureName}</h5>
                <p class="text-muted mb-3">
                    This feature requires a <strong>Professional license</strong>.
                </p>
                <div class="alert alert-light border d-inline-block">
                    <i class="bi bi-stars me-2 text-warning"></i>
                    Upgrade to Professional to unlock ${featureName.toLowerCase()} and more advanced features.
                </div>
            </div>
        </div>
    `;
}

/**
 * Check if a specific feature is licensed
 * Can be called from anywhere after license is loaded
 */
function isFeatureLicensed(feature) {
    const license = window.licenseInfo;
    if (!license) return false;
    if (license.is_professional) return true;
    return (license.features || []).includes(feature);
}

async function loadLicenseInfo() {
    try {
        const response = await fetch('/api/license');
        if (!response.ok) {
            throw new Error('Failed to load license info');
        }

        const data = await response.json();
        displayLicenseInfo(data);

    } catch (error) {
        console.error('Error loading license:', error);
        document.getElementById('licenseDetails').innerHTML = `
            <div class="alert alert-danger mb-0">
                <i class="bi bi-exclamation-triangle me-2"></i>Failed to load license info
            </div>
        `;
    }
}

function displayLicenseInfo(data) {
    const detailsEl = document.getElementById('licenseDetails');
    const usageEl = document.getElementById('licenseUsage');
    const badgeEl = document.getElementById('licenseEditionBadge');
    const removeBtn = document.getElementById('removeLicenseBtn');

    // Update edition badge
    if (data.is_professional) {
        badgeEl.className = 'badge bg-success';
        badgeEl.textContent = 'Professional';
        removeBtn.style.display = 'inline-block';
    } else {
        badgeEl.className = 'badge bg-secondary';
        badgeEl.textContent = 'Community';
        removeBtn.style.display = 'none';
    }

    // License details
    let statusHtml = '';
    if (data.is_professional) {
        statusHtml = `
            <div class="mb-2">
                <span class="badge bg-success mb-2"><i class="bi bi-patch-check me-1"></i>Professional License</span>
            </div>
            <table class="table table-sm table-borderless mb-0">
                <tr>
                    <td class="text-muted" style="width: 100px;">Customer</td>
                    <td><strong>${escapeHtml(data.customer || '-')}</strong></td>
                </tr>
                <tr>
                    <td class="text-muted">License ID</td>
                    <td><code>${escapeHtml(data.license_id || '-')}</code></td>
                </tr>
                <tr>
                    <td class="text-muted">Expires</td>
                    <td>${data.expires_at ? formatDate(data.expires_at) : '<span class="text-success">Never (Perpetual)</span>'}</td>
                </tr>
                ${data.days_until_expiry !== null ? `
                <tr>
                    <td class="text-muted">Status</td>
                    <td>${data.is_expired
                        ? '<span class="badge bg-danger">Expired</span>'
                        : data.days_until_expiry <= 30
                            ? `<span class="badge bg-warning text-dark">${data.days_until_expiry} days remaining</span>`
                            : `<span class="badge bg-success">${data.days_until_expiry} days remaining</span>`
                    }</td>
                </tr>
                ` : ''}
            </table>
        `;
    } else {
        statusHtml = `
            <div class="mb-2">
                <span class="badge bg-secondary mb-2"><i class="bi bi-box me-1"></i>Community Edition</span>
            </div>
            <p class="text-muted small mb-2">Free for personal and small team use.</p>
            <p class="mb-0">
                <a href="#" class="text-primary" onclick="document.getElementById('licenseKeyInput').focus(); return false;">
                    <i class="bi bi-arrow-up-circle me-1"></i>Upgrade to Professional
                </a>
            </p>
        `;
    }
    detailsEl.innerHTML = statusHtml;

    // Usage info
    const limits = data.limits || {};
    const usage = data.usage || {};

    const formatLimit = (current, max) => {
        if (max === -1) return `${current} <span class="text-success">(unlimited)</span>`;
        const percent = (current / max) * 100;
        const colorClass = percent >= 100 ? 'text-danger' : percent >= 80 ? 'text-warning' : 'text-success';
        return `<span class="${colorClass}">${current}</span> / ${max}`;
    };

    usageEl.innerHTML = `
        <table class="table table-sm table-borderless mb-0">
            <tr>
                <td class="text-muted" style="width: 100px;">Users</td>
                <td>${formatLimit(usage.users || 0, limits.max_users)}</td>
            </tr>
            <tr>
                <td class="text-muted">Organizations</td>
                <td>${formatLimit(usage.organizations || 0, limits.max_organizations)}</td>
            </tr>
            <tr>
                <td class="text-muted">Products</td>
                <td>${formatLimit(usage.products || 0, limits.max_products)}</td>
            </tr>
        </table>
        ${!data.is_professional && (
            (usage.users >= limits.max_users) ||
            (usage.organizations >= limits.max_organizations) ||
            (usage.products >= limits.max_products)
        ) ? `
            <div class="alert alert-warning mt-3 mb-0 py-2">
                <small><i class="bi bi-exclamation-triangle me-1"></i>You've reached Community limits. Upgrade to Professional for unlimited usage.</small>
            </div>
        ` : ''}
    `;
}

async function activateLicense() {
    const licenseKey = document.getElementById('licenseKeyInput').value.trim();

    if (!licenseKey) {
        showToast('Please enter a license key', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/license', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ license_key: licenseKey })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast(data.message, 'success');
            document.getElementById('licenseKeyInput').value = '';
            loadLicenseInfo();
            // Reload page to apply license changes (like removing "Powered by")
            setTimeout(() => window.location.reload(), 1500);
        } else {
            showToast(data.error || 'Failed to activate license', 'error');
        }

    } catch (error) {
        console.error('Error activating license:', error);
        showToast('Failed to activate license: ' + error.message, 'error');
    }
}

async function removeLicense() {
    const confirmed = await showConfirm('Are you sure you want to remove the license?<br><br>This will revert to <strong>Community edition</strong>.', 'Remove License', 'Remove', 'btn-danger');
    if (!confirmed) return;

    try {
        const response = await fetch('/api/license', {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast(data.message, 'success');
            loadLicenseInfo();
            // Reload page to apply changes
            setTimeout(() => window.location.reload(), 1500);
        } else {
            showToast(data.error || 'Failed to remove license', 'error');
        }

    } catch (error) {
        console.error('Error removing license:', error);
        showToast('Failed to remove license: ' + error.message, 'error');
    }
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// ============================================================================
// URL HASH HANDLING - Switch to tab based on URL hash
// ============================================================================

/**
 * Handle URL hash to switch to the correct tab on page load
 * Supports: #users, #organizations, #settings, #ldapUsers, #ldapGroups, #license
 */
function handleUrlHash() {
    const hash = window.location.hash.substring(1); // Remove the '#'
    if (!hash) return;

    console.log('URL hash detected:', hash);

    // Map of hash values to tab button IDs
    const tabMap = {
        'users': 'users-tab',
        'organizations': 'organizations-tab',
        'settings': 'settings-tab',
        'ldapUsers': 'ldap-users-tab',
        'ldapGroups': 'ldap-groups-tab',
        'license': 'license-tab'
    };

    const tabButtonId = tabMap[hash];
    if (tabButtonId) {
        const tabButton = document.getElementById(tabButtonId);
        if (tabButton) {
            console.log('Switching to tab:', tabButtonId);
            // Use Bootstrap's Tab API to switch tabs
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
        } else {
            console.warn('Tab button not found:', tabButtonId);
        }
    }
}

// Initialize hash handling when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Handle URL hash on page load
    handleUrlHash();

    // Also handle hash changes (e.g., if user clicks back button)
    window.addEventListener('hashchange', handleUrlHash);
});
