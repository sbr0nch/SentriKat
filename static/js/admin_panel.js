/**
 * Admin Panel JavaScript
 * Handles user management, organization management, and settings
 *
 * This module uses SK.DOM utilities from sentrikat-core.js for safe DOM access.
 */

// ============================================================================
// SK NAMESPACE FALLBACK - Ensure SK.DOM is available
// ============================================================================

if (typeof SK === 'undefined' || !SK.DOM) {
    console.warn('[AdminPanel] SK namespace not found, creating fallback');
    window.SK = window.SK || {};
    SK.DOM = {
        get: function(id) { return document.getElementById(id); },
        getValue: function(id) {
            const el = document.getElementById(id);
            return el ? el.value : '';
        },
        getChecked: function(id) {
            const el = document.getElementById(id);
            return el ? el.checked : false;
        },
        setValue: function(id, value) {
            const el = document.getElementById(id);
            if (el) el.value = value ?? '';
        },
        setHtml: function(id, html) {
            const el = document.getElementById(id);
            if (el) el.innerHTML = html ?? '';
        },
        setChecked: function(id, checked) {
            const el = document.getElementById(id);
            if (el) el.checked = !!checked;
        },
        setDisplay: function(id, display) {
            const el = document.getElementById(id);
            if (el) {
                if (typeof display === 'boolean') {
                    el.style.display = display ? '' : 'none';
                } else {
                    el.style.display = display;
                }
            }
        },
        setText: function(id, text) {
            const el = document.getElementById(id);
            if (el) el.textContent = text ?? '';
        },
        setRequired: function(id, required) {
            const el = document.getElementById(id);
            if (el) el.required = !!required;
        },
        setDisabled: function(id, disabled) {
            const el = document.getElementById(id);
            if (el) el.disabled = !!disabled;
        }
    };
    SK.Modal = SK.Modal || {};
    SK.warn = function(...args) { console.warn('[SentriKat]', ...args); };
}

// ============================================================================
// STATE VARIABLES
// ============================================================================

let currentUserId = null;
let currentOrgId = null;
let organizations = [];

// Global current user info - loaded at page init
window.currentUserInfo = null;

// Global license info - loaded at page init
window.licenseInfo = null;

// Track if initial load has completed
window.adminPanelInitialized = false;

// Selection state for bulk actions
let selectedUsers = new Map(); // Map of userId -> { id, username, is_active }
let selectedOrgs = new Map();  // Map of orgId -> { id, name, active }
let selectedMappings = new Map(); // Map of mappingId -> { id, group_cn, is_active }

// ============================================================================
// RETRY UTILITY - Handle startup timing issues
// ============================================================================

/**
 * Fetch with automatic retry for transient failures
 * Useful during app startup when API might not be ready
 * @param {string} url - URL to fetch
 * @param {object} options - Fetch options
 * @param {number} maxRetries - Maximum retry attempts (default: 3)
 * @param {number} delayMs - Initial delay between retries in ms (default: 1000)
 * @returns {Promise<Response>}
 */
async function fetchWithRetry(url, options = {}, maxRetries = 3, delayMs = 1000) {
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await fetch(url, options);

            // For server errors (5xx), retry
            if (response.status >= 500 && attempt < maxRetries) {
                console.warn(`[Retry ${attempt}/${maxRetries}] Server error ${response.status} for ${url}, retrying...`);
                await sleep(delayMs * attempt);
                continue;
            }

            return response;
        } catch (error) {
            lastError = error;
            console.warn(`[Retry ${attempt}/${maxRetries}] Network error for ${url}: ${error.message}`);

            if (attempt < maxRetries) {
                await sleep(delayMs * attempt);
            }
        }
    }

    throw lastError || new Error(`Failed to fetch ${url} after ${maxRetries} attempts`);
}

/**
 * Sleep helper for retry delays
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Safely parse JSON response with detailed error messages
 * @param {Response} response - Fetch response
 * @param {string} context - Context for error messages (e.g., "organizations", "assets")
 * @returns {Promise<any>} Parsed JSON data
 * @throws {Error} with detailed message if parsing fails
 */
async function safeParseJSON(response, context = 'data') {
    const contentType = response.headers.get('content-type') || '';

    // Check if response is JSON
    if (!contentType.includes('application/json')) {
        // Try to read the response to provide better error info
        const text = await response.text();
        if (text.startsWith('<!') || text.startsWith('<html')) {
            // HTML response - likely an error page or redirect
            console.error(`API returned HTML instead of JSON for ${context}:`, text.substring(0, 200));
            throw new Error(`Server returned an error page. Please refresh and try again.`);
        }
        throw new Error(`Unexpected response type: ${contentType || 'unknown'}`);
    }

    return response.json();
}

/**
 * Load data with retry and update element state
 * @param {string} elementId - Element to update on error
 * @param {Function} loadFn - Async function to load data
 * @param {string} errorMessage - Message to show on failure
 */
async function loadWithRetry(elementId, loadFn, errorMessage = 'Failed to load') {
    const element = SK.DOM.get(elementId);

    try {
        await loadFn();
    } catch (error) {
        console.error(`Error loading ${elementId}:`, error);
        if (element) {
            // Check if still showing "Loading..."
            if (element.textContent?.includes('Loading') || element.innerHTML?.includes('Loading')) {
                element.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle me-1"></i>${errorMessage}</span>`;
            }
        }
    }
}

// ============================================================================
// MODAL UTILITIES - Use SK.Modal from sentrikat-core.js
// ============================================================================

/**
 * Safely hide a modal and clean up
 * Uses SK.Modal.hideById from sentrikat-core.js
 * @param {string} modalId - The ID of the modal element
 */
function safeHideModal(modalId) {
    SK.Modal.hideById(modalId);
}

/**
 * Safely dispose of a modal completely
 * @param {string} modalId - The ID of the modal element
 * @param {boolean} removeElement - Whether to remove the modal element from DOM
 */
function safeDisposeModal(modalId, removeElement = false) {
    const modalEl = SK.DOM.get(modalId);
    if (modalEl) {
        const modalInstance = bootstrap.Modal.getInstance(modalEl);
        if (modalInstance) {
            try {
                modalInstance.hide();
                modalInstance.dispose();
            } catch (e) {
                SK.warn('Error disposing modal:', e);
            }
        }
        if (removeElement) {
            modalEl.remove();
        }
    }
    // Bootstrap handles backdrop cleanup when modals are properly disposed
}

// ============================================================================
// CURRENT USER INFO - For permission-aware API calls
// ============================================================================

/**
 * Load current user info and store globally for permission checks
 */
async function loadCurrentUserInfo() {
    try {
        const response = await fetch('/api/current-user');
        if (response.ok) {
            window.currentUserInfo = await response.json();
            console.log('Loaded current user info:', window.currentUserInfo?.username, 'role:', window.currentUserInfo?.role);
        }
    } catch (error) {
        console.error('Error loading current user info:', error);
    }
}

/**
 * Get organization_id query parameter for API calls (for non-super-admin users)
 */
function getOrgIdParam() {
    if (!window.currentUserInfo) {
        console.warn('getOrgIdParam: currentUserInfo not loaded yet');
        return '';
    }
    if (window.currentUserInfo.role === 'super_admin') return '';

    // Try organization_id first, then active_organization_id
    const orgId = window.currentUserInfo.organization_id || window.currentUserInfo.active_organization_id;
    if (orgId) {
        return `?organization_id=${orgId}`;
    }
    console.warn('getOrgIdParam: No organization_id found for user', window.currentUserInfo.username);
    return '';
}

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
    const selectAll = SK.DOM.get('selectAllUsers');
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
    const selectAllUsers = SK.DOM.get('selectAllUsers');
    if (selectAllUsers) selectAllUsers.checked = false;
    updateUsersBulkToolbar();
}

function updateUsersBulkToolbar() {
    const toolbar = SK.DOM.get('usersBulkActions');
    if (!toolbar) return;
    const count = selectedUsers.size;
    const countEl = SK.DOM.get('usersSelectedCount');
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
    let successCount = 0;
    let failCount = 0;
    try {
        for (const user of selectedUsers.values()) {
            const response = await fetch(`/api/users/${user.id}`, { method: 'DELETE' });
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
            }
        }
        if (failCount === 0) {
            showToast(`${successCount} user(s) deleted successfully`, 'success');
        } else if (successCount === 0) {
            showToast(`Failed to delete ${failCount} user(s)`, 'danger');
        } else {
            showToast(`Deleted ${successCount}, failed ${failCount}`, 'warning');
        }
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
    const selectAll = SK.DOM.get('selectAllOrgs');
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
    const selectAllOrgs = SK.DOM.get('selectAllOrgs');
    if (selectAllOrgs) selectAllOrgs.checked = false;
    updateOrgsBulkToolbar();
}

function updateOrgsBulkToolbar() {
    const toolbar = SK.DOM.get('orgsBulkActions');
    if (!toolbar) return;
    const count = selectedOrgs.size;
    const countEl = SK.DOM.get('orgsSelectedCount');
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
    let successCount = 0;
    let failCount = 0;
    try {
        for (const org of selectedOrgs.values()) {
            const response = await fetch(`/api/organizations/${org.id}`, { method: 'DELETE' });
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
            }
        }
        if (failCount === 0) {
            showToast(`${successCount} organization(s) deleted successfully`, 'success');
        } else if (successCount === 0) {
            showToast(`Failed to delete ${failCount} organization(s)`, 'danger');
        } else {
            showToast(`Deleted ${successCount}, failed ${failCount}`, 'warning');
        }
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
    const selectAll = SK.DOM.get('selectAllMappings');
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
    const toolbar = SK.DOM.get('mappingsBulkActions');
    const count = SK.DOM.get('mappingsSelectedCount');
    if (toolbar && count) {
        count.textContent = selectedMappings.size;
        toolbar.style.display = selectedMappings.size > 0 ? 'block' : 'none';
    }
}

function clearMappingSelection() {
    selectedMappings.clear();
    document.querySelectorAll('.mapping-checkbox').forEach(cb => cb.checked = false);
    const selectAllMappings = SK.DOM.get('selectAllMappings');
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
    let successCount = 0;
    let failCount = 0;
    try {
        for (const [mappingId, mapping] of selectedMappings) {
            const response = await fetch(`/api/ldap/groups/mappings/${mappingId}`, {
                method: 'DELETE'
            });
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
            }
        }
        if (failCount === 0) {
            showToast(`${successCount} mapping(s) deleted successfully`, 'success');
        } else if (successCount === 0) {
            showToast(`Failed to delete ${failCount} mapping(s)`, 'danger');
        } else {
            showToast(`Deleted ${successCount}, failed ${failCount}`, 'warning');
        }
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

    // Check if Bootstrap is loaded - retry a few times as it might still be loading
    let bootstrapReady = false;
    for (let i = 0; i < 10 && !bootstrapReady; i++) {
        if (typeof bootstrap !== 'undefined') {
            bootstrapReady = true;
        } else {
            console.log(`Waiting for Bootstrap... attempt ${i + 1}`);
            await sleep(200);
        }
    }

    if (!bootstrapReady) {
        console.error('Bootstrap is not loaded! Modals will not work.');
        showToast('Error: Bootstrap JavaScript library is not loaded. Please refresh the page.', 'danger');
        return;
    }

    try {
        // Load license info first and apply UI restrictions (await to ensure restrictions apply before showing tabs)
        // Uses retry logic internally to handle startup timing
        await loadLicenseAndApplyRestrictions();

        // Load current user info for permission checks
        await loadCurrentUserInfo();

        // Load users and orgs with retry
        loadUsersWithRetry();
        loadOrganizationsWithRetry();
        loadOrganizationsDropdown();
        checkLdapPermissions();  // Check if user can access LDAP features (also checks license)

        // Pre-load settings in background (don't wait for tab click)
        // This ensures settings are ready when user navigates to Settings tab
        setTimeout(() => {
            loadAllSettings();
        }, 500);

        // Pre-load integrations summary (for Overview stats)
        setTimeout(() => {
            loadIntegrationsSummary();
        }, 300);

        // Tab change handlers
        const orgTab = SK.DOM.get('organizations-tab');
        if (orgTab) {
            orgTab.addEventListener('shown.bs.tab', function() {
                loadOrganizationsWithRetry();
            });
        } else {
            console.warn('organizations-tab element not found');
        }

        // Settings tab handler
        const settingsTab = SK.DOM.get('settings-tab');
        if (settingsTab) {
            settingsTab.addEventListener('shown.bs.tab', function() {
                loadAllSettings();
            });
        } else {
            console.warn('settings-tab element not found');
        }

        // LDAP Users tab handler - auto-load users when tab is shown
        const ldapUsersTab = SK.DOM.get('ldapUsers-tab');
        if (ldapUsersTab) {
            ldapUsersTab.addEventListener('shown.bs.tab', function() {
                loadLDAPUsersDefault();
            });
        }

        // LDAP Groups tab handler
        const ldapGroupsTab = SK.DOM.get('ldapGroups-tab');
        if (ldapGroupsTab) {
            ldapGroupsTab.addEventListener('shown.bs.tab', function() {
                // Pre-fill Group Search Base DN from LDAP settings if empty
                const groupSearchBaseInline = SK.DOM.get('groupSearchBaseInline');
                const ldapBaseDN = SK.DOM.get('ldapBaseDN');
                if (groupSearchBaseInline && !groupSearchBaseInline.value && ldapBaseDN && ldapBaseDN.value) {
                    groupSearchBaseInline.value = ldapBaseDN.value;
                }
                loadGroupMappings();
                loadSyncStats();
                loadSyncHistory();
            });
        }

        // LDAP Groups sub-tab handlers
        const groupMappingsTab = SK.DOM.get('group-mappings-tab');
        if (groupMappingsTab) {
            groupMappingsTab.addEventListener('shown.bs.pill', function() {
                loadGroupMappings();
            });
        }

        const syncDashboardTab = SK.DOM.get('sync-dashboard-tab');
        if (syncDashboardTab) {
            syncDashboardTab.addEventListener('shown.bs.pill', function() {
                loadSyncStats();
                loadSyncHistory();
            });
        }

        // Load sync status immediately (doesn't require settings to be configured)
        loadSyncStatus();

        window.adminPanelInitialized = true;
        console.log('Admin Panel: Initialization complete');
    } catch (error) {
        console.error('Error during admin panel initialization:', error);
        showToast('Some components failed to load. Try refreshing the page.', 'warning');
    }
});

/**
 * Load users with retry support
 */
async function loadUsersWithRetry() {
    try {
        await loadUsers();
    } catch (error) {
        console.error('Initial user load failed, retrying...', error);
        await sleep(1000);
        try {
            await loadUsers();
        } catch (retryError) {
            console.error('User load retry failed:', retryError);
        }
    }
}

/**
 * Load organizations with retry support
 */
async function loadOrganizationsWithRetry() {
    try {
        await loadOrganizations();
    } catch (error) {
        console.error('Initial org load failed, retrying...', error);
        await sleep(1000);
        try {
            await loadOrganizations();
        } catch (retryError) {
            console.error('Org load retry failed:', retryError);
        }
    }
}

// ============================================================================
// User Management
// ============================================================================

async function loadUsers() {
    const tbody = SK.DOM.get('usersTable');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    // Clear selection state
    selectedUsers.clear();
    updateUsersBulkToolbar();

    try {
        const response = await fetchWithRetry('/api/users', {}, 3, 800);

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
                                ` : (user.auth_type === 'local' ? `
                                <button class="btn-action btn-action-primary" onclick="require2FAForUser(${user.id}, '${escapeHtml(user.username)}')" title="Require 2FA Setup">
                                    <i class="bi bi-shield-plus"></i>
                                </button>
                                ` : '')}
                                ${user.auth_type === 'local' ? `
                                <button class="btn-action btn-action-secondary" onclick="forcePasswordChange(${user.id}, '${escapeHtml(user.username)}')" title="Force Password Change">
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
        const selectAllUsers = SK.DOM.get('selectAllUsers');
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
                    <i class="bi bi-exclamation-triangle text-danger"></i> Error loading users: ${error.message}
                </td>
            </tr>
        `;
    }
}

function showCreateUserModal() {
    try {
        currentUserId = null;
        SK.DOM.setHtml('userModalTitle', '<i class="bi bi-person-plus me-2"></i>Create User');

        const userForm = SK.DOM.get('userForm');
        if (userForm) userForm.reset();

        // Reset to local auth and completely hide LDAP option for creation
        SK.DOM.setChecked('authLocal', true);
        SK.DOM.setDisplay('authLdap', 'none');
        SK.DOM.setDisplay('authLdapLabel', 'none');
        SK.DOM.setChecked('isActive', true);
        SK.DOM.setValue('userRole', 'user');
        SK.DOM.setChecked('canManageProducts', true);

        // Hide org memberships section (only shown when editing)
        SK.DOM.setDisplay('orgMembershipsSection', 'none');

        // Show primary org field (for new users)
        SK.DOM.setDisplay('primaryOrgField', 'block');
        SK.DOM.setRequired('organization', true);

        toggleAuthFields();
        updateRoleDescription();

        const modalElement = SK.DOM.get('userModal');
        if (!modalElement) {
            console.error('userModal element not found');
            return;
        }

        const modal = bootstrap.Modal.getOrCreateInstance(modalElement);
        modal.show();
    } catch (error) {
        console.error('Error in showCreateUserModal:', error);
        showToast('Error opening user modal: ' + error.message, 'danger');
    }
}

async function editUser(userId) {
    currentUserId = userId;
    SK.DOM.setHtml('userModalTitle', '<i class="bi bi-pencil me-2"></i>Edit User');

    try {
        const response = await fetch(`/api/users/${userId}`);
        const user = await response.json();

        SK.DOM.setValue('username', user.username);
        SK.DOM.setValue('email', user.email);
        SK.DOM.setValue('fullName', user.full_name || '');
        SK.DOM.setValue('organization', user.organization_id || '');
        SK.DOM.setValue('userRole', user.role || 'user');
        SK.DOM.setChecked('canManageProducts', user.can_manage_products);
        SK.DOM.setChecked('canViewAllOrgs', user.can_view_all_orgs);
        SK.DOM.setChecked('isActive', user.is_active);

        // Set auth type and show/hide LDAP option for editing
        if (user.auth_type === 'ldap') {
            SK.DOM.setChecked('authLdap', true);
            // Show LDAP option for existing LDAP users (read-only display)
            SK.DOM.setDisplay('authLdap', '');
            SK.DOM.setDisplay('authLdapLabel', '');
            SK.DOM.setDisabled('authLdap', false);
            SK.DOM.setDisabled('authLocal', true);  // Can't change LDAP user to local
        } else {
            SK.DOM.setChecked('authLocal', true);
            // Hide LDAP option (can't convert local to LDAP)
            SK.DOM.setDisplay('authLdap', 'none');
            SK.DOM.setDisplay('authLdapLabel', 'none');
            SK.DOM.setDisabled('authLocal', false);
        }

        toggleAuthFields();
        updateRoleDescription();

        // For edit mode, password is optional
        SK.DOM.setRequired('password', false);
        SK.DOM.setRequired('passwordConfirm', false);

        // Hide primary org field (managed via memberships when editing)
        SK.DOM.setDisplay('primaryOrgField', 'none');
        SK.DOM.setRequired('organization', false);

        // Show organization memberships section and load memberships
        SK.DOM.setDisplay('orgMembershipsSection', 'block');
        loadUserOrgMemberships(userId);

        // Show security settings section for local users and load 2FA status
        const securitySection = SK.DOM.get('securitySettingsSection');
        if (securitySection) {
            if (user.auth_type === 'local') {
                securitySection.style.display = 'block';
                updateUser2FAStatus(user);
                updateUserPasswordStatus(user);
            } else {
                securitySection.style.display = 'none';
            }
        }

        const userModal = SK.DOM.get('userModal');
        if (userModal) {
            bootstrap.Modal.getOrCreateInstance(userModal).show();
        }
    } catch (error) {
        showToast(`Error loading user: ${error.message}`, 'danger');
    }
}

// Update 2FA status display in user modal
function updateUser2FAStatus(user) {
    const statusDiv = SK.DOM.get('user2FAStatus');
    const actionsDiv = SK.DOM.get('user2FAActions');

    if (user.totp_enabled) {
        statusDiv.innerHTML = '<span class="badge bg-success"><i class="bi bi-shield-check me-1"></i>Enabled</span>';
        actionsDiv.innerHTML = `
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="reset2FAFromModal(${user.id}, '${escapeHtml(user.username)}')">
                <i class="bi bi-phone-flip me-1"></i>Reset 2FA
            </button>
        `;
    } else {
        statusDiv.innerHTML = '<span class="badge bg-warning text-dark"><i class="bi bi-shield-exclamation me-1"></i>Not Enabled</span>';
        actionsDiv.innerHTML = `
            <button type="button" class="btn btn-sm btn-outline-primary" onclick="require2FAForUser(${user.id}, '${escapeHtml(user.username)}')">
                <i class="bi bi-shield-plus me-1"></i>Require 2FA
            </button>
        `;
    }
}

// Update password status display in user modal
function updateUserPasswordStatus(user) {
    const statusDiv = SK.DOM.get('userPasswordStatus');
    const forceBtn = SK.DOM.get('forcePasswordChangeBtn');

    if (user.must_change_password) {
        statusDiv.innerHTML = '<span class="badge bg-warning text-dark"><i class="bi bi-exclamation-triangle me-1"></i>Change Required</span>';
        forceBtn.disabled = true;
        forceBtn.innerHTML = '<i class="bi bi-check me-1"></i>Already Required';
    } else if (user.password_days_until_expiry !== null && user.password_days_until_expiry <= 7) {
        statusDiv.innerHTML = `<span class="badge bg-warning text-dark"><i class="bi bi-clock me-1"></i>Expires in ${user.password_days_until_expiry} days</span>`;
        forceBtn.disabled = false;
        forceBtn.innerHTML = '<i class="bi bi-key me-1"></i>Force Password Change';
    } else {
        statusDiv.innerHTML = '<span class="badge bg-success"><i class="bi bi-check-circle me-1"></i>OK</span>';
        forceBtn.disabled = false;
        forceBtn.innerHTML = '<i class="bi bi-key me-1"></i>Force Password Change';
    }
}

// Reset 2FA from modal
async function reset2FAFromModal(userId, username) {
    if (!confirm(`Are you sure you want to reset 2FA for ${username}? They will need to set up 2FA again.`)) {
        return;
    }
    await reset2FA(userId, username);
    // Refresh the user data
    const response = await fetch(`/api/users/${userId}`);
    const user = await response.json();
    updateUser2FAStatus(user);
}

// Force password change from modal
async function forcePasswordChangeFromModal() {
    if (!currentUserId) return;

    const response = await fetch(`/api/users/${currentUserId}`);
    const user = await response.json();

    await forcePasswordChange(currentUserId, user.username);

    // Refresh status
    const updatedResponse = await fetch(`/api/users/${currentUserId}`);
    const updatedUser = await updatedResponse.json();
    updateUserPasswordStatus(updatedUser);
}

// Require 2FA for a user (admin function)
async function require2FAForUser(userId, username) {
    if (!confirm(`Require 2FA for ${username}? They will be prompted to set up 2FA on their next login.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/require-2fa`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to require 2FA');
        }

        showToast(`2FA requirement set for ${username}`, 'success');

        // Refresh the user data
        const userResponse = await fetch(`/api/users/${userId}`);
        const user = await userResponse.json();
        updateUser2FAStatus(user);
        loadUsers();
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
    }
}

// =============================================================================
// Organization Memberships Functions
// =============================================================================

async function loadUserOrgMemberships(userId) {
    const tbody = SK.DOM.get('orgMembershipsTable');
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

    SK.DOM.getValue('addOrgMembershipUserId') = currentUserId;

    // Load available organizations
    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();

        // Get current memberships to exclude
        const membershipsResponse = await fetch(`/api/users/${currentUserId}/organizations`);
        const memberships = await membershipsResponse.json();
        const memberOrgIds = new Set(memberships.map(m => m.organization_id));

        const select = SK.DOM.get('addOrgMembershipOrg');
        select.innerHTML = '<option value="">Select organization...</option>';

        orgs.filter(org => !memberOrgIds.has(org.id)).forEach(org => {
            select.innerHTML += `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`;
        });

        if (select.options.length <= 1) {
            select.innerHTML = '<option value="">No available organizations</option>';
        }

        bootstrap.Modal.getOrCreateInstance(SK.DOM.get('addOrgMembershipModal')).show();
    } catch (error) {
        showToast('Error loading organizations: ' + error.message, 'danger');
    }
}

async function addOrgMembership() {
    const userId = SK.DOM.getValue('addOrgMembershipUserId');
    const orgId = SK.DOM.getValue('addOrgMembershipOrg');
    const role = SK.DOM.getValue('addOrgMembershipRole');

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
            safeHideModal('addOrgMembershipModal');
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
                SK.DOM.getValue('userRole') = newRole;
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
    const authLocal = SK.DOM.get('authLocal');
    const isLocal = authLocal ? authLocal.checked : true;
    const passwordField = SK.DOM.get('passwordField');
    const passwordConfirmField = SK.DOM.get('passwordConfirmField');
    const usernameHelp = SK.DOM.get('usernameHelp');
    const passwordEl = SK.DOM.get('password');
    const passwordConfirmEl = SK.DOM.get('passwordConfirm');

    if (isLocal) {
        if (passwordField) passwordField.style.display = 'block';
        if (passwordConfirmField) passwordConfirmField.style.display = 'block';
        if (passwordEl) passwordEl.required = currentUserId === null; // Required for new users
        if (passwordConfirmEl) passwordConfirmEl.required = currentUserId === null;
        if (usernameHelp) usernameHelp.textContent = 'Unique username for login';
    } else {
        if (passwordField) passwordField.style.display = 'none';
        if (passwordConfirmField) passwordConfirmField.style.display = 'none';
        if (passwordEl) passwordEl.required = false;
        if (passwordConfirmEl) passwordConfirmEl.required = false;
        if (usernameHelp) usernameHelp.textContent = 'For LDAP: Use AD sAMAccountName (e.g., jdoe)';
    }
}

async function saveUser() {
    const username = SK.DOM.getValue('username').trim();
    const email = SK.DOM.getValue('email').trim();
    const password = SK.DOM.getValue('password');
    const passwordConfirm = SK.DOM.getValue('passwordConfirm');
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
        full_name: SK.DOM.getValue('fullName').trim(),
        organization_id: parseInt(SK.DOM.getValue('organization')) || null,
        auth_type: authType,
        role: SK.DOM.getValue('userRole'),
        is_admin: SK.DOM.getValue('userRole') !== 'user' && SK.DOM.getValue('userRole') !== 'manager',
        can_manage_products: SK.DOM.getChecked('canManageProducts'),
        can_view_all_orgs: SK.DOM.getChecked('canViewAllOrgs'),
        is_active: SK.DOM.getChecked('isActive')
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
            safeHideModal('userModal');
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
    const tbody = SK.DOM.get('orgsTable');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4"><div class="spinner-border text-primary"></div></td></tr>';

    // Clear selection state
    selectedOrgs.clear();
    updateOrgsBulkToolbar();

    try {
        const response = await fetchWithRetry('/api/organizations', {}, 3, 800);

        if (!response.ok) {
            // Try to get error message from response
            try {
                const errorData = await safeParseJSON(response, 'organizations');
                throw new Error(errorData.error || `HTTP ${response.status}`);
            } catch (e) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        }

        organizations = await safeParseJSON(response, 'organizations');

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
                        <td>
                            <input type="checkbox" class="form-check-input org-checkbox"
                                   data-org-id="${org.id}" onchange="toggleOrgSelect(${org.id}, this)">
                        </td>
                        <td data-column="displayname" class="fw-semibold">${escapeHtml(org.display_name)}</td>
                        <td data-column="users"><span class="badge badge-role-manager">${org.user_count || 0}</span></td>
                        <td data-column="smtp">${smtpBadge}</td>
                        <td data-column="status">${statusBadge}</td>
                        <td data-column="actions">
                            <div class="d-flex gap-1">
                                <button class="btn-action btn-action-edit" onclick="editOrganization(${org.id})" title="Edit">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                ${org.is_default !== true ? `
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
        const selectAllOrgs = SK.DOM.get('selectAllOrgs');
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
                <td colspan="6" class="text-center text-danger py-4">
                    <i class="bi bi-exclamation-triangle text-danger"></i> Error loading organizations: ${error.message}
                </td>
            </tr>
        `;
    }
}

async function loadOrganizationsDropdown() {
    const select = SK.DOM.get('organization');
    if (!select) {
        console.warn('Organization select element not found');
        return;
    }

    try {
        const response = await fetch('/api/organizations');
        if (!response.ok) {
            try {
                const errorData = await safeParseJSON(response, 'organizations dropdown');
                throw new Error(errorData.error || `HTTP ${response.status}`);
            } catch (e) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        }
        const orgs = await safeParseJSON(response, 'organizations dropdown');

        if (orgs.length === 0) {
            select.innerHTML = '<option value="">No organizations available</option>';
        } else {
            select.innerHTML = '<option value="">Select organization...</option>' +
                orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`).join('');
        }
    } catch (error) {
        console.error('Error loading organizations dropdown:', error);
        select.innerHTML = `<option value="">Error: ${error.message}</option>`;
    }
}

function showCreateOrgModal() {
    try {
        console.log('showCreateOrgModal called');
        currentOrgId = null;
        SK.DOM.setHtml('orgModalTitle', '<i class="bi bi-building me-2"></i>Create Organization');

        const orgForm = SK.DOM.get('orgForm');
        if (orgForm) orgForm.reset();

        // Make sure orgName is enabled and editable for new organizations
        const orgNameField = SK.DOM.get('orgName');
        if (orgNameField) {
            orgNameField.disabled = false;
            orgNameField.readOnly = false;
            orgNameField.value = '';
        }

        SK.DOM.setChecked('orgActive', true);
        SK.DOM.setChecked('alertCritical', true);
        SK.DOM.setChecked('alertNewCVE', true);
        SK.DOM.setChecked('alertRansomware', true);
        SK.DOM.setChecked('smtpUseTls', true);
        SK.DOM.setValue('smtpPort', 587);

        const modalElement = SK.DOM.get('orgModal');
        if (!modalElement) {
            console.error('orgModal element not found');
            return;
        }

        const modal = bootstrap.Modal.getOrCreateInstance(modalElement);
        console.log('Modal created, showing...');
        modal.show();
    } catch (error) {
        console.error('Error in showCreateOrgModal:', error);
        showToast('Error opening organization modal: ' + error.message, 'danger');
    }
}

async function editOrganization(orgId) {
    currentOrgId = orgId;
    SK.DOM.get('orgModalTitle').innerHTML = '<i class="bi bi-pencil me-2"></i>Edit Organization';

    try {
        const response = await fetch(`/api/organizations/${orgId}`);
        const org = await response.json();

        // Basic info
        SK.DOM.getValue('orgName') = org.name;
        SK.DOM.getValue('orgDisplayName') = org.display_name;
        SK.DOM.getValue('orgDescription') = org.description || '';

        // Parse emails
        let emails = [];
        try {
            emails = JSON.parse(org.notification_emails || '[]');
        } catch (e) {
            emails = [];
        }
        SK.DOM.getValue('orgEmails') = emails.join(', ');
        SK.DOM.getChecked('orgActive') = org.active;

        // SMTP settings
        SK.DOM.getValue('smtpHost') = org.smtp_host || '';
        SK.DOM.getValue('smtpPort') = org.smtp_port || 587;
        SK.DOM.getValue('smtpUsername') = org.smtp_username || '';
        // Don't pre-fill masked password - leave blank so user can enter new one if needed
        SK.DOM.getValue('smtpPassword') = '';
        SK.DOM.get('smtpPassword').placeholder = org.smtp_password ? '(password saved - leave blank to keep)' : 'Password';
        SK.DOM.getValue('smtpFromEmail') = org.smtp_from_email || '';
        SK.DOM.getValue('smtpFromName') = org.smtp_from_name || 'SentriKat Alerts';
        SK.DOM.getChecked('smtpUseTls') = org.smtp_use_tls !== false;
        SK.DOM.getChecked('smtpUseSsl') = org.smtp_use_ssl === true;

        // Alert settings
        SK.DOM.getChecked('alertCritical') = org.alert_on_critical;
        SK.DOM.getChecked('alertHigh') = org.alert_on_high;
        SK.DOM.getChecked('alertNewCVE') = org.alert_on_new_cve;
        SK.DOM.getChecked('alertRansomware') = org.alert_on_ransomware;

        // Alert mode settings (org.alert_settings contains nested values)
        const alertMode = org.alert_settings?.mode || '';
        const escalationDays = org.alert_settings?.escalation_days || '';
        SK.DOM.getValue('orgAlertMode') = alertMode;
        SK.DOM.getValue('orgEscalationDays') = escalationDays;

        // Webhook settings
        SK.DOM.getChecked('orgWebhookEnabled') = org.webhook_enabled || false;
        SK.DOM.getValue('orgWebhookUrl') = org.webhook_url || '';
        SK.DOM.getValue('orgWebhookFormat') = org.webhook_format || 'slack';
        SK.DOM.getValue('orgWebhookName') = org.webhook_name || '';
        SK.DOM.getValue('orgWebhookToken') = '';
        SK.DOM.get('orgWebhookToken').placeholder = org.webhook_token ? '(token saved - leave blank to keep)' : 'Leave empty if not needed';

        // Disable name field for existing orgs
        SK.DOM.get('orgName').readOnly = true;

        bootstrap.Modal.getOrCreateInstance(SK.DOM.get('orgModal')).show();
    } catch (error) {
        showToast(`Error loading organization: ${error.message}`, 'danger');
    }
}

async function saveOrganization() {
    const name = SK.DOM.getValue('orgName').trim();
    const displayName = SK.DOM.getValue('orgDisplayName').trim();

    if (!name || !displayName) {
        showToast('Organization name and display name are required', 'warning');
        return;
    }

    // Parse emails
    const emailsText = SK.DOM.getValue('orgEmails');
    const emails = emailsText ? emailsText.split(',').map(e => e.trim()).filter(e => e) : [];

    const orgData = {
        name: name.toLowerCase().replace(/\s+/g, '_'),
        display_name: displayName,
        description: SK.DOM.getValue('orgDescription').trim(),
        notification_emails: JSON.stringify(emails),
        active: SK.DOM.getChecked('orgActive'),

        // SMTP settings
        smtp_host: SK.DOM.getValue('smtpHost').trim() || null,
        smtp_port: parseInt(SK.DOM.getValue('smtpPort')) || 587,
        smtp_username: SK.DOM.getValue('smtpUsername').trim() || null,
        smtp_password: SK.DOM.getValue('smtpPassword').trim() || null,
        smtp_from_email: SK.DOM.getValue('smtpFromEmail').trim() || null,
        smtp_from_name: SK.DOM.getValue('smtpFromName').trim() || 'SentriKat Alerts',
        smtp_use_tls: SK.DOM.getChecked('smtpUseTls'),
        smtp_use_ssl: SK.DOM.getChecked('smtpUseSsl'),

        // Alert settings
        alert_on_critical: SK.DOM.getChecked('alertCritical'),
        alert_on_high: SK.DOM.getChecked('alertHigh'),
        alert_on_new_cve: SK.DOM.getChecked('alertNewCVE'),
        alert_on_ransomware: SK.DOM.getChecked('alertRansomware'),

        // Alert mode settings (empty = use global default)
        alert_mode: SK.DOM.getValue('orgAlertMode') || null,
        escalation_days: SK.DOM.getValue('orgEscalationDays') ? parseInt(SK.DOM.getValue('orgEscalationDays')) : null,

        // Webhook settings
        webhook_enabled: SK.DOM.getChecked('orgWebhookEnabled'),
        webhook_url: SK.DOM.getValue('orgWebhookUrl').trim() || null,
        webhook_format: SK.DOM.getValue('orgWebhookFormat'),
        webhook_name: SK.DOM.getValue('orgWebhookName').trim() || null,
        webhook_token: SK.DOM.getValue('orgWebhookToken').trim() || null
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
            safeHideModal('orgModal');
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
    const webhookUrl = SK.DOM.getValue('orgWebhookUrl').trim();

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
                webhook_format: SK.DOM.getValue('orgWebhookFormat'),
                webhook_name: SK.DOM.getValue('orgWebhookName') || 'Organization Webhook',
                webhook_token: SK.DOM.getValue('orgWebhookToken') || null
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
    let toastContainer = SK.DOM.get('toastContainer');
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
    const toastElement = SK.DOM.get(toastId);
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
    const userRoleEl = SK.DOM.get('userRole');
    const role = userRoleEl ? userRoleEl.value : 'user';
    const descDiv = SK.DOM.get('roleDescription');
    const viewAllOrgsCheck = SK.DOM.get('viewAllOrgsCheck');
    const canManageProductsEl = SK.DOM.get('canManageProducts');

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

    const desc = descriptions[role] || descriptions['user'];
    if (descDiv) {
        descDiv.textContent = desc.text;
        descDiv.className = `alert alert-sm mt-2 ${desc.class}`;
    }
    if (canManageProductsEl) canManageProductsEl.checked = desc.canManageProducts;
    if (viewAllOrgsCheck) viewAllOrgsCheck.style.display = desc.showViewAllOrgs ? 'block' : 'none';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function autoConfigureSmtpSecurity() {
    const port = parseInt(SK.DOM.getValue('smtpPort'));
    const tlsCheckbox = SK.DOM.get('smtpUseTls');

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
        ldap_enabled: SK.DOM.getChecked('ldapEnabled'),
        ldap_server: SK.DOM.getValue('ldapServer'),
        ldap_port: SK.DOM.getValue('ldapPort'),
        ldap_base_dn: SK.DOM.getValue('ldapBaseDN'),
        ldap_bind_dn: SK.DOM.getValue('ldapBindDN'),
        ldap_bind_password: SK.DOM.getValue('ldapBindPassword'),
        ldap_search_filter: SK.DOM.getValue('ldapSearchFilter'),
        ldap_username_attr: SK.DOM.getValue('ldapUsernameAttr'),
        ldap_email_attr: SK.DOM.getValue('ldapEmailAttr'),
        ldap_use_tls: SK.DOM.getChecked('ldapUseTLS'),
        ldap_sync_enabled: SK.DOM.getChecked('ldapSyncEnabled'),
        ldap_sync_interval_hours: SK.DOM.getValue('ldapSyncInterval')
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
        smtp_host: SK.DOM.getValue('globalSmtpHost'),
        smtp_port: SK.DOM.getValue('globalSmtpPort'),
        smtp_username: SK.DOM.getValue('globalSmtpUsername'),
        smtp_password: SK.DOM.getValue('globalSmtpPassword'),
        smtp_from_email: SK.DOM.getValue('globalSmtpFromEmail'),
        smtp_from_name: SK.DOM.getValue('globalSmtpFromName'),
        smtp_use_tls: SK.DOM.getChecked('globalSmtpUseTLS'),
        smtp_use_ssl: SK.DOM.getChecked('globalSmtpUseSSL')
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
    const host = SK.DOM.getValue('globalSmtpHost');
    const fromEmail = SK.DOM.getValue('globalSmtpFromEmail');

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
        auto_sync_enabled: SK.DOM.getChecked('autoSyncEnabled'),
        sync_interval: SK.DOM.getValue('syncInterval'),
        sync_time: SK.DOM.getValue('syncTime'),
        nvd_api_key: SK.DOM.getValue('nvdApiKey'),
        cisa_kev_url: SK.DOM.getValue('cisaKevUrl')
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
    // Only super admins can access sync status
    if (!window.currentUserInfo || window.currentUserInfo.role !== 'super_admin') {
        return;
    }

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

        SK.DOM.get('lastSyncTime').innerHTML = lastSyncHtml;
        SK.DOM.get('nextSyncTime').textContent = status.next_sync || 'Not scheduled';
        SK.DOM.get('totalVulns').textContent = status.total_vulnerabilities || '0';
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

            SK.DOM.get('alertResultsContent').innerHTML = html;
            SK.DOM.get('alertResultsContainer').style.display = 'block';

            showToast(`Critical CVE alerts processed: ${summary.emails_sent} emails sent`, 'success');
        } else {
            showToast(`Error: ${result.error}`, 'danger');
        }
    } catch (error) {
        showToast(`Error triggering alerts: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// Proxy Settings
async function saveProxySettings() {
    const settings = {
        verify_ssl: SK.DOM.getChecked('verifySSL'),
        http_proxy: SK.DOM.getValue('httpProxy'),
        https_proxy: SK.DOM.getValue('httpsProxy'),
        no_proxy: SK.DOM.getValue('noProxy')
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
        session_timeout: parseInt(SK.DOM.getValue('sessionTimeout')) || 480,
        max_failed_logins: parseInt(SK.DOM.getValue('maxFailedLogins')) || 5,
        lockout_duration: parseInt(SK.DOM.getValue('lockoutDuration')) || 30,
        password_min_length: parseInt(SK.DOM.getValue('passwordMinLength')) || 8,
        password_require_uppercase: SK.DOM.getChecked('passwordRequireUppercase'),
        password_require_lowercase: SK.DOM.getChecked('passwordRequireLowercase'),
        password_require_numbers: SK.DOM.getChecked('passwordRequireNumbers'),
        password_require_special: SK.DOM.getChecked('passwordRequireSpecial'),
        password_expiry_days: parseInt(SK.DOM.getValue('passwordExpiryDays')) || 0,
        require_2fa: SK.DOM.getChecked('require2FA')
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
            const sessionTimeout = SK.DOM.get('sessionTimeout');
            const maxFailedLogins = SK.DOM.get('maxFailedLogins');
            const lockoutDuration = SK.DOM.get('lockoutDuration');
            const passwordMinLength = SK.DOM.get('passwordMinLength');
            const passwordRequireUppercase = SK.DOM.get('passwordRequireUppercase');
            const passwordRequireLowercase = SK.DOM.get('passwordRequireLowercase');
            const passwordRequireNumbers = SK.DOM.get('passwordRequireNumbers');
            const passwordRequireSpecial = SK.DOM.get('passwordRequireSpecial');

            if (sessionTimeout) sessionTimeout.value = settings.session_timeout || 480;
            if (maxFailedLogins) maxFailedLogins.value = settings.max_failed_logins || 5;
            if (lockoutDuration) lockoutDuration.value = settings.lockout_duration || 30;
            if (passwordMinLength) passwordMinLength.value = settings.password_min_length || 8;
            if (passwordRequireUppercase) passwordRequireUppercase.checked = settings.password_require_uppercase !== false;
            if (passwordRequireLowercase) passwordRequireLowercase.checked = settings.password_require_lowercase !== false;
            if (passwordRequireNumbers) passwordRequireNumbers.checked = settings.password_require_numbers !== false;
            if (passwordRequireSpecial) passwordRequireSpecial.checked = settings.password_require_special === true;

            // Password expiration and 2FA settings
            const passwordExpiryDays = SK.DOM.get('passwordExpiryDays');
            const require2FA = SK.DOM.get('require2FA');
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
    SK.DOM.get('restoreFullFile').click();
}

// Setup restore file input listeners
document.addEventListener('DOMContentLoaded', function() {
    const restoreFile = SK.DOM.get('restoreFile');
    if (restoreFile) {
        restoreFile.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                restoreBackup(e.target.files[0]);
                e.target.value = '';
            }
        });
    }

    const restoreFullFile = SK.DOM.get('restoreFullFile');
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
        app_name: SK.DOM.getValue('appName') || 'SentriKat',
        login_message: SK.DOM.getValue('loginMessage') || '',
        support_email: SK.DOM.getValue('supportEmail') || '',
        show_version: SK.DOM.getChecked('showVersion')
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
            const appName = SK.DOM.get('appName');
            const loginMessage = SK.DOM.get('loginMessage');
            const supportEmail = SK.DOM.get('supportEmail');
            const showVersion = SK.DOM.get('showVersion');
            const logoPreview = SK.DOM.get('currentLogoPreview');
            const deleteLogoBtn = SK.DOM.get('deleteLogoBtn');

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
    const fileInput = SK.DOM.get('logoUpload');
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
            const logoPreview = SK.DOM.get('currentLogoPreview');
            const deleteLogoBtn = SK.DOM.get('deleteLogoBtn');
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
            const logoPreview = SK.DOM.get('currentLogoPreview');
            const deleteLogoBtn = SK.DOM.get('deleteLogoBtn');
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
        slack_enabled: SK.DOM.getChecked('slackEnabled'),
        slack_webhook_url: SK.DOM.getValue('slackWebhookUrl') || '',
        teams_enabled: SK.DOM.getChecked('teamsEnabled'),
        teams_webhook_url: SK.DOM.getValue('teamsWebhookUrl') || '',
        // Generic webhook settings
        generic_webhook_enabled: SK.DOM.getChecked('genericWebhookEnabled'),
        generic_webhook_url: SK.DOM.getValue('genericWebhookUrl') || '',
        generic_webhook_name: SK.DOM.getValue('genericWebhookName') || 'Custom Webhook',
        generic_webhook_format: SK.DOM.getValue('genericWebhookFormat') || 'slack',
        generic_webhook_custom_template: SK.DOM.getValue('genericWebhookTemplate') || '',
        generic_webhook_token: SK.DOM.getValue('genericWebhookToken') || '',
        // Email settings
        critical_email_enabled: SK.DOM.getChecked('criticalEmailEnabled'),
        critical_email_time: SK.DOM.getValue('criticalEmailTime') || '09:00',
        critical_email_max_age_days: parseInt(SK.DOM.getValue('criticalEmailMaxAge')) || 30,
        // Alert mode defaults
        default_alert_mode: SK.DOM.getValue('defaultAlertMode') || 'daily_reminder',
        default_escalation_days: parseInt(SK.DOM.getValue('defaultEscalationDays')) || 3
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
            const slackEnabled = SK.DOM.get('slackEnabled');
            const slackWebhookUrl = SK.DOM.get('slackWebhookUrl');
            const teamsEnabled = SK.DOM.get('teamsEnabled');
            const teamsWebhookUrl = SK.DOM.get('teamsWebhookUrl');
            const genericWebhookEnabled = SK.DOM.get('genericWebhookEnabled');
            const genericWebhookUrl = SK.DOM.get('genericWebhookUrl');
            const genericWebhookName = SK.DOM.get('genericWebhookName');
            const genericWebhookFormat = SK.DOM.get('genericWebhookFormat');
            const genericWebhookTemplate = SK.DOM.get('genericWebhookTemplate');
            const genericWebhookToken = SK.DOM.get('genericWebhookToken');
            const customTemplateContainer = SK.DOM.get('customTemplateContainer');
            const criticalEmailEnabled = SK.DOM.get('criticalEmailEnabled');
            const criticalEmailTime = SK.DOM.get('criticalEmailTime');
            const criticalEmailMaxAge = SK.DOM.get('criticalEmailMaxAge');

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
            const defaultAlertMode = SK.DOM.get('defaultAlertMode');
            const defaultEscalationDays = SK.DOM.get('defaultEscalationDays');
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
        audit_log_retention_days: parseInt(SK.DOM.getValue('auditLogRetention')) || 365,
        sync_history_retention_days: parseInt(SK.DOM.getValue('syncHistoryRetention')) || 90,
        session_log_retention_days: parseInt(SK.DOM.getValue('sessionLogRetention')) || 30
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
            const auditLogRetention = SK.DOM.get('auditLogRetention');
            const syncHistoryRetention = SK.DOM.get('syncHistoryRetention');
            const sessionLogRetention = SK.DOM.get('sessionLogRetention');

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
    const tbody = SK.DOM.get('auditLogsTable');
    const statsDiv = SK.DOM.get('auditLogsStats');
    const countSpan = SK.DOM.get('auditLogsCount');

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
    const action = SK.DOM.get('auditActionFilter')?.value || '';
    const resource = SK.DOM.get('auditResourceFilter')?.value || '';
    const limit = SK.DOM.get('auditLimitFilter')?.value || '100';

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
    // Only super admins can access most settings
    if (!window.currentUserInfo || window.currentUserInfo.role !== 'super_admin') {
        console.log('Skipping settings load - not a super admin');
        return;
    }

    console.log('Loading all settings...');

    // Load settings in parallel with retry support
    const loadPromises = [];

    // Load LDAP settings
    loadPromises.push(
        fetchWithRetry('/api/settings/ldap', {}, 3, 800)
            .then(async response => {
                if (response.ok) {
                    const ldap = await response.json();
                    const ldapEnabled = SK.DOM.get('ldapEnabled');
                    const ldapServer = SK.DOM.get('ldapServer');
                    const ldapPort = SK.DOM.get('ldapPort');
                    const ldapBaseDN = SK.DOM.get('ldapBaseDN');
                    const ldapBindDN = SK.DOM.get('ldapBindDN');
                    const ldapSearchFilter = SK.DOM.get('ldapSearchFilter');
                    const ldapUsernameAttr = SK.DOM.get('ldapUsernameAttr');
                    const ldapEmailAttr = SK.DOM.get('ldapEmailAttr');
                    const ldapUseTLS = SK.DOM.get('ldapUseTLS');
                    const ldapSyncEnabled = SK.DOM.get('ldapSyncEnabled');
                    const ldapSyncInterval = SK.DOM.get('ldapSyncInterval');

                    if (ldapEnabled) ldapEnabled.checked = ldap.ldap_enabled || false;
                    if (ldapServer) ldapServer.value = ldap.ldap_server || '';
                    if (ldapPort) ldapPort.value = ldap.ldap_port || 389;
                    if (ldapBaseDN) ldapBaseDN.value = ldap.ldap_base_dn || '';
                    if (ldapBindDN) ldapBindDN.value = ldap.ldap_bind_dn || '';
                    if (ldapSearchFilter) ldapSearchFilter.value = ldap.ldap_search_filter || '(sAMAccountName={username})';
                    if (ldapUsernameAttr) ldapUsernameAttr.value = ldap.ldap_username_attr || 'sAMAccountName';
                    if (ldapEmailAttr) ldapEmailAttr.value = ldap.ldap_email_attr || 'mail';
                    if (ldapUseTLS) ldapUseTLS.checked = ldap.ldap_use_tls || false;
                    if (ldapSyncEnabled) ldapSyncEnabled.checked = ldap.ldap_sync_enabled || false;
                    if (ldapSyncInterval) ldapSyncInterval.value = ldap.ldap_sync_interval_hours || '24';

                    // Populate Group Search Base DN with LDAP Base DN as default
                    const groupSearchBaseInline = SK.DOM.get('groupSearchBaseInline');
                    const groupSearchBase = SK.DOM.get('groupSearchBase');
                    if (groupSearchBaseInline && !groupSearchBaseInline.value && ldap.ldap_base_dn) {
                        groupSearchBaseInline.value = ldap.ldap_base_dn;
                    }
                    if (groupSearchBase && !groupSearchBase.value && ldap.ldap_base_dn) {
                        groupSearchBase.value = ldap.ldap_base_dn;
                    }

                    loadLastScheduledSync();
                    console.log('LDAP settings loaded');
                }
            })
            .catch(err => console.error('Failed to load LDAP settings:', err))
    );

    // Load Global SMTP settings
    loadPromises.push(
        fetchWithRetry('/api/settings/smtp', {}, 3, 800)
            .then(async response => {
                if (response.ok) {
                    const smtp = await response.json();
                    const globalSmtpHost = SK.DOM.get('globalSmtpHost');
                    const globalSmtpPort = SK.DOM.get('globalSmtpPort');
                    const globalSmtpUsername = SK.DOM.get('globalSmtpUsername');
                    const globalSmtpFromEmail = SK.DOM.get('globalSmtpFromEmail');
                    const globalSmtpFromName = SK.DOM.get('globalSmtpFromName');
                    const globalSmtpUseTLS = SK.DOM.get('globalSmtpUseTLS');
                    const globalSmtpUseSSL = SK.DOM.get('globalSmtpUseSSL');

                    if (globalSmtpHost) globalSmtpHost.value = smtp.smtp_host || '';
                    if (globalSmtpPort) globalSmtpPort.value = smtp.smtp_port || 587;
                    if (globalSmtpUsername) globalSmtpUsername.value = smtp.smtp_username || '';
                    if (globalSmtpFromEmail) globalSmtpFromEmail.value = smtp.smtp_from_email || '';
                    if (globalSmtpFromName) globalSmtpFromName.value = smtp.smtp_from_name || 'SentriKat Alerts';
                    if (globalSmtpUseTLS) globalSmtpUseTLS.checked = smtp.smtp_use_tls !== false;
                    if (globalSmtpUseSSL) globalSmtpUseSSL.checked = smtp.smtp_use_ssl === true;
                    console.log('SMTP settings loaded');
                }
            })
            .catch(err => console.error('Failed to load SMTP settings:', err))
    );

    // Load Sync settings
    loadPromises.push(
        fetchWithRetry('/api/settings/sync', {}, 3, 800)
            .then(async response => {
                if (response.ok) {
                    const sync = await response.json();
                    const autoSyncEnabled = SK.DOM.get('autoSyncEnabled');
                    const syncInterval = SK.DOM.get('syncInterval');
                    const syncTime = SK.DOM.get('syncTime');
                    const cisaKevUrl = SK.DOM.get('cisaKevUrl');
                    const nvdKeyInput = SK.DOM.get('nvdApiKey');

                    if (autoSyncEnabled) autoSyncEnabled.checked = sync.auto_sync_enabled || false;
                    if (syncInterval) syncInterval.value = sync.sync_interval || 'daily';
                    if (syncTime) syncTime.value = sync.sync_time || '02:00';
                    if (cisaKevUrl) cisaKevUrl.value = sync.cisa_kev_url || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
                    if (nvdKeyInput) {
                        nvdKeyInput.value = '';
                        nvdKeyInput.placeholder = sync.nvd_api_key_configured
                            ? '(API key saved - leave blank to keep)'
                            : 'Enter your NVD API key (optional)';
                    }
                    console.log('Sync settings loaded');
                }
            })
            .catch(err => console.error('Failed to load sync settings:', err))
    );

    // Load Proxy/General settings
    loadPromises.push(
        fetchWithRetry('/api/settings/general', {}, 3, 800)
            .then(async response => {
                if (response.ok) {
                    const general = await response.json();
                    const verifySSL = SK.DOM.get('verifySSL');
                    const httpProxy = SK.DOM.get('httpProxy');
                    const httpsProxy = SK.DOM.get('httpsProxy');
                    const noProxy = SK.DOM.get('noProxy');
                    if (verifySSL) verifySSL.checked = general.verify_ssl !== false;
                    if (httpProxy) httpProxy.value = general.http_proxy || '';
                    if (httpsProxy) httpsProxy.value = general.https_proxy || '';
                    if (noProxy) noProxy.value = general.no_proxy || '';
                    console.log('Proxy settings loaded');
                }
            })
            .catch(err => console.error('Failed to load proxy settings:', err))
    );

    // Wait for all critical settings, then load additional ones
    await Promise.allSettled(loadPromises);

    loadSyncStatus();

    // Load additional settings (these can fail independently)
    loadSecuritySettings();
    loadBrandingSettings();
    loadNotificationSettings();
    loadRetentionSettings();

    console.log('All settings loading complete');
}

// ============================================================================
// LDAP User Management
// ============================================================================

/**
 * Load LDAP users by default when tab is shown (uses wildcard search)
 */
async function loadLDAPUsersDefault() {
    const resultsDiv = SK.DOM.get('ldapSearchResultsTable');
    const statsDiv = SK.DOM.get('ldapSearchStats');
    const searchInput = SK.DOM.get('ldapUserSearchQuery');

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
    const resultsDiv = SK.DOM.get('ldapSearchResultsTable');
    const statsDiv = SK.DOM.get('ldapSearchStats');
    const pageSize = parseInt(SK.DOM.get('ldapSearchPageSize')?.value) || 25;

    const allResults = ldapSearchCache.results || [];
    ldapSearchCache.currentPage = page;
    ldapSearchCache.pageSize = pageSize;

    if (allResults.length === 0) {
        resultsDiv.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="bi bi-inbox text-primary" style="font-size: 3rem;"></i>
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
    if (SK.DOM.get('ldapResultCount')) {
        SK.DOM.get('ldapResultCount').textContent =
            `${startIdx + 1}-${endIdx} of ${allResults.length}`;
    }
    if (statsDiv) {
        statsDiv.style.display = 'block';
    }

    // Build pagination controls
    const paginationHtml = buildLdapPagination(page, totalPages);
    if (SK.DOM.get('ldapPagination')) {
        SK.DOM.get('ldapPagination').innerHTML = paginationHtml;
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

            const ldapUsersTab = SK.DOM.get('ldap-users-tab-item');
            const ldapGroupsTab = SK.DOM.get('ldap-groups-tab-item');

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
    const query = SK.DOM.getValue('ldapUserSearchQuery').trim();
    const pageSize = parseInt(SK.DOM.getValue('ldapSearchPageSize')) || 25;

    if (!query) {
        showToast('Please enter a search query', 'warning');
        return;
    }

    const resultsDiv = SK.DOM.get('ldapSearchResultsTable');
    const statsDiv = SK.DOM.get('ldapSearchStats');

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
                    <i class="bi bi-inbox text-primary" style="font-size: 3rem;"></i>
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
        SK.DOM.get('ldapResultCount').textContent =
            `${startIdx + 1}-${endIdx} of ${allResults.length}`;
        statsDiv.style.display = 'block';

        // Build pagination controls
        const paginationHtml = buildLdapPagination(page, totalPages);
        SK.DOM.get('ldapPagination').innerHTML = paginationHtml;

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
    SK.DOM.getValue('ldapInviteUsername') = user.username;
    SK.DOM.getValue('ldapInviteEmail') = user.email;
    SK.DOM.getValue('ldapInviteFullName') = user.full_name || '';
    SK.DOM.getValue('ldapUserDN') = user.dn;

    // Set groups loading state
    const groupsSpan = SK.DOM.get('ldapGroupsList');
    if (groupsSpan) {
        groupsSpan.textContent = 'Loading...';
    }

    // Load organizations dropdown
    try {
        const response = await fetch('/api/organizations');
        if (response.ok) {
            const orgs = await response.json();
            const select = SK.DOM.get('ldapInviteOrganization');
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

    const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('ldapInviteModal'));
    modal.show();
}

// Keep old function for backward compatibility
function showLdapSearchModal() {
    // Deprecated - now using inline search
    showToast('Please use the search box above', 'info');
}

async function searchLdapUsers() {
    const query = SK.DOM.getValue('ldapSearchQuery').trim();
    if (!query) {
        showToast('Please enter a search query', 'warning');
        return;
    }

    const resultsDiv = SK.DOM.get('ldapSearchResultsTable');
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
                    <i class="bi bi-inbox text-primary" style="font-size: 2rem;"></i>
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
                <i class="bi bi-exclamation-triangle text-danger" style="font-size: 2rem;"></i>
                <p class="mt-2">Error: ${escapeHtml(error.message)}</p>
            </div>
        `;
        showToast(`Search failed: ${error.message}`, 'danger');
    }
}

async function showInviteLdapUserModal(userData) {
    try {
        // Populate form with user data
        SK.DOM.getValue('ldapUserDN') = userData.dn;
        SK.DOM.getValue('ldapInviteUsername') = userData.username;
        SK.DOM.getValue('ldapInviteEmail') = userData.email;
        SK.DOM.getValue('ldapInviteFullName') = userData.full_name || '';

        // Load organizations into dropdown
        const orgResponse = await fetch('/api/organizations');
        const orgs = await orgResponse.json();
        const orgSelect = SK.DOM.get('ldapInviteOrganization');
        orgSelect.innerHTML = '<option value="">Select organization...</option>' +
            orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`).join('');

        // Load user's LDAP groups
        SK.DOM.get('ldapGroupsList').textContent = 'Loading...';

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
            SK.DOM.get('ldapGroupsList').textContent = groupsList;
        } else {
            SK.DOM.get('ldapGroupsList').textContent = 'Could not load groups';
        }

        // Show the modal
        const modalElement = SK.DOM.get('ldapInviteModal');
        const modal = bootstrap.Modal.getOrCreateInstance(modalElement);
        modal.show();

    } catch (error) {
        console.error('Error showing invite modal:', error);
        showToast('Error opening invite modal: ' + error.message, 'danger');
    }
}

async function inviteLdapUser() {
    const username = SK.DOM.getValue('ldapInviteUsername');
    const email = SK.DOM.getValue('ldapInviteEmail');
    const fullName = SK.DOM.getValue('ldapInviteFullName');
    const dn = SK.DOM.getValue('ldapUserDN');
    const organizationId = parseInt(SK.DOM.getValue('ldapInviteOrganization'));
    const role = SK.DOM.getValue('ldapInviteRole');

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
                safeHideModal('ldapInviteModal');

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
            const searchQuery = SK.DOM.get('ldapUserSearchQuery')?.value;
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
    const tableBody = SK.DOM.get('groupMappingsTable');
    if (!tableBody) return;

    // Check if LDAP feature is licensed before attempting to load
    if (!isFeatureLicensed('ldap')) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="10" class="text-center py-5">
                    <i class="bi bi-shield-lock text-muted" style="font-size: 3rem;"></i>
                    <h5 class="mt-3 text-muted">LDAP Integration Not Available</h5>
                    <p class="text-muted mb-0">LDAP integration requires a Professional license.</p>
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = `
        <tr>
            <td colspan="10" class="text-center py-4">
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
            const selectAllMappings = SK.DOM.get('selectAllMappings');
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
            // Handle license required case gracefully
            if (error.license_required) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="10" class="text-center py-5">
                            <i class="bi bi-shield-lock text-muted" style="font-size: 3rem;"></i>
                            <h5 class="mt-3 text-muted">LDAP Integration Not Available</h5>
                            <p class="text-muted mb-0">LDAP integration requires a Professional license.</p>
                        </td>
                    </tr>
                `;
            } else {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="10" class="text-center py-4 text-danger">
                            <i class="bi bi-exclamation-triangle text-danger" style="font-size: 3rem;"></i>
                            <p class="mt-3">Error loading mappings: ${escapeHtml(error.error || 'Unknown error')}</p>
                        </td>
                    </tr>
                `;
            }
        }
    } catch (error) {
        console.error('Error loading group mappings:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="10" class="text-center py-4 text-danger">
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
        const form = SK.DOM.get('groupMappingForm');
        if (form) {
            form.reset();
            // Clear member count data attribute
            delete form.dataset.memberCount;
        }

        const mappingIdEl = SK.DOM.get('mappingId');
        if (mappingIdEl) mappingIdEl.value = '';

        const titleEl = SK.DOM.get('groupMappingModalTitle');
        if (titleEl) titleEl.textContent = 'Create Group Mapping';

        // Load organizations dropdown
        await loadOrganizationsForMapping();

        // Show modal
        const modalEl = SK.DOM.get('groupMappingModal');
        if (!modalEl) {
            console.error('groupMappingModal element not found');
            showToast('Error: Modal not found', 'danger');
            return;
        }
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
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
            SK.DOM.getValue('mappingId') = mapping.id;
            SK.DOM.getValue('ldapGroupDn') = mapping.ldap_group_dn;
            SK.DOM.getValue('ldapGroupCn') = mapping.ldap_group_cn;
            SK.DOM.getValue('ldapGroupDescription') = mapping.ldap_group_description || '';
            SK.DOM.getValue('mappingRole') = mapping.role;
            SK.DOM.getValue('mappingPriority') = mapping.priority;
            SK.DOM.getChecked('autoProvision') = mapping.auto_provision;
            SK.DOM.getChecked('autoDeprovision') = mapping.auto_deprovision;
            SK.DOM.getChecked('syncEnabled') = mapping.sync_enabled;

            // Load organizations and set selected
            await loadOrganizationsForMapping();
            SK.DOM.getValue('mappingOrganization') = mapping.organization_id || '';

            SK.DOM.get('groupMappingModalTitle').textContent = 'Edit Group Mapping';

            const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('groupMappingModal'));
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
    const mappingId = SK.DOM.getValue('mappingId');
    const form = SK.DOM.get('groupMappingForm');
    const data = {
        ldap_group_dn: SK.DOM.getValue('ldapGroupDn').trim(),
        ldap_group_cn: SK.DOM.getValue('ldapGroupCn').trim(),
        ldap_group_description: SK.DOM.getValue('ldapGroupDescription').trim(),
        organization_id: SK.DOM.getValue('mappingOrganization') || null,
        role: SK.DOM.getValue('mappingRole'),
        priority: parseInt(SK.DOM.getValue('mappingPriority')),
        auto_provision: SK.DOM.getChecked('autoProvision'),
        auto_deprovision: SK.DOM.getChecked('autoDeprovision'),
        sync_enabled: SK.DOM.getChecked('syncEnabled')
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

            safeHideModal('groupMappingModal');
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
    const select = SK.DOM.get('mappingOrganization');
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
    const panel = SK.DOM.get('groupDiscoveryPanel');
    const icon = SK.DOM.get('discoveryToggleIcon');

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
    const searchBase = SK.DOM.getValue('groupSearchBaseInline').trim();
    const container = SK.DOM.get('discoveredGroupsContainerInline');

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
    const form = SK.DOM.get('groupMappingForm');
    const dnField = SK.DOM.get('ldapGroupDn');
    const cnField = SK.DOM.get('ldapGroupCn');
    const descField = SK.DOM.get('ldapGroupDescription');

    if (dnField) dnField.value = dn;
    if (cnField) cnField.value = cn;
    if (descField && description) descField.value = description;

    // Store member count in data attribute for submission
    if (form) form.dataset.memberCount = memberCount || 0;

    // Update modal title
    const titleEl = SK.DOM.get('groupMappingModalTitle');
    if (titleEl) titleEl.textContent = 'Create Group Mapping';

    // Optionally collapse the discovery panel
    const panel = SK.DOM.get('groupDiscoveryPanel');
    const icon = SK.DOM.get('discoveryToggleIcon');
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
    const searchBase = SK.DOM.getValue('groupSearchBase').trim();
    const container = SK.DOM.get('discoveredGroupsContainer');

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
    safeHideModal('ldapDiscoveryModal');

    // Pre-fill mapping form
    const form = SK.DOM.get('groupMappingForm');
    form.reset();
    SK.DOM.getValue('mappingId') = '';
    SK.DOM.getValue('ldapGroupDn') = dn;
    SK.DOM.getValue('ldapGroupCn') = cn;
    SK.DOM.getValue('ldapGroupDescription') = description;
    // Store member count in data attribute for submission
    form.dataset.memberCount = memberCount || 0;
    SK.DOM.get('groupMappingModalTitle').textContent = 'Create Group Mapping';

    // Load organizations
    loadOrganizationsForMapping();

    // Show mapping modal
    const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('groupMappingModal'));
    modal.show();
}

/**
 * Trigger manual LDAP sync
 */
async function triggerManualSync() {
    const button = SK.DOM.get('syncButton');
    const statusDiv = SK.DOM.get('syncStatus');

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
    // Skip if LDAP is not licensed
    if (!isFeatureLicensed('ldap')) return;

    try {
        const response = await fetch('/api/ldap/groups/sync/history?limit=1');
        if (response.ok) {
            const result = await response.json();
            const logs = result.logs || [];
            const latestSync = logs.length > 0 ? logs[0] : null;

            // Update stats displays - use 'timestamp' field from backend
            if (latestSync && latestSync.timestamp) {
                SK.DOM.get('syncStatsLastSync').textContent =
                    new Date(latestSync.timestamp).toLocaleString();
            }

            // Count total LDAP users
            const usersResponse = await fetch('/api/users');
            if (usersResponse.ok) {
                const users = await usersResponse.json();
                const ldapUsers = users.filter(u => u.auth_type === 'ldap');
                SK.DOM.get('syncStatsTotal').textContent = ldapUsers.length;
            }

            // Count successful syncs and errors from history
            // Backend uses 'success' not 'completed' for status
            const historyResponse = await fetch('/api/ldap/groups/sync/history?limit=100');
            if (historyResponse.ok) {
                const historyResult = await historyResponse.json();
                const allHistory = historyResult.logs || [];
                const successCount = allHistory.filter(s => s.status === 'success').length;
                const errorCount = allHistory.filter(s => s.status === 'failed').length;

                SK.DOM.get('syncStatsSuccess').textContent = successCount;
                SK.DOM.get('syncStatsErrors').textContent = errorCount;
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
    const tableBody = SK.DOM.get('syncHistoryTable');
    if (!tableBody) return;

    // Skip if LDAP is not licensed
    if (!isFeatureLicensed('ldap')) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4 text-muted">
                    LDAP integration requires a Professional license.
                </td>
            </tr>
        `;
        return;
    }

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
    const tableBody = SK.DOM.get('auditLogTable');
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
    const pagination = SK.DOM.get('auditPagination');
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
    const searchInput = SK.DOM.get('auditSearchInput');
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
            const displayElement = SK.DOM.get('ldapLastScheduledSync');

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
    const tbody = SK.DOM.get('auditLogsTable');
    if (!tbody) return;

    currentAuditPage = page;

    // Get filter values
    const action = SK.DOM.get('auditActionFilter')?.value || '';
    const resource = SK.DOM.get('auditResourceFilter')?.value || '';
    const search = SK.DOM.get('auditSearchInput')?.value || '';
    const startDate = SK.DOM.get('auditStartDate')?.value || '';
    const endDate = SK.DOM.get('auditEndDate')?.value || '';
    const perPage = SK.DOM.get('auditPerPage')?.value || '50';
    const sortField = SK.DOM.get('auditSortField')?.value || 'timestamp';
    const sortOrder = SK.DOM.get('auditSortOrder')?.value || 'desc';

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
        const infoEl = SK.DOM.get('auditPaginationInfo');
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
    const pagination = SK.DOM.get('auditPagination');
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
    const sortFieldEl = SK.DOM.get('auditSortField');
    const sortOrderEl = SK.DOM.get('auditSortOrder');

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
    SK.DOM.getValue('auditSearchInput') = '';
    SK.DOM.getValue('auditActionFilter') = '';
    SK.DOM.getValue('auditResourceFilter') = '';
    SK.DOM.getValue('auditStartDate') = '';
    SK.DOM.getValue('auditEndDate') = '';
    SK.DOM.getValue('auditPerPage') = '50';
    SK.DOM.getValue('auditSortField') = 'timestamp';
    SK.DOM.getValue('auditSortOrder') = 'desc';
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
    const action = SK.DOM.get('auditActionFilter')?.value || '';
    const resource = SK.DOM.get('auditResourceFilter')?.value || '';
    const search = SK.DOM.get('auditSearchInput')?.value || '';

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
    const auditLogsTab = SK.DOM.get('audit-logs-tab');
    if (auditLogsTab) {
        auditLogsTab.addEventListener('shown.bs.tab', function() {
            loadAuditLogs(1);
        });
    }

    // Load license info when tab is shown
    const licenseTab = SK.DOM.get('license-tab');
    if (licenseTab) {
        licenseTab.addEventListener('shown.bs.tab', function() {
            loadLicenseInfo();
        });
    }

    // Load integrations data when main tab is shown
    const integrationsTab = SK.DOM.get('integrations-tab');
    if (integrationsTab) {
        integrationsTab.addEventListener('shown.bs.tab', function() {
            loadIntegrationsSummary();
            loadImportQueueCount();
        });
    }

    // Integrations sub-tab handlers (new unified structure)
    const overviewSubTab = SK.DOM.get('integrations-overview-tab');
    if (overviewSubTab) {
        overviewSubTab.addEventListener('shown.bs.tab', function() {
            loadIntegrationsSummary();
        });
    }

    const importQueueSubTab = SK.DOM.get('import-queue-tab');
    if (importQueueSubTab) {
        importQueueSubTab.addEventListener('shown.bs.tab', function() {
            loadImportQueue();
        });
    }

    const pullSourcesSubTab = SK.DOM.get('pull-sources-tab');
    if (pullSourcesSubTab) {
        pullSourcesSubTab.addEventListener('shown.bs.tab', function() {
            loadIntegrations();
        });
    }

    const pushAgentsSubTab = SK.DOM.get('push-agents-tab');
    if (pushAgentsSubTab) {
        pushAgentsSubTab.addEventListener('shown.bs.tab', function() {
            loadAgentKeys();
            loadAgentScriptOrganizations();
            loadAssets();
        });
    }
});

// ============================================================================
// LICENSE MANAGEMENT
// ============================================================================

/**
 * Load license info and apply UI restrictions for premium features
 * This is called early during page initialization
 * Uses retry logic to handle app startup timing issues
 */
async function loadLicenseAndApplyRestrictions() {
    try {
        const response = await fetchWithRetry('/api/license', {}, 5, 800);
        if (!response.ok) {
            console.warn('Failed to load license info, status:', response.status);
            window.licenseInfo = { is_professional: false, features: [] };
            updateLicenseLoadingState('error');
            return;
        }

        window.licenseInfo = await response.json();
        applyLicenseRestrictions();
        updateLicenseLoadingState('success');

    } catch (error) {
        console.error('Error loading license for restrictions:', error);
        window.licenseInfo = { is_professional: false, features: [] };
        updateLicenseLoadingState('error');
    }
}

/**
 * Update UI elements that show "Loading..." for license data
 */
function updateLicenseLoadingState(status) {
    const installIdEl = SK.DOM.get('installationIdDisplay');

    if (status === 'error') {
        if (installIdEl && (installIdEl.value === 'Loading...' || !installIdEl.value)) {
            installIdEl.value = 'Error loading - click License tab to retry';
        }

        const licenseDetails = SK.DOM.get('licenseDetails');
        if (licenseDetails && licenseDetails.innerHTML.includes('Loading')) {
            licenseDetails.innerHTML = `
                <div class="alert alert-warning mb-0 py-2">
                    <i class="bi bi-exclamation-triangle me-1"></i>
                    Failed to load. <a href="#" onclick="loadLicenseInfo(); return false;">Retry</a>
                </div>
            `;
        }

        const licenseUsage = SK.DOM.get('licenseUsage');
        if (licenseUsage && licenseUsage.innerHTML.includes('Loading')) {
            licenseUsage.innerHTML = `<span class="text-muted">Click License tab to load</span>`;
        }
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
    if (hasFeature('ldap')) {
        // SHOW LDAP tabs when user has license (they start hidden)
        const ldapUsersTab = SK.DOM.get('ldap-users-tab-item');
        const ldapGroupsTab = SK.DOM.get('ldap-groups-tab-item');
        if (ldapUsersTab) ldapUsersTab.style.display = '';
        if (ldapGroupsTab) ldapGroupsTab.style.display = '';
    } else {
        // Hide LDAP tabs completely for Community
        const ldapUsersTab = SK.DOM.get('ldap-users-tab-item');
        const ldapGroupsTab = SK.DOM.get('ldap-groups-tab-item');
        if (ldapUsersTab) ldapUsersTab.style.display = 'none';
        if (ldapGroupsTab) ldapGroupsTab.style.display = 'none';

        // Hide LDAP settings section completely
        const ldapSettingsPane = SK.DOM.get('ldapSettings');
        if (ldapSettingsPane) {
            ldapSettingsPane.style.display = 'none';
        }
    }

    // ========================================
    // Backup & Restore - requires 'backup_restore' license
    // ========================================
    if (!hasFeature('backup_restore')) {
        // Hide the Backup & Restore card completely
        const backupCard = SK.DOM.get('backupRestoreCard');
        if (backupCard) {
            backupCard.style.display = 'none';
        }
    }

    // ========================================
    // Email Alerts / Webhooks - requires 'email_alerts' license
    // ========================================
    if (!hasFeature('email_alerts')) {
        // Hide notifications settings completely
        const notificationsPane = SK.DOM.get('notificationsSettings');
        if (notificationsPane) {
            notificationsPane.style.display = 'none';
        }

        // Also hide the org webhook tab in organization modal
        const orgWebhookTab = SK.DOM.get('webhook-tab');
        if (orgWebhookTab) {
            orgWebhookTab.closest('li')?.style.setProperty('display', 'none');
        }
    }

    // ========================================
    // White Label / Branding - requires 'white_label' license
    // ========================================
    if (!hasFeature('white_label')) {
        // Hide branding settings completely
        const brandingPane = SK.DOM.get('brandingSettings');
        if (brandingPane) {
            brandingPane.style.display = 'none';
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
    const detailsEl = SK.DOM.get('licenseDetails');
    const usageEl = SK.DOM.get('licenseUsage');

    // Show loading state
    if (detailsEl) detailsEl.innerHTML = '<div class="text-center py-2"><div class="spinner-border spinner-border-sm"></div> Loading...</div>';
    if (usageEl) usageEl.innerHTML = '<div class="text-center py-2"><div class="spinner-border spinner-border-sm"></div> Loading...</div>';

    try {
        const response = await fetchWithRetry('/api/license', {}, 3, 1000);
        if (!response.ok) {
            throw new Error('Failed to load license info');
        }

        const data = await response.json();
        window.licenseInfo = data; // Update global
        displayLicenseInfo(data);

    } catch (error) {
        console.error('Error loading license:', error);
        if (detailsEl) {
            detailsEl.innerHTML = `
                <div class="alert alert-danger mb-0">
                    <i class="bi bi-exclamation-triangle me-2"></i>Failed to load license info.
                    <a href="#" onclick="loadLicenseInfo(); return false;" class="alert-link ms-2">Retry</a>
                </div>
            `;
        }
        if (usageEl) {
            usageEl.innerHTML = `<span class="text-muted">-</span>`;
        }
    }
}

function displayLicenseInfo(data) {
    const detailsEl = SK.DOM.get('licenseDetails');
    const usageEl = SK.DOM.get('licenseUsage');
    const badgeEl = SK.DOM.get('licenseEditionBadge');
    const removeBtn = SK.DOM.get('removeLicenseBtn');

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

    // Display installation ID
    const installIdEl = SK.DOM.get('installationIdDisplay');
    if (installIdEl && data.installation_id) {
        installIdEl.value = data.installation_id;
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
                <a href="#" class="text-primary" onclick="SK.DOM.get('licenseKeyInput').focus(); return false;">
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
    const licenseKey = SK.DOM.getValue('licenseKeyInput').trim();

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
            SK.DOM.getValue('licenseKeyInput') = '';
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

function formatRelativeTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    if (diffSec < 60) return 'Just now';
    if (diffMin < 60) return `${diffMin} min ago`;
    if (diffHour < 24) return `${diffHour}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    if (diffDay < 30) return `${Math.floor(diffDay / 7)}w ago`;
    return formatDate(dateStr);
}

// ============================================================================
// INSTALLATION ID HELPER
// ============================================================================

function copyInstallationId() {
    const installIdEl = SK.DOM.get('installationIdDisplay');
    if (!installIdEl) {
        showToast('Installation ID element not found', 'error');
        return;
    }

    const value = installIdEl.value;
    if (!value || value === 'Loading...' || value.length < 10) {
        showToast('Installation ID not loaded yet. Please wait or refresh the page.', 'warning');
        return;
    }

    // Try modern clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(() => {
            showToast('Installation ID copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Clipboard write failed:', err);
            fallbackCopy(installIdEl);
        });
    } else {
        // Use fallback for non-HTTPS contexts
        fallbackCopy(installIdEl);
    }
}

function fallbackCopy(inputEl) {
    try {
        inputEl.select();
        inputEl.setSelectionRange(0, 99999); // For mobile
        const success = document.execCommand('copy');
        if (success) {
            showToast('Installation ID copied to clipboard!', 'success');
        } else {
            showToast('Copy failed. Please select and copy manually (Ctrl+C)', 'warning');
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showToast('Copy failed. Please select and copy manually (Ctrl+C)', 'warning');
    }
}

// ============================================================================
// AGENT API KEYS MANAGEMENT
// ============================================================================

let agentKeysLoaded = false;

// Temporary storage for recently created API keys (cleared on page refresh)
// Maps key_prefix -> full_key for re-download capability
const recentlyCreatedKeys = new Map();

async function loadAgentKeys() {
    const tbody = SK.DOM.get('agentKeysTableBody');
    if (!tbody) return;

    try {
        const response = await fetchWithRetry('/api/agent-keys' + getOrgIdParam(), {}, 3, 800);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        const keys = data.api_keys || [];

        if (keys.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-4 text-muted">
                        <i class="bi bi-key text-warning" style="font-size: 2rem;"></i>
                        <p class="mt-2 mb-0">No agent API keys configured</p>
                        <p class="small">Create an API key to download agents with embedded authentication</p>
                    </td>
                </tr>
            `;
        } else {
            tbody.innerHTML = keys.map(key => `
                <tr>
                    <td>
                        <strong>${escapeHtml(key.name)}</strong>
                        <br><small class="text-muted font-monospace">${escapeHtml(key.key_prefix || '')}...</small>
                    </td>
                    <td>${escapeHtml(key.organization_name || 'Unknown')}</td>
                    <td>
                        ${key.auto_approve
                            ? '<span class="badge bg-success" title="Products are added directly to inventory"><i class="bi bi-check-circle me-1"></i>Auto</span>'
                            : '<span class="badge bg-info" title="Products go to Import Queue for review"><i class="bi bi-inbox me-1"></i>Queue</span>'}
                    </td>
                    <td>${key.last_used_at ? formatRelativeTime(key.last_used_at) : '<span class="text-muted">Never</span>'}</td>
                    <td>
                        <span class="badge bg-secondary">${key.usage_count || 0}</span>
                    </td>
                    <td>${key.expires_at ? formatDate(key.expires_at) : '<span class="text-muted">-</span>'}</td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" onclick="downloadAgentWithKey('${escapeHtml(key.key_prefix)}', 'windows')" title="Download Windows Agent">
                                <i class="bi bi-windows"></i>
                            </button>
                            <button class="btn btn-outline-success" onclick="downloadAgentWithKey('${escapeHtml(key.key_prefix)}', 'linux')" title="Download Linux Agent">
                                <i class="bi bi-ubuntu"></i>
                            </button>
                            <button class="btn btn-outline-danger" onclick="deleteAgentKey(${key.id}, '${escapeHtml(key.name)}')" title="Delete key">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }
        agentKeysLoaded = true;
    } catch (error) {
        console.error('Error loading agent keys:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-danger">
                    <i class="bi bi-exclamation-triangle text-danger"></i>
                    <span class="ms-2">Error loading agent keys: ${error.message}</span>
                </td>
            </tr>
        `;
    }
}

async function showCreateAgentKeyModal() {
    // Populate organizations dropdown
    const orgSelect = SK.DOM.get('agentKeyOrg');
    if (orgSelect && organizations.length > 0) {
        orgSelect.innerHTML = '<option value="">Select organization...</option>' +
            organizations.map(org => `<option value="${org.id}">${escapeHtml(org.name)}</option>`).join('');
    } else {
        // Load organizations if not loaded
        try {
            const response = await fetch('/api/organizations');
            if (response.ok) {
                const data = await response.json();
                organizations = data.organizations || [];
                orgSelect.innerHTML = '<option value="">Select organization...</option>' +
                    organizations.map(org => `<option value="${org.id}">${escapeHtml(org.name)}</option>`).join('');
            }
        } catch (error) {
            console.error('Error loading organizations:', error);
        }
    }

    // Reset form
    SK.DOM.get('agentKeyForm').reset();

    // Show modal
    const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('agentKeyModal'));
    modal.show();
}

async function createAgentKey() {
    const name = SK.DOM.getValue('agentKeyName').trim();
    const orgId = SK.DOM.getValue('agentKeyOrg');
    const maxAssets = parseInt(SK.DOM.getValue('agentKeyMaxAssets')) || 0;
    const expiresAt = SK.DOM.getValue('agentKeyExpires') || null;
    const autoApprove = SK.DOM.get('agentKeyAutoApprove')?.checked || false;

    if (!name) {
        showToast('Please enter a key name', 'warning');
        return;
    }
    if (!orgId) {
        showToast('Please select an organization', 'warning');
        return;
    }

    showLoading();
    try {
        const response = await fetch('/api/agent-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                organization_id: parseInt(orgId),
                max_assets: maxAssets,
                expires_at: expiresAt,
                auto_approve: autoApprove
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `HTTP ${response.status}`);
        }

        const data = await response.json();

        // Store the full key temporarily for re-download from table
        if (data.key_prefix && data.api_key) {
            recentlyCreatedKeys.set(data.key_prefix, data.api_key);
        }

        // Hide create modal
        safeHideModal('agentKeyModal');

        // Show the key to user
        const keyValueField = SK.DOM.get('newAgentKeyValue');
        const showModalEl = SK.DOM.get('showAgentKeyModal');
        if (keyValueField) keyValueField.value = data.api_key;
        if (showModalEl) {
            const showModal = bootstrap.Modal.getOrCreateInstance(showModalEl);
            showModal.show();
        }

        // Refresh the keys table to show the new key
        loadAgentKeys();

        showToast('Agent API key created successfully', 'success');
    } catch (error) {
        showToast(`Error creating key: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

async function deleteAgentKey(keyId, keyName) {
    const confirmed = await showConfirm(
        `Are you sure you want to delete the API key "${keyName}"? Agents using this key will no longer be able to report inventory.`,
        'Delete API Key',
        'Delete',
        'btn-danger'
    );
    if (!confirmed) return;

    showLoading();
    try {
        const response = await fetch(`/api/agent-keys/${keyId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `HTTP ${response.status}`);
        }

        showToast('API key deleted', 'success');
        loadAgentKeys();
    } catch (error) {
        showToast(`Error deleting key: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

function copyAgentKey() {
    const keyInput = SK.DOM.get('newAgentKeyValue');
    if (!keyInput) return;

    const key = keyInput.value;
    copyTextToClipboard(key);
}

/**
 * Download agent script with the API key embedded from the "Key Created" modal.
 * This is called when user clicks download in the modal where we have the full key.
 */
async function downloadAgentFromModal(platform) {
    const keyInput = SK.DOM.get('newAgentKeyValue');
    if (!keyInput || !keyInput.value) {
        showToast('No API key found', 'warning');
        return;
    }

    const apiKey = keyInput.value;
    showToast(`Downloading ${platform === 'windows' ? 'Windows' : 'Linux'} agent with embedded key...`, 'info');

    try {
        const url = `/api/agents/script/${platform}?api_key=${encodeURIComponent(apiKey)}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to download: ${response.status}`);
        }

        const script = await response.text();
        const filename = platform === 'windows' ? 'sentrikat-agent.ps1' : 'sentrikat-agent.sh';
        downloadScript(filename, script);

        showToast(`${platform === 'windows' ? 'Windows' : 'Linux'} agent downloaded with API key embedded!`, 'success');
    } catch (error) {
        showToast(`Error downloading agent: ${error.message}`, 'danger');
    }
}

function copyTextToClipboard(text) {
    // Try modern clipboard API first (requires HTTPS or localhost)
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copied to clipboard!', 'success');
        }).catch(() => {
            fallbackCopyText(text);
        });
    } else {
        fallbackCopyText(text);
    }
}

function fallbackCopyText(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    textarea.setAttribute('readonly', '');
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, 99999); // For mobile
    try {
        const success = document.execCommand('copy');
        if (success) {
            showToast('Copied to clipboard!', 'success');
        } else {
            showToast('Copy failed. Please select and copy manually (Ctrl+C)', 'warning');
        }
    } catch (e) {
        showToast('Copy failed. Please select and copy manually (Ctrl+C)', 'warning');
    }
    document.body.removeChild(textarea);
}

/**
 * Download agent script with a specific API key embedded
 * Called from the API keys table download buttons
 */
async function downloadAgentWithKey(keyPrefix, platform) {
    // Check if we have the full key stored from recent creation
    const fullKey = recentlyCreatedKeys.get(keyPrefix);
    const hasKey = !!fullKey;

    showToast(`Downloading ${platform === 'windows' ? 'Windows' : 'Linux'} agent${hasKey ? ' with embedded key' : ''}...`, 'info');

    try {
        // If we have the full key, embed it in the download
        let url = `/api/agents/script/${platform}`;
        if (hasKey) {
            url += `?api_key=${encodeURIComponent(fullKey)}`;
        }

        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to download: ${response.status}`);
        }

        const script = await response.text();
        const filename = platform === 'windows' ? 'sentrikat-agent.ps1' : 'sentrikat-agent.sh';
        downloadScript(filename, script);

        if (hasKey) {
            showToast(`${platform === 'windows' ? 'Windows' : 'Linux'} agent downloaded with API key embedded!`, 'success');
        } else {
            showToast(`Agent script downloaded. Replace YOUR_API_KEY with your key (only available at creation time).`, 'warning');
        }
    } catch (error) {
        showToast(`Error downloading agent: ${error.message}`, 'danger');
    }
}

// ============================================================================
// ASSETS MANAGEMENT
// ============================================================================

let assetsLoaded = false;
let assetsPage = 1;
const assetsPerPage = 20;
let assetsSortColumn = 'hostname';
let assetsSortDirection = 'asc';

function sortAssets(column) {
    if (assetsSortColumn === column) {
        assetsSortDirection = assetsSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        assetsSortColumn = column;
        assetsSortDirection = 'asc';
    }
    loadAssets(1);
}

function updateAssetsSortIndicators() {
    document.querySelectorAll('#assetsTable th[data-sort]').forEach(th => {
        const col = th.dataset.sort;
        th.classList.remove('sort-asc', 'sort-desc');
        if (col === assetsSortColumn) {
            th.classList.add(assetsSortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });
}

async function loadAssets(page = 1) {
    assetsPage = page;
    const tbody = SK.DOM.get('assetsTableBody');
    const countEl = SK.DOM.get('assetsCount');
    const paginationEl = SK.DOM.get('assetsPagination');
    if (!tbody) return;

    const search = SK.DOM.get('assetSearchInput')?.value || '';

    tbody.innerHTML = `
        <tr>
            <td colspan="7" class="text-center py-4">
                <div class="spinner-border spinner-border-sm text-primary"></div>
                <span class="ms-2">Loading assets...</span>
            </td>
        </tr>
    `;

    try {
        const params = new URLSearchParams({
            page: page,
            per_page: assetsPerPage,
            order: assetsSortColumn,
            direction: assetsSortDirection
        });
        if (search) params.set('search', search);

        const response = await fetch(`/api/assets?${params}`);
        if (!response.ok) {
            // Try to get error message from response
            try {
                const errorData = await safeParseJSON(response, 'assets');
                throw new Error(errorData.error || `HTTP ${response.status}`);
            } catch (e) {
                if (e.message.includes('Server returned')) throw e;
                throw new Error(`HTTP ${response.status}`);
            }
        }
        const data = await safeParseJSON(response, 'assets');
        const assets = data.assets || [];
        const total = data.total || 0;
        const pages = Math.ceil(total / assetsPerPage);

        if (countEl) {
            countEl.textContent = `Showing ${assets.length} of ${total} assets`;
        }

        if (assets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-4 text-muted">
                        <i class="bi bi-pc-display text-primary" style="font-size: 2rem;"></i>
                        <p class="mt-2 mb-0">No endpoints discovered</p>
                        <p class="small">Endpoints will appear here when agents report their inventory</p>
                    </td>
                </tr>
            `;
            if (paginationEl) paginationEl.innerHTML = '';
        } else {
            tbody.innerHTML = assets.map(asset => {
                // Status badge with color
                const statusBadges = {
                    'online': '<span class="badge bg-success"><i class="bi bi-circle-fill me-1" style="font-size: 0.5rem;"></i>Online</span>',
                    'offline': '<span class="badge bg-secondary"><i class="bi bi-circle-fill me-1" style="font-size: 0.5rem;"></i>Offline</span>',
                    'stale': '<span class="badge bg-warning text-dark"><i class="bi bi-exclamation-circle me-1"></i>Stale</span>',
                    'decommissioned': '<span class="badge bg-dark"><i class="bi bi-x-circle me-1"></i>Decommissioned</span>'
                };
                const statusBadge = statusBadges[asset.status] || `<span class="badge bg-secondary">${asset.status || 'Unknown'}</span>`;

                // Vulnerability badge
                const vulnCount = asset.total_vulnerabilities || asset.vulnerable_products_count || 0;
                const vulnBadge = vulnCount > 0 ? `<span class="badge bg-danger ms-1" title="${vulnCount} vulnerabilities">${vulnCount} CVEs</span>` : '';

                // Last seen time with relative formatting
                const lastSeen = asset.last_checkin || asset.last_inventory_at;
                const lastSeenDisplay = lastSeen ? formatRelativeTime(lastSeen) : '<span class="text-muted">Never</span>';

                return `
                <tr>
                    <td>
                        <a href="#" onclick="showAssetDetails(${asset.id}); return false;" class="fw-semibold text-decoration-none">
                            ${escapeHtml(asset.hostname)}
                        </a>
                        ${asset.environment ? `<br><small class="text-muted">${escapeHtml(asset.environment)}</small>` : ''}
                    </td>
                    <td><code>${escapeHtml(asset.ip_address || '-')}</code></td>
                    <td>${escapeHtml(asset.os_name || '-')} ${escapeHtml(asset.os_version || '')}</td>
                    <td>${escapeHtml(asset.organization_name || 'Unknown')}</td>
                    <td>
                        <span class="badge bg-primary">${asset.product_count || 0}</span>
                        ${vulnBadge}
                    </td>
                    <td>${statusBadge}</td>
                    <td>${lastSeenDisplay}</td>
                    <td>
                        <button class="btn btn-outline-primary btn-sm" onclick="showAssetDetails(${asset.id})" title="View details">
                            <i class="bi bi-eye"></i>
                        </button>
                        <button class="btn btn-outline-danger btn-sm ms-1" onclick="deleteAsset(${asset.id}, '${escapeHtml(asset.hostname)}')" title="Delete asset">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `}).join('');

            // Build pagination
            if (paginationEl && pages > 1) {
                let paginationHtml = '';
                paginationHtml += `<li class="page-item ${page === 1 ? 'disabled' : ''}">
                    <a class="page-link" href="#" onclick="loadAssets(${page - 1}); return false;">&laquo;</a>
                </li>`;
                for (let i = 1; i <= pages; i++) {
                    if (i === 1 || i === pages || (i >= page - 2 && i <= page + 2)) {
                        paginationHtml += `<li class="page-item ${i === page ? 'active' : ''}">
                            <a class="page-link" href="#" onclick="loadAssets(${i}); return false;">${i}</a>
                        </li>`;
                    } else if (i === page - 3 || i === page + 3) {
                        paginationHtml += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
                    }
                }
                paginationHtml += `<li class="page-item ${page === pages ? 'disabled' : ''}">
                    <a class="page-link" href="#" onclick="loadAssets(${page + 1}); return false;">&raquo;</a>
                </li>`;
                paginationEl.innerHTML = paginationHtml;
            } else if (paginationEl) {
                paginationEl.innerHTML = '';
            }
        }
        assetsLoaded = true;
        updateAssetsSortIndicators();
    } catch (error) {
        console.error('Error loading assets:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-danger">
                    <i class="bi bi-exclamation-triangle text-danger"></i>
                    <span class="ms-2">Error loading assets: ${error.message}</span>
                </td>
            </tr>
        `;
    }
}

// Asset Details Products Table State
let assetProductsData = [];
let assetProductsPage = 1;
let assetProductsPageSize = 15;
let assetProductsSortField = 'product';
let assetProductsSortDir = 'asc';

function sortAssetProducts(field) {
    if (assetProductsSortField === field) {
        assetProductsSortDir = assetProductsSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        assetProductsSortField = field;
        assetProductsSortDir = 'asc';
    }
    assetProductsPage = 1;
    renderAssetProductsTable();
}

function changeAssetProductsPage(newPage) {
    assetProductsPage = newPage;
    renderAssetProductsTable();
}

function renderAssetProductsTable() {
    const container = SK.DOM.get('assetProductsTableContainer');
    if (!container || assetProductsData.length === 0) return;

    // Sort products
    const sortedProducts = [...assetProductsData].sort((a, b) => {
        let aVal, bVal;
        switch (assetProductsSortField) {
            case 'product':
                aVal = `${a.vendor || ''} ${a.product_name || a.name || ''}`.toLowerCase();
                bVal = `${b.vendor || ''} ${b.product_name || b.name || ''}`.toLowerCase();
                break;
            case 'version':
                aVal = (a.version || '').toLowerCase();
                bVal = (b.version || '').toLowerCase();
                break;
            case 'status':
                aVal = a.is_vulnerable ? 1 : 0;
                bVal = b.is_vulnerable ? 1 : 0;
                break;
            default:
                aVal = '';
                bVal = '';
        }
        if (aVal < bVal) return assetProductsSortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return assetProductsSortDir === 'asc' ? 1 : -1;
        return 0;
    });

    // Paginate
    const totalPages = Math.ceil(sortedProducts.length / assetProductsPageSize);
    const startIdx = (assetProductsPage - 1) * assetProductsPageSize;
    const pageProducts = sortedProducts.slice(startIdx, startIdx + assetProductsPageSize);

    const getSortIcon = (field) => {
        if (assetProductsSortField !== field) return '<i class="bi bi-chevron-expand text-muted"></i>';
        return assetProductsSortDir === 'asc'
            ? '<i class="bi bi-sort-up"></i>'
            : '<i class="bi bi-sort-down"></i>';
    };

    container.innerHTML = `
        <div class="table-responsive" style="max-height: 350px; overflow-y: auto;">
            <table class="table table-sm table-hover mb-0">
                <thead class="table-light sticky-top">
                    <tr>
                        <th style="width: 55%; cursor: pointer;" onclick="sortAssetProducts('product')">
                            Product ${getSortIcon('product')}
                        </th>
                        <th style="width: 25%; cursor: pointer;" onclick="sortAssetProducts('version')">
                            Version ${getSortIcon('version')}
                        </th>
                        <th style="width: 20%; cursor: pointer;" onclick="sortAssetProducts('status')">
                            Status ${getSortIcon('status')}
                        </th>
                    </tr>
                </thead>
                <tbody>
                    ${pageProducts.map(p => `
                        <tr>
                            <td class="text-truncate" style="max-width: 300px;" title="${escapeHtml(p.vendor || '')} ${escapeHtml(p.product_name || p.name || 'Unknown')}">
                                ${escapeHtml(p.vendor || '')} ${escapeHtml(p.product_name || p.name || 'Unknown')}
                            </td>
                            <td><code class="small">${escapeHtml(p.version || '-')}</code></td>
                            <td>
                                ${p.is_vulnerable
                                    ? '<span class="badge bg-danger">Vulnerable</span>'
                                    : '<span class="badge bg-success">OK</span>'}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
        ${totalPages > 1 ? `
        <div class="d-flex justify-content-between align-items-center mt-2 pt-2 border-top">
            <small class="text-muted">
                Showing ${startIdx + 1}-${Math.min(startIdx + assetProductsPageSize, sortedProducts.length)} of ${sortedProducts.length}
            </small>
            <nav>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item ${assetProductsPage === 1 ? 'disabled' : ''}">
                        <a class="page-link" href="#" onclick="changeAssetProductsPage(${assetProductsPage - 1}); return false;">&laquo;</a>
                    </li>
                    ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
                        let pageNum;
                        if (totalPages <= 5) {
                            pageNum = i + 1;
                        } else if (assetProductsPage <= 3) {
                            pageNum = i + 1;
                        } else if (assetProductsPage >= totalPages - 2) {
                            pageNum = totalPages - 4 + i;
                        } else {
                            pageNum = assetProductsPage - 2 + i;
                        }
                        return `
                            <li class="page-item ${pageNum === assetProductsPage ? 'active' : ''}">
                                <a class="page-link" href="#" onclick="changeAssetProductsPage(${pageNum}); return false;">${pageNum}</a>
                            </li>
                        `;
                    }).join('')}
                    <li class="page-item ${assetProductsPage === totalPages ? 'disabled' : ''}">
                        <a class="page-link" href="#" onclick="changeAssetProductsPage(${assetProductsPage + 1}); return false;">&raquo;</a>
                    </li>
                </ul>
            </nav>
        </div>
        ` : ''}
    `;
}

async function showAssetDetails(assetId) {
    const modalBody = SK.DOM.get('assetDetailsBody');
    if (!modalBody) return;

    // Reset pagination state
    assetProductsPage = 1;
    assetProductsSortField = 'product';
    assetProductsSortDir = 'asc';

    modalBody.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary"></div>
            <p class="mt-2">Loading asset details...</p>
        </div>
    `;

    const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('assetDetailsModal'));
    modal.show();

    try {
        const response = await fetch(`/api/assets/${assetId}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const asset = await response.json();

        // Store products for pagination
        assetProductsData = asset.products || [];

        let productsHtml = '';
        if (assetProductsData.length > 0) {
            productsHtml = `
                <h6 class="mt-4 mb-3"><i class="bi bi-box me-2 text-success"></i>Installed Products (${assetProductsData.length})</h6>
                <div id="assetProductsTableContainer"></div>
            `;
        } else {
            productsHtml = '<p class="text-muted mt-4">No products reported by agent</p>';
        }

        modalBody.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="bi bi-pc-display me-2 text-primary"></i>System Information</h6>
                    <table class="table table-sm">
                        <tr><td class="text-muted" style="width: 100px;">Hostname</td><td><strong>${escapeHtml(asset.hostname)}</strong></td></tr>
                        <tr><td class="text-muted">IP Address</td><td><code>${escapeHtml(asset.ip_address || '-')}</code></td></tr>
                        <tr><td class="text-muted">OS</td><td>${escapeHtml(asset.os_name || '-')} ${escapeHtml(asset.os_version || '')}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6><i class="bi bi-info-circle me-2 text-info"></i>Agent Information</h6>
                    <table class="table table-sm">
                        <tr><td class="text-muted" style="width: 110px;">Agent ID</td><td><code class="small">${escapeHtml(asset.agent_id || '-')}</code></td></tr>
                        <tr><td class="text-muted">Agent Version</td><td>${escapeHtml(asset.agent_version || '-')}</td></tr>
                        <tr><td class="text-muted">Organization</td><td>${escapeHtml(asset.organization_name || 'Unknown')}</td></tr>
                        <tr><td class="text-muted">Last Seen</td><td>${asset.last_seen ? formatDate(asset.last_seen) : '<span class="text-warning">Pending first report</span>'}</td></tr>
                    </table>
                </div>
            </div>
            ${productsHtml}
        `;

        // Render paginated products table if we have products
        if (assetProductsData.length > 0) {
            renderAssetProductsTable();
        }
    } catch (error) {
        console.error('Error loading asset details:', error);
        modalBody.innerHTML = `
            <div class="text-center py-4 text-danger">
                <i class="bi bi-exclamation-triangle text-danger" style="font-size: 2rem;"></i>
                <p class="mt-2">Error loading asset details: ${error.message}</p>
            </div>
        `;
    }
}

async function deleteAsset(assetId, hostname) {
    const confirmed = await showConfirm(
        `Are you sure you want to delete the asset "${hostname}"? This will remove all inventory data for this asset.`,
        'Delete Asset',
        'Delete',
        'btn-danger'
    );
    if (!confirmed) return;

    showLoading();
    try {
        const response = await fetch(`/api/assets/${assetId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `HTTP ${response.status}`);
        }

        showToast('Asset deleted', 'success');
        loadAssets(assetsPage);
    } catch (error) {
        showToast(`Error deleting asset: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

// ============================================================================
// INTEGRATIONS - Import Queue, Connectors, Discovery Agents
// ============================================================================

let selectedQueueItems = new Set();
let integrationsList = [];
let importQueueData = [];

// Import Queue pagination/sorting state
let importQueuePage = 1;
let importQueuePageSize = 15;
let importQueueSortField = 'vendor';
let importQueueSortDir = 'asc';

// Pull Sources pagination/sorting state
let pullSourcesPage = 1;
let pullSourcesPageSize = 15;
let pullSourcesSortField = 'name';
let pullSourcesSortDir = 'asc';

// Load import queue count for badge
async function loadImportQueueCount() {
    try {
        const response = await fetch('/api/import/queue/count');
        if (response.ok) {
            const data = await response.json();
            const count = data.pending || 0;
            const badge = SK.DOM.get('importQueueBadge');
            const countEl = SK.DOM.get('importQueueCount');

            if (badge) {
                badge.textContent = count;
                badge.style.display = count > 0 ? 'inline-block' : 'none';
            }
            if (countEl) {
                countEl.textContent = count;
            }
        }
    } catch (error) {
        console.error('Error loading queue count:', error);
    }
}

// Import Queue sorting
function sortImportQueue(field) {
    if (importQueueSortField === field) {
        importQueueSortDir = importQueueSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        importQueueSortField = field;
        importQueueSortDir = 'asc';
    }
    importQueuePage = 1;
    renderImportQueue();
}

function changeImportQueuePage(newPage) {
    importQueuePage = newPage;
    renderImportQueue();
}

function getImportQueueSortIcon(field) {
    if (importQueueSortField !== field) return '<i class="bi bi-chevron-expand text-muted"></i>';
    return importQueueSortDir === 'asc' ? '<i class="bi bi-sort-up"></i>' : '<i class="bi bi-sort-down"></i>';
}

function renderImportQueue() {
    const tbody = SK.DOM.get('importQueueTable');
    const paginationContainer = SK.DOM.get('importQueuePagination');
    if (!tbody) return;

    if (importQueueData.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-muted">
                    <i class="bi bi-inbox text-success" style="font-size: 2rem;"></i>
                    <p class="mb-0 mt-2">No items in queue</p>
                </td>
            </tr>
        `;
        if (paginationContainer) paginationContainer.innerHTML = '';
        return;
    }

    // Sort data
    const sortedData = [...importQueueData].sort((a, b) => {
        let aVal, bVal;
        switch (importQueueSortField) {
            case 'vendor':
                aVal = `${a.vendor || ''} ${a.product_name || ''}`.toLowerCase();
                bVal = `${b.vendor || ''} ${b.product_name || ''}`.toLowerCase();
                break;
            case 'version':
                aVal = (a.detected_version || '').toLowerCase();
                bVal = (b.detected_version || '').toLowerCase();
                break;
            case 'organization':
                aVal = (a.organization_name || '').toLowerCase();
                bVal = (b.organization_name || '').toLowerCase();
                break;
            case 'source':
                aVal = (a.integration_name || 'zzz').toLowerCase();
                bVal = (b.integration_name || 'zzz').toLowerCase();
                break;
            default:
                aVal = '';
                bVal = '';
        }
        if (aVal < bVal) return importQueueSortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return importQueueSortDir === 'asc' ? 1 : -1;
        return 0;
    });

    // Paginate
    const totalPages = Math.ceil(sortedData.length / importQueuePageSize);
    const startIdx = (importQueuePage - 1) * importQueuePageSize;
    const pageData = sortedData.slice(startIdx, startIdx + importQueuePageSize);

    tbody.innerHTML = pageData.map(item => {
        const versions = item.available_versions || [];
        const versionOptions = versions.length > 0
            ? versions.map(v => `<option value="${escapeHtml(v)}" ${v === item.selected_version ? 'selected' : ''}>${escapeHtml(v)}</option>`).join('')
            : `<option value="${escapeHtml(item.detected_version || '')}">${escapeHtml(item.detected_version || 'Any')}</option>`;

        return `
            <tr data-queue-id="${item.id}">
                <td>
                    <input type="checkbox" class="form-check-input queue-item-checkbox"
                           data-queue-id="${item.id}" onchange="toggleQueueSelect(${item.id}, this)"
                           ${item.status !== 'pending' ? 'disabled' : ''}>
                </td>
                <td>
                    <div class="fw-semibold">${escapeHtml(item.vendor)}</div>
                    <div class="text-muted small">${escapeHtml(item.product_name)}</div>
                </td>
                <td>
                    ${item.status === 'pending' ? `
                        <select class="form-select form-select-sm" style="width: 120px;"
                                onchange="updateQueueItemVersion(${item.id}, this.value)">
                            <option value="">Any version</option>
                            ${versionOptions}
                        </select>
                    ` : `<span class="text-muted">${escapeHtml(item.selected_version || item.detected_version || 'Any')}</span>`}
                </td>
                <td>
                    ${item.status === 'pending' ? `
                        <select class="form-select form-select-sm" style="width: 140px;"
                                onchange="updateQueueItemOrg(${item.id}, this.value)">
                            <option value="">Select org...</option>
                            ${organizations.map(o => `<option value="${o.id}" ${o.id === item.organization_id ? 'selected' : ''}>${escapeHtml(o.display_name || o.name)}</option>`).join('')}
                        </select>
                    ` : `<span class="text-muted">${escapeHtml(item.organization_name || '-')}</span>`}
                </td>
                <td>
                    <small class="text-muted">${escapeHtml(item.integration_name || 'Manual')}</small>
                </td>
                <td>
                    ${item.status === 'pending' ? `
                        <button class="btn btn-success btn-sm me-1" onclick="approveQueueItem(${item.id})" title="Approve">
                            <i class="bi bi-check"></i>
                        </button>
                        <button class="btn btn-outline-danger btn-sm" onclick="rejectQueueItem(${item.id})" title="Reject">
                            <i class="bi bi-x"></i>
                        </button>
                    ` : `
                        <span class="badge bg-${item.status === 'approved' ? 'success' : 'secondary'}">${item.status}</span>
                    `}
                </td>
            </tr>
        `;
    }).join('');

    // Render pagination
    if (paginationContainer && totalPages > 1) {
        paginationContainer.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-muted">Showing ${startIdx + 1}-${Math.min(startIdx + importQueuePageSize, sortedData.length)} of ${sortedData.length}</small>
                <nav>
                    <ul class="pagination pagination-sm mb-0">
                        <li class="page-item ${importQueuePage === 1 ? 'disabled' : ''}">
                            <a class="page-link" href="#" onclick="changeImportQueuePage(${importQueuePage - 1}); return false;">&laquo;</a>
                        </li>
                        ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
                            let pageNum;
                            if (totalPages <= 5) pageNum = i + 1;
                            else if (importQueuePage <= 3) pageNum = i + 1;
                            else if (importQueuePage >= totalPages - 2) pageNum = totalPages - 4 + i;
                            else pageNum = importQueuePage - 2 + i;
                            return `<li class="page-item ${pageNum === importQueuePage ? 'active' : ''}">
                                <a class="page-link" href="#" onclick="changeImportQueuePage(${pageNum}); return false;">${pageNum}</a>
                            </li>`;
                        }).join('')}
                        <li class="page-item ${importQueuePage === totalPages ? 'disabled' : ''}">
                            <a class="page-link" href="#" onclick="changeImportQueuePage(${importQueuePage + 1}); return false;">&raquo;</a>
                        </li>
                    </ul>
                </nav>
            </div>
        `;
    } else if (paginationContainer) {
        paginationContainer.innerHTML = sortedData.length > 0 ? `<small class="text-muted">${sortedData.length} items</small>` : '';
    }
}

// Load import queue
async function loadImportQueue() {
    const status = SK.DOM.get('queueFilterStatus')?.value || 'pending';
    const perPage = parseInt(SK.DOM.get('queuePerPage')?.value) || 25;
    const tbody = SK.DOM.get('importQueueTable');

    if (!tbody) return;

    importQueuePage = 1;  // Reset to first page on filter change
    importQueuePageSize = perPage;  // Update page size from dropdown

    // Reset select-all checkbox and clear selection
    const selectAllCheckbox = SK.DOM.get('selectAllQueue');
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    selectedQueueItems.clear();
    updateQueueBulkButtons();

    tbody.innerHTML = `
        <tr>
            <td colspan="7" class="text-center py-4 text-muted">
                <div class="spinner-border spinner-border-sm me-2"></div>Loading...
            </td>
        </tr>
    `;

    try {
        const response = await fetch(`/api/import/queue?status=${status}`);
        if (!response.ok) throw new Error('Failed to load queue');

        const data = await response.json();
        importQueueData = data.items || [];

        renderImportQueue();
        loadImportQueueCount();

    } catch (error) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-danger">
                    <i class="bi bi-exclamation-triangle text-danger" style="font-size: 2rem;"></i>
                    <p class="mb-0 mt-2">Error loading queue: ${escapeHtml(error.message)}</p>
                </td>
            </tr>
        `;
    }
}

function toggleQueueSelect(itemId, checkbox) {
    if (checkbox.checked) {
        selectedQueueItems.add(itemId);
    } else {
        selectedQueueItems.delete(itemId);
    }
    updateQueueBulkButtons();
}

function toggleSelectAllQueue() {
    const selectAll = SK.DOM.get('selectAllQueue');
    const checkboxes = document.querySelectorAll('.queue-item-checkbox:not(:disabled)');

    checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
        const itemId = parseInt(cb.dataset.queueId);
        if (selectAll.checked) {
            selectedQueueItems.add(itemId);
        } else {
            selectedQueueItems.delete(itemId);
        }
    });
    updateQueueBulkButtons();
}

function updateQueueBulkButtons() {
    const count = selectedQueueItems.size;
    const approveBtn = SK.DOM.get('bulkApproveBtn');
    const rejectBtn = SK.DOM.get('bulkRejectBtn');
    if (approveBtn) approveBtn.disabled = count === 0;
    if (rejectBtn) rejectBtn.disabled = count === 0;
}

async function updateQueueItemVersion(itemId, version) {
    try {
        await fetch(`/api/import/queue/${itemId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ selected_version: version || null })
        });
    } catch (error) {
        showToast('Error updating version: ' + error.message, 'danger');
    }
}

async function updateQueueItemOrg(itemId, orgId) {
    try {
        await fetch(`/api/import/queue/${itemId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ organization_id: orgId ? parseInt(orgId) : null })
        });
    } catch (error) {
        showToast('Error updating organization: ' + error.message, 'danger');
    }
}

async function approveQueueItem(itemId) {
    try {
        const response = await fetch(`/api/import/queue/${itemId}/approve`, { method: 'POST' });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to approve');
        }
        showToast('Product added successfully', 'success');
        loadImportQueue();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function rejectQueueItem(itemId) {
    try {
        const response = await fetch(`/api/import/queue/${itemId}/reject`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to reject');
        showToast('Item rejected', 'success');
        loadImportQueue();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function bulkApproveQueue() {
    if (selectedQueueItems.size === 0) return;

    const confirmed = await showConfirm(
        `Approve ${selectedQueueItems.size} item(s) and add to product inventory?`,
        'Bulk Approve',
        'Approve All',
        'btn-success'
    );

    if (!confirmed) return;

    try {
        const response = await fetch('/api/import/queue/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'approve',
                item_ids: Array.from(selectedQueueItems)
            })
        });

        const result = await response.json();
        showToast(`Approved ${result.processed} items`, 'success');
        selectedQueueItems.clear();
        loadImportQueue();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function bulkRejectQueue() {
    if (selectedQueueItems.size === 0) return;

    const confirmed = await showConfirm(
        `Reject ${selectedQueueItems.size} item(s)?`,
        'Bulk Reject',
        'Reject All',
        'btn-danger'
    );

    if (!confirmed) return;

    try {
        const response = await fetch('/api/import/queue/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'reject',
                item_ids: Array.from(selectedQueueItems)
            })
        });

        const result = await response.json();
        showToast(`Rejected ${result.processed} items`, 'success');
        selectedQueueItems.clear();
        loadImportQueue();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

// ============================================================================
// INTEGRATIONS - Overview Summary
// ============================================================================

async function loadIntegrationsSummary() {
    try {
        const response = await fetch('/api/integrations/summary');
        if (!response.ok) {
            console.warn('Could not load integrations summary');
            return;
        }

        const data = await response.json();

        // Update stats cards
        const pullSources = SK.DOM.get('statPullSources');
        if (pullSources) pullSources.textContent = data.pull_sources?.total || 0;

        const endpointsOnline = SK.DOM.get('statEndpointsOnline');
        if (endpointsOnline) endpointsOnline.textContent = data.push_agents?.online || 0;

        const endpointsTotal = SK.DOM.get('statEndpointsTotal');
        if (endpointsTotal) endpointsTotal.textContent = data.push_agents?.endpoints || 0;

        const pendingImports = SK.DOM.get('statPendingImports');
        if (pendingImports) pendingImports.textContent = data.import_queue?.pending || 0;

        const recentCheckins = SK.DOM.get('statRecentCheckins');
        if (recentCheckins) recentCheckins.textContent = data.activity?.recent_checkins || 0;

    } catch (error) {
        console.error('Error loading integrations summary:', error);
    }
}

// ============================================================================
// INTEGRATIONS - Pull Sources (formerly Connectors)
// ============================================================================

const pullSourcesTypeLabels = {
    'generic_rest': 'REST API',
    'agent': 'Discovery Agent'
};

function sortPullSources(field) {
    if (pullSourcesSortField === field) {
        pullSourcesSortDir = pullSourcesSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        pullSourcesSortField = field;
        pullSourcesSortDir = 'asc';
    }
    pullSourcesPage = 1;
    renderPullSources();
}

function changePullSourcesPage(newPage) {
    pullSourcesPage = newPage;
    renderPullSources();
}

function getPullSourcesSortIcon(field) {
    if (pullSourcesSortField !== field) return '<i class="bi bi-chevron-expand text-muted"></i>';
    return pullSourcesSortDir === 'asc' ? '<i class="bi bi-sort-up"></i>' : '<i class="bi bi-sort-down"></i>';
}

function renderPullSources() {
    const tbody = SK.DOM.get('integrationsTable');
    const paginationContainer = SK.DOM.get('pullSourcesPagination');
    if (!tbody) return;

    // Update sort icons
    ['name', 'type', 'organization', 'last_sync', 'status'].forEach(field => {
        const iconEl = SK.DOM.get(`pullSourcesSort${field.charAt(0).toUpperCase() + field.slice(1).replace('_', '')}`);
        if (iconEl) iconEl.innerHTML = getPullSourcesSortIcon(field);
    });

    if (integrationsList.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4 text-muted">
                    <i class="bi bi-plug text-primary" style="font-size: 2rem;"></i>
                    <p class="mb-0 mt-2">No integrations configured</p>
                    <button class="btn btn-primary btn-sm mt-2" onclick="showCreateIntegrationModal()">
                        <i class="bi bi-plus-circle me-1"></i>Add First Integration
                    </button>
                </td>
            </tr>
        `;
        if (paginationContainer) paginationContainer.innerHTML = '';
        return;
    }

    // Sort data
    const sortedData = [...integrationsList].sort((a, b) => {
        let aVal, bVal;
        switch (pullSourcesSortField) {
            case 'name':
                aVal = (a.name || '').toLowerCase();
                bVal = (b.name || '').toLowerCase();
                break;
            case 'type':
                aVal = (pullSourcesTypeLabels[a.integration_type] || a.integration_type || '').toLowerCase();
                bVal = (pullSourcesTypeLabels[b.integration_type] || b.integration_type || '').toLowerCase();
                break;
            case 'organization':
                aVal = (a.organization_name || 'zzz').toLowerCase();
                bVal = (b.organization_name || 'zzz').toLowerCase();
                break;
            case 'last_sync':
                aVal = a.last_sync_at ? new Date(a.last_sync_at).getTime() : 0;
                bVal = b.last_sync_at ? new Date(b.last_sync_at).getTime() : 0;
                break;
            case 'status':
                const statusOrder = { success: 0, error: 1, failed: 1 };
                aVal = a.last_sync_status ? (statusOrder[a.last_sync_status] ?? 2) : 3;
                bVal = b.last_sync_status ? (statusOrder[b.last_sync_status] ?? 2) : 3;
                break;
            default:
                aVal = '';
                bVal = '';
        }
        if (aVal < bVal) return pullSourcesSortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return pullSourcesSortDir === 'asc' ? 1 : -1;
        return 0;
    });

    // Paginate
    const totalPages = Math.ceil(sortedData.length / pullSourcesPageSize);
    const startIdx = (pullSourcesPage - 1) * pullSourcesPageSize;
    const pageData = sortedData.slice(startIdx, startIdx + pullSourcesPageSize);

    tbody.innerHTML = pageData.map(int => {
        const statusBadge = int.last_sync_status
            ? `<span class="badge bg-${int.last_sync_status === 'success' ? 'success' : 'danger'}">${int.last_sync_status}</span>`
            : '<span class="badge bg-secondary">Never synced</span>';

        return `
            <tr>
                <td class="fw-semibold">${escapeHtml(int.name)}</td>
                <td><span class="badge bg-info">${pullSourcesTypeLabels[int.integration_type] || int.integration_type}</span></td>
                <td>${escapeHtml(int.organization_name || 'All')}</td>
                <td>
                    ${int.last_sync_at ? `<small>${new Date(int.last_sync_at).toLocaleString()}</small>` : '-'}
                    <br><small class="text-muted">${int.last_sync_count || 0} items</small>
                </td>
                <td>${statusBadge}</td>
                <td>
                    ${int.integration_type !== 'agent' ? `
                        <button class="btn btn-outline-primary btn-sm me-1" onclick="syncIntegration(${int.id})" title="Sync Now">
                            <i class="bi bi-arrow-repeat"></i>
                        </button>
                    ` : ''}
                    <button class="btn btn-outline-secondary btn-sm me-1" onclick="showEditIntegrationModal(${int.id})" title="Edit">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-outline-secondary btn-sm me-1" onclick="showIntegrationApiKey(${int.id})" title="View API Key">
                        <i class="bi bi-key"></i>
                    </button>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteIntegration(${int.id})" title="Delete">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    // Render pagination
    if (paginationContainer && totalPages > 1) {
        paginationContainer.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-muted">Showing ${startIdx + 1}-${Math.min(startIdx + pullSourcesPageSize, sortedData.length)} of ${sortedData.length}</small>
                <nav>
                    <ul class="pagination pagination-sm mb-0">
                        <li class="page-item ${pullSourcesPage === 1 ? 'disabled' : ''}">
                            <a class="page-link" href="#" onclick="changePullSourcesPage(${pullSourcesPage - 1}); return false;">&laquo;</a>
                        </li>
                        ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
                            let pageNum;
                            if (totalPages <= 5) pageNum = i + 1;
                            else if (pullSourcesPage <= 3) pageNum = i + 1;
                            else if (pullSourcesPage >= totalPages - 2) pageNum = totalPages - 4 + i;
                            else pageNum = pullSourcesPage - 2 + i;
                            return `<li class="page-item ${pageNum === pullSourcesPage ? 'active' : ''}">
                                <a class="page-link" href="#" onclick="changePullSourcesPage(${pageNum}); return false;">${pageNum}</a>
                            </li>`;
                        }).join('')}
                        <li class="page-item ${pullSourcesPage === totalPages ? 'disabled' : ''}">
                            <a class="page-link" href="#" onclick="changePullSourcesPage(${pullSourcesPage + 1}); return false;">&raquo;</a>
                        </li>
                    </ul>
                </nav>
            </div>
        `;
    } else if (paginationContainer) {
        paginationContainer.innerHTML = sortedData.length > 0 ? `<small class="text-muted">${sortedData.length} source(s)</small>` : '';
    }
}

async function loadIntegrations() {
    const tbody = SK.DOM.get('integrationsTable');
    if (!tbody) return;

    pullSourcesPage = 1;  // Reset to first page on reload

    try {
        const response = await fetchWithRetry('/api/integrations' + getOrgIdParam(), {}, 3, 800);
        if (!response.ok) throw new Error('Failed to load integrations');

        integrationsList = await response.json();
        renderPullSources();

    } catch (error) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4 text-danger">
                    Error loading integrations: ${escapeHtml(error.message)}
                </td>
            </tr>
        `;
    }
}

function showCreateIntegrationModal() {
    // Clean up any existing modal first
    safeDisposeModal('createIntegrationModal', true);

    const modalHtml = `
        <div class="modal fade" id="createIntegrationModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-plug me-2"></i>Create Pull Source</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-info mb-3">
                            <i class="bi bi-info-circle me-2"></i>
                            <strong>REST API Connector</strong> - Connect to any external system that provides a JSON REST API.
                            Configure the URL, authentication, and field mappings to match your source system.
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Name <span class="text-danger">*</span></label>
                                    <input type="text" class="form-control" id="integrationName" placeholder="My Inventory System">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Default Organization</label>
                                    <select class="form-select" id="integrationOrg">
                                        <option value="">None (assign per-item)</option>
                                        ${organizations.map(o => `<option value="${o.id}">${escapeHtml(o.display_name || o.name)}</option>`).join('')}
                                    </select>
                                </div>
                            </div>
                        </div>
                        <hr>
                        <h6 class="text-muted mb-3"><i class="bi bi-link-45deg me-2"></i>Connection Settings</h6>
                        <div class="mb-3">
                            <label class="form-label">API URL <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="configApiUrl" placeholder="https://inventory.example.com/api/software">
                            <div class="form-text">
                                <strong>Test locally:</strong> Use <code>/api/test/mock-software</code> to test with sample data
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">Authentication Type</label>
                                    <select class="form-select" id="configAuthType">
                                        <option value="none">None</option>
                                        <option value="header" selected>API Key (Header)</option>
                                        <option value="bearer">Bearer Token</option>
                                        <option value="basic">Basic Auth</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3" id="authHeaderField">
                                    <label class="form-label">Header Name</label>
                                    <input type="text" class="form-control" id="configAuthHeader" value="X-API-Key" placeholder="X-API-Key">
                                </div>
                            </div>
                        </div>
                        <div class="row" id="authCredentialsRow">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label" id="authFieldLabel">API Key</label>
                                    <input type="password" class="form-control" id="configApiKey" placeholder="Your API key">
                                </div>
                            </div>
                            <div class="col-md-6" id="basicAuthPasswordField" style="display: none;">
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" id="configPassword">
                                </div>
                            </div>
                        </div>
                        <hr>
                        <h6 class="text-muted mb-3"><i class="bi bi-braces me-2"></i>Response Mapping</h6>
                        <div class="mb-3">
                            <label class="form-label">Response Path</label>
                            <input type="text" class="form-control" id="configResponsePath" placeholder="software" value="software">
                            <div class="form-text">JSON path to the software array (e.g., <code>data.items</code> or <code>software</code>). Leave empty if root is array.</div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label class="form-label">Vendor Field</label>
                                    <input type="text" class="form-control" id="configVendorField" value="vendor" placeholder="vendor">
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label class="form-label">Product Field</label>
                                    <input type="text" class="form-control" id="configProductField" value="product" placeholder="product">
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label class="form-label">Version Field</label>
                                    <input type="text" class="form-control" id="configVersionField" value="version" placeholder="version">
                                </div>
                            </div>
                        </div>
                        <hr>
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input" id="integrationAutoApprove">
                            <label class="form-check-label">Auto-approve imported items (skip Import Queue)</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="saveIntegration()">
                            <i class="bi bi-plus-circle me-1"></i>Create Pull Source
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // Handle auth type change
    SK.DOM.get('configAuthType').addEventListener('change', function() {
        const authType = this.value;
        const headerField = SK.DOM.get('authHeaderField');
        const credentialsRow = SK.DOM.get('authCredentialsRow');
        const passwordField = SK.DOM.get('basicAuthPasswordField');
        const fieldLabel = SK.DOM.get('authFieldLabel');

        if (authType === 'none') {
            headerField.style.display = 'none';
            credentialsRow.style.display = 'none';
        } else if (authType === 'basic') {
            headerField.style.display = 'none';
            credentialsRow.style.display = 'flex';
            passwordField.style.display = 'block';
            fieldLabel.textContent = 'Username';
        } else {
            headerField.style.display = authType === 'header' ? 'block' : 'none';
            credentialsRow.style.display = 'flex';
            passwordField.style.display = 'none';
            fieldLabel.textContent = authType === 'bearer' ? 'Bearer Token' : 'API Key';
        }
    });

    const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('createIntegrationModal'));
    modal.show();
}

async function saveIntegration() {
    const name = SK.DOM.getValue('integrationName').trim();
    const orgId = SK.DOM.getValue('integrationOrg');
    const autoApprove = SK.DOM.getChecked('integrationAutoApprove');

    if (!name) {
        showToast('Please enter a name', 'warning');
        return;
    }

    const apiUrl = SK.DOM.get('configApiUrl')?.value.trim() || '';
    if (!apiUrl) {
        showToast('Please enter an API URL', 'warning');
        return;
    }

    // Build configuration object
    const config = {
        api_url: apiUrl,
        auth_type: SK.DOM.get('configAuthType')?.value || 'none',
        auth_header: SK.DOM.get('configAuthHeader')?.value || 'X-API-Key',
        api_key: SK.DOM.get('configApiKey')?.value || '',
        username: SK.DOM.get('configApiKey')?.value || '',  // Reuse field for basic auth
        password: SK.DOM.get('configPassword')?.value || '',
        response_path: SK.DOM.get('configResponsePath')?.value || '',
        vendor_field: SK.DOM.get('configVendorField')?.value || 'vendor',
        product_field: SK.DOM.get('configProductField')?.value || 'product',
        version_field: SK.DOM.get('configVersionField')?.value || 'version',
        verify_ssl: true
    };

    try {
        const response = await fetch('/api/integrations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                integration_type: 'generic_rest',
                organization_id: orgId ? parseInt(orgId) : null,
                auto_approve: autoApprove,
                config: config
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create integration');
        }

        const integration = await response.json();

        safeDisposeModal('createIntegrationModal', true);
        showToast('Pull Source created successfully', 'success');
        loadIntegrations();

    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function syncIntegration(integrationId) {
    showToast('Starting sync...', 'info');

    try {
        const response = await fetch(`/api/integrations/${integrationId}/sync`, { method: 'POST' });
        const result = await response.json();

        if (result.success) {
            showToast(`Sync complete: ${result.queued} queued, ${result.auto_approved} auto-approved`, 'success');
            loadIntegrations();
            loadImportQueue();
        } else {
            showToast('Sync failed: ' + (result.error || 'Unknown error'), 'danger');
        }
    } catch (error) {
        showToast('Sync error: ' + error.message, 'danger');
    }
}

async function showIntegrationApiKey(integrationId) {
    try {
        const response = await fetch(`/api/integrations/${integrationId}`);
        const integration = await response.json();

        if (integration.api_key) {
            SK.DOM.get('viewApiKeyTitle').textContent = `API Key - ${integration.name}`;
            SK.DOM.getValue('viewApiKeyValue') = integration.api_key;
            const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('viewApiKeyModal'));
            modal.show();
        } else {
            showToast('No API key available', 'info');
        }
    } catch (error) {
        showToast('Error loading integration', 'danger');
    }
}

function copyViewedApiKey() {
    const keyInput = SK.DOM.get('viewApiKeyValue');
    if (!keyInput || !keyInput.value) {
        showToast('No API key to copy', 'warning');
        return;
    }

    const key = keyInput.value;

    // Try selecting and using execCommand first (most reliable)
    try {
        keyInput.select();
        keyInput.setSelectionRange(0, 99999);
        const success = document.execCommand('copy');
        if (success) {
            showToast('API key copied to clipboard', 'success');
            return;
        }
    } catch (e) {
        console.log('execCommand copy failed, trying clipboard API');
    }

    // Try clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(key).then(() => {
            showToast('API key copied to clipboard', 'success');
        }).catch((err) => {
            console.error('Clipboard API failed:', err);
            showToast('Copy failed. Please select the key and press Ctrl+C', 'warning');
            keyInput.select();
        });
    } else {
        showToast('Copy failed. Please select the key and press Ctrl+C', 'warning');
        keyInput.select();
    }
}

async function deleteIntegration(integrationId) {
    const confirmed = await showConfirm(
        'Are you sure you want to delete this integration?',
        'Delete Integration',
        'Delete',
        'btn-danger'
    );

    if (!confirmed) return;

    try {
        const response = await fetch(`/api/integrations/${integrationId}`, { method: 'DELETE' });
        if (!response.ok) throw new Error('Failed to delete');
        showToast('Integration deleted', 'success');
        loadIntegrations();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

async function showEditIntegrationModal(integrationId) {
    try {
        const response = await fetch(`/api/integrations/${integrationId}`);
        if (!response.ok) throw new Error('Failed to load integration');
        const integration = await response.json();

        const config = integration.config || {};

        const modalHtml = `
            <div class="modal fade" id="editIntegrationModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"><i class="bi bi-pencil me-2"></i>Edit Pull Source</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="editIntegrationId" value="${integration.id}">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">Name <span class="text-danger">*</span></label>
                                        <input type="text" class="form-control" id="editIntegrationName" value="${escapeHtml(integration.name || '')}">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">Default Organization</label>
                                        <select class="form-select" id="editIntegrationOrg">
                                            <option value="">None (assign per-item)</option>
                                            ${organizations.map(o => `<option value="${o.id}" ${o.id == integration.organization_id ? 'selected' : ''}>${escapeHtml(o.display_name || o.name)}</option>`).join('')}
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <hr>
                            <h6 class="text-muted mb-3"><i class="bi bi-link-45deg me-2"></i>Connection Settings</h6>
                            <div class="mb-3">
                                <label class="form-label">API URL <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="editConfigApiUrl" value="${escapeHtml(config.api_url || '')}">
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">Authentication Type</label>
                                        <select class="form-select" id="editConfigAuthType">
                                            <option value="none" ${config.auth_type === 'none' ? 'selected' : ''}>None</option>
                                            <option value="header" ${config.auth_type === 'header' || !config.auth_type ? 'selected' : ''}>API Key (Header)</option>
                                            <option value="bearer" ${config.auth_type === 'bearer' ? 'selected' : ''}>Bearer Token</option>
                                            <option value="basic" ${config.auth_type === 'basic' ? 'selected' : ''}>Basic Auth</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">Header Name</label>
                                        <input type="text" class="form-control" id="editConfigAuthHeader" value="${escapeHtml(config.auth_header || 'X-API-Key')}">
                                    </div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">API Key / Username</label>
                                        <input type="password" class="form-control" id="editConfigApiKey" value="${escapeHtml(config.api_key || config.username || '')}" placeholder="Leave empty to keep current">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label">Password (Basic Auth)</label>
                                        <input type="password" class="form-control" id="editConfigPassword" value="${escapeHtml(config.password || '')}" placeholder="Leave empty to keep current">
                                    </div>
                                </div>
                            </div>
                            <hr>
                            <h6 class="text-muted mb-3"><i class="bi bi-braces me-2"></i>Response Mapping</h6>
                            <div class="mb-3">
                                <label class="form-label">Response Path</label>
                                <input type="text" class="form-control" id="editConfigResponsePath" value="${escapeHtml(config.response_path || '')}" placeholder="e.g., software or data.items">
                            </div>
                            <div class="row">
                                <div class="col-md-4">
                                    <div class="mb-3">
                                        <label class="form-label">Vendor Field</label>
                                        <input type="text" class="form-control" id="editConfigVendorField" value="${escapeHtml(config.vendor_field || 'vendor')}">
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="mb-3">
                                        <label class="form-label">Product Field</label>
                                        <input type="text" class="form-control" id="editConfigProductField" value="${escapeHtml(config.product_field || 'product')}">
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="mb-3">
                                        <label class="form-label">Version Field</label>
                                        <input type="text" class="form-control" id="editConfigVersionField" value="${escapeHtml(config.version_field || 'version')}">
                                    </div>
                                </div>
                            </div>
                            <hr>
                            <div class="form-check">
                                <input type="checkbox" class="form-check-input" id="editIntegrationAutoApprove" ${integration.auto_approve ? 'checked' : ''}>
                                <label class="form-check-label">Auto-approve imported items (skip Import Queue)</label>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" onclick="saveEditIntegration()">
                                <i class="bi bi-check-circle me-1"></i>Save Changes
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Clean up any existing modal first
        safeDisposeModal('editIntegrationModal', true);

        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = bootstrap.Modal.getOrCreateInstance(SK.DOM.get('editIntegrationModal'));
        modal.show();

    } catch (error) {
        showToast('Error loading integration: ' + error.message, 'danger');
    }
}

async function saveEditIntegration() {
    const integrationId = SK.DOM.getValue('editIntegrationId');
    const name = SK.DOM.getValue('editIntegrationName').trim();
    const orgId = SK.DOM.getValue('editIntegrationOrg');
    const autoApprove = SK.DOM.getChecked('editIntegrationAutoApprove');

    if (!name) {
        showToast('Please enter a name', 'warning');
        return;
    }

    const apiUrl = SK.DOM.get('editConfigApiUrl')?.value.trim() || '';
    if (!apiUrl) {
        showToast('Please enter an API URL', 'warning');
        return;
    }

    const config = {
        api_url: apiUrl,
        auth_type: SK.DOM.get('editConfigAuthType')?.value || 'none',
        auth_header: SK.DOM.get('editConfigAuthHeader')?.value || 'X-API-Key',
        response_path: SK.DOM.get('editConfigResponsePath')?.value || '',
        vendor_field: SK.DOM.get('editConfigVendorField')?.value || 'vendor',
        product_field: SK.DOM.get('editConfigProductField')?.value || 'product',
        version_field: SK.DOM.get('editConfigVersionField')?.value || 'version',
        verify_ssl: true
    };

    // Only include credentials if provided (to avoid overwriting with empty)
    const apiKey = SK.DOM.get('editConfigApiKey')?.value;
    const password = SK.DOM.get('editConfigPassword')?.value;
    if (apiKey) {
        config.api_key = apiKey;
        config.username = apiKey;  // For basic auth
    }
    if (password) {
        config.password = password;
    }

    try {
        const response = await fetch(`/api/integrations/${integrationId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                organization_id: orgId ? parseInt(orgId) : null,
                auto_approve: autoApprove,
                config: config
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update integration');
        }

        safeDisposeModal('editIntegrationModal', true);
        showToast('Pull Source updated successfully', 'success');
        loadIntegrations();

    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

// ============================================================================
// INTEGRATIONS - Discovery Agents
// ============================================================================

async function loadDiscoveryAgents() {
    const tbody = SK.DOM.get('discoveryAgentsTable');
    if (!tbody) return;

    try {
        const response = await fetch('/api/agents');
        if (!response.ok) throw new Error('Failed to load agents');

        const agents = await response.json();

        if (agents.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-4 text-muted">
                        <i class="bi bi-pc-display text-primary" style="font-size: 2rem;"></i>
                        <p class="mb-0 mt-2">No agents registered yet</p>
                        <small>Create an agent integration and deploy the script to get started</small>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = agents.map(agent => `
            <tr>
                <td class="fw-semibold">${escapeHtml(agent.hostname)}</td>
                <td>
                    <span class="badge bg-${agent.os_type === 'windows' ? 'primary' : 'warning'}">
                        ${agent.os_type}
                    </span>
                    <small class="text-muted ms-1">${escapeHtml(agent.os_version || '')}</small>
                </td>
                <td>${escapeHtml(agent.organization_name || '-')}</td>
                <td>
                    ${agent.last_seen_at ? `<small>${new Date(agent.last_seen_at).toLocaleString()}</small>` : '-'}
                </td>
                <td>${agent.software_count || 0}</td>
                <td>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteDiscoveryAgent(${agent.id})" title="Remove">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4 text-danger">
                    Error loading agents: ${escapeHtml(error.message)}
                </td>
            </tr>
        `;
    }
}

async function deleteDiscoveryAgent(agentId) {
    const confirmed = await showConfirm(
        'Remove this agent from the system?',
        'Remove Agent',
        'Remove',
        'btn-danger'
    );

    if (!confirmed) return;

    try {
        const response = await fetch(`/api/agents/${agentId}`, { method: 'DELETE' });
        if (!response.ok) throw new Error('Failed to delete');
        showToast('Agent removed', 'success');
        loadDiscoveryAgents();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}

// Load organizations for agent script dropdown
async function loadAgentScriptOrganizations() {
    const orgSelect = SK.DOM.get('agentScriptOrg');
    if (!orgSelect) return;

    try {
        const response = await fetch('/api/organizations');
        const orgs = await response.json();
        orgSelect.innerHTML = '<option value="">Select organization...</option>' +
            orgs.map(org => `<option value="${org.id}">${escapeHtml(org.display_name)}</option>`).join('');
    } catch (error) {
        console.error('Error loading organizations:', error);
    }
}

// Generate a new agent API key and set it in the input
async function generateAndSetAgentKey() {
    const orgSelect = SK.DOM.get('agentScriptOrg');
    const keyInput = SK.DOM.get('agentScriptApiKey');

    const orgId = orgSelect?.value;
    if (!orgId) {
        showToast('Please select an organization first', 'warning');
        return;
    }

    const orgName = orgSelect.options[orgSelect.selectedIndex].text;
    const keyName = `Agent Script - ${new Date().toLocaleDateString()}`;

    try {
        const response = await fetch('/api/agent-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                organization_id: parseInt(orgId),
                name: keyName
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create key');
        }

        const data = await response.json();
        keyInput.value = data.api_key;
        showToast(`API Key created for ${orgName}. Now download the script!`, 'success');

        // Also refresh the agent keys list
        loadAgentKeys();

    } catch (error) {
        showToast('Error creating API key: ' + error.message, 'danger');
    }
}

async function downloadWindowsAgent() {
    const apiKey = SK.DOM.get('agentScriptApiKey')?.value?.trim() || '';

    try {
        // Fetch script from server with embedded API key
        const url = `/api/agents/script/windows${apiKey ? `?api_key=${encodeURIComponent(apiKey)}` : ''}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to download script: ${response.status}`);
        }

        const script = await response.text();
        downloadScript('sentrikat-agent.ps1', script);
    } catch (error) {
        console.error('Error downloading Windows agent:', error);
        showToast('Failed to download agent script: ' + error.message, 'danger');
    }
}

async function downloadLinuxAgent() {
    const apiKey = SK.DOM.get('agentScriptApiKey')?.value?.trim() || '';

    try {
        // Fetch script from server with embedded API key
        const url = `/api/agents/script/linux${apiKey ? `?api_key=${encodeURIComponent(apiKey)}` : ''}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to download script: ${response.status}`);
        }

        const script = await response.text();
        downloadScript('sentrikat-agent.sh', script);
    } catch (error) {
        console.error('Error downloading Linux agent:', error);
        showToast('Failed to download agent script: ' + error.message, 'danger');
    }
}

function downloadScript(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ============================================================================
// URL HASH HANDLING & TAB PERSISTENCE
// ============================================================================

/**
 * Map of hash values to tab button IDs
 */
const adminTabMap = {
    'users': 'users-tab',
    'organizations': 'organizations-tab',
    'settings': 'settings-tab',
    'ldapUsers': 'ldapUsers-tab',
    'ldapGroups': 'ldapGroups-tab',
    'license': 'license-tab',
    'integrations': 'integrations-tab'
};

/**
 * Save current admin tab to localStorage for persistence
 */
function saveCurrentAdminTab(tabName) {
    try {
        localStorage.setItem('adminCurrentTab', tabName);
    } catch (e) {
        console.warn('Could not save tab to localStorage:', e);
    }
}

/**
 * Get saved admin tab from localStorage
 */
function getSavedAdminTab() {
    try {
        return localStorage.getItem('adminCurrentTab');
    } catch (e) {
        return null;
    }
}

/**
 * Handle URL hash to switch to the correct tab on page load
 * Falls back to localStorage if no hash is present
 */
function handleUrlHash() {
    const hash = window.location.hash.substring(1); // Remove the '#'

    // Use hash if present, otherwise check localStorage
    const tabName = hash || getSavedAdminTab();
    if (!tabName) return;

    console.log('Switching to tab:', tabName, hash ? '(from URL)' : '(from localStorage)');

    // Use manual tab switching to avoid Bootstrap Tab issues with hidden buttons
    const tabPaneId = tabName; // Tab pane IDs match the tab names
    const tabPane = document.getElementById(tabPaneId);
    const tabContent = document.getElementById('adminTabsContent');

    if (tabPane && tabContent) {
        // Hide all tab panes
        tabContent.querySelectorAll(':scope > .tab-pane').forEach(pane => {
            pane.classList.remove('show', 'active');
        });

        // Show the target tab pane
        tabPane.classList.add('show', 'active');

        // Save to localStorage
        saveCurrentAdminTab(tabName);
    } else {
        console.warn('Tab pane not found:', tabPaneId);
    }
}

// Initialize hash handling and tab persistence when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Handle URL hash on page load (or restore from localStorage)
    handleUrlHash();

    // Also handle hash changes (e.g., if user clicks back button)
    window.addEventListener('hashchange', handleUrlHash);

    // Save tab to localStorage whenever a main tab is clicked
    const adminTabs = SK.DOM.get('adminTabs');
    if (adminTabs) {
        adminTabs.querySelectorAll('button[data-bs-toggle="tab"]').forEach(tabButton => {
            tabButton.addEventListener('shown.bs.tab', function(e) {
                // Extract tab name from button ID (e.g., 'integrations-tab' -> 'integrations')
                const tabName = e.target.id.replace('-tab', '');
                saveCurrentAdminTab(tabName);
            });
        });
    }
});
