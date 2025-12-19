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

async function saveOrganization() {
    const orgId = document.getElementById('orgId').value;
    const isEdit = !!orgId;

    const orgData = {
        name: document.getElementById('orgName').value.trim(),
        description: document.getElementById('orgDescription').value.trim(),
        active: document.getElementById('orgActive').checked
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
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Load initial data if on admin panel page
    if (document.getElementById('usersTable')) {
        loadUsers();
    }
    if (document.getElementById('organizationsTable')) {
        loadOrganizations();
    }
});
