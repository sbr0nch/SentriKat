/**
 * SentriKat Modal Configurations
 *
 * Registers all modals with the SK.Modal manager for centralized handling.
 * Import this after sentrikat-core.js
 *
 * @version 1.0.0
 * @author SentriKat Team
 */

(function(window) {
    'use strict';

    // Wait for SK to be available
    if (typeof window.SK === 'undefined') {
        console.error('[SentriKat Modals] SK namespace not found. Load sentrikat-core.js first.');
        return;
    }

    const SK = window.SK;

    // ========================================================================
    // USER MANAGEMENT MODAL
    // ========================================================================
    SK.Modal.register('user', {
        id: 'userModal',
        titleId: 'userModalTitle',
        formId: 'userForm',
        defaults: {
            userId: '',
            userAuthType: 'local',
            userIsActive: true,
            userRole: 'user'
        },
        fields: {
            id: 'userId',
            username: 'userUsername',
            email: 'userEmail',
            auth_type: 'userAuthType',
            is_active: 'userIsActive',
            role: 'userRole',
            ldap_dn: 'userLdapDn'
        },
        icons: {
            create: 'bi-person-plus',
            edit: 'bi-person-gear'
        },
        titles: {
            create: 'Create User',
            edit: 'Edit User'
        },
        onShow: function(mode, data, options) {
            // Handle auth type UI
            const authType = data?.auth_type || 'local';
            const passwordFields = SK.DOM.get('localPasswordFields');
            const ldapFields = SK.DOM.get('ldapUserFields');

            if (passwordFields) {
                passwordFields.style.display = authType === 'local' ? 'block' : 'none';
            }
            if (ldapFields) {
                ldapFields.style.display = authType === 'ldap' ? 'block' : 'none';
            }

            // Password required only for new local users
            const passwordField = SK.DOM.get('userPassword');
            if (passwordField) {
                passwordField.required = mode === 'create' && authType === 'local';
            }
        }
    });

    // ========================================================================
    // ORGANIZATION MANAGEMENT MODAL
    // ========================================================================
    SK.Modal.register('organization', {
        id: 'orgModal',
        titleId: 'orgModalTitle',
        formId: 'orgForm',
        defaults: {
            orgId: '',
            orgIsActive: true
        },
        fields: {
            id: 'orgId',
            name: 'orgName',
            display_name: 'orgDisplayName',
            description: 'orgDescription',
            is_active: 'orgIsActive',
            contact_email: 'orgContactEmail',
            contact_name: 'orgContactName'
        },
        icons: {
            create: 'bi-building-add',
            edit: 'bi-building-gear'
        },
        titles: {
            create: 'Create Organization',
            edit: 'Edit Organization'
        }
    });

    // ========================================================================
    // PRODUCT MANAGEMENT MODAL
    // ========================================================================
    SK.Modal.register('product', {
        id: 'productModal',
        titleId: 'productModalTitle',
        formId: 'productForm',
        defaults: {
            productId: '',
            productVendor: '',
            productName: '',
            productVersion: '',
            productCPE: ''
        },
        fields: {
            id: 'productId',
            vendor: 'productVendor',
            name: 'productName',
            version: 'productVersion',
            cpe_string: 'productCPE'
        },
        icons: {
            create: 'bi-box-seam',
            edit: 'bi-pencil-square'
        },
        titles: {
            create: 'Add Product',
            edit: 'Edit Product'
        },
        onShow: function(mode, data, options) {
            // Reset to first step for new products
            if (mode === 'create') {
                const step1 = SK.DOM.get('step1');
                const step2 = SK.DOM.get('step2');
                const step3 = SK.DOM.get('step3');
                if (step1) step1.style.display = 'block';
                if (step2) step2.style.display = 'none';
                if (step3) step3.style.display = 'none';
            }
        }
    });

    // ========================================================================
    // AGENT KEY MODAL
    // ========================================================================
    SK.Modal.register('agentKey', {
        id: 'agentKeyModal',
        titleId: null,
        formId: 'agentKeyForm',
        defaults: {
            agentKeyName: '',
            agentKeyOrg: ''
        },
        fields: {
            name: 'agentKeyName',
            organization_id: 'agentKeyOrg'
        },
        icons: {
            create: 'bi-key'
        },
        titles: {
            create: 'Create Agent Key'
        }
    });

    // ========================================================================
    // GROUP MAPPING MODAL
    // ========================================================================
    SK.Modal.register('groupMapping', {
        id: 'groupMappingModal',
        titleId: 'groupMappingModalTitle',
        formId: 'groupMappingForm',
        defaults: {
            mappingId: '',
            ldapGroupDn: '',
            localGroup: 'user',
            autoSync: true
        },
        fields: {
            id: 'mappingId',
            ldap_group_dn: 'ldapGroupDn',
            local_group: 'localGroup',
            auto_sync: 'autoSync'
        },
        icons: {
            create: 'bi-diagram-3',
            edit: 'bi-pencil'
        },
        titles: {
            create: 'Create Group Mapping',
            edit: 'Edit Group Mapping'
        }
    });

    // ========================================================================
    // LDAP INVITE MODAL
    // ========================================================================
    SK.Modal.register('ldapInvite', {
        id: 'ldapInviteModal',
        formId: 'ldapInviteForm',
        defaults: {
            ldapInviteRole: 'user'
        },
        icons: {
            create: 'bi-person-plus'
        },
        titles: {
            create: 'Invite LDAP Users'
        }
    });

    // ========================================================================
    // ASSET DETAILS MODAL
    // ========================================================================
    SK.Modal.register('assetDetails', {
        id: 'assetDetailsModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-pc-display'
        },
        titles: {
            view: 'Asset Details'
        }
    });

    // ========================================================================
    // SYNC HISTORY MODAL
    // ========================================================================
    SK.Modal.register('syncHistory', {
        id: 'syncHistoryModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-clock-history'
        },
        titles: {
            view: 'Sync History'
        }
    });

    // ========================================================================
    // SHARE MODAL
    // ========================================================================
    SK.Modal.register('share', {
        id: 'shareModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-share'
        },
        titles: {
            view: 'Share View'
        }
    });

    // ========================================================================
    // VIEW API KEY MODAL
    // ========================================================================
    SK.Modal.register('viewApiKey', {
        id: 'viewApiKeyModal',
        titleId: 'viewApiKeyTitle',
        formId: null,
        icons: {
            view: 'bi-key'
        },
        titles: {
            view: 'API Key'
        }
    });

    // ========================================================================
    // SERVICE CATALOG MODAL
    // ========================================================================
    SK.Modal.register('serviceCatalog', {
        id: 'serviceCatalogModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-collection'
        },
        titles: {
            view: 'Service Catalog'
        }
    });

    // ========================================================================
    // LDAP SEARCH MODAL
    // ========================================================================
    SK.Modal.register('ldapSearch', {
        id: 'ldapSearchModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-search'
        },
        titles: {
            view: 'LDAP Search'
        }
    });

    // ========================================================================
    // LDAP DISCOVERY MODAL
    // ========================================================================
    SK.Modal.register('ldapDiscovery', {
        id: 'ldapDiscoveryModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-diagram-3'
        },
        titles: {
            view: 'LDAP Group Discovery'
        }
    });

    // ========================================================================
    // ADMIN RESULT MODAL
    // ========================================================================
    SK.Modal.register('adminResult', {
        id: 'adminResultModal',
        titleId: 'adminResultModalLabel',
        formId: null,
        icons: {
            view: 'bi-info-circle'
        },
        titles: {
            view: 'Result'
        }
    });

    // ========================================================================
    // ADMIN CONFIRM MODAL
    // ========================================================================
    SK.Modal.register('adminConfirm', {
        id: 'adminConfirmModal',
        titleId: 'adminConfirmModalLabel',
        formId: null,
        icons: {
            view: 'bi-question-circle'
        },
        titles: {
            view: 'Confirm Action'
        }
    });

    // ========================================================================
    // CONFIRMATION MODAL (admin.html)
    // ========================================================================
    SK.Modal.register('confirmation', {
        id: 'confirmationModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-exclamation-triangle'
        },
        titles: {
            view: 'Confirm'
        }
    });

    // ========================================================================
    // ORG MANAGEMENT MODAL (admin.html)
    // ========================================================================
    SK.Modal.register('orgManagement', {
        id: 'orgManagementModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-building'
        },
        titles: {
            view: 'Manage Organizations'
        }
    });

    // ========================================================================
    // ADD ORG MEMBERSHIP MODAL
    // ========================================================================
    SK.Modal.register('addOrgMembership', {
        id: 'addOrgMembershipModal',
        titleId: null,
        formId: null,
        icons: {
            view: 'bi-person-plus'
        },
        titles: {
            view: 'Add Organization Membership'
        }
    });

    // ========================================================================
    // SECURITY SETTINGS MODAL
    // ========================================================================
    SK.Modal.register('securitySettings', {
        id: 'securitySettingsModal',
        titleId: null,
        formId: 'changePasswordForm',
        icons: {
            view: 'bi-shield-lock'
        },
        titles: {
            view: 'Security Settings'
        }
    });

    // ========================================================================
    // HELPER FUNCTIONS FOR COMMON MODAL OPERATIONS
    // ========================================================================

    /**
     * Show a generic view modal (no form)
     * @param {string} name - Modal name
     */
    SK.Modal.showView = function(name) {
        const config = this.registry[name];
        if (!config) {
            SK.error('Modal not registered:', name);
            return;
        }

        const modalEl = SK.DOM.get(config.id);
        if (!modalEl) {
            SK.error('Modal element not found:', config.id);
            return;
        }

        this.showElement(modalEl);
        this.active = name;
    };

    /**
     * Quick show modal by ID (for modals that don't need setup)
     * @param {string} modalId - Modal element ID
     */
    SK.Modal.showById = function(modalId) {
        const modalEl = SK.DOM.get(modalId);
        if (modalEl) {
            this.showElement(modalEl);
        }
    };

    /**
     * Quick hide modal by ID
     * @param {string} modalId - Modal element ID
     */
    SK.Modal.hideById = function(modalId) {
        const modalEl = SK.DOM.get(modalId);
        if (!modalEl) return;

        const instance = bootstrap.Modal.getInstance(modalEl);
        if (instance) {
            instance.hide();
        }
        // Let Bootstrap handle backdrop cleanup - no manual intervention needed
    };

    SK.log('Modal configurations loaded:', Object.keys(SK.Modal.registry).length, 'modals registered');

})(window);
