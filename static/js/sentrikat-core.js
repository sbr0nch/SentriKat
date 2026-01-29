/**
 * SentriKat Core Module
 *
 * Centralized utilities for DOM manipulation, modal management, form handling,
 * API requests, and UI state management.
 *
 * @version 1.0.0
 * @author SentriKat Team
 */

(function(window) {
    'use strict';

    // ========================================================================
    // SENTRIKAT NAMESPACE
    // ========================================================================

    const SK = {
        version: '1.0.0',
        debug: false,
        initialized: false
    };

    // ========================================================================
    // LOGGING UTILITY
    // ========================================================================

    SK.log = function(...args) {
        if (SK.debug) {
            console.log('[SentriKat]', ...args);
        }
    };

    SK.warn = function(...args) {
        console.warn('[SentriKat]', ...args);
    };

    SK.error = function(...args) {
        console.error('[SentriKat]', ...args);
    };

    // ========================================================================
    // DOM UTILITIES - Safe element access
    // ========================================================================

    SK.DOM = {
        /**
         * Safely get an element by ID
         * @param {string} id - Element ID
         * @returns {HTMLElement|null}
         */
        get: function(id) {
            if (!id) return null;
            return document.getElementById(id);
        },

        /**
         * Safely query a single element
         * @param {string} selector - CSS selector
         * @param {HTMLElement} parent - Parent element (default: document)
         * @returns {HTMLElement|null}
         */
        query: function(selector, parent = document) {
            if (!selector) return null;
            try {
                return parent.querySelector(selector);
            } catch (e) {
                SK.error('Invalid selector:', selector);
                return null;
            }
        },

        /**
         * Safely query multiple elements
         * @param {string} selector - CSS selector
         * @param {HTMLElement} parent - Parent element (default: document)
         * @returns {NodeList}
         */
        queryAll: function(selector, parent = document) {
            if (!selector) return [];
            try {
                return parent.querySelectorAll(selector);
            } catch (e) {
                SK.error('Invalid selector:', selector);
                return [];
            }
        },

        /**
         * Safely set element value
         * @param {string|HTMLElement} el - Element or ID
         * @param {*} value - Value to set
         */
        setValue: function(el, value) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && 'value' in element) {
                element.value = value ?? '';
            }
        },

        /**
         * Safely get element value
         * @param {string|HTMLElement} el - Element or ID
         * @returns {string}
         */
        getValue: function(el) {
            const element = typeof el === 'string' ? this.get(el) : el;
            return element && 'value' in element ? element.value : '';
        },

        /**
         * Safely set element innerHTML
         * @param {string|HTMLElement} el - Element or ID
         * @param {string} html - HTML content
         */
        setHtml: function(el, html) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element) {
                element.innerHTML = html ?? '';
            }
        },

        /**
         * Safely set element textContent
         * @param {string|HTMLElement} el - Element or ID
         * @param {string} text - Text content
         */
        setText: function(el, text) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element) {
                element.textContent = text ?? '';
            }
        },

        /**
         * Safely set element checked state
         * @param {string|HTMLElement} el - Element or ID
         * @param {boolean} checked - Checked state
         */
        setChecked: function(el, checked) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && 'checked' in element) {
                element.checked = !!checked;
            }
        },

        /**
         * Safely get element checked state
         * @param {string|HTMLElement} el - Element or ID
         * @returns {boolean}
         */
        getChecked: function(el) {
            const element = typeof el === 'string' ? this.get(el) : el;
            return element && 'checked' in element ? element.checked : false;
        },

        /**
         * Safely set element display style
         * @param {string|HTMLElement} el - Element or ID
         * @param {string|boolean} display - Display value or boolean (true='block', false='none')
         */
        setDisplay: function(el, display) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element) {
                if (typeof display === 'boolean') {
                    element.style.display = display ? '' : 'none';
                } else {
                    element.style.display = display;
                }
            }
        },

        /**
         * Safely show element
         * @param {string|HTMLElement} el - Element or ID
         */
        show: function(el) {
            this.setDisplay(el, '');
        },

        /**
         * Safely hide element
         * @param {string|HTMLElement} el - Element or ID
         */
        hide: function(el) {
            this.setDisplay(el, 'none');
        },

        /**
         * Safely toggle element visibility
         * @param {string|HTMLElement} el - Element or ID
         * @param {boolean} visible - Optional force state
         */
        toggle: function(el, visible) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element) {
                if (typeof visible === 'boolean') {
                    element.style.display = visible ? '' : 'none';
                } else {
                    element.style.display = element.style.display === 'none' ? '' : 'none';
                }
            }
        },

        /**
         * Safely add class to element
         * @param {string|HTMLElement} el - Element or ID
         * @param {...string} classes - Classes to add
         */
        addClass: function(el, ...classes) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && element.classList) {
                element.classList.add(...classes.filter(c => c));
            }
        },

        /**
         * Safely remove class from element
         * @param {string|HTMLElement} el - Element or ID
         * @param {...string} classes - Classes to remove
         */
        removeClass: function(el, ...classes) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && element.classList) {
                element.classList.remove(...classes.filter(c => c));
            }
        },

        /**
         * Safely toggle class on element
         * @param {string|HTMLElement} el - Element or ID
         * @param {string} className - Class to toggle
         * @param {boolean} force - Optional force state
         */
        toggleClass: function(el, className, force) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && element.classList && className) {
                element.classList.toggle(className, force);
            }
        },

        /**
         * Safely set element attribute
         * @param {string|HTMLElement} el - Element or ID
         * @param {string} attr - Attribute name
         * @param {*} value - Attribute value
         */
        setAttr: function(el, attr, value) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && attr) {
                if (value === null || value === undefined || value === false) {
                    element.removeAttribute(attr);
                } else {
                    element.setAttribute(attr, value);
                }
            }
        },

        /**
         * Safely set element disabled state
         * @param {string|HTMLElement} el - Element or ID
         * @param {boolean} disabled - Disabled state
         */
        setDisabled: function(el, disabled) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && 'disabled' in element) {
                element.disabled = !!disabled;
            }
        },

        /**
         * Safely set element required state
         * @param {string|HTMLElement} el - Element or ID
         * @param {boolean} required - Required state
         */
        setRequired: function(el, required) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && 'required' in element) {
                element.required = !!required;
            }
        },

        /**
         * Safely set element readonly state
         * @param {string|HTMLElement} el - Element or ID
         * @param {boolean} readonly - Readonly state
         */
        setReadonly: function(el, readonly) {
            const element = typeof el === 'string' ? this.get(el) : el;
            if (element && 'readOnly' in element) {
                element.readOnly = !!readonly;
            }
        }
    };

    // ========================================================================
    // LOADING OVERLAY MANAGER
    // ========================================================================

    SK.Loading = {
        count: 0,
        timeout: null,
        TIMEOUT_MS: 30000,

        /**
         * Show loading overlay
         */
        show: function() {
            this.count++;
            SK.log('Loading show, count:', this.count);

            const overlay = SK.DOM.get('loadingOverlay');
            if (overlay) {
                overlay.classList.add('show');
            }

            // Clear existing timeout
            if (this.timeout) {
                clearTimeout(this.timeout);
            }

            // Set safety timeout
            this.timeout = setTimeout(() => {
                SK.warn('Loading timeout - forcing hide');
                this.forceHide();
            }, this.TIMEOUT_MS);
        },

        /**
         * Hide loading overlay
         */
        hide: function() {
            this.count = Math.max(0, this.count - 1);
            SK.log('Loading hide, count:', this.count);

            if (this.count === 0) {
                this.forceHide();
            }
        },

        /**
         * Force hide loading overlay regardless of count
         */
        forceHide: function() {
            this.count = 0;

            if (this.timeout) {
                clearTimeout(this.timeout);
                this.timeout = null;
            }

            const overlay = SK.DOM.get('loadingOverlay');
            if (overlay) {
                overlay.classList.remove('show');
            }

            // Also cleanup any modal backdrops
            SK.Modal.cleanupBackdrops();
        }
    };

    // ========================================================================
    // TOAST NOTIFICATIONS
    // ========================================================================

    SK.Toast = {
        container: null,

        /**
         * Initialize toast container
         */
        init: function() {
            this.container = SK.DOM.get('toastContainer');
            if (!this.container) {
                // Create container if it doesn't exist
                this.container = document.createElement('div');
                this.container.id = 'toastContainer';
                this.container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                this.container.style.zIndex = '9999';
                document.body.appendChild(this.container);
            }
        },

        /**
         * Show a toast notification
         * @param {string} message - Message to display
         * @param {string} type - Type: 'success', 'danger', 'warning', 'info'
         * @param {number} duration - Duration in ms (default: 5000)
         */
        show: function(message, type = 'info', duration = 5000) {
            if (!this.container) this.init();

            const icons = {
                success: 'bi-check-circle-fill',
                danger: 'bi-exclamation-triangle-fill',
                warning: 'bi-exclamation-circle-fill',
                info: 'bi-info-circle-fill'
            };

            const toastId = 'toast-' + Date.now();
            const toastHtml = `
                <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
                    <div class="d-flex">
                        <div class="toast-body">
                            <i class="bi ${icons[type] || icons.info} me-2"></i>
                            ${this.escapeHtml(message)}
                        </div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                    </div>
                </div>
            `;

            this.container.insertAdjacentHTML('beforeend', toastHtml);

            const toastEl = SK.DOM.get(toastId);
            if (toastEl && typeof bootstrap !== 'undefined') {
                const toast = new bootstrap.Toast(toastEl, { delay: duration });
                toast.show();

                // Remove from DOM after hidden
                toastEl.addEventListener('hidden.bs.toast', () => {
                    toastEl.remove();
                });
            }
        },

        /**
         * Escape HTML to prevent XSS
         * @param {string} text - Text to escape
         * @returns {string}
         */
        escapeHtml: function(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        // Convenience methods
        success: function(message, duration) { this.show(message, 'success', duration); },
        error: function(message, duration) { this.show(message, 'danger', duration); },
        warning: function(message, duration) { this.show(message, 'warning', duration); },
        info: function(message, duration) { this.show(message, 'info', duration); }
    };

    // ========================================================================
    // MODAL MANAGER
    // ========================================================================

    SK.Modal = {
        // Modal configurations registry
        registry: {},

        // Currently active modal
        active: null,

        /**
         * Register a modal configuration
         * @param {string} name - Unique modal name
         * @param {Object} config - Modal configuration
         */
        register: function(name, config) {
            this.registry[name] = {
                id: config.id,
                titleId: config.titleId || config.id + 'Title',
                formId: config.formId || config.id.replace('Modal', 'Form'),
                defaults: config.defaults || {},
                fields: config.fields || {},
                onShow: config.onShow || null,
                onHide: config.onHide || null,
                onCreate: config.onCreate || null,
                onEdit: config.onEdit || null,
                icons: config.icons || { create: 'bi-plus-circle', edit: 'bi-pencil' },
                titles: config.titles || { create: 'Create', edit: 'Edit' }
            };
            SK.log('Modal registered:', name);
        },

        /**
         * Show a modal in create mode
         * @param {string} name - Modal name
         * @param {Object} options - Additional options
         */
        showCreate: function(name, options = {}) {
            const config = this.registry[name];
            if (!config) {
                SK.error('Modal not registered:', name);
                return;
            }

            SK.log('Showing modal (create):', name);

            // Get elements
            const modalEl = SK.DOM.get(config.id);
            const titleEl = SK.DOM.get(config.titleId);
            const formEl = SK.DOM.get(config.formId);

            if (!modalEl) {
                SK.error('Modal element not found:', config.id);
                return;
            }

            // Reset form
            if (formEl) {
                formEl.reset();
            }

            // Set title
            if (titleEl) {
                const icon = config.icons.create;
                const title = config.titles.create;
                titleEl.innerHTML = `<i class="bi ${icon} me-2"></i>${title}`;
            }

            // Apply defaults
            this.applyDefaults(config);

            // Call onCreate callback
            if (config.onCreate) {
                config.onCreate(options);
            }

            // Call onShow callback
            if (config.onShow) {
                config.onShow('create', null, options);
            }

            // Show modal
            this.showElement(modalEl);
            this.active = name;
        },

        /**
         * Show a modal in edit mode
         * @param {string} name - Modal name
         * @param {Object} data - Data to populate
         * @param {Object} options - Additional options
         */
        showEdit: function(name, data, options = {}) {
            const config = this.registry[name];
            if (!config) {
                SK.error('Modal not registered:', name);
                return;
            }

            SK.log('Showing modal (edit):', name, data);

            // Get elements
            const modalEl = SK.DOM.get(config.id);
            const titleEl = SK.DOM.get(config.titleId);
            const formEl = SK.DOM.get(config.formId);

            if (!modalEl) {
                SK.error('Modal element not found:', config.id);
                return;
            }

            // Reset form first
            if (formEl) {
                formEl.reset();
            }

            // Set title
            if (titleEl) {
                const icon = config.icons.edit;
                const title = config.titles.edit;
                titleEl.innerHTML = `<i class="bi ${icon} me-2"></i>${title}`;
            }

            // Populate form with data
            if (data) {
                this.populateForm(config, data);
            }

            // Call onEdit callback
            if (config.onEdit) {
                config.onEdit(data, options);
            }

            // Call onShow callback
            if (config.onShow) {
                config.onShow('edit', data, options);
            }

            // Show modal
            this.showElement(modalEl);
            this.active = name;
        },

        /**
         * Hide the current modal
         * @param {string} name - Optional modal name (uses active if not provided)
         */
        hide: function(name) {
            const modalName = name || this.active;
            if (!modalName) return;

            const config = this.registry[modalName];
            if (!config) return;

            const modalEl = SK.DOM.get(config.id);
            if (!modalEl) return;

            const instance = bootstrap.Modal.getInstance(modalEl);
            if (instance) {
                instance.hide();
            }

            // Call onHide callback
            if (config.onHide) {
                config.onHide();
            }

            this.active = null;

            // Cleanup after animation
            setTimeout(() => this.cleanupBackdrops(), 300);
        },

        /**
         * Show a modal element using Bootstrap
         * @param {HTMLElement} modalEl - Modal element
         */
        showElement: function(modalEl) {
            if (!modalEl || typeof bootstrap === 'undefined') return;

            const instance = bootstrap.Modal.getOrCreateInstance(modalEl);
            instance.show();
        },

        /**
         * Apply default values to form fields
         * @param {Object} config - Modal configuration
         */
        applyDefaults: function(config) {
            if (!config.defaults) return;

            for (const [fieldId, value] of Object.entries(config.defaults)) {
                const el = SK.DOM.get(fieldId);
                if (!el) continue;

                if (el.type === 'checkbox' || el.type === 'radio') {
                    el.checked = !!value;
                } else {
                    el.value = value ?? '';
                }
            }
        },

        /**
         * Populate form with data
         * @param {Object} config - Modal configuration
         * @param {Object} data - Data to populate
         */
        populateForm: function(config, data) {
            // Use field mappings if defined
            const mappings = config.fields || {};

            for (const [key, value] of Object.entries(data)) {
                // Get field ID from mapping or use key directly
                const fieldId = mappings[key] || key;
                const el = SK.DOM.get(fieldId);

                if (!el) continue;

                if (el.type === 'checkbox' || el.type === 'radio') {
                    el.checked = !!value;
                } else {
                    el.value = value ?? '';
                }
            }
        },

        /**
         * Get form data as object
         * @param {string} formId - Form element ID
         * @returns {Object}
         */
        getFormData: function(formId) {
            const form = SK.DOM.get(formId);
            if (!form) return {};

            const formData = new FormData(form);
            const data = {};

            for (const [key, value] of formData.entries()) {
                data[key] = value;
            }

            // Handle checkboxes (they don't appear in FormData when unchecked)
            form.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                data[cb.name || cb.id] = cb.checked;
            });

            return data;
        },

        /**
         * Clean up orphaned modal backdrops
         */
        cleanupBackdrops: function() {
            const backdrops = document.querySelectorAll('.modal-backdrop');
            const openModals = document.querySelectorAll('.modal.show');

            if (openModals.length === 0 && backdrops.length > 0) {
                SK.log('Cleaning up orphaned backdrops:', backdrops.length);
                backdrops.forEach(b => b.remove());
            }

            // Reset body state if no modals open
            if (openModals.length === 0) {
                document.body.classList.remove('modal-open');
                document.body.style.removeProperty('padding-right');
                document.body.style.removeProperty('overflow');
            }
        }
    };

    // ========================================================================
    // FORM UTILITIES
    // ========================================================================

    SK.Form = {
        /**
         * Reset a form and clear validation states
         * @param {string|HTMLElement} form - Form element or ID
         */
        reset: function(form) {
            const formEl = typeof form === 'string' ? SK.DOM.get(form) : form;
            if (!formEl) return;

            formEl.reset();
            this.clearValidation(formEl);
        },

        /**
         * Clear validation states from form
         * @param {string|HTMLElement} form - Form element or ID
         */
        clearValidation: function(form) {
            const formEl = typeof form === 'string' ? SK.DOM.get(form) : form;
            if (!formEl) return;

            formEl.querySelectorAll('.is-invalid').forEach(el => {
                el.classList.remove('is-invalid');
            });
            formEl.querySelectorAll('.is-valid').forEach(el => {
                el.classList.remove('is-valid');
            });
            formEl.querySelectorAll('.invalid-feedback').forEach(el => {
                el.textContent = '';
            });
        },

        /**
         * Show validation error on a field
         * @param {string|HTMLElement} field - Field element or ID
         * @param {string} message - Error message
         */
        showError: function(field, message) {
            const fieldEl = typeof field === 'string' ? SK.DOM.get(field) : field;
            if (!fieldEl) return;

            fieldEl.classList.add('is-invalid');
            fieldEl.classList.remove('is-valid');

            // Find or create feedback element
            let feedback = fieldEl.parentElement?.querySelector('.invalid-feedback');
            if (!feedback) {
                feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                fieldEl.parentElement?.appendChild(feedback);
            }
            feedback.textContent = message;
        },

        /**
         * Show validation success on a field
         * @param {string|HTMLElement} field - Field element or ID
         */
        showSuccess: function(field) {
            const fieldEl = typeof field === 'string' ? SK.DOM.get(field) : field;
            if (!fieldEl) return;

            fieldEl.classList.remove('is-invalid');
            fieldEl.classList.add('is-valid');
        },

        /**
         * Validate required fields in a form
         * @param {string|HTMLElement} form - Form element or ID
         * @returns {boolean} - True if valid
         */
        validateRequired: function(form) {
            const formEl = typeof form === 'string' ? SK.DOM.get(form) : form;
            if (!formEl) return false;

            let valid = true;
            formEl.querySelectorAll('[required]').forEach(field => {
                const value = field.value?.trim();
                if (!value) {
                    this.showError(field, 'This field is required');
                    valid = false;
                } else {
                    this.showSuccess(field);
                }
            });

            return valid;
        },

        /**
         * Serialize form to object
         * @param {string|HTMLElement} form - Form element or ID
         * @returns {Object}
         */
        serialize: function(form) {
            return SK.Modal.getFormData(typeof form === 'string' ? form : form.id);
        }
    };

    // ========================================================================
    // API UTILITIES
    // ========================================================================

    SK.API = {
        baseUrl: '',

        /**
         * Make an API request
         * @param {string} endpoint - API endpoint
         * @param {Object} options - Fetch options
         * @returns {Promise<Object>}
         */
        request: async function(endpoint, options = {}) {
            const url = this.baseUrl + endpoint;
            const defaults = {
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            const config = { ...defaults, ...options };
            if (config.body && typeof config.body === 'object') {
                config.body = JSON.stringify(config.body);
            }

            try {
                const response = await fetch(url, config);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || data.message || `HTTP ${response.status}`);
                }

                return data;
            } catch (error) {
                SK.error('API request failed:', endpoint, error);
                throw error;
            }
        },

        /**
         * GET request
         * @param {string} endpoint - API endpoint
         * @returns {Promise<Object>}
         */
        get: function(endpoint) {
            return this.request(endpoint, { method: 'GET' });
        },

        /**
         * POST request
         * @param {string} endpoint - API endpoint
         * @param {Object} data - Request body
         * @returns {Promise<Object>}
         */
        post: function(endpoint, data) {
            return this.request(endpoint, { method: 'POST', body: data });
        },

        /**
         * PUT request
         * @param {string} endpoint - API endpoint
         * @param {Object} data - Request body
         * @returns {Promise<Object>}
         */
        put: function(endpoint, data) {
            return this.request(endpoint, { method: 'PUT', body: data });
        },

        /**
         * DELETE request
         * @param {string} endpoint - API endpoint
         * @returns {Promise<Object>}
         */
        delete: function(endpoint) {
            return this.request(endpoint, { method: 'DELETE' });
        }
    };

    // ========================================================================
    // CONFIRMATION DIALOG
    // ========================================================================

    SK.Confirm = {
        /**
         * Show a confirmation dialog
         * @param {string} message - Confirmation message
         * @param {Object} options - Options (title, confirmText, confirmClass)
         * @returns {Promise<boolean>}
         */
        show: function(message, options = {}) {
            return new Promise((resolve) => {
                const modal = SK.DOM.get('confirmModal');
                const titleEl = SK.DOM.get('confirmModalLabel');
                const bodyEl = SK.DOM.get('confirmModalBody');
                const confirmBtn = SK.DOM.get('confirmModalButton');

                if (!modal || !confirmBtn) {
                    // Fallback to native confirm
                    resolve(window.confirm(message));
                    return;
                }

                // Set content
                const title = options.title || 'Confirm Action';
                const confirmText = options.confirmText || 'Confirm';
                const confirmClass = options.confirmClass || 'btn-primary';

                if (titleEl) {
                    titleEl.innerHTML = `<i class="bi bi-question-circle me-2"></i>${title}`;
                }
                if (bodyEl) {
                    bodyEl.innerHTML = message.replace(/\n/g, '<br>');
                }
                confirmBtn.textContent = confirmText;
                confirmBtn.className = `btn ${confirmClass}`;

                const bsModal = bootstrap.Modal.getOrCreateInstance(modal);

                const handleConfirm = () => {
                    cleanup();
                    resolve(true);
                };

                const handleCancel = () => {
                    cleanup();
                    resolve(false);
                };

                const cleanup = () => {
                    confirmBtn.removeEventListener('click', handleConfirm);
                    modal.removeEventListener('hidden.bs.modal', handleCancel);
                    bsModal.hide();
                    setTimeout(() => SK.Modal.cleanupBackdrops(), 100);
                };

                confirmBtn.addEventListener('click', handleConfirm);
                modal.addEventListener('hidden.bs.modal', handleCancel, { once: true });

                bsModal.show();
            });
        },

        /**
         * Show a danger confirmation (for destructive actions)
         * @param {string} message - Confirmation message
         * @param {string} title - Dialog title
         * @returns {Promise<boolean>}
         */
        danger: function(message, title = 'Confirm Delete') {
            return this.show(message, {
                title: title,
                confirmText: 'Delete',
                confirmClass: 'btn-danger'
            });
        }
    };

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    SK.init = function(options = {}) {
        if (this.initialized) return;

        this.debug = options.debug || false;
        SK.log('Initializing SentriKat Core v' + this.version);

        // Initialize toast container
        SK.Toast.init();

        // Setup global modal cleanup
        document.addEventListener('hidden.bs.modal', () => {
            setTimeout(() => SK.Modal.cleanupBackdrops(), 100);
        });

        // Periodic cleanup
        setInterval(() => SK.Modal.cleanupBackdrops(), 5000);

        this.initialized = true;
        SK.log('SentriKat Core initialized');
    };

    // ========================================================================
    // BACKWARDS COMPATIBILITY - Global functions
    // ========================================================================

    // These maintain compatibility with existing code
    window.showLoading = function() { SK.Loading.show(); };
    window.hideLoading = function() { SK.Loading.hide(); };
    window.showToast = function(message, type) { SK.Toast.show(message, type); };
    window.cleanupModalBackdrops = function() { SK.Modal.cleanupBackdrops(); };
    window.fixGreyScreen = function() {
        SK.Loading.forceHide();
        SK.Modal.cleanupBackdrops();
    };

    // ========================================================================
    // EXPORT
    // ========================================================================

    window.SK = SK;

    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => SK.init());
    } else {
        SK.init();
    }

})(window);
