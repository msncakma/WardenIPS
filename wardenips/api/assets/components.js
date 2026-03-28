/**
 * WardenIPS Interactive Components
 * =================================
 * 
 * Enhanced UI components with accessibility and keyboard navigation
 * Supports dark/light modes and real-time updates
 */

/**
 * Expandable Card Component
 * Allows collapsing/expanding card content
 */
class ExpandableCard {
  constructor(element) {
    this.element = element;
    this.header = this.element.querySelector('.card-header');
    this.body = this.element.querySelector('.card-body');
    this.isExpanded = true;

    if (this.header) {
      this.header.addEventListener('click', () => this.toggle());
      this.header.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.toggle();
        }
      });
      this.header.setAttribute('role', 'button');
      this.header.setAttribute('tabindex', '0');
    }
  }

  toggle() {
    this.isExpanded = !this.isExpanded;
    this.element.classList.toggle('collapsed', !this.isExpanded);
    this.body?.setAttribute('aria-hidden', !this.isExpanded);
  }

  expand() {
    this.isExpanded = false;
    this.toggle();
  }

  collapse() {
    this.isExpanded = true;
    this.toggle();
  }
}

/**
 * Tabs Component
 * Accessible tab navigation with keyboard support
 */
class TabManager {
  constructor(containerSelector) {
    this.container = document.querySelector(containerSelector);
    if (!this.container) return;

    this.tabs = Array.from(this.container.querySelectorAll('[role="tab"]'));
    this.panels = Array.from(this.container.querySelectorAll('[role="tabpanel"]'));

    this.tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => this.selectTab(index));
      tab.addEventListener('keydown', (e) => this.handleKeyPress(e, index));
      tab.setAttribute('aria-selected', index === 0);
    });

    this.panels.forEach((panel, index) => {
      panel.setAttribute('aria-hidden', index !== 0);
    });
  }

  selectTab(index) {
    // Deselect all tabs
    this.tabs.forEach((tab) => {
      tab.setAttribute('aria-selected', 'false');
      tab.classList.remove('active');
    });
    this.panels.forEach((panel) => {
      panel.setAttribute('aria-hidden', 'true');
    });

    // Select current tab
    if (this.tabs[index]) {
      this.tabs[index].setAttribute('aria-selected', 'true');
      this.tabs[index].classList.add('active');
      this.tabs[index].focus();
    }
    if (this.panels[index]) {
      this.panels[index].setAttribute('aria-hidden', 'false');
    }
  }

  handleKeyPress(event, index) {
    let newIndex = index;

    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      newIndex = index > 0 ? index - 1 : this.tabs.length - 1;
    } else if (event.key === 'ArrowRight') {
      event.preventDefault();
      newIndex = index < this.tabs.length - 1 ? index + 1 : 0;
    } else if (event.key === 'Home') {
      event.preventDefault();
      newIndex = 0;
    } else if (event.key === 'End') {
      event.preventDefault();
      newIndex = this.tabs.length - 1;
    }

    this.selectTab(newIndex);
  }
}

/**
 * Dropdown Menu Component
 * Accessible dropdown with keyboard navigation
 */
class DropdownMenu {
  constructor(triggerSelector, menuSelector) {
    this.trigger = document.querySelector(triggerSelector);
    this.menu = document.querySelector(menuSelector);
    this.isOpen = false;
    this.items = Array.from(this.menu?.querySelectorAll('[role="menuitem"]') || []);

    if (this.trigger && this.menu) {
      this.trigger.addEventListener('click', () => this.toggle());
      this.trigger.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          this.open();
          this.focusItem(0);
        }
      });

      this.items.forEach((item, index) => {
        item.addEventListener('click', () => this.handleItemClick(item));
        item.addEventListener('keydown', (e) => this.handleItemKeyPress(e, index));
      });

      // Close on outside click
      document.addEventListener('click', (e) => {
        if (!this.trigger.contains(e.target) && !this.menu.contains(e.target)) {
          this.close();
        }
      });
    }
  }

  toggle() {
    this.isOpen ? this.close() : this.open();
  }

  open() {
    this.isOpen = true;
    this.menu.classList.add('open');
    this.trigger.setAttribute('aria-expanded', 'true');
  }

  close() {
    this.isOpen = false;
    this.menu.classList.remove('open');
    this.trigger.setAttribute('aria-expanded', 'false');
  }

  focusItem(index) {
    if (this.items[index]) {
      this.items[index].focus();
    }
  }

  handleItemKeyPress(event, index) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      this.focusItem(index + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      this.focusItem(index - 1);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      this.close();
      this.trigger.focus();
    }
  }

  handleItemClick(item) {
    this.close();
    this.trigger.focus();
  }
}

/**
 * Modal Dialog Component
 * Accessible modal with focus trap and keyboard support
 */
class Modal {
  constructor(modalSelector) {
    this.modal = document.querySelector(modalSelector);
    this.closeButton = this.modal?.querySelector('[data-close]');
    this.isOpen = false;
    this.focusTrap = null;

    if (this.modal) {
      if (this.closeButton) {
        this.closeButton.addEventListener('click', () => this.close());
      }

      this.modal.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          this.close();
        }
      });

      // Click outside to close
      this.modal.addEventListener('click', (e) => {
        if (e.target === this.modal) {
          this.close();
        }
      });
    }
  }

  open() {
    if (!this.modal) return;

    this.isOpen = true;
    this.modal.classList.add('open');
    this.modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';

    // Focus first focusable element
    const focusable = this.modal.querySelector(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable) focusable.focus();

    this.setupFocusTrap();
  }

  close() {
    if (!this.modal) return;

    this.isOpen = false;
    this.modal.classList.remove('open');
    this.modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    this.removeFocusTrap();
  }

  setupFocusTrap() {
    const focusableElements = this.modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    const handleTab = (e) => {
      if (e.key !== 'Tab') return;

      if (e.shiftKey) {
        if (document.activeElement === firstElement) {
          e.preventDefault();
          lastElement?.focus();
        }
      } else {
        if (document.activeElement === lastElement) {
          e.preventDefault();
          firstElement?.focus();
        }
      }
    };

    this.modal.addEventListener('keydown', handleTab);
    this.focusTrap = handleTab;
  }

  removeFocusTrap() {
    if (this.focusTrap) {
      this.modal.removeEventListener('keydown', this.focusTrap);
    }
  }
}

/**
 * Data Table Component
 * Sortable, filterable, paginated table with accessibility
 */
class DataTable {
  constructor(tableSelector, options = {}) {
    this.table = document.querySelector(tableSelector);
    this.currentPage = 1;
    this.itemsPerPage = options.itemsPerPage || 10;
    this.sortColumn = null;
    this.sortDirection = 'asc';
    this.filteredData = [];
    this.data = [];

    if (this.table) {
      this.initHeaders();
      this.initPagination();
    }
  }

  initHeaders() {
    const headers = this.table.querySelectorAll('th');
    headers.forEach((header, index) => {
      if (!header.dataset.nosort) {
        header.style.cursor = 'pointer';
        header.setAttribute('role', 'button');
        header.setAttribute('tabindex', '0');
        header.setAttribute('aria-sort', 'none');

        header.addEventListener('click', () => this.sortBy(index, header));
        header.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') this.sortBy(index, header);
        });
      }
    });
  }

  sortBy(columnIndex, headerElement) {
    if (this.sortColumn === columnIndex) {
      this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortColumn = columnIndex;
      this.sortDirection = 'asc';
    }

    // Update aria-sort
    const headers = this.table.querySelectorAll('th');
    headers.forEach((h) => {
      h.setAttribute('aria-sort', 'none');
    });
    headerElement.setAttribute(
      'aria-sort',
      this.sortDirection === 'asc' ? 'ascending' : 'descending'
    );

    this.render();
  }

  filter(searchTerm) {
    this.filteredData = this.data.filter((row) =>
      Object.values(row).some((val) =>
        val?.toString().toLowerCase().includes(searchTerm.toLowerCase())
      )
    );
    this.currentPage = 1;
    this.render();
  }

  render() {
    const tbody = this.table.querySelector('tbody');
    if (!tbody) return;

    const start = (this.currentPage - 1) * this.itemsPerPage;
    const end = start + this.itemsPerPage;
    const pageData = this.filteredData.slice(start, end);

    tbody.innerHTML = '';
    pageData.forEach((row) => {
      const tr = document.createElement('tr');
      Object.values(row).forEach((value) => {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  initPagination() {
    const paginationContainer = this.table.parentElement?.querySelector(
      '.pagination'
    );
    if (!paginationContainer) return;

    const totalPages = Math.ceil(this.filteredData.length / this.itemsPerPage);
    paginationContainer.innerHTML = '';

    for (let i = 1; i <= totalPages; i++) {
      const button = document.createElement('button');
      button.textContent = i;
      button.className = i === this.currentPage ? 'active' : '';
      button.addEventListener('click', () => {
        this.currentPage = i;
        this.render();
      });
      paginationContainer.appendChild(button);
    }
  }
}

/**
 * Toast Notification Component
 * Lightweight alert system with auto-dismiss
 */
class Toast {
  static container = null;

  static init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      this.container.setAttribute('role', 'region');
      this.container.setAttribute('aria-live', 'polite');
      this.container.setAttribute('aria-atomic', 'true');
      document.body.appendChild(this.container);
    }
  }

  static show(message, type = 'info', duration = 3000) {
    this.init();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'status');
    toast.textContent = message;

    this.container.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    if (duration > 0) {
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      }, duration);
    }

    return toast;
  }

  static success(message, duration = 3000) {
    return this.show(message, 'success', duration);
  }

  static error(message, duration = 5000) {
    return this.show(message, 'error', duration);
  }

  static warning(message, duration = 4000) {
    return this.show(message, 'warning', duration);
  }

  static info(message, duration = 3000) {
    return this.show(message, 'info', duration);
  }
}

/**
 * Search Input Component
 * Debounced search with live results
 */
class SearchInput {
  constructor(inputSelector, onSearch, debounceMs = 300) {
    this.input = document.querySelector(inputSelector);
    this.onSearch = onSearch;
    this.debounceMs = debounceMs;
    this.debounceTimer = null;

    if (this.input) {
      this.input.addEventListener('input', (e) => {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
          this.onSearch(e.target.value);
        }, this.debounceMs);
      });

      this.input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          this.clear();
        }
      });
    }
  }

  clear() {
    this.input.value = '';
    this.input.dispatchEvent(new Event('input', { bubbles: true }));
  }

  getValue() {
    return this.input?.value || '';
  }

  setValue(value) {
    if (this.input) {
      this.input.value = value;
      this.input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }
}

/**
 * Form Validation Component
 * Real-time form validation with error messages
 */
class FormValidator {
  constructor(formSelector) {
    this.form = document.querySelector(formSelector);
    this.fields = new Map();

    if (this.form) {
      this.form.querySelectorAll('[data-validate]').forEach((field) => {
        const rules = field.dataset.validate.split('|');
        this.fields.set(field.name, { element: field, rules });

        field.addEventListener('blur', () => this.validateField(field.name));
        field.addEventListener('change', () => this.validateField(field.name));
      });

      this.form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (this.validateForm()) {
          // Form is valid
          console.log('Form is valid');
        }
      });
    }
  }

  validateField(fieldName) {
    const fieldData = this.fields.get(fieldName);
    if (!fieldData) return true;

    const { element, rules } = fieldData;
    let isValid = true;

    rules.forEach((rule) => {
      switch (rule) {
        case 'required':
          isValid = element.value.trim() !== '';
          break;
        case 'email':
          isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(element.value);
          break;
        case 'number':
          isValid = !isNaN(element.value) && element.value !== '';
          break;
        case 'url':
          try {
            new URL(element.value);
            isValid = true;
          } catch {
            isValid = false;
          }
          break;
        case 'ip':
          isValid = /^(\d{1,3}\.){3}\d{1,3}$/.test(element.value);
          break;
      }
    });

    this.setFieldState(element, isValid);
    return isValid;
  }

  validateForm() {
    let formIsValid = true;
    this.fields.forEach((_, fieldName) => {
      if (!this.validateField(fieldName)) {
        formIsValid = false;
      }
    });
    return formIsValid;
  }

  setFieldState(element, isValid) {
    const wrapper = element.closest('.form-group');
    if (!wrapper) return;

    wrapper.classList.toggle('has-error', !isValid);
    wrapper.classList.toggle('has-success', isValid && element.value);

    let errorElement = wrapper.querySelector('.error-message');
    if (!isValid && !errorElement) {
      errorElement = document.createElement('span');
      errorElement.className = 'error-message';
      errorElement.setAttribute('role', 'alert');
      wrapper.appendChild(errorElement);
    }

    if (errorElement) {
      errorElement.textContent = isValid ? '' : `Invalid ${element.name}`;
    }
  }
}

/**
 * Progress Bar Component
 * Animated progress indicator
 */
class ProgressBar {
  constructor(containerSelector) {
    this.container = document.querySelector(containerSelector);
    this.bar = this.container?.querySelector('.progress-fill');
    this.label = this.container?.querySelector('.progress-label');
  }

  setProgress(percentage) {
    if (this.bar) {
      this.bar.style.width = `${Math.min(100, Math.max(0, percentage))}%`;
      this.bar.setAttribute('aria-valuenow', percentage);
    }
    if (this.label) {
      this.label.textContent = `${Math.round(percentage)}%`;
    }
  }

  increment(amount = 10) {
    const current = parseFloat(this.bar?.style.width || 0);
    this.setProgress(current + amount);
  }

  complete() {
    this.setProgress(100);
  }

  reset() {
    this.setProgress(0);
  }
}

/**
 * Copy to Clipboard Utility
 * Easy copy button functionality
 */
class CopyButton {
  constructor(buttonSelector, targetSelector, successMessage = 'Copied!') {
    this.button = document.querySelector(buttonSelector);
    this.target = document.querySelector(targetSelector);
    this.successMessage = successMessage;

    if (this.button && this.target) {
      this.button.addEventListener('click', () => this.copy());
    }
  }

  async copy() {
    try {
      const text = this.target.textContent || this.target.value;
      await navigator.clipboard.writeText(text);
      Toast.success(this.successMessage, 2000);
    } catch (err) {
      Toast.error('Failed to copy');
    }
  }
}

/**
 * Lazy Load Images
 * Progressive image loading with IntersectionObserver
 */
class LazyLoadImages {
  static init() {
    const images = document.querySelectorAll('img[data-src]');
    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.removeAttribute('data-src');
          obs.unobserve(img);
        }
      });
    });

    images.forEach((img) => observer.observe(img));
  }
}

/**
 * Export utility
 */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ExpandableCard,
    TabManager,
    DropdownMenu,
    Modal,
    DataTable,
    Toast,
    SearchInput,
    FormValidator,
    ProgressBar,
    CopyButton,
    LazyLoadImages,
  };
}
