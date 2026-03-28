/**
 * WardenIPS WebSocket Real-Time Updates
 * ======================================
 * 
 * Phase 7 - Real-time monitoring with WebSocket support
 * Enables live updates for bans, firewall status, and system metrics
 */

class WardenIPSWebSocket {
  constructor(url = null, retryInterval = 3000, maxRetries = 5) {
    this.url = url || this._buildUrl();
    this.retryInterval = retryInterval;
    this.maxRetries = maxRetries;
    this.retryCount = 0;
    this.ws = null;
    this.isConnected = false;
    this.messageQueue = [];
    this.handlers = new Map();
    this.isInitialized = false;
  }

  _buildUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/api/ws`;
  }

  connect() {
    if (this.isConnected) return Promise.resolve();

    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('[WS] Connected to WardenIPS WebSocket');
          this.isConnected = true;
          this.retryCount = 0;
          this._flushQueue();
          resolve();
          this._emit('connected', { timestamp: Date.now() });
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this._handleMessage(data);
          } catch (e) {
            console.error('[WS] Failed to parse message:', e);
          }
        };

        this.ws.onerror = (error) => {
          console.error('[WS] WebSocket error:', error);
          this._emit('error', { error, timestamp: Date.now() });
          reject(error);
        };

        this.ws.onclose = () => {
          console.warn('[WS] WebSocket disconnected');
          this.isConnected = false;
          this._emit('disconnected', { timestamp: Date.now() });
          this._attemptReconnect();
        };
      } catch (e) {
        console.error('[WS] Failed to create WebSocket:', e);
        reject(e);
      }
    });
  }

  disconnect() {
    if (this.ws) {
      this.isConnected = false;
      this.ws.close();
      this.ws = null;
    }
  }

  send(type, data = {}) {
    const message = {
      type,
      data,
      timestamp: Date.now(),
    };

    if (this.isConnected) {
      try {
        this.ws.send(JSON.stringify(message));
      } catch (e) {
        console.error('[WS] Failed to send message:', e);
        this.messageQueue.push(message);
      }
    } else {
      this.messageQueue.push(message);
    }
  }

  on(event, callback) {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, []);
    }
    this.handlers.get(event).push(callback);
  }

  off(event, callback) {
    if (!this.handlers.has(event)) return;
    const callbacks = this.handlers.get(event);
    const index = callbacks.indexOf(callback);
    if (index > -1) {
      callbacks.splice(index, 1);
    }
  }

  _emit(event, data) {
    if (!this.handlers.has(event)) return;
    this.handlers.get(event).forEach((callback) => {
      try {
        callback(data);
      } catch (e) {
        console.error(`[WS] Error in event handler for '${event}':`, e);
      }
    });
  }

  _handleMessage(data) {
    const { type, payload } = data;

    switch (type) {
      case 'ban:added':
        this._emit('ban-added', payload);
        break;
      case 'ban:removed':
        this._emit('ban-removed', payload);
        break;
      case 'ban:expired':
        this._emit('ban-expired', payload);
        break;
      case 'firewall:updated':
        this._emit('firewall-updated', payload);
        break;
      case 'stats:updated':
        this._emit('stats-updated', payload);
        break;
      case 'event:new':
        this._emit('event-new', payload);
        break;
      case 'health:update':
        this._emit('health-update', payload);
        break;
      default:
        this._emit(type, payload);
    }
  }

  _flushQueue() {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (this.isConnected) {
        try {
          this.ws.send(JSON.stringify(message));
        } catch (e) {
          console.error('[WS] Failed to flush queued message:', e);
          this.messageQueue.unshift(message);
          break;
        }
      }
    }
  }

  _attemptReconnect() {
    if (this.retryCount >= this.maxRetries) {
      console.error('[WS] Max reconnection attempts reached');
      this._emit('reconnect-failed', { retryCount: this.retryCount });
      return;
    }

    this.retryCount++;
    const delay = this.retryInterval * (1 + Math.random());
    console.log(`[WS] Attempting reconnect in ${Math.round(delay)}ms (attempt ${this.retryCount}/${this.maxRetries})`);

    setTimeout(() => {
      this.connect().catch((e) => {
        console.error('[WS] Reconnection failed:', e);
        this._attemptReconnect();
      });
    }, delay);
  }
}

/**
 * Dashboard Data Manager
 * Manages real-time data updates and state synchronization
 */
class DashboardDataManager {
  constructor() {
    this.data = {
      stats: {},
      bans: [],
      firewall: {},
      health: {},
      events: [],
    };
    this.listeners = new Map();
    this.ws = null;
  }

  init(wsUrl = null) {
    this.ws = new WardenIPSWebSocket(wsUrl);

    // Set up WebSocket handlers
    this.ws.on('ban-added', (data) => this._onBanAdded(data));
    this.ws.on('ban-removed', (data) => this._onBanRemoved(data));
    this.ws.on('stats-updated', (data) => this._onStatsUpdated(data));
    this.ws.on('firewall-updated', (data) => this._onFirewallUpdated(data));
    this.ws.on('event-new', (data) => this._onEventNew(data));
    this.ws.on('health-update', (data) => this._onHealthUpdate(data));

    return this.ws.connect();
  }

  subscribe(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, []);
    }
    this.listeners.get(key).push(callback);
  }

  unsubscribe(key, callback) {
    if (!this.listeners.has(key)) return;
    const callbacks = this.listeners.get(key);
    const index = callbacks.indexOf(callback);
    if (index > -1) {
      callbacks.splice(index, 1);
    }
  }

  _emit(key, value) {
    if (!this.listeners.has(key)) return;
    this.listeners.get(key).forEach((callback) => {
      try {
        callback(value);
      } catch (e) {
        console.error(`[Data] Error in listener for '${key}':`, e);
      }
    });
  }

  _onBanAdded(ban) {
    this.data.bans.unshift(ban);
    if (this.data.bans.length > 1000) {
      this.data.bans.pop();
    }
    this._emit('bans', this.data.bans);
    this._emit('bans:added', ban);
  }

  _onBanRemoved(data) {
    const index = this.data.bans.findIndex((b) => b.ip === data.ip);
    if (index > -1) {
      this.data.bans.splice(index, 1);
      this._emit('bans', this.data.bans);
      this._emit('bans:removed', data);
    }
  }

  _onStatsUpdated(stats) {
    this.data.stats = { ...this.data.stats, ...stats };
    this._emit('stats', this.data.stats);
  }

  _onFirewallUpdated(firewall) {
    this.data.firewall = { ...this.data.firewall, ...firewall };
    this._emit('firewall', this.data.firewall);
  }

  _onEventNew(event) {
    this.data.events.unshift(event);
    if (this.data.events.length > 1000) {
      this.data.events.pop();
    }
    this._emit('events', this.data.events);
    this._emit('events:new', event);
  }

  _onHealthUpdate(health) {
    this.data.health = { ...this.data.health, ...health };
    this._emit('health', this.data.health);
  }

  getData(key) {
    return this.data[key] || null;
  }

  setData(key, value) {
    this.data[key] = value;
    this._emit(key, value);
  }

  getStats() {
    return this.data.stats;
  }

  getBans() {
    return this.data.bans;
  }

  getFirewall() {
    return this.data.firewall;
  }

  getHealth() {
    return this.data.health;
  }

  getEvents() {
    return this.data.events;
  }

  request(type, data = {}) {
    if (this.ws) {
      this.ws.send(type, data);
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.disconnect();
    }
  }
}

/**
 * UI Notification Manager
 * Handles toast notifications and alerts
 */
class NotificationManager {
  constructor() {
    this.toasts = [];
    this.container = null;
    this._initContainer();
  }

  _initContainer() {
    this.container = document.createElement('div');
    this.container.className = 'toast-container';
    this.container.setAttribute('role', 'status');
    this.container.setAttribute('aria-live', 'polite');
    this.container.setAttribute('aria-atomic', 'true');
    document.body.appendChild(this.container);
  }

  show(message, type = 'info', duration = 5000) {
    const toastId = this._generateId();
    const toast = document.createElement('div');
    
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');
    toast.id = toastId;
    
    const typeEmoji = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ⓘ',
    }[type] || 'ⓘ';

    toast.innerHTML = `
      <span style="font-size: 1.2em; margin-right: 0.5rem;">${typeEmoji}</span>
      <span>${this._escapeHtml(message)}</span>
      <button class="toast-close" aria-label="Close notification">×</button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', () => this._removeToast(toastId));

    this.container.appendChild(toast);
    this.toasts.push(toastId);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    if (duration > 0) {
      setTimeout(() => this._removeToast(toastId), duration);
    }

    return toastId;
  }

  success(message, duration = 5000) {
    return this.show(message, 'success', duration);
  }

  error(message, duration = 7000) {
    return this.show(message, 'error', duration);
  }

  warning(message, duration = 6000) {
    return this.show(message, 'warning', duration);
  }

  info(message, duration = 5000) {
    return this.show(message, 'info', duration);
  }

  _removeToast(toastId) {
    const toast = document.getElementById(toastId);
    if (!toast) return;

    toast.classList.remove('show');
    setTimeout(() => {
      toast.remove();
      const index = this.toasts.indexOf(toastId);
      if (index > -1) {
        this.toasts.splice(index, 1);
      }
    }, 300);
  }

  _generateId() {
    return `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  _escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  clear() {
    this.toasts.forEach((id) => this._removeToast(id));
  }
}

/**
 * Theme Manager
 * Manages dark/light mode switching
 */
class ThemeManager {
  constructor() {
    this.currentTheme = this._loadTheme();
    this._applyTheme();
  }

  _loadTheme() {
    // Check user preference
    let theme = localStorage.getItem('wardenips_theme');
    
    if (!theme) {
      // Check system preference
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        theme = 'dark';
      } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
        theme = 'light';
      } else {
        theme = 'dark'; // Fallback
      }
    }
    
    return theme;
  }

  _applyTheme() {
    const root = document.documentElement;
    root.setAttribute('data-theme', this.currentTheme);
    localStorage.setItem('wardenips_theme', this.currentTheme);
  }

  toggle() {
    this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    this._applyTheme();
    return this.currentTheme;
  }

  set(theme) {
    if (['dark', 'light'].includes(theme)) {
      this.currentTheme = theme;
      this._applyTheme();
    }
  }

  get() {
    return this.currentTheme;
  }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    WardenIPSWebSocket,
    DashboardDataManager,
    NotificationManager,
    ThemeManager,
  };
}
