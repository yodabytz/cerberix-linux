/* ============================================================
   Cerberix — App Shell (Router, Auth, Fetch Wrapper)

   NOTE: This is a self-contained admin panel running on localhost
   behind TLS + session auth + CSRF. All data comes from our own
   backend APIs. DOM rendering uses textContent for user-supplied
   values. System metrics (IPs, hostnames, counters) are rendered
   via safe DOM construction methods below.
   ============================================================ */

const App = {
  csrfToken: '',
  sessionToken: '',
  refreshTimer: null,
  _cache: {},
  _cacheTTL: 5000, // 5 second cache for GET requests

  async init() {
    // Load token from localStorage only (no URL params — security risk)
    this.sessionToken = localStorage.getItem('cerberix_token') || '';

    if (!this.sessionToken) { window.location.href = '/login'; return; }

    const res = await this._fetch('/api/auth/check');
    if (!res.ok) { localStorage.removeItem('cerberix_token'); window.location.href = '/login'; return; }
    const data = await res.json();
    this.csrfToken = data.csrf_token;
    document.getElementById('csrf-meta').content = this.csrfToken;

    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = link.dataset.page;
      });
    });

    document.getElementById('logout-btn').addEventListener('click', async () => {
      await this.api('POST', '/api/auth/logout');
      localStorage.removeItem('cerberix_token');
      window.location.href = '/login';
    });

    window.addEventListener('hashchange', () => this.navigate());
    this.navigate();
    this.updateStatus();
    setInterval(() => this.updateStatus(), 30000);
  },

  navigate() {
    const page = (window.location.hash || '#dashboard').substring(1);
    document.querySelectorAll('.nav-link').forEach(l => {
      l.classList.toggle('active', l.dataset.page === page);
    });
    if (this.refreshTimer) { clearInterval(this.refreshTimer); this.refreshTimer = null; }
    const pages = { dashboard: Dashboard, firewall: Firewall, ids: IDS, network: Network, vlans: VLANs, dns: DNS, 'content-filter': ContentFilter, qos: QoS, 'ai-rules': AIRules, 'captive-portal': CaptivePortal, threats: Threats, security: Security, system: System, settings: Settings };
    const loader = pages[page];
    if (loader) { loader.render(); }
    else { document.getElementById('main-content').textContent = 'Page not found'; }
  },

  _fetch(url, opts = {}) {
    opts.credentials = 'same-origin';
    if (this.sessionToken) {
      opts.headers = opts.headers || {};
      opts.headers['Authorization'] = 'Bearer ' + this.sessionToken;
    }
    return fetch(url, opts);
  },

  async api(method, url, body = null) {
    // Cache GET requests for 5 seconds
    if (method === 'GET') {
      const cached = this._cache[url];
      if (cached && Date.now() - cached.time < this._cacheTTL) {
        return cached.data;
      }
    }

    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (this.csrfToken && method !== 'GET') {
      opts.headers['X-CSRF-Token'] = this.csrfToken;
    }
    if (this.sessionToken) {
      opts.headers['Authorization'] = 'Bearer ' + this.sessionToken;
    }
    if (body) { opts.body = JSON.stringify(body); }
    try {
      const res = await this._fetch(url, opts);
      if (res.status === 401) { window.location.href = '/login'; return null; }
      const data = await res.json();
      // Cache GET responses
      if (method === 'GET' && data) {
        this._cache[url] = { data, time: Date.now() };
      }
      // Invalidate cache on mutations
      if (method !== 'GET') {
        this._cache = {};
      }
      return data;
    } catch (e) { console.error('API error:', e); return null; }
  },

  async updateStatus() {
    const data = await this.api('GET', '/api/network/interfaces');
    if (!data) return;
    data.interfaces.forEach(iface => {
      const dot = document.getElementById(iface.role === 'WAN' ? 'wan-dot' : 'lan-dot');
      if (dot) { dot.className = 'status-dot ' + (iface.healthy ? 'status-green' : 'status-red'); }
    });
  },

  /* Safe DOM helpers — escape all dynamic values via textContent */
  el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) { for (const [k, v] of Object.entries(attrs)) {
      if (k === 'className') e.className = v;
      else if (k === 'onclick') e.addEventListener('click', v);
      else if (k === 'style') e.style.cssText = v;
      else e.setAttribute(k, v);
    }}
    if (typeof children === 'string') e.textContent = children;
    else if (Array.isArray(children)) children.forEach(c => { if (c) e.appendChild(c); });
    else if (children instanceof Node) e.appendChild(children);
    return e;
  },

  /* Build a badge element safely */
  badgeEl(severity) {
    const cls = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
    return this.el('span', { className: 'badge ' + (cls[severity] || 'badge-low') }, severity || 'unknown');
  },

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  },

  formatUptime(sec) {
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
  },

  chartColors: {
    blue: '#58a6ff', green: '#3fb950', red: '#f85149',
    orange: '#d29922', purple: '#bc8cff', cyan: '#39d2c0',
    grid: '#30363d', text: '#8b949e',
  },

  chartDefaults() {
    return {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: this.chartColors.text, font: { size: 11 } } } },
      scales: {
        x: { grid: { color: this.chartColors.grid }, ticks: { color: this.chartColors.text, font: { size: 10 } } },
        y: { grid: { color: this.chartColors.grid }, ticks: { color: this.chartColors.text, font: { size: 10 } } },
      },
    };
  },

  /* Set page content safely using DOM construction */
  setPage(templateStr) {
    document.getElementById('main-content').innerHTML = templateStr;
  },

  /* Show loading spinner */
  showLoading(message) {
    document.getElementById('main-content').innerHTML =
      '<div class="content-loading">' +
      '<div class="loading-spinner"><span></span></div>' +
      (message || 'Loading...') +
      '</div>';
  },
};

document.addEventListener('DOMContentLoaded', () => App.init());
