const DNS = {
  charts: {},
  async render() {
    App.setPage(`
      <div class="page-header"><h2>DNS</h2><button class="btn btn-sm" id="dns-refresh">Refresh</button></div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-label">Total Queries</div><div class="stat-value text-green" id="dns-total">-</div></div>
        <div class="stat-card"><div class="stat-label">Unique Domains</div><div class="stat-value text-blue" id="dns-domains">-</div></div>
        <div class="stat-card"><div class="stat-label">Blocked Domains</div><div class="stat-value text-red" id="dns-blocked-count">-</div></div>
      </div>
      <div class="charts-grid">
        <div class="chart-card"><h3>Top Queried Domains</h3><div style="height:300px"><canvas id="chart-domains"></canvas></div></div>
        <div class="chart-card"><h3>Top Clients</h3><div style="height:300px"><canvas id="chart-clients"></canvas></div></div>
      </div>
      <div class="table-card"><h3>Blocked Domains</h3>
        <div style="display:flex;gap:8px;margin-bottom:12px"><input type="text" id="block-domain" placeholder="domain.com" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;color:var(--text-primary);flex:1"><button class="btn btn-primary btn-sm" id="dns-block-btn">Block</button></div>
        <div id="dns-blocked-list"></div>
      </div>`);
    document.getElementById('dns-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('dns-block-btn').addEventListener('click', () => this.blockDomain());
    await this.loadData();
  },
  async loadData() {
    const [stats, blocked] = await Promise.all([App.api('GET', '/api/dns/stats'), App.api('GET', '/api/dns/blocked')]);
    if (stats) {
      document.getElementById('dns-total').textContent = stats.total_queries.toLocaleString();
      document.getElementById('dns-domains').textContent = stats.top_domains.length;
      this.renderChart('chart-domains', 'domains', stats.top_domains.map(d => d.domain.length > 25 ? d.domain.substring(0,22)+'...' : d.domain), stats.top_domains.map(d => d.count), App.chartColors.blue, 'y');
      this.renderChart('chart-clients', 'clients', stats.top_clients.map(c => c.client), stats.top_clients.map(c => c.count), App.chartColors.green);
    }
    if (blocked) {
      document.getElementById('dns-blocked-count').textContent = blocked.blocked_domains.length;
      const el = document.getElementById('dns-blocked-list');
      el.replaceChildren();
      if (blocked.blocked_domains.length === 0) { el.appendChild(App.el('p',{className:'text-muted'},'No blocked domains')); }
      else blocked.blocked_domains.forEach(d => {
        const row = App.el('div',{style:'display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)'},[
          App.el('code',{},d),
          App.el('button',{className:'btn btn-sm btn-danger',onclick:()=>this.unblockDomain(d)},'Remove'),
        ]);
        el.appendChild(row);
      });
    }
  },
  renderChart(canvasId, key, labels, data, color, axis) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const config = {type:'bar',data:{labels,datasets:[{data,backgroundColor:color+'80',borderColor:color,borderWidth:1}]},options:{...App.chartDefaults(),plugins:{legend:{display:false}}}};
    if (axis === 'y') config.options.indexAxis = 'y';
    if (this.charts[key]) { this.charts[key].data = config.data; this.charts[key].update('none'); }
    else { this.charts[key] = new Chart(ctx, config); }
  },
  async blockDomain() { const d = document.getElementById('block-domain').value.trim(); if (!d) return; await App.api('POST', '/api/dns/block', {domain:d}); document.getElementById('block-domain').value = ''; this.loadData(); },
  async unblockDomain(d) { await App.api('DELETE', '/api/dns/block/' + d); this.loadData(); },
};
