const Firewall = {
  async render() {
    App.setPage(`
      <div class="page-header"><h2>Firewall</h2><div><button class="btn btn-sm" id="fw-refresh">Refresh</button> <button class="btn btn-sm btn-danger" id="fw-flush">Flush AI Blocks</button></div></div>
      <div class="stats-grid" id="fw-chains"></div>
      <div class="table-card"><h3>Manual Block</h3><div style="display:flex;gap:8px;margin-bottom:16px"><input type="text" id="block-ip" placeholder="IP Address" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;color:var(--text-primary);flex:1"><input type="number" id="block-duration" placeholder="Seconds" value="3600" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;color:var(--text-primary);width:120px"><button class="btn btn-primary btn-sm" id="fw-block-btn">Block</button></div></div>
      <div class="chart-card"><h3>nftables Ruleset</h3><pre class="code-block" id="fw-rules">Loading...</pre></div>`);
    document.getElementById('fw-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('fw-flush').addEventListener('click', () => this.flushAI());
    document.getElementById('fw-block-btn').addEventListener('click', () => this.blockIP());
    await this.loadData();
  },
  async loadData() {
    const [rules, counters] = await Promise.all([App.api('GET', '/api/firewall/rules'), App.api('GET', '/api/firewall/counters')]);
    if (rules) document.getElementById('fw-rules').textContent = rules.ruleset || 'No rules loaded';
    if (counters && counters.chains) {
      const el = document.getElementById('fw-chains');
      el.replaceChildren();
      counters.chains.forEach(c => {
        const card = App.el('div', {className:'stat-card'}, [
          App.el('div', {className:'stat-label'}, c.name),
          App.el('div', {className:'stat-value'}, String(c.rules)),
          App.el('div', {className:'stat-sub'}, c.accepts + ' accept / ' + c.drops + ' drop'),
        ]);
        el.appendChild(card);
      });
    }
  },
  async blockIP() {
    const ip = document.getElementById('block-ip').value.trim();
    const duration = parseInt(document.getElementById('block-duration').value) || 3600;
    if (!ip) return;
    await App.api('POST', '/api/firewall/block', { ip, duration });
    document.getElementById('block-ip').value = '';
    this.loadData();
  },
  async flushAI() { if (confirm('Flush all AI blocks?')) { await App.api('POST', '/api/firewall/flush-ai'); this.loadData(); } },
};
