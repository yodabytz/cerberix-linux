const Network = {
  async render() {
    App.setPage(`
      <div class="page-header"><h2>Network</h2><button class="btn btn-sm" id="net-refresh">Refresh</button></div>
      <div class="stats-grid" id="net-interfaces"></div>
      <div class="charts-grid">
        <div class="table-card"><h3>DHCP Leases</h3><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead><tbody id="tbl-leases"></tbody></table></div>
        <div class="table-card"><h3>Connection Tracking</h3><div id="net-conntrack"></div><h3 style="margin-top:20px">Routing Table</h3><pre class="code-block" id="net-routes" style="max-height:200px"></pre></div>
      </div>`);
    document.getElementById('net-refresh').addEventListener('click', () => this.loadData());
    await this.loadData();
    App.refreshTimer = setInterval(() => this.loadData(), 10000);
  },
  async loadData() {
    const [ifaces, dhcp, routes, ct] = await Promise.all([
      App.api('GET', '/api/network/interfaces'), App.api('GET', '/api/network/dhcp'),
      App.api('GET', '/api/network/routes'), App.api('GET', '/api/network/conntrack'),
    ]);
    if (ifaces) {
      const el = document.getElementById('net-interfaces');
      el.replaceChildren();
      ifaces.interfaces.forEach(i => {
        const card = App.el('div', {className:'stat-card'}, [
          App.el('div', {className:'stat-label'}, [
            document.createTextNode(i.role + ' \u2014 ' + i.name + ' '),
            App.el('span', {className:'badge ' + (i.state==='up'?'badge-green':'badge-red')}, i.state.toUpperCase()),
          ]),
          App.el('div', {className:'info-grid', style:'margin-top:8px'}, [
            App.el('span',{className:'label'},'IP'), App.el('span',{className:'value'},i.ip||'N/A'),
            App.el('span',{className:'label'},'MAC'), App.el('span',{className:'value',style:'font-size:12px'},i.mac||'N/A'),
            App.el('span',{className:'label'},'RX'), App.el('span',{className:'value'},App.formatBytes(i.rx_bytes)),
            App.el('span',{className:'label'},'TX'), App.el('span',{className:'value'},App.formatBytes(i.tx_bytes)),
          ]),
        ]);
        el.appendChild(card);
      });
    }
    if (dhcp) {
      const tbody = document.getElementById('tbl-leases');
      tbody.replaceChildren();
      if (dhcp.leases.length === 0) tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'3',className:'text-muted'},'No active leases')]));
      else dhcp.leases.forEach(l => tbody.appendChild(App.el('tr',{},[App.el('td',{},[App.el('code',{},l.ip)]),App.el('td',{className:'text-muted'},l.mac),App.el('td',{},l.hostname||'-')])));
    }
    if (routes) document.getElementById('net-routes').textContent = routes.routes.join('\n') || 'No routes';
    if (ct) {
      const pct = ct.usage_pct || 0;
      const color = pct > 80 ? 'fill-red' : pct > 50 ? 'fill-orange' : 'fill-green';
      const el = document.getElementById('net-conntrack');
      el.replaceChildren();
      el.appendChild(App.el('div',{className:'info-grid'},[
        App.el('span',{className:'label'},'Active'), App.el('span',{className:'value'},ct.count.toLocaleString()),
        App.el('span',{className:'label'},'Max'), App.el('span',{className:'value'},ct.max.toLocaleString()),
        App.el('span',{className:'label'},'Usage'), App.el('span',{className:'value'},pct+'%'),
      ]));
      const bar = App.el('div',{className:'progress-bar'},[App.el('div',{className:'fill '+color,style:'width:'+pct+'%'})]);
      el.appendChild(bar);
    }
  },
};
