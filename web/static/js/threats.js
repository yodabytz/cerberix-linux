const Threats = {
  _allThreats: [],
  charts: {},
  async render() {
    // Destroy old charts to prevent Chart.js conflicts
    Object.values(this.charts).forEach(c => { try { c.destroy(); } catch(e) {} });
    this.charts = {};
    App.showLoading('Loading...');
    const [recent, stats, blocklist, analysis] = await Promise.all([
      App.api('GET','/api/threats/recent'),
      App.api('GET','/api/threats/stats'),
      App.api('GET','/api/threats/blocklist'),
      App.api('GET','/api/threats/analysis'),
    ]);
    App.setPage(`
      <div class="page-header"><h2>AI Threats</h2><button class="btn btn-sm" id="threats-refresh">Refresh</button></div>
      <div class="stats-grid" id="threat-stats"></div>
      <div class="charts-grid">
        <div class="chart-card"><h3>Attacks by Server</h3><div style="height:260px"><canvas id="chart-by-server"></canvas></div></div>
        <div class="chart-card"><h3>Attacks by Type</h3><div style="height:260px"><canvas id="chart-by-type"></canvas></div></div>
      </div>
      <div class="table-card">
        <h3>Threat Log</h3>
        <div class="search-bar">
          <input type="text" id="threat-search" placeholder="Search by IP, detector, severity, server, reason...">
          <span class="search-count" id="threat-count"></span>
        </div>
        <div class="table-scroll">
          <table><thead><tr><th>Time</th><th>Severity</th><th>Detector</th><th>Attacker</th><th>Target Server</th><th>Detail</th></tr></thead>
          <tbody id="tbl-all-threats"></tbody></table>
        </div>
      </div>
      <div class="panels-grid">
        <div class="table-card">
          <h3>AI Blocklist</h3>
          <div class="table-scroll" style="max-height:300px">
            <table><thead><tr><th>IP</th><th>Severity</th><th>Detector</th><th>Action</th></tr></thead>
            <tbody id="tbl-ai-blocklist"></tbody></table>
          </div>
        </div>
        <div class="table-card">
          <h3>Claude Analysis</h3>
          <div class="table-scroll" style="max-height:300px" id="analysis-log"></div>
        </div>
      </div>`);
    document.getElementById('threats-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('threat-search').addEventListener('input', (e) => this._filterThreats(e.target.value));
    this._renderData(recent, stats, blocklist, analysis);
    App.refreshTimer = setInterval(() => this.loadData(), 15000);
  },
  async loadData() {
    const [recent, stats, blocklist, analysis] = await Promise.all([
      App.api('GET','/api/threats/recent'),
      App.api('GET','/api/threats/stats'),
      App.api('GET','/api/threats/blocklist'),
      App.api('GET','/api/threats/analysis'),
    ]);
    this._renderData(recent, stats, blocklist, analysis);
  },
  _renderData(recent, stats, blocklist, analysis) {
    if (stats) {
      const el = document.getElementById('threat-stats');
      if (!el) return;
      el.replaceChildren();
      const running = stats.running;
      [{l:'AI Engine',v:running?'RUNNING':'STOPPED',c:running?'badge-green':'badge-red',badge:true},
       {l:'Events Processed',v:(stats.events_processed||0).toLocaleString()},
       {l:'Alerts Generated',v:String(stats.alerts_generated||0),cls:'text-orange'},
       {l:'IPs Auto-Blocked',v:String(stats.ips_blocked||0),cls:'text-red'}].forEach(s => {
        const valEl = s.badge ? App.el('span',{className:'badge '+s.c},s.v) : App.el('div',{className:'stat-value '+(s.cls||'')},s.v);
        el.appendChild(App.el('div',{className:'stat-card'},[App.el('div',{className:'stat-label'},s.l), valEl]));
      });
    }
    if (recent) {
      this._allThreats = recent.threats || [];
      this._filterThreats(document.getElementById('threat-search')?.value || '');
      this._renderCharts();
    }
    if (blocklist) {
      const tbody = document.getElementById('tbl-ai-blocklist'); tbody.replaceChildren();
      if (blocklist.blocklist.length===0) tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'4',className:'text-muted'},'No blocked IPs')]));
      else blocklist.blocklist.forEach(b => {
        tbody.appendChild(App.el('tr',{},[App.el('td',{},[App.el('code',{},b.ip)]),App.el('td',{},[App.badgeEl(b.severity)]),App.el('td',{},b.detector||''),App.el('td',{},[App.el('button',{className:'btn btn-sm btn-danger',onclick:()=>this.unblock(b.ip)},'Unblock')])]));
      });
    }
    if (analysis) {
      const el = document.getElementById('analysis-log'); el.replaceChildren();
      if (analysis.analyses.length===0) el.appendChild(App.el('p',{className:'text-muted'},'No Claude analyses yet'));
      else analysis.analyses.forEach(a => {
        el.appendChild(App.el('div',{style:'padding:8px 0;border-bottom:1px solid var(--border)'},[
          App.el('div',{className:'text-muted',style:'font-size:12px'},a.timestamp||''),
          App.el('div',{},[App.badgeEl(a.assessment||'unknown'),document.createTextNode(' confidence: '+(a.confidence||'?'))]),
          App.el('div',{style:'font-size:13px;margin-top:4px'},a.summary||''),
        ]));
      });
    }
  },
  _renderCharts() {
    // Count attacks by server
    const serverCounts = {};
    const typeCounts = {};
    this._allThreats.forEach(t => {
      // Server chart
      let server = t.server || '';
      if (!server) {
        if (t.server_ip) server = t.server_ip;
        else if ((t.detector||'').startsWith('remote_')) server = 'quantumbytz.com';
        else server = 'quantumbytz.com';
      }
      // Normalize names
      if (server === 'cerberix-gateway' || server === 'gateway' || server === '192.168.1.1') server = 'Cerberix Gateway';
      if (server === 'quantumbytz.com' || server === 'mail' || server === '50.21.187.13') server = 'quantumbytz.com';
      if (server === 'vibrixmedia.com' || server === 'vibrixmedia' || server === '54.39.90.215') server = 'vibrixmedia.com';
      serverCounts[server] = (serverCounts[server]||0) + 1;
      // Type chart — group by category
      let type = t.detector || 'unknown';
      if (type.startsWith('remote_')) type = type.replace('remote_','');
      if (type.includes('ssh')) type = 'SSH Brute Force';
      else if (type.includes('smtp') || type.includes('postfix')) type = 'SMTP Attack';
      else if (type.includes('imap') || type.includes('dovecot')) type = 'IMAP Attack';
      else if (type.includes('modsec')) type = 'ModSecurity (WAF)';
      else if (type.includes('portscan')) type = 'Port Scan';
      else if (type.includes('bruteforce')) type = 'Brute Force';
      else if (type.includes('dga')) type = 'DGA Domain';
      else if (type.includes('dns_tunnel')) type = 'DNS Tunnel';
      else if (type.includes('suricata')) type = 'Suricata IDS';
      else if (type.includes('arp')) type = 'ARP Spoof';
      else if (type.includes('anomaly')) type = 'Traffic Anomaly';
      typeCounts[type] = (typeCounts[type]||0) + 1;
    });

    // Server chart
    const serverCtx = document.getElementById('chart-by-server');
    if (serverCtx) {
      const labels = Object.keys(serverCounts);
      const values = Object.values(serverCounts);
      const colors = [App.chartColors.blue, App.chartColors.green, App.chartColors.orange, App.chartColors.purple, App.chartColors.red, App.chartColors.cyan];
      const config = {type:'bar',data:{labels,datasets:[{data:values,backgroundColor:colors.map(c=>c+'80'),borderColor:colors,borderWidth:1}]},options:{...App.chartDefaults(),plugins:{legend:{display:false}}}};
      if (labels.length===0) config.data={labels:['No data'],datasets:[{data:[0],backgroundColor:['#21262d']}]};
      if (this.charts.server) {this.charts.server.data=config.data;this.charts.server.update('none');}
      else {this.charts.server=new Chart(serverCtx,config);}
    }

    // Type chart
    const typeCtx = document.getElementById('chart-by-type');
    if (typeCtx) {
      const labels = Object.keys(typeCounts).sort((a,b)=>(typeCounts[b]||0)-(typeCounts[a]||0));
      const values = labels.map(l=>typeCounts[l]);
      const colors = [App.chartColors.red, App.chartColors.orange, App.chartColors.blue, App.chartColors.purple, App.chartColors.cyan, App.chartColors.green, '#f0883e', '#a371f7', '#56d4dd'];
      const config = {type:'doughnut',data:{labels,datasets:[{data:values,backgroundColor:colors.slice(0,labels.length),borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:App.chartColors.text,padding:8,font:{size:11}}}},cutout:'60%'}};
      if (labels.length===0) config.data={labels:['No data'],datasets:[{data:[1],backgroundColor:['#21262d'],borderWidth:0}]};
      if (this.charts.type) {this.charts.type.data=config.data;this.charts.type.update('none');}
      else {this.charts.type=new Chart(typeCtx,config);}
    }
  },
  _filterThreats(query) {
    const tbody = document.getElementById('tbl-all-threats');
    const countEl = document.getElementById('threat-count');
    if (!tbody) return;
    tbody.replaceChildren();
    const q = query.toLowerCase();
    const filtered = q ? this._allThreats.filter(t => {
      return (t.severity||'').toLowerCase().includes(q) ||
             (t.detector||'').toLowerCase().includes(q) ||
             (t.target||'').toLowerCase().includes(q) ||
             (t.action||'').toLowerCase().includes(q) ||
             (t.reason||'').toLowerCase().includes(q) ||
             (t.server||'').toLowerCase().includes(q) ||
             (t.server_ip||'').toLowerCase().includes(q) ||
             (t.timestamp||'').toLowerCase().includes(q);
    }) : this._allThreats;

    if (countEl) countEl.textContent = filtered.length + ' of ' + this._allThreats.length;

    if (filtered.length === 0) {
      tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'6',className:'text-muted'},q?'No matches':'No threats')]));
    } else {
      filtered.forEach(t => {
        const ts = t.timestamp ? (t.timestamp.split('T')[1]||'').substring(0,8) : '';
        const serverText = t.server || t.server_ip || '';
        tbody.appendChild(App.el('tr',{},[
          App.el('td',{},ts),
          App.el('td',{},[App.badgeEl(t.severity)]),
          App.el('td',{},t.detector||''),
          App.el('td',{},[App.el('code',{},t.target||'')]),
          App.el('td',{style:'font-size:12px;color:var(--accent-purple)'},serverText),
          App.el('td',{className:'text-muted'},(t.reason||'').substring(0,40)),
        ]));
      });
    }
  },
  async unblock(ip) { await App.api('DELETE','/api/threats/blocklist/'+ip); this.loadData(); },
};
