const IDS = {
  charts: {},
  _allAlerts: [],
  async render() {
    Object.values(this.charts||{}).forEach(c=>{try{c.destroy()}catch(e){}});this.charts={};
    App.showLoading('Loading...');
    const [status, alerts, sigs, sources] = await Promise.all([
      App.api('GET','/api/ids/status'),
      App.api('GET','/api/ids/alerts'),
      App.api('GET','/api/ids/signatures'),
      App.api('GET','/api/ids/sources'),
    ]);
    App.setPage(`
      <div class="page-header"><h2>Intrusion Detection (Suricata)</h2>
        <div><button class="btn btn-sm" id="ids-refresh">Refresh</button>
        <button class="btn btn-sm btn-primary" id="ids-update">Update Rules</button></div>
      </div>
      <div class="stats-grid" id="ids-overview"></div>
      <div class="charts-grid">
        <div class="chart-card"><h3>Top Signatures</h3><div style="height:300px"><canvas id="chart-sigs"></canvas></div></div>
        <div class="chart-card"><h3>Top Source IPs</h3><div style="height:300px"><canvas id="chart-sources"></canvas></div></div>
      </div>
      <div class="table-card"><h3>Alerts</h3>
        <div class="search-bar">
          <input type="text" id="ids-search" placeholder="Search by signature, IP, protocol...">
          <span class="search-count" id="ids-count"></span>
        </div>
        <div class="table-scroll">
          <table><thead><tr><th>Time</th><th>Sev</th><th>Signature</th><th>Source</th><th>Dest</th><th>Proto</th></tr></thead>
          <tbody id="tbl-ids-alerts"></tbody></table>
        </div>
      </div>`);
    document.getElementById('ids-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('ids-update').addEventListener('click', () => this.updateRules());
    document.getElementById('ids-search').addEventListener('input', (e) => this._filterAlerts(e.target.value));
    this._renderData(status, alerts, sigs, sources);
    App.refreshTimer = setInterval(() => this.loadData(), 15000);
  },
  async loadData() {
    const [status, alerts, sigs, sources] = await Promise.all([
      App.api('GET','/api/ids/status'),
      App.api('GET','/api/ids/alerts'),
      App.api('GET','/api/ids/signatures'),
      App.api('GET','/api/ids/sources'),
    ]);
    this._renderData(status, alerts, sigs, sources);
  },
  _renderData(status, alerts, sigs, sources) {
    const ov = document.getElementById('ids-overview');
    if (!ov) return;
    ov.replaceChildren();
    [{l:'Suricata',v:status&&status.running?'RUNNING':'STOPPED',c:status&&status.running?'badge-green':'badge-red',badge:true},
     {l:'Rules Loaded',v:String(status?status.rules||0:0)},
     {l:'Total Alerts',v:String(status?status.alerts||0:0),cls:'text-orange'},
     {l:'Unique Signatures',v:String(sigs?sigs.signatures.length||0:0)},
    ].forEach(c => {
      const valEl = c.badge ? App.el('span',{className:'badge '+(c.c||'')},c.v) : App.el('div',{className:'stat-value '+(c.cls||'')},c.v);
      ov.appendChild(App.el('div',{className:'stat-card'},[App.el('div',{className:'stat-label'},c.l),valEl]));
    });

    if (alerts) {
      this._allAlerts = alerts.alerts || [];
      this._filterAlerts(document.getElementById('ids-search')?.value || '');
    }

    if (sigs&&sigs.signatures&&sigs.signatures.length>0) {
      const ctx = document.getElementById('chart-sigs');
      if (ctx) {
        const config = {type:'bar',data:{labels:sigs.signatures.map(s=>s.name.length>40?s.name.substring(0,37)+'...':s.name),datasets:[{data:sigs.signatures.map(s=>s.count),backgroundColor:App.chartColors.orange+'80',borderColor:App.chartColors.orange,borderWidth:1}]},options:{...App.chartDefaults(),indexAxis:'y',plugins:{legend:{display:false}}}};
        if (this.charts.sigs) {this.charts.sigs.data=config.data;this.charts.sigs.update('none');}
        else {this.charts.sigs=new Chart(ctx,config);}
      }
    }
    if (sources&&sources.sources&&sources.sources.length>0) {
      const ctx = document.getElementById('chart-sources');
      if (ctx) {
        const config = {type:'bar',data:{labels:sources.sources.map(s=>s.ip),datasets:[{data:sources.sources.map(s=>s.count),backgroundColor:App.chartColors.red+'80',borderColor:App.chartColors.red,borderWidth:1}]},options:{...App.chartDefaults(),plugins:{legend:{display:false}}}};
        if (this.charts.sources) {this.charts.sources.data=config.data;this.charts.sources.update('none');}
        else {this.charts.sources=new Chart(ctx,config);}
      }
    }
  },
  _filterAlerts(query) {
    const tbody = document.getElementById('tbl-ids-alerts');
    const countEl = document.getElementById('ids-count');
    if (!tbody) return;
    tbody.replaceChildren();
    const q = query.toLowerCase();
    const sevMap = {1:'critical',2:'high',3:'medium'};
    const filtered = q ? this._allAlerts.filter(a => {
      return (a.signature||'').toLowerCase().includes(q) ||
             (a.src_ip||'').includes(q) ||
             (a.dest_ip||'').includes(q) ||
             (a.protocol||'').toLowerCase().includes(q) ||
             (a.category||'').toLowerCase().includes(q) ||
             (sevMap[a.severity]||'').includes(q);
    }) : this._allAlerts;

    if (countEl) countEl.textContent = filtered.length + ' of ' + this._allAlerts.length;

    if (filtered.length === 0) {
      tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'6',className:'text-muted'},q?'No matches':'No alerts — network is clean')]));
    } else {
      filtered.forEach(a => {
        tbody.appendChild(App.el('tr',{},[
          App.el('td',{style:'font-size:12px'},a.timestamp||''),
          App.el('td',{},[App.badgeEl(sevMap[a.severity]||'low')]),
          App.el('td',{style:'font-size:12px'},(a.signature||'').substring(0,60)),
          App.el('td',{},[App.el('code',{},a.src_ip||'')]),
          App.el('td',{},[App.el('code',{},a.dest_ip+':'+a.dest_port)]),
          App.el('td',{className:'text-muted'},a.protocol||''),
        ]));
      });
    }
  },
  async updateRules() {
    document.getElementById('ids-update').textContent='Updating...';
    await App.api('POST','/api/ids/update-rules');
    document.getElementById('ids-update').textContent='Update Rules';
    this.loadData();
  },
};
