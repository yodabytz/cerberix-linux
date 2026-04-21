const Dashboard = {
  charts: {},
  async render() {
    Object.values(this.charts||{}).forEach(c=>{try{c.destroy()}catch(e){}});this.charts={};
    App.showLoading('Loading...');
    const data = await App.api('GET', '/api/dashboard');
    App.setPage(`
      <div class="page-header"><h2>Dashboard</h2><span class="text-muted" id="dash-uptime"></span></div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-label">Threats Today</div><div class="stat-value text-red" id="s-threats">-</div><div class="stat-sub" id="s-threats-sub">loading</div></div>
        <div class="stat-card"><div class="stat-label">Blocked IPs</div><div class="stat-value text-orange" id="s-blocked">-</div><div class="stat-sub">active blocks</div></div>
        <div class="stat-card"><div class="stat-label">Connections</div><div class="stat-value text-blue" id="s-conns">-</div><div class="stat-sub">tracked sessions</div></div>
        <div class="stat-card"><div class="stat-label">DNS Queries</div><div class="stat-value text-green" id="s-dns">-</div><div class="stat-sub">total resolved</div></div>
      </div>
      <div class="charts-grid">
        <div class="chart-card"><h3>Bandwidth</h3><div style="height:260px"><canvas id="chart-traffic"></canvas></div></div>
        <div class="chart-card"><h3>Threats by Type</h3><div style="height:260px"><canvas id="chart-threats"></canvas></div></div>
      </div>
      <div class="panels-grid">
        <div class="table-card"><h3>Recent Threats</h3><div class="table-scroll" style="max-height:300px"><table><thead><tr><th>Time</th><th>Severity</th><th>Detector</th><th>Description</th></tr></thead><tbody id="tbl-threats"></tbody></table></div></div>
        <div class="table-card"><h3>Blocked IPs</h3><div class="table-scroll" style="max-height:300px"><table><thead><tr><th>IP</th><th>Reason</th><th>Action</th></tr></thead><tbody id="tbl-blocked"></tbody></table></div></div>
      </div>`);
    if (data) this._renderData(data);
    App.refreshTimer = setInterval(() => this.loadData(), 15000);
  },
  async loadData() {
    const data = await App.api('GET', '/api/dashboard');
    if (data) this._renderData(data);
  },
  _renderData(data) {
    const s = data.stats;
    document.getElementById('s-threats').textContent = s.threats_today;
    document.getElementById('s-threats-sub').textContent = s.alerts_total + ' total alerts';
    document.getElementById('s-blocked').textContent = s.blocked_ips;
    document.getElementById('s-conns').textContent = s.connections.toLocaleString();
    document.getElementById('s-dns').textContent = s.dns_queries.toLocaleString();
    document.getElementById('dash-uptime').textContent = 'Uptime: ' + App.formatUptime(s.uptime_sec);
    const tbody = document.getElementById('tbl-threats');
    tbody.replaceChildren();
    if (data.recent_threats.length === 0) {
      tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'4',className:'text-muted'},'No threats detected')]));
    } else {
      data.recent_threats.forEach(t => {
        const ts = t.timestamp ? (t.timestamp.split('T')[1]||'').substring(0,8) : '';
        tbody.appendChild(App.el('tr',{},[App.el('td',{},ts),App.el('td',{},[App.badgeEl(t.severity)]),App.el('td',{},t.detector||''),App.el('td',{},(t.reason||t.detail||t.target||'').substring(0,50))]));
      });
    }
    const btbody = document.getElementById('tbl-blocked');
    btbody.replaceChildren();
    if (data.blocked_list.length === 0) {
      btbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'3',className:'text-muted'},'No blocked IPs')]));
    } else {
      data.blocked_list.forEach(b => {
        btbody.appendChild(App.el('tr',{},[App.el('td',{},[App.el('code',{},b.ip)]),App.el('td',{className:'text-muted'},(b.reason||'').substring(0,30)),App.el('td',{},[App.el('button',{className:'btn btn-sm btn-danger',onclick:()=>this.unblock(b.ip)},'Unblock')])]));
      });
    }
    this.renderTrafficChart(data.traffic_timeline);
    this.renderThreatChart(data.threat_types);
  },
  renderTrafficChart(timeline) {
    const ctx = document.getElementById('chart-traffic');
    if (!ctx) return;
    const labels = timeline.map((_,i)=>i);
    const config = {type:'line',data:{labels,datasets:[
      {label:'RX (inbound)',data:timeline.map(t=>t.rx_bps||0),borderColor:App.chartColors.blue,backgroundColor:'rgba(88,166,255,0.1)',fill:true,tension:0.3,pointRadius:0},
      {label:'TX (outbound)',data:timeline.map(t=>t.tx_bps||0),borderColor:App.chartColors.green,backgroundColor:'rgba(63,185,80,0.1)',fill:true,tension:0.3,pointRadius:0},
    ]},options:{...App.chartDefaults(),plugins:{legend:{labels:{color:App.chartColors.text,font:{size:11}}}}}};
    if (this.charts.traffic) {this.charts.traffic.data=config.data;this.charts.traffic.update('none');}
    else {this.charts.traffic=new Chart(ctx,config);}
  },
  renderThreatChart(types) {
    const ctx = document.getElementById('chart-threats');
    if (!ctx) return;
    const labels = Object.keys(types);
    const values = Object.values(types);
    const colors = [App.chartColors.red,App.chartColors.orange,App.chartColors.purple,App.chartColors.cyan,App.chartColors.blue];
    const config = {type:'doughnut',data:{labels,datasets:[{data:values,backgroundColor:colors.slice(0,labels.length),borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:App.chartColors.text,padding:12,font:{size:11}}}},cutout:'65%'}};
    if (labels.length===0) config.data={labels:['No data'],datasets:[{data:[1],backgroundColor:['#21262d'],borderWidth:0}]};
    if (this.charts.threats) {this.charts.threats.data=config.data;this.charts.threats.update('none');}
    else {this.charts.threats=new Chart(ctx,config);}
  },
  async unblock(ip) { await App.api('DELETE','/api/threats/blocklist/'+ip); this.loadData(); },
};
