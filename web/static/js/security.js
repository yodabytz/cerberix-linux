const Security = {
  charts: {},
  async render() {
    Object.values(this.charts||{}).forEach(c=>{try{c.destroy()}catch(e){}});this.charts={};
    App.showLoading('Loading...');
    const [f2b, geo, feeds, rl, arp, bw] = await Promise.all([
      App.api('GET','/api/security/fail2ban'),
      App.api('GET','/api/security/geoip'),
      App.api('GET','/api/security/feeds'),
      App.api('GET','/api/security/ratelimit'),
      App.api('GET','/api/security/arp'),
      App.api('GET','/api/security/bandwidth'),
    ]);
    App.setPage(`
      <div class="page-header"><h2>Security</h2><button class="btn btn-sm" id="sec-refresh">Refresh</button></div>
      <div class="stats-grid" id="sec-overview"></div>
      <div class="charts-grid">
        <div class="chart-card"><h3>Bandwidth (per interface)</h3><div style="height:260px"><canvas id="chart-bw"></canvas></div></div>
        <div class="table-card">
          <h3>fail2ban Jails</h3>
          <table><thead><tr><th>Jail</th><th>Banned</th><th>Total Banned</th><th>Failures</th></tr></thead>
          <tbody id="tbl-jails"></tbody></table>
        </div>
      </div>
      <div class="charts-grid">
        <div class="table-card">
          <h3>Threat Feeds (SecuNX)</h3>
          <div id="feed-toggle" style="margin-bottom:12px"></div>
          <div id="feed-info"></div>
          <button class="btn btn-sm btn-primary" id="btn-update-feeds" style="margin-top:12px">Update Feeds Now</button>
        </div>
        <div class="table-card">
          <h3>GeoIP Blocking</h3>
          <div id="geoip-info"></div>
          <div style="display:flex;gap:8px;margin-top:12px">
            <input type="text" id="geo-cc" placeholder="Country code (e.g. CN)" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;color:var(--text-primary);width:180px">
            <button class="btn btn-sm btn-primary" id="btn-geo-block">Block Country</button>
          </div>
        </div>
      </div>
      <div class="charts-grid">
        <div class="table-card"><h3>ARP Watch</h3><div id="arp-info"></div></div>
        <div class="table-card"><h3>Connection Rate Limiting</h3><div id="ratelimit-info"></div></div>
      </div>`);
    document.getElementById('sec-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('btn-update-feeds').addEventListener('click', () => this.updateFeeds());
    document.getElementById('btn-geo-block').addEventListener('click', () => this.blockCountry());
    this._renderData(f2b, geo, feeds, rl, arp, bw);
    App.refreshTimer = setInterval(() => this.loadData(), 15000);
  },
  async loadData() {
    const [f2b, geo, feeds, rl, arp, bw] = await Promise.all([
      App.api('GET','/api/security/fail2ban'),
      App.api('GET','/api/security/geoip'),
      App.api('GET','/api/security/feeds'),
      App.api('GET','/api/security/ratelimit'),
      App.api('GET','/api/security/arp'),
      App.api('GET','/api/security/bandwidth'),
    ]);
    this._renderData(f2b, geo, feeds, rl, arp, bw);
  },
  _renderData(f2b, geo, feeds, rl, arp, bw) {
    // Overview cards
    const ov = document.getElementById('sec-overview');
    if (!ov) return;
    ov.replaceChildren();
    [{l:'fail2ban',v:f2b&&f2b.running?'ACTIVE':'INACTIVE',c:f2b&&f2b.running?'badge-green':'badge-red',badge:true},
     {l:'Threat Feed IPs',v:String(feeds?feeds.ip_count||0:0)},
     {l:'Blocked Domains',v:String(feeds?feeds.domain_count||0:0)},
     {l:'GeoIP',v:geo&&geo.enabled?geo.blocked_countries.join(', ')||'ACTIVE':'OFF'},
     {l:'Rate Limiting',v:rl&&rl.active?'ACTIVE':'OFF',c:rl&&rl.active?'badge-green':'badge-red',badge:true},
     {l:'ARP Bindings',v:String(arp?Object.keys(arp.bindings||{}).length:0)},
    ].forEach(c => {
      const valEl = c.badge ? App.el('span',{className:'badge '+(c.c||'badge-green')},c.v) : App.el('div',{className:'stat-value'},c.v);
      ov.appendChild(App.el('div',{className:'stat-card'},[App.el('div',{className:'stat-label'},c.l),valEl]));
    });

    // fail2ban
    if (f2b) {
      const tbody = document.getElementById('tbl-jails');
      tbody.replaceChildren();
      if (!f2b.jails||f2b.jails.length===0) {
        tbody.appendChild(App.el('tr',{},[App.el('td',{colspan:'4',className:'text-muted'},f2b.running?'No jails active':'fail2ban not running')]));
      } else {
        f2b.jails.forEach(j => tbody.appendChild(App.el('tr',{},[
          App.el('td',{},j.name),
          App.el('td',{className:j.banned>0?'text-red':''},String(j.banned)),
          App.el('td',{},String(j.total_banned)),
          App.el('td',{},String(j.failures)),
        ])));
      }
    }

    // Feeds toggle
    if (feeds) {
      const toggle = document.getElementById('feed-toggle');
      toggle.replaceChildren();
      const isOn = feeds.enabled !== false;
      toggle.appendChild(App.el('div',{style:'display:flex;align-items:center;gap:8px'},[
        App.el('span',{},'Status: '),
        App.el('span',{className:'badge '+(isOn?'badge-green':'badge-red')},isOn?'ENABLED':'DISABLED'),
        App.el('button',{className:'btn btn-sm '+(isOn?'btn-danger':'btn-primary'),style:'margin-left:8px',onclick:()=>this.toggleFeeds(!isOn)},isOn?'Disable':'Enable'),
      ]));
      const el = document.getElementById('feed-info');
      el.replaceChildren();
      el.appendChild(App.el('div',{className:'info-grid'},[
        App.el('span',{className:'label'},'IPs blocked'), App.el('span',{className:'value'},String(feeds.ip_count)),
        App.el('span',{className:'label'},'Domains sinkholed'), App.el('span',{className:'value'},String(feeds.domain_count)),
        App.el('span',{className:'label'},'Last update'), App.el('span',{className:'value'},feeds.last_update||'Never'),
      ]));
      if (feeds.feeds&&feeds.feeds.length>0) {
        const list = App.el('div',{style:'margin-top:8px;font-size:12px'});
        feeds.feeds.forEach(f => list.appendChild(App.el('div',{style:'display:flex;justify-content:space-between;padding:2px 0'},[
          App.el('span',{className:'text-muted'},f.name), App.el('span',{},String(f.count)),
        ])));
        el.appendChild(list);
      }
    }

    // GeoIP
    if (geo) {
      const el = document.getElementById('geoip-info');
      el.replaceChildren();
      el.appendChild(App.el('div',{className:'info-grid'},[
        App.el('span',{className:'label'},'Status'), App.el('span',{className:'value'},geo.enabled?'Active':'Inactive'),
        App.el('span',{className:'label'},'Last update'), App.el('span',{className:'value'},geo.last_update||'Never'),
      ]));
      if (geo.blocked_countries&&geo.blocked_countries.length>0) {
        const list = App.el('div',{style:'margin-top:10px'});
        geo.blocked_countries.forEach(cc => {
          list.appendChild(App.el('div',{style:'display:inline-flex;align-items:center;gap:4px;margin:4px 4px 4px 0;padding:4px 8px;background:var(--bg-tertiary);border-radius:4px;font-size:13px'},[
            App.el('span',{style:'font-weight:600'},cc),
            App.el('button',{className:'btn btn-sm btn-danger',style:'padding:2px 6px;font-size:11px',onclick:()=>this.unblockCountry(cc)},'X'),
          ]));
        });
        list.appendChild(App.el('button',{className:'btn btn-sm btn-danger',style:'margin-top:8px;display:block',onclick:()=>this.clearGeoIP()},'Clear All'));
        el.appendChild(list);
      } else {
        el.appendChild(App.el('p',{className:'text-muted',style:'margin-top:8px'},'No countries blocked'));
      }
    }

    // ARP
    if (arp) {
      const el = document.getElementById('arp-info');
      el.replaceChildren();
      const bindings = arp.bindings||{};
      const alerts = arp.alerts||[];
      el.appendChild(App.el('div',{className:'info-grid'},[
        App.el('span',{className:'label'},'Known bindings'), App.el('span',{className:'value'},String(Object.keys(bindings).length)),
        App.el('span',{className:'label'},'Spoof alerts'), App.el('span',{className:'value '+(alerts.length>0?'text-red':'')},String(alerts.length)),
      ]));
      alerts.slice(-5).forEach(a => el.appendChild(App.el('div',{style:'margin-top:6px;padding:6px;background:rgba(248,81,73,0.1);border-radius:4px;font-size:12px'},a.description||'')));
    }

    // Rate limiting
    if (rl) {
      const el = document.getElementById('ratelimit-info');
      el.replaceChildren();
      el.appendChild(App.el('div',{className:'info-grid'},[
        App.el('span',{className:'label'},'Status'), App.el('span',{className:'value'},rl.active?'Active':'Inactive'),
      ]));
    }

    // Bandwidth
    if (bw&&bw.history&&bw.history.length>0) this.renderBandwidthChart(bw.history);
  },
  renderBandwidthChart(history) {
    const ctx = document.getElementById('chart-bw');
    if (!ctx) return;
    const ifaces = {};
    history.forEach(h => { if (h.interfaces) Object.entries(h.interfaces).forEach(([name,data]) => {
      if (!ifaces[name]) ifaces[name]={rx:[],tx:[]};
      ifaces[name].rx.push(data.rx_bps||0);
      ifaces[name].tx.push(data.tx_bps||0);
    });});
    const labels = history.map((_,i)=>i);
    const colors = [App.chartColors.blue,App.chartColors.green,App.chartColors.purple,App.chartColors.orange];
    const datasets = [];
    let ci = 0;
    Object.entries(ifaces).forEach(([name,data]) => {
      const c = colors[ci%colors.length];
      datasets.push({label:name+' RX',data:data.rx,borderColor:c,backgroundColor:c+'20',fill:true,tension:0.3,pointRadius:0});
      ci++;
    });
    const config = {type:'line',data:{labels,datasets},options:{...App.chartDefaults(),plugins:{legend:{labels:{color:App.chartColors.text,font:{size:11}}}}}};
    if (datasets.length===0) return;
    if (this.charts.bw) {this.charts.bw.data=config.data;this.charts.bw.update('none');}
    else {this.charts.bw=new Chart(ctx,config);}
  },
  async toggleFeeds(enable) { await App.api('POST','/api/security/feeds/toggle',{enabled:enable}); this.loadData(); },
  async updateFeeds() {
    document.getElementById('btn-update-feeds').textContent='Updating...';
    await App.api('POST','/api/security/feeds/update');
    document.getElementById('btn-update-feeds').textContent='Update Feeds Now';
    this.loadData();
  },
  async blockCountry() { const cc=document.getElementById('geo-cc').value.trim(); if(!cc)return; await App.api('POST','/api/security/geoip/block',{country:cc}); document.getElementById('geo-cc').value=''; this.loadData(); },
  async unblockCountry(cc) { await App.api('POST','/api/security/geoip/unblock',{country:cc}); this.loadData(); },
  async clearGeoIP() { if(!confirm('Remove all GeoIP blocks?'))return; await App.api('POST','/api/security/geoip/clear'); this.loadData(); },
};
