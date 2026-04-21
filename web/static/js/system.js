const System = {
  async render() {
    App.setPage(`
      <div class="page-header"><h2>System</h2><button class="btn btn-sm" id="sys-refresh">Refresh</button></div>
      <div class="charts-grid"><div class="stat-card" id="sys-info"></div><div class="stat-card" id="sys-resources"></div></div>
      <div class="stats-grid" id="sys-services"></div>
      <div class="chart-card"><h3>Logs</h3>
        <div class="log-controls">
          <select id="log-select"><option value="firewall">Firewall</option><option value="dnsmasq">DNS/DHCP</option><option value="ai-threats">AI Threats</option><option value="ai-analysis">AI Analysis</option><option value="cerberix">System</option><option value="webui-audit">Audit</option></select>
          <button class="btn btn-sm" id="log-refresh">Refresh Log</button>
        </div>
        <pre class="code-block" id="log-output" style="max-height:400px">Select a log file...</pre>
      </div>`);
    document.getElementById('sys-refresh').addEventListener('click', () => this.loadData());
    document.getElementById('log-refresh').addEventListener('click', () => this.loadLog());
    document.getElementById('log-select').addEventListener('change', () => this.loadLog());
    await this.loadData();
    await this.loadLog();
    App.refreshTimer = setInterval(() => this.loadData(), 10000);
  },
  async loadData() {
    const [info, services] = await Promise.all([App.api('GET','/api/system/info'), App.api('GET','/api/system/services')]);
    if (info) {
      const si = document.getElementById('sys-info'); si.replaceChildren();
      si.appendChild(App.el('div',{className:'stat-label'},'System Info'));
      const grid = App.el('div',{className:'info-grid',style:'margin-top:12px'},[
        App.el('span',{className:'label'},'Hostname'), App.el('span',{className:'value'},info.hostname),
        App.el('span',{className:'label'},'Uptime'), App.el('span',{className:'value'},App.formatUptime(info.uptime_sec)),
        App.el('span',{className:'label'},'Load'), App.el('span',{className:'value'},info.cpu_load.map(l=>l.toFixed(2)).join(' / ')),
      ]);
      si.appendChild(grid);
      const ver = App.el('pre',{style:'font-size:11px;color:var(--text-muted);margin-top:12px;white-space:pre-wrap'}); ver.textContent = info.version; si.appendChild(ver);

      const sr = document.getElementById('sys-resources'); sr.replaceChildren();
      sr.appendChild(App.el('div',{className:'stat-label'},'Resources'));
      const m = info.memory, d = info.disk;
      const mc = m.pct>80?'fill-red':m.pct>60?'fill-orange':'fill-green';
      const dc = d.pct>80?'fill-red':d.pct>60?'fill-orange':'fill-green';
      const memDiv = App.el('div',{style:'margin-top:12px'},[
        App.el('div',{style:'display:flex;justify-content:space-between;font-size:13px'},[App.el('span',{},'Memory'),App.el('span',{},App.formatBytes(m.used*1024)+' / '+App.formatBytes(m.total*1024)+' ('+m.pct+'%)')]),
        App.el('div',{className:'progress-bar'},[App.el('div',{className:'fill '+mc,style:'width:'+m.pct+'%'})]),
      ]);
      const diskDiv = App.el('div',{style:'margin-top:16px'},[
        App.el('div',{style:'display:flex;justify-content:space-between;font-size:13px'},[App.el('span',{},'Disk'),App.el('span',{},App.formatBytes(d.used)+' / '+App.formatBytes(d.total)+' ('+d.pct+'%)')]),
        App.el('div',{className:'progress-bar'},[App.el('div',{className:'fill '+dc,style:'width:'+d.pct+'%'})]),
      ]);
      sr.appendChild(memDiv); sr.appendChild(diskDiv);
    }
    if (services) {
      const el = document.getElementById('sys-services'); el.replaceChildren();
      services.services.forEach(s => {
        el.appendChild(App.el('div',{className:'stat-card'},[
          App.el('div',{className:'stat-label'},s.name),
          App.el('span',{className:'badge '+(s.running?'badge-green':'badge-red')},s.running?'RUNNING':'STOPPED'),
        ]));
      });
    }
  },
  async loadLog() {
    const name = document.getElementById('log-select').value;
    const data = await App.api('GET', '/api/system/logs/' + name);
    if (data) {
      const output = document.getElementById('log-output');
      output.textContent = data.lines.join('\n') || 'Log is empty';
      output.scrollTop = output.scrollHeight;
    }
  },
};
