const Settings = {
  async render() {
    App.showLoading('Loading Settings...');
    const [tfa, notif, report] = await Promise.all([
      App.api('GET','/api/settings/2fa'),
      App.api('GET','/api/settings/notifications'),
      App.api('GET','/api/settings/report'),
    ]);
    App.setPage(`
      <div class="page-header"><h2>Settings</h2></div>
      <div class="charts-grid">
        <div class="table-card">
          <h3>Two-Factor Authentication</h3>
          <div id="tfa-section"></div>
        </div>
        <div class="table-card">
          <h3>Change Password</h3>
          <div class="form-group" style="margin-bottom:10px">
            <input type="password" id="pw-current" placeholder="Current password" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;color:var(--text-primary);width:100%;margin-bottom:8px">
            <input type="password" id="pw-new" placeholder="New password" style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;color:var(--text-primary);width:100%;margin-bottom:8px">
            <button class="btn btn-primary btn-sm" id="btn-pw-change">Change Password</button>
            <span id="pw-msg" style="margin-left:10px;font-size:13px"></span>
          </div>
        </div>
      </div>
      <div class="table-card">
        <h3>Alert Notifications</h3>
        <div id="notif-section"></div>
      </div>
      <div class="table-card">
        <h3>Daily Security Report</h3>
        <div id="report-section"></div>
        <button class="btn btn-sm btn-primary" id="btn-gen-report" style="margin-top:12px">Generate Report Now</button>
      </div>`);

    document.getElementById('btn-pw-change').addEventListener('click', () => this.changePassword());
    document.getElementById('btn-gen-report').addEventListener('click', () => this.generateReport());

    this._render2FA(tfa);
    this._renderNotifications(notif);
    this._renderReport(report);
  },

  _render2FA(tfa) {
    const el = document.getElementById('tfa-section');
    if (!el) return;
    el.replaceChildren();

    if (tfa && tfa.enabled) {
      el.appendChild(App.el('div',{style:'display:flex;align-items:center;gap:10px'},[
        App.el('span',{className:'badge badge-green'},'ENABLED'),
        App.el('button',{className:'btn btn-sm btn-danger',onclick:()=>this.disable2FA()},'Disable 2FA'),
      ]));
    } else {
      el.appendChild(App.el('div',{},[
        App.el('span',{className:'badge badge-red',style:'margin-bottom:12px;display:inline-block'},'DISABLED'),
        App.el('div',{style:'margin-top:8px'},[
          App.el('button',{className:'btn btn-sm btn-primary',onclick:()=>this.setup2FA()},'Enable 2FA'),
        ]),
      ]));
    }
  },

  async setup2FA() {
    const data = await App.api('POST','/api/settings/2fa/setup');
    if (!data) return;
    const el = document.getElementById('tfa-section');
    el.replaceChildren();
    el.appendChild(App.el('div',{},[
      App.el('p',{style:'font-size:13px;margin-bottom:8px'},'Add this to your authenticator app:'),
      App.el('code',{style:'display:block;padding:10px;background:var(--bg-primary);border-radius:4px;font-size:12px;word-break:break-all;margin-bottom:12px'},data.secret),
      App.el('p',{style:'font-size:12px;color:var(--text-muted);margin-bottom:8px'},'Or scan: '+data.uri),
      App.el('input',{type:'text',id:'tfa-code',placeholder:'Enter 6-digit code',style:'background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;color:var(--text-primary);width:150px;margin-right:8px'}),
      App.el('button',{className:'btn btn-sm btn-primary',onclick:()=>this.confirm2FA(data.secret)},'Verify & Enable'),
      App.el('span',{id:'tfa-msg',style:'margin-left:10px;font-size:13px'}),
    ]));
  },

  async confirm2FA(secret) {
    const code = document.getElementById('tfa-code').value.trim();
    if (!code) return;
    const result = await App.api('POST','/api/settings/2fa/confirm',{code,secret});
    const msg = document.getElementById('tfa-msg');
    if (result && result.success) {
      msg.textContent = 'Enabled!';
      msg.style.color = 'var(--accent-green)';
      setTimeout(() => this.render(), 1000);
    } else {
      msg.textContent = result ? result.error : 'Failed';
      msg.style.color = 'var(--accent-red)';
    }
  },

  async disable2FA() {
    if (!confirm('Disable 2FA?')) return;
    await App.api('POST','/api/settings/2fa/disable');
    this.render();
  },

  async changePassword() {
    const current = document.getElementById('pw-current').value;
    const newPw = document.getElementById('pw-new').value;
    const msg = document.getElementById('pw-msg');
    if (!current || !newPw) return;
    const result = await App.api('POST','/api/settings/password',{current,new_password:newPw});
    if (result && result.success) {
      msg.textContent = 'Password changed!';
      msg.style.color = 'var(--accent-green)';
      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
    } else {
      msg.textContent = result ? result.error : 'Failed';
      msg.style.color = 'var(--accent-red)';
    }
  },

  _renderNotifications(notif) {
    const el = document.getElementById('notif-section');
    if (!el) return;
    el.replaceChildren();
    const conf = notif || {enabled:false,min_severity:'high',webhook:{enabled:false,url:''},telegram:{enabled:false,bot_token:'',chat_id:''},discord:{enabled:false,webhook_url:''}};

    const mkInput = (id, val, placeholder) => {
      const inp = App.el('input',{type:'text',id:id,placeholder:placeholder,style:'background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;color:var(--text-primary);width:100%;margin-bottom:6px;font-size:13px'});
      inp.value = val || '';
      return inp;
    };

    const form = App.el('div',{style:'font-size:13px'},[
      App.el('div',{style:'margin-bottom:12px'},[
        App.el('label',{style:'display:flex;align-items:center;gap:6px;cursor:pointer'},[
          Object.assign(App.el('input',{type:'checkbox',id:'notif-enabled'}),{checked:conf.enabled}),
          document.createTextNode('Enable notifications'),
        ]),
        App.el('div',{style:'margin-top:6px'},[
          App.el('span',{className:'text-muted'},'Min severity: '),
          Object.assign(App.el('select',{id:'notif-severity',style:'background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-primary);padding:4px;border-radius:4px'})
          ,{innerHTML:'<option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>'}),
        ]),
      ]),
      App.el('div',{style:'margin-bottom:12px;padding:12px;background:var(--bg-primary);border-radius:4px'},[
        App.el('div',{style:'font-weight:600;margin-bottom:6px'},'Webhook'),
        Object.assign(App.el('input',{type:'checkbox',id:'notif-wh-enabled'}),{checked:conf.webhook?.enabled}),
        document.createTextNode(' Enabled'),
        App.el('br'),
        mkInput('notif-wh-url', conf.webhook?.url, 'https://your-webhook-url.com/hook'),
      ]),
      App.el('div',{style:'margin-bottom:12px;padding:12px;background:var(--bg-primary);border-radius:4px'},[
        App.el('div',{style:'font-weight:600;margin-bottom:6px'},'Telegram'),
        Object.assign(App.el('input',{type:'checkbox',id:'notif-tg-enabled'}),{checked:conf.telegram?.enabled}),
        document.createTextNode(' Enabled'),
        App.el('br'),
        mkInput('notif-tg-token', conf.telegram?.bot_token, 'Bot token'),
        mkInput('notif-tg-chat', conf.telegram?.chat_id, 'Chat ID'),
      ]),
      App.el('div',{style:'margin-bottom:12px;padding:12px;background:var(--bg-primary);border-radius:4px'},[
        App.el('div',{style:'font-weight:600;margin-bottom:6px'},'Discord'),
        Object.assign(App.el('input',{type:'checkbox',id:'notif-dc-enabled'}),{checked:conf.discord?.enabled}),
        document.createTextNode(' Enabled'),
        App.el('br'),
        mkInput('notif-dc-url', conf.discord?.webhook_url, 'Discord webhook URL'),
      ]),
      App.el('button',{className:'btn btn-sm btn-primary',onclick:()=>this.saveNotifications()},'Save Notifications'),
      App.el('span',{id:'notif-msg',style:'margin-left:10px;font-size:13px'}),
    ]);
    el.appendChild(form);
    // Set severity dropdown
    setTimeout(() => {
      const sel = document.getElementById('notif-severity');
      if (sel) sel.value = conf.min_severity || 'high';
    }, 0);
  },

  async saveNotifications() {
    const config = {
      enabled: document.getElementById('notif-enabled').checked,
      min_severity: document.getElementById('notif-severity').value,
      webhook: {
        enabled: document.getElementById('notif-wh-enabled').checked,
        url: document.getElementById('notif-wh-url').value,
      },
      telegram: {
        enabled: document.getElementById('notif-tg-enabled').checked,
        bot_token: document.getElementById('notif-tg-token').value,
        chat_id: document.getElementById('notif-tg-chat').value,
      },
      discord: {
        enabled: document.getElementById('notif-dc-enabled').checked,
        webhook_url: document.getElementById('notif-dc-url').value,
      },
    };
    const result = await App.api('POST','/api/settings/notifications',config);
    const msg = document.getElementById('notif-msg');
    if (result && result.success) {
      msg.textContent = 'Saved!';
      msg.style.color = 'var(--accent-green)';
    } else {
      msg.textContent = 'Failed';
      msg.style.color = 'var(--accent-red)';
    }
  },

  _renderReport(report) {
    const el = document.getElementById('report-section');
    if (!el) return;
    el.replaceChildren();
    if (!report || !report.summary || report.summary === 'No reports generated yet') {
      el.appendChild(App.el('p',{className:'text-muted'},'No reports generated yet. Click below to generate one.'));
      return;
    }
    const s = report.summary;
    el.appendChild(App.el('div',{className:'info-grid'},[
      App.el('span',{className:'label'},'Period'), App.el('span',{className:'value'},report.period||''),
      App.el('span',{className:'label'},'Generated'), App.el('span',{className:'value'},report.generated_at||''),
      App.el('span',{className:'label'},'Total Threats'), App.el('span',{className:'value'},String(s.total_threats||0)),
      App.el('span',{className:'label'},'Unique IPs'), App.el('span',{className:'value'},String(s.unique_source_ips||0)),
      App.el('span',{className:'label'},'IPs Blocked'), App.el('span',{className:'value'},String(s.ips_blocked||0)),
      App.el('span',{className:'label'},'Suricata Alerts'), App.el('span',{className:'value'},String(s.suricata_alerts||0)),
    ]));
    if (report.ai_analysis && report.ai_analysis.summary) {
      el.appendChild(App.el('div',{style:'margin-top:12px;padding:10px;background:var(--bg-primary);border-radius:4px'},[
        App.el('div',{style:'font-weight:600;margin-bottom:4px;color:var(--accent-purple)'},'Claude Analysis'),
        App.el('p',{style:'font-size:13px'},report.ai_analysis.summary),
      ]));
    }
  },

  async generateReport() {
    document.getElementById('btn-gen-report').textContent = 'Generating...';
    const report = await App.api('POST','/api/settings/report/generate');
    document.getElementById('btn-gen-report').textContent = 'Generate Report Now';
    if (report) this._renderReport(report);
  },
};
