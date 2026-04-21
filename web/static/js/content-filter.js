/* ============================================================
   Cerberix — Content Filter Page
   ============================================================ */

const ContentFilter = {
  async render() {
    const main = document.getElementById('main-content');
    while (main.firstChild) main.removeChild(main.firstChild);
    App.showLoading(main);

    const data = await App.api('GET', '/api/content-filter/status');
    if (!data) return;

    while (main.firstChild) main.removeChild(main.firstChild);

    // Header with master toggle
    const header = App.el('div', {className: 'page-header'}, [
      App.el('div', {}, [
        App.el('h1', {}, ['Content Filter']),
        App.el('p', {className: 'text-muted'}, ['DNS-based content filtering with category blocklists']),
      ]),
      App.el('div', {style: 'display:flex;gap:10px;align-items:center'}, [
        App.el('span', {className: 'badge ' + (data.enabled ? 'badge-green' : 'badge-red')},
          [data.enabled ? 'ENABLED' : 'DISABLED']),
        App.el('button', {
          className: 'btn btn-sm ' + (data.enabled ? 'btn-danger' : 'btn-primary'),
          onclick: () => this._toggleFilter(!data.enabled),
        }, [data.enabled ? 'Disable' : 'Enable']),
        App.el('button', {className: 'btn btn-sm btn-ghost', onclick: () => this._updateLists()}, ['Update Lists']),
      ]),
    ]);
    main.appendChild(header);

    // Stats cards
    const stats = App.el('div', {className: 'stats-grid'}, [
      this._statCard('Blocked Domains', data.total_blocked_domains.toLocaleString(), 'Across all categories'),
      this._statCard('Categories', data.categories.filter(c => c.enabled).length + '/' + data.categories.length, 'Active filters'),
      this._statCard('Whitelist', data.whitelist_count.toString(), 'Allowed overrides'),
      this._statCard('Blacklist', data.blacklist_count.toString(), 'Custom blocks'),
    ]);
    main.appendChild(stats);

    // Category cards
    const catSection = App.el('div', {className: 'card', style: 'margin-top:20px'}, [
      App.el('div', {className: 'card-header'}, [
        App.el('h3', {}, ['Filter Categories']),
      ]),
      App.el('div', {className: 'card-body'}, [
        this._buildCategoryGrid(data.categories),
      ]),
    ]);
    main.appendChild(catSection);

    // Whitelist / Blacklist
    const customSection = App.el('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px'}, [
      this._buildListCard('Whitelist', 'whitelist', 'Domains that are always allowed, even if in a blocklist'),
      this._buildListCard('Blacklist', 'blacklist', 'Custom domains to block regardless of category'),
    ]);
    main.appendChild(customSection);

    // Search
    const searchResults = App.el('div', {id: 'cf-search-results', style: 'margin-top:15px'});
    const searchSection = App.el('div', {className: 'card', style: 'margin-top:20px'}, [
      App.el('div', {className: 'card-header'}, [
        App.el('h3', {}, ['Search Blocklists']),
      ]),
      App.el('div', {className: 'card-body'}, [
        App.el('div', {style: 'display:flex;gap:10px'}, [
          App.el('input', {
            type: 'text', id: 'cf-search', className: 'input',
            placeholder: 'Search for a domain...', style: 'flex:1',
            onkeydown: (e) => { if (e.key === 'Enter') this._search(); },
          }),
          App.el('button', {className: 'btn btn-primary', onclick: () => this._search()}, ['Search']),
        ]),
        searchResults,
      ]),
    ]);
    main.appendChild(searchSection);
  },

  _statCard(label, value, sub) {
    return App.el('div', {className: 'stat-card'}, [
      App.el('div', {className: 'stat-value'}, [value]),
      App.el('div', {className: 'stat-label'}, [label]),
      App.el('div', {className: 'text-muted', style: 'font-size:11px;margin-top:4px'}, [sub]),
    ]);
  },

  _buildCategoryGrid(categories) {
    const grid = App.el('div', {style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:15px'});
    for (const cat of categories) {
      const children = [
        App.el('div', {style: 'display:flex;justify-content:space-between;align-items:center'}, [
          App.el('h4', {style: 'margin:0'}, [cat.name]),
          App.el('span', {className: 'badge ' + (cat.enabled ? 'badge-green' : 'badge-muted')},
            [cat.enabled ? 'ON' : 'OFF']),
        ]),
        App.el('p', {className: 'text-muted', style: 'font-size:12px;margin:8px 0'}, [cat.description]),
        App.el('div', {style: 'display:flex;justify-content:space-between;align-items:center;margin-top:10px'}, [
          App.el('span', {className: 'text-muted', style: 'font-size:12px'},
            [cat.domain_count > 0 ? cat.domain_count.toLocaleString() + ' domains' : 'Not downloaded']),
          App.el('button', {
            className: 'btn btn-sm ' + (cat.enabled ? 'btn-danger' : 'btn-primary'),
            onclick: () => this._toggleCategory(cat.id, !cat.enabled),
          }, [cat.enabled ? 'Disable' : 'Enable']),
        ]),
      ];
      if (cat.last_updated) {
        children.push(App.el('div', {className: 'text-muted', style: 'font-size:11px;margin-top:6px'},
          ['Updated: ' + cat.last_updated]));
      }
      const card = App.el('div', {
        className: 'card',
        style: 'border:1px solid ' + (cat.enabled ? 'var(--accent)' : 'var(--border)') + ';padding:16px',
      }, children);
      grid.appendChild(card);
    }
    return grid;
  },

  _buildListCard(title, type, description) {
    const listContainer = App.el('div', {id: `cf-${type}-list`});
    const input = App.el('input', {
      type: 'text', id: `cf-${type}-input`, className: 'input',
      placeholder: 'example.com', style: 'flex:1',
      onkeydown: (e) => { if (e.key === 'Enter') this._addToList(type); },
    });
    const card = App.el('div', {className: 'card'}, [
      App.el('div', {className: 'card-header'}, [
        App.el('h3', {}, [title]),
      ]),
      App.el('div', {className: 'card-body'}, [
        App.el('p', {className: 'text-muted', style: 'font-size:12px;margin-bottom:12px'}, [description]),
        App.el('div', {style: 'display:flex;gap:8px;margin-bottom:12px'}, [
          input,
          App.el('button', {className: 'btn btn-sm btn-primary', onclick: () => this._addToList(type)}, ['Add']),
        ]),
        listContainer,
      ]),
    ]);

    this._loadList(type);
    return card;
  },

  async _loadList(type) {
    const data = await App.api('GET', `/api/content-filter/${type}`);
    if (!data) return;
    const container = document.getElementById(`cf-${type}-list`);
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);

    if (data.domains.length === 0) {
      container.appendChild(App.el('div', {className: 'text-muted', style: 'font-size:13px'}, ['No entries']));
      return;
    }

    const list = App.el('div', {style: 'max-height:200px;overflow-y:auto'});
    for (const domain of data.domains) {
      const row = App.el('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--border)'}, [
        App.el('span', {style: 'font-size:13px;font-family:monospace'}, [domain]),
        App.el('button', {
          className: 'btn btn-xs btn-danger',
          style: 'padding:2px 8px;font-size:11px',
          onclick: () => this._removeFromList(type, domain),
        }, ['Remove']),
      ]);
      list.appendChild(row);
    }
    container.appendChild(list);
  },

  async _toggleFilter(enabled) {
    await App.api('POST', '/api/content-filter/toggle', {enabled});
    this.render();
  },

  async _toggleCategory(category, enabled) {
    const main = document.getElementById('main-content');
    if (enabled) App.showLoading(main, 'Downloading blocklist...');
    await App.api('POST', '/api/content-filter/category', {category, enabled});
    this.render();
  },

  async _updateLists() {
    const main = document.getElementById('main-content');
    App.showLoading(main, 'Updating all blocklists...');
    await App.api('POST', '/api/content-filter/update');
    this.render();
  },

  async _addToList(type) {
    const input = document.getElementById(`cf-${type}-input`);
    const domain = input.value.trim();
    if (!domain) return;
    await App.api('POST', `/api/content-filter/${type}`, {domain});
    input.value = '';
    this._loadList(type);
  },

  async _removeFromList(type, domain) {
    await App.api('DELETE', `/api/content-filter/${type}/${domain}`);
    this._loadList(type);
  },

  async _search() {
    const input = document.getElementById('cf-search');
    const query = input.value.trim();
    if (!query) return;

    const container = document.getElementById('cf-search-results');
    while (container.firstChild) container.removeChild(container.firstChild);
    container.appendChild(App.el('div', {className: 'text-muted'}, ['Searching...']));

    const data = await App.api('GET', `/api/content-filter/search?q=${encodeURIComponent(query)}`);
    while (container.firstChild) container.removeChild(container.firstChild);

    if (!data || data.results.length === 0) {
      container.appendChild(App.el('div', {className: 'text-muted'}, ['No matches found']));
      return;
    }

    const table = App.el('table', {className: 'table'});
    const thead = App.el('thead', {}, [
      App.el('tr', {}, [
        App.el('th', {}, ['Domain']),
        App.el('th', {}, ['Source']),
        App.el('th', {}, ['Status']),
      ]),
    ]);
    table.appendChild(thead);

    const tbody = App.el('tbody');
    for (const r of data.results.slice(0, 25)) {
      const badgeClass = r.status === 'blocked' ? 'badge-red' : (r.status === 'allowed' || r.status === 'whitelisted') ? 'badge-green' : 'badge-muted';
      tbody.appendChild(App.el('tr', {}, [
        App.el('td', {style: 'font-family:monospace;font-size:13px'}, [r.domain]),
        App.el('td', {}, [r.source]),
        App.el('td', {}, [
          App.el('span', {className: 'badge ' + badgeClass}, [r.status]),
        ]),
      ]));
    }
    table.appendChild(tbody);
    container.appendChild(table);
  },
};
