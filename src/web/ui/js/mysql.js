// =========================================================================
// MySQL management (DN7 Panel-provisioned instances only)
// =========================================================================
function renderMysql(v) {
  v.innerHTML = `<div style="padding:8px">${loading(tr('my.detecting'))}</div>`;
  if (getJob('mysql:install')) {
    v.innerHTML = `<div class="card"><h3>${tr('my.creating')}</h3><div id="myInstallJob"></div></div>`;
    reattachJob($('myInstallJob'), 'mysql:install', { onDone: () => setTimeout(() => renderMysql(v), 800) });
    return;
  }
  op('mysql', { op: 'info' }).then((info) => {
    if (info && info.docker_ok === false) {
      v.innerHTML = `<div class="card"><h3>MySQL</h3><p class="mut">${tr('my.need_docker')}</p></div>`;
      return;
    }
    op('mysql', { op: 'list' }).then((d) => {
      const arr = d.instances || [];
      const m = arr[0];
      if (!m) {
        v.innerHTML = `<div class="card"><h3>MySQL / MariaDB</h3><p class="mut">${tr('my.none_desc')}</p><button class="btn" id="myNew">${tr('my.create_db')}</button></div>`;
        $('myNew').onclick = () => myInstall(() => renderMysql(v));
        return;
      }
      // Single-instance layout: a header card with status + lifecycle actions,
      // then the management panel (databases / accounts / SQL / settings) inline.
      const running = m.running;
      const phase = m.phase === 'initializing' ? tr('my.phase_init') : (running ? tr('my.phase_running') : tr('my.phase_stopped'));
      const cls = m.phase === 'initializing' ? 'warn' : (running ? 'on' : 'off');
      v.innerHTML = `
        <div class="card" style="margin-bottom:16px">
          <div class="row" style="align-items:center">
            <div style="flex:1">
              <div style="font-size:18px;font-weight:650">${esc(m.engine)} <span class="mut" style="font-size:14px;font-weight:400">${esc(m.version || '')}</span></div>
              <div class="mut" style="font-size:12.5px;margin-top:3px">${tr('my.port')} ${m.port ? m.port : tr('my.port_unmapped')} · <span class="chip ${cls}"><span class="dot-s ${running ? 'on' : ''}"></span>${phase}</span></div>
            </div>
            <div class="actions" id="myLifecycle"></div>
          </div>
        </div>
        <div id="myPanel"></div>`;
      const reload = () => renderMysql(v);
      const lc = $('myLifecycle');
      const mk = (label, klass, fn) => { const b = el('button', { class: 'btn sm ' + (klass || 'sec') }, label); b.onclick = fn; lc.appendChild(b); };
      if (running) {
        mk(tr('my.stop'), 'sec', () => op('mysql', { op: 'stop', inst: m.id }).then(() => { toast(tr('common.stopped'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
        mk(tr('my.restart'), 'sec', () => op('mysql', { op: 'restart', inst: m.id }).then(() => { toast(tr('common.restarted'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
      } else {
        mk(tr('my.start'), '', () => op('mysql', { op: 'start', inst: m.id }).then(() => { toast(tr('common.started'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
      }
      mk(tr('my.delete'), 'danger', async () => { const keep = await confirmKeepData(); if (keep === null) return; op('mysql', { op: 'remove', inst: m.id, keep_data: keep }).then(() => { toast(tr('common.deleted'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err')); });
      // Management panel — only meaningful when the instance can serve queries.
      if (running) myPanel($('myPanel'), m.id, reload);
      else $('myPanel').innerHTML = `<div class="empty">${tr('my.not_running')}</div>`;
    }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}
function confirmKeepData() { return new Promise((res) => { modal(tr('my.del_title'), `<p style="margin:0 0 16px">${tr('my.del_desc')}</p><div class="row" style="justify-content:flex-end"><button class="btn sec" id="kdCancel">${tr('common.cancel')}</button><button class="btn sec" id="kdKeep">${tr('my.keep_data')}</button><button class="btn danger" id="kdDrop">${tr('my.drop_with_data')}</button></div>`, (close) => { $('kdCancel').onclick = () => { close(); res(null); }; $('kdKeep').onclick = () => { close(); res(true); }; $('kdDrop').onclick = () => { close(); res(false); }; }); }); }

function myInstall(reload) {
  // Engine + version are separate selects (default MariaDB 11.4).
  const VER = { mariadb: ['11.4', '10.11', '10.6'], mysql: ['8.4', '8.0', '5.7'] };
  const EYE = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9 9 0 0 1 12 4c6.5 0 10 7 10 7a13 13 0 0 1-1.67 2.4M6.6 6.6A13 13 0 0 0 2 12s3.5 7 10 7a9 9 0 0 0 3.4-.66"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M2 2l20 20"/></svg>';
  const genPw = (n) => {
    const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const a = new Uint8Array(n);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a); else for (let i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
    return Array.from(a).map((b) => cs[b % cs.length]).join('');
  };
  const verOpts = (eng) => VER[eng].map((x, i) => `<option value="${x}"${i === 0 ? ' selected' : ''}>${x}</option>`).join('');
  modal(tr('my.create_db'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('my.engine')}</label><select id="miEngine" class="field"><option value="mariadb" selected>MariaDB</option><option value="mysql">MySQL</option></select></div>
      <div><label class="lbl">${tr('my.version')}</label><select id="miVer" class="field">${verOpts('mariadb')}</select></div>
    </div>
    <div class="formgrid" style="margin-top:12px">
      <div><label class="lbl">${tr('my.username')}</label><input id="miUser" class="field" value="root" autocomplete="off" /></div>
      <div><label class="lbl">${tr('my.password')}</label><div class="pwf"><input id="miPw" class="field" type="password" value="${genPw(12)}" autocomplete="new-password" /><button type="button" class="pwf-eye" id="miPwEye" title="${tr('set.show')}">${EYE}</button></div></div>
    </div>
    <div class="row" style="align-items:center;gap:14px;margin-top:16px">
      <label class="switch" style="padding:0"><input type="checkbox" id="miExpose" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('my.expose')}</b></span></label>
      <span class="sp" style="flex:1"></span>
      <div id="miPortWrap" style="display:flex;align-items:center;gap:8px"><label class="lbl" style="margin:0;white-space:nowrap">${tr('my.ext_port_label')}</label><input id="miPort" class="field" type="number" value="3306" placeholder="3306" style="max-width:130px" /></div>
    </div>
    <p class="mut" style="font-size:12px;margin-top:10px">${tr('my.cred_note')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="miGo">${tr('my.create')}</button></div>
    <div class="hidden" id="miJob" style="margin-top:14px"></div>`, (close) => {
    $('miEngine').onchange = () => { $('miVer').innerHTML = verOpts($('miEngine').value); };
    // Password field: hidden by default; eye toggles persistent reveal; typing
    // briefly reveals the freshly-entered characters, then re-masks.
    const pwi = $('miPw'), eye = $('miPwEye');
    let shown = false, t;
    eye.onclick = () => { shown = !shown; pwi.type = shown ? 'text' : 'password'; eye.innerHTML = shown ? EYE_OFF : EYE; eye.title = shown ? tr('set.hide') : tr('set.show'); };
    pwi.addEventListener('input', () => { if (shown) return; pwi.type = 'text'; clearTimeout(t); t = setTimeout(() => { if (!shown) pwi.type = 'password'; }, 900); });
    const syncExpose = () => { $('miPortWrap').classList.toggle('hidden', !$('miExpose').checked); };
    $('miExpose').onchange = syncExpose; syncExpose();
    $('miGo').onclick = () => {
      const engine = $('miEngine').value, version = $('miVer').value;
      const username = $('miUser').value.trim() || 'root';
      const password = pwi.value;
      if (password.length < 6 || password.length > 128) { toast(tr('set.pw_len'), 'err'); return; }
      const body = { op: 'install', engine, version, username, password, expose: $('miExpose').checked };
      if (body.expose && $('miPort').value) body.port = Number($('miPort').value);
      $('miGo').disabled = true; $('miJob').classList.remove('hidden');
      op('mysql', body).then((r) => renderJob($('miJob'), 'mysql', r.op_id, 'mysql:install', { onDone: () => { toast(tr('my.db_created'), 'ok'); close(); reload(); }, onError: () => { $('miGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('miGo').disabled = false; });
    };
  });
}


// =========================================================================
// Management panel: Databases (browse tables/columns/rows), Accounts
// (with per-database permissions), and Settings (connection info + ops).
// =========================================================================
function myPanel(host, id, reload) {
  host.innerHTML = `
    <div class="subtabs" id="myTabs"><button data-t="db" class="on">${tr('my.tab_db')}</button><button data-t="users">${tr('my.tab_users')}</button><button data-t="more">${tr('my.tab_settings')}</button></div>
    <div id="myMBody"></div>`;
  const tabs = host.querySelector('#myTabs');
  const sel = (t) => {
    tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t));
    if (t === 'db') myDbList(id);
    else if (t === 'users') myUsers(id);
    else myMore(id, reload);
  };
  tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
  sel('db');
}

// Small breadcrumb bar used inside the Databases tab while drilling in.
function myCrumb(parts) {
  // parts: [{label, fn}|{label}] — last item is the current (non-clickable) level.
  const row = el('div', { class: 'mycrumb' });
  parts.forEach((p, i) => {
    if (i) row.appendChild(el('span', { class: 'mycrumb-sep' }, '/'));
    if (p.fn) { const a = el('button', { class: 'mycrumb-link' }, esc(p.label)); a.onclick = p.fn; row.appendChild(a); }
    else row.appendChild(el('span', { class: 'mycrumb-cur' }, esc(p.label)));
  });
  return row;
}

// ---- Databases: list ----
function myDbList(id) {
  const b = $('myMBody');
  b.innerHTML = `<div class="sechead"><h3>${tr('my.tab_db')}</h3><span class="sp"></span><button class="btn sm" id="myAddDb">${tr('my.new_db')}</button></div><div id="myDbs">${loading()}</div>`;
  $('myAddDb').onclick = () => modal(tr('my.new_db'), `<label class="lbl">${tr('my.db_name')}</label><input id="cdbName" class="field" placeholder="myapp" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="cdbGo">${tr('my.create')}</button></div>`, (close) => { $('cdbGo').onclick = () => { const name = $('cdbName').value.trim(); if (!name) return; op('mysql', { op: 'create_database', inst: id, database: name }).then(() => { close(); toast(tr('common.created'), 'ok'); myDbList(id); }).catch((e) => toast(e.message, 'err')); }; $('cdbName').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('cdbGo').click(); }); });
  op('mysql', { op: 'databases', inst: id }).then((d) => {
    const arr = d.databases || [];
    if (!arr.length) { $('myDbs').innerHTML = `<div class="empty">${tr('my.none')}</div>`; return; }
    $('myDbs').innerHTML = `<table class="optable"><tr><th>${tr('my.db_name')}</th><th>${tr('my.tables')}</th><th>${tr('my.size')}</th><th class="act">${tr('my.actions')}</th></tr>` + arr.map((x) => `<tr><td>${x.system ? esc(x.name) : `<button class="linklike" data-open="${esc(x.name)}">${esc(x.name)}</button>`}${x.system ? ` <span class="mut" style="font-size:11px">${tr('my.system')}</span>` : ''}</td><td>${x.tables != null ? x.tables : '-'}</td><td class="mut">${x.bytes != null ? fmtBytes(x.bytes) : '-'}</td><td class="act"><div class="actions">${x.system ? '' : `<button class="btn sm sec" data-open="${esc(x.name)}">${tr('my.open')}</button><button class="btn sm danger" data-db="${esc(x.name)}">${tr('my.delete')}</button>`}</div></td></tr>`).join('') + '</table>';
    $('myDbs').querySelectorAll('[data-open]').forEach((n) => n.onclick = () => myTables(id, n.dataset.open));
    $('myDbs').querySelectorAll('[data-db]').forEach((btn) => btn.onclick = async () => { if (await confirmDanger(tr('my.confirm_drop_db', { db: btn.dataset.db }))) op('mysql', { op: 'drop_database', inst: id, database: btn.dataset.db }).then(() => { toast(tr('common.deleted'), 'ok'); myDbList(id); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('myDbs').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ---- Databases: tables within a database ----
function myTables(id, db) {
  const b = $('myMBody');
  b.innerHTML = '';
  b.appendChild(myCrumb([{ label: tr('my.tab_db'), fn: () => myDbList(id) }, { label: db }]));
  const body = el('div', { id: 'myTblBody' }, loading());
  b.appendChild(body);
  op('mysql', { op: 'tables', inst: id, database: db }).then((d) => {
    const arr = d.tables || [];
    if (!arr.length) { body.innerHTML = `<div class="empty">${tr('my.no_tables')}</div>`; return; }
    body.innerHTML = `<table class="optable"><tr><th>${tr('my.col_name')}</th><th>${tr('my.rows')}</th><th>${tr('my.size')}</th><th>${tr('my.engine')}</th><th class="act">${tr('my.actions')}</th></tr>` + arr.map((t) => `<tr><td><button class="linklike" data-tbl="${esc(t.name)}">${esc(t.name)}</button></td><td class="mut">${t.rows != null ? t.rows : '-'}</td><td class="mut">${t.bytes != null ? fmtBytes(t.bytes) : '-'}</td><td class="mut">${esc(t.engine || '')}</td><td class="act"><div class="actions"><button class="btn sm sec" data-tbl="${esc(t.name)}">${tr('my.open')}</button></div></td></tr>`).join('') + '</table>';
    body.querySelectorAll('[data-tbl]').forEach((n) => n.onclick = () => myTableDetail(id, db, n.dataset.tbl));
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ---- Databases: a single table (structure + data sub-tabs) ----
function myTableDetail(id, db, tbl) {
  const b = $('myMBody');
  b.innerHTML = '';
  b.appendChild(myCrumb([{ label: tr('my.tab_db'), fn: () => myDbList(id) }, { label: db, fn: () => myTables(id, db) }, { label: tbl }]));
  const sub = el('div', { class: 'subtabs', style: 'margin-top:12px' });
  sub.innerHTML = `<button data-s="struct" class="on">${tr('my.tab_structure')}</button><button data-s="data">${tr('my.tab_data')}</button>`;
  b.appendChild(sub);
  const body = el('div', { id: 'myTdBody' });
  b.appendChild(body);
  const sel = (s) => { sub.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.s === s)); if (s === 'struct') myColumns(id, db, tbl); else myRows(id, db, tbl); };
  sub.querySelectorAll('button').forEach((x) => x.onclick = () => sel(x.dataset.s));
  sel('struct');
}

// Structure: list columns with an Edit action per column.
function myColumns(id, db, tbl) {
  const body = $('myTdBody'); body.innerHTML = loading();
  op('mysql', { op: 'columns', inst: id, database: db, table: tbl }).then((d) => {
    const cols = d.columns || [];
    if (!cols.length) { body.innerHTML = `<div class="empty">${tr('my.no_columns')}</div>`; return; }
    const defv = (c) => c.default === null || c.default === undefined ? `<span class="mut">${tr('my.null')}</span>` : esc(String(c.default));
    body.innerHTML = `<table class="optable"><tr><th>${tr('my.col_name')}</th><th>${tr('my.col_type')}</th><th>${tr('my.col_null')}</th><th>${tr('my.col_key')}</th><th>${tr('my.col_default')}</th><th>${tr('my.col_extra')}</th><th class="act">${tr('my.actions')}</th></tr>` + cols.map((c, i) => `<tr><td class="mono">${esc(c.name)}</td><td class="mut mono">${esc(c.type)}</td><td>${c.nullable ? 'YES' : 'NO'}</td><td class="mut">${esc(c.key || '')}</td><td class="mut mono">${defv(c)}</td><td class="mut">${esc(c.extra || '')}</td><td class="act"><div class="actions"><button class="btn sm sec" data-i="${i}">${tr('my.edit')}</button></div></td></tr>`).join('') + '</table>';
    body.querySelectorAll('[data-i]').forEach((btn) => btn.onclick = () => myEditColumn(id, db, tbl, cols[+btn.dataset.i]));
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Edit a single column: name / type / null / default → modify_column.
function myEditColumn(id, db, tbl, col) {
  const dval = col.default === null || col.default === undefined ? '' : String(col.default);
  modal(tr('my.edit_column'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('my.col_name')}</label><input id="ecName" class="field" value="${esc(col.name)}" /></div>
      <div><label class="lbl">${tr('my.col_type')}</label><input id="ecType" class="field" value="${esc(col.type)}" /></div>
      <div><label class="lbl">${tr('my.col_default')}</label><input id="ecDef" class="field" value="${esc(dval)}" placeholder="${tr('my.null')}" /></div>
      <div style="display:flex;align-items:flex-end"><label class="switch" style="padding:0"><input type="checkbox" id="ecNull"${col.nullable ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt">${tr('my.allow_null')}</span></label></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="ecGo">${tr('set.save')}</button></div>`, (close) => {
    $('ecGo').onclick = () => {
      const body = { op: 'modify_column', inst: id, database: db, table: tbl, column: col.name, new_name: $('ecName').value.trim(), col_type: $('ecType').value.trim(), col_null: $('ecNull').checked };
      const dv = $('ecDef').value.trim(); if (dv) body.col_default = dv;
      op('mysql', body).then(() => { close(); toast(tr('my.col_saved'), 'ok'); myColumns(id, db, tbl); }).catch((e) => toast(e.message, 'err'));
    };
  });
}

// Data: preview rows (read-only) with a row-limit selector.
function myRows(id, db, tbl, limit) {
  const body = $('myTdBody'); body.innerHTML = loading();
  const lim = limit || 100;
  op('mysql', { op: 'table_rows', inst: id, database: db, table: tbl, limit: lim }).then((d) => {
    const cols = d.columns || [], rows = d.rows || [];
    const ctrl = `<div class="row" style="align-items:center;gap:10px;margin-bottom:10px"><label class="lbl" style="margin:0">${tr('my.row_limit')}</label><select id="myRowLim" class="field" style="max-width:110px"><option${lim === 100 ? ' selected' : ''}>100</option><option${lim === 200 ? ' selected' : ''}>200</option><option${lim === 500 ? ' selected' : ''}>500</option></select><span class="sp" style="flex:1"></span><span class="mut" style="font-size:12px">${tr('my.showing_rows', { n: d.limit || lim })}</span></div>`;
    if (!rows.length) { body.innerHTML = ctrl + `<div class="empty">${tr('my.no_rows')}</div>`; }
    else {
      const head = cols.map((c) => `<th>${esc(c)}</th>`).join('');
      const trs = rows.map((r) => '<tr>' + r.map((cell) => cell === null ? `<td class="mut">${tr('my.null')}</td>` : `<td class="mono">${esc(String(cell))}</td>`).join('') + '</tr>').join('');
      body.innerHTML = ctrl + `<div class="tablescroll"><table class="optable datatbl"><tr>${head}</tr>${trs}</table></div>`;
    }
    $('myRowLim').onchange = () => myRows(id, db, tbl, Number($('myRowLim').value));
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ---- Accounts: list + create (with permissions) + edit permissions ----
function myUsers(id) {
  const b = $('myMBody');
  b.innerHTML = `<div class="sechead"><h3>${tr('my.tab_users')}</h3><span class="sp"></span><button class="btn sm" id="myAddU">${tr('my.new_user')}</button></div><div id="myUList">${loading()}</div>`;
  $('myAddU').onclick = () => myUserForm(id, null);
  op('mysql', { op: 'list_users', inst: id }).then((d) => {
    const users = d.users || [];
    if (!users.length) { $('myUList').innerHTML = `<div class="empty">${tr('my.none')}</div>`; return; }
    $('myUList').innerHTML = `<table class="optable"><tr><th>${tr('my.user')}</th><th>${tr('my.host')}</th><th class="act">${tr('my.actions')}</th></tr>` + users.map((u) => `<tr><td class="mono">${esc(u.user)}</td><td class="mut">${esc(u.host)}</td><td class="act"><div class="actions">${u.system ? `<span class="mut" style="font-size:12px">${tr('my.system')}</span>` : `<button class="btn sm sec" data-perm="${esc(u.user)}" data-h="${esc(u.host)}">${tr('my.edit_perms')}</button><button class="btn sm danger" data-u="${esc(u.user)}" data-h="${esc(u.host)}">${tr('my.delete')}</button>`}</div></td></tr>`).join('') + '</table>';
    $('myUList').querySelectorAll('[data-perm]').forEach((btn) => btn.onclick = () => myUserPerms(id, btn.dataset.perm, btn.dataset.h));
    $('myUList').querySelectorAll('[data-u]').forEach((btn) => btn.onclick = async () => { if (await confirmDanger(tr('my.confirm_drop_user', { u: btn.dataset.u, h: btn.dataset.h }))) op('mysql', { op: 'drop_user', inst: id, username: btn.dataset.u, host: btn.dataset.h }).then(() => { toast(tr('common.deleted'), 'ok'); myUsers(id); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('myUList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Build a per-database permission picker. `dbs` is the list of non-system db
// names, `cur` a map of db→"all"|"ro" (plus "*" for all-databases). Returns the
// inner HTML; read selections later with myReadPerms().
function myPermGrid(dbs, cur) {
  cur = cur || {};
  const opts = (v) => `<option value="none"${!v ? ' selected' : ''}>${tr('my.priv_none')}</option><option value="ro"${v === 'ro' ? ' selected' : ''}>${tr('my.priv_ro')}</option><option value="all"${v === 'all' ? ' selected' : ''}>${tr('my.priv_all')}</option>`;
  let rows = `<tr><td>${tr('my.all_databases')}</td><td><select class="field perm-sel" data-db="*">${opts(cur['*'])}</select></td></tr>`;
  rows += dbs.map((d) => `<tr><td class="mono">${esc(d)}</td><td><select class="field perm-sel" data-db="${esc(d)}">${opts(cur[d])}</select></td></tr>`).join('');
  return `<div class="sechead" style="margin-top:6px"><h3>${tr('my.db_access')}</h3></div><table class="optable permtbl"><tr><th>${tr('my.db_name')}</th><th style="width:160px">${tr('my.permissions')}</th></tr>${rows}</table>`;
}
function myReadPerms(root) {
  const out = {};
  root.querySelectorAll('.perm-sel').forEach((s) => { out[s.dataset.db] = s.value; });
  return out;
}
// Apply a desired permission map by diffing against the current one.
async function myApplyPerms(id, user, host, desired, current) {
  current = current || {};
  const keys = new Set([...Object.keys(desired), ...Object.keys(current)]);
  for (const db of keys) {
    const want = desired[db] || 'none';
    const have = current[db] || 'none';
    if (want === have) continue;
    if (want === 'none') await op('mysql', { op: 'revoke', inst: id, username: user, host, database: db });
    else { if (have !== 'none' && have !== want) await op('mysql', { op: 'revoke', inst: id, username: user, host, database: db }); await op('mysql', { op: 'grant', inst: id, username: user, host, database: db, privilege: want }); }
  }
}

// New-account form: identity + password + initial permissions.
function myUserForm(id) {
  op('mysql', { op: 'databases', inst: id }).then((d) => {
    const dbs = (d.databases || []).filter((x) => !x.system).map((x) => x.name);
    modal(tr('my.new_user'), `
      <div class="formgrid">
        <div><label class="lbl">${tr('my.username')}</label><input id="auU" class="field" autocomplete="off" /></div>
        <div><label class="lbl">${tr('my.src_host')}</label><input id="auH" class="field" value="%" /></div>
        <div class="full"><label class="lbl">${tr('my.password')}</label><input id="auP" class="field" type="password" autocomplete="new-password" /></div>
      </div>
      ${myPermGrid(dbs, {})}
      <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="auGo">${tr('my.create')}</button></div>`, (close, root) => {
      $('auGo').onclick = async () => {
        const user = $('auU').value.trim(), host = $('auH').value.trim() || '%', pwd = $('auP').value;
        if (!user || !pwd) { toast(tr('set.fill_all'), 'err'); return; }
        try {
          await op('mysql', { op: 'create_user', inst: id, username: user, host, password: pwd });
          await myApplyPerms(id, user, host, myReadPerms(root), {});
          close(); toast(tr('common.created'), 'ok'); myUsers(id);
        } catch (e) { toast(e.message, 'err'); }
      };
    });
  }).catch((e) => toast(e.message, 'err'));
}

// Edit an existing account's per-database permissions.
function myUserPerms(id, user, host) {
  Promise.all([op('mysql', { op: 'databases', inst: id }), op('mysql', { op: 'user_grants', inst: id, username: user, host })]).then(([dd, gg]) => {
    const dbs = (dd.databases || []).filter((x) => !x.system).map((x) => x.name);
    const cur = gg.grants || {};
    modal(`${user}@${host}`, `${myPermGrid(dbs, cur)}<div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="upGo">${tr('set.save')}</button></div>`, (close, root) => {
      $('upGo').onclick = async () => {
        try { await myApplyPerms(id, user, host, myReadPerms(root), cur); close(); toast(tr('my.saved'), 'ok'); } catch (e) { toast(e.message, 'err'); }
      };
    });
  }).catch((e) => toast(e.message, 'err'));
}

// ---- Settings: connection info (moved here) + lifecycle ops ----
function myMore(id, reload) {
  const b = $('myMBody'); b.innerHTML = loading();
  const EYE = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9 9 0 0 1 12 4c6.5 0 10 7 10 7a13 13 0 0 1-1.67 2.4M6.6 6.6A13 13 0 0 0 2 12s3.5 7 10 7a9 9 0 0 0 3.4-.66"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M2 2l20 20"/></svg>';
  op('mysql', { op: 'credentials', inst: id }).then((c) => {
    b.innerHTML = `
      <div class="sechead"><h3>${tr('my.conn_info')}</h3></div>
      <table class="kvtbl">
        <tr><th style="width:130px">${tr('my.host')}</th><td class="mono">${esc(c.host || '127.0.0.1')}</td></tr>
        <tr><th>${tr('my.port')}</th><td class="mono">${c.port ? esc(String(c.port)) : `<span class="mut">${tr('my.port_unmapped')}</span>`}</td></tr>
        <tr><th>${tr('my.user')}</th><td class="mono">${esc(c.user || 'root')}</td></tr>
        <tr><th>${tr('my.password')}</th><td><span class="mono" id="myPwDisp">••••••••••••</span> <button class="pwf-eye" id="myPwEye" style="position:static;display:inline-flex;vertical-align:middle" title="${tr('set.show')}">${EYE}</button></td></tr>
      </table>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.reset_root')}</h3></div><div class="row"><button class="btn sec sm" id="myReset">${tr('my.reset_show')}</button></div>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.port_map')}</h3></div><div class="row" style="align-items:center"><label class="switch" style="padding:0"><input type="checkbox" id="myExpose"${c.exposed ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt">${tr('my.expose_short')}</span></label><div id="myPortWrap" style="display:flex;align-items:center;gap:8px"><label class="lbl" style="margin:0">${tr('my.ext_port_label')}</label><input id="myPort" class="field" type="number" value="${c.port || 3306}" placeholder="3306" style="max-width:130px" /></div><button class="btn sec sm" id="myPortGo">${tr('my.apply_recreate')}</button></div>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.backup')}</h3></div><div class="row"><button class="btn sec sm" id="myBackup">${tr('my.export_dump')}</button></div>
      <div id="myMoreLine" class="ok" style="margin-top:10px"></div>
      <div class="hidden" id="myBackupJob" style="margin-top:12px"></div>`;
    let shown = false;
    $('myPwEye').onclick = () => { shown = !shown; $('myPwDisp').textContent = shown ? (c.password || '') : '••••••••••••'; $('myPwEye').innerHTML = shown ? EYE_OFF : EYE; $('myPwEye').title = shown ? tr('set.hide') : tr('set.show'); };
    const syncExpose = () => { $('myPortWrap').classList.toggle('hidden', !$('myExpose').checked); };
    $('myExpose').onchange = syncExpose; syncExpose();
    $('myReset').onclick = () => op('mysql', { op: 'reset_password', inst: id }).then((r) => { $('myMoreLine').textContent = tr('my.new_root_pw') + (r.password || ''); }).catch((e) => toast(e.message, 'err'));
    $('myPortGo').onclick = () => { const body = { op: 'change_port', inst: id, expose: $('myExpose').checked }; if (body.expose && $('myPort').value) body.port = Number($('myPort').value); op('mysql', body).then(() => { toast(tr('common.applied'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err')); };
    $('myBackup').onclick = () => { $('myBackup').disabled = true; $('myBackupJob').classList.remove('hidden'); op('mysql', { op: 'backup', inst: id }).then((r) => renderJob($('myBackupJob'), 'mysql', r.op_id, '', { onDone: () => { toast(tr('my.backup') + ' ✓', 'ok'); $('myBackup').disabled = false; }, onError: () => { $('myBackup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('myBackup').disabled = false; }); };
  }).catch((e) => { b.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
