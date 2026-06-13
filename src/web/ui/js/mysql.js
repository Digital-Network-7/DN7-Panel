// =========================================================================
// MySQL management (DN7 Panel-provisioned instances only)
// =========================================================================

// Shared password-field widgets (eye toggle + one-tap random generator), used
// by the install dialog, the new-account dialog, and anywhere a managed
// password is entered. The generate button lives INSIDE the input, before the
// eye, so the control stays compact.
const MY_EYE = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
const MY_EYE_OFF = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9 9 0 0 1 12 4c6.5 0 10 7 10 7a13 13 0 0 1-1.67 2.4M6.6 6.6A13 13 0 0 0 2 12s3.5 7 10 7a9 9 0 0 0 3.4-.66"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M2 2l20 20"/></svg>';
const MY_DICE = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>';
function myGenPw(n) {
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const a = new Uint8Array(n);
  if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a); else for (let i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
  return Array.from(a).map((b) => cs[b % cs.length]).join('');
}
// HTML for a password field with an in-field generate button (optional) + eye.
// `vis` starts the field revealed (plain text) rather than masked.
function myPwFieldHtml(id, val, gen, vis) {
  const g = gen ? `<button type="button" class="pwf-gen" id="${id}Gen" title="${tr('my.gen_pw')}">${MY_DICE}</button>` : '';
  const type = vis ? 'text' : 'password';
  const eyeIcon = vis ? MY_EYE_OFF : MY_EYE;
  const eyeTitle = vis ? tr('set.hide') : tr('set.show');
  return `<div class="pwf${gen ? ' gen' : ''}"><input id="${id}" class="field" type="${type}" value="${esc(val || '')}" autocomplete="new-password" />${g}<button type="button" class="pwf-eye" id="${id}Eye" title="${eyeTitle}">${eyeIcon}</button></div>`;
}
// Wire the eye toggle, brief reveal-on-type, and (if present) generate button.
// `startShown` keeps the field revealed initially (matches a `vis` field HTML).
function myWirePw(id, startShown) {
  const pwi = $(id), eye = $(id + 'Eye'), gen = $(id + 'Gen');
  let shown = !!startShown, t;
  const reveal = (on) => { shown = on; pwi.type = on ? 'text' : 'password'; eye.innerHTML = on ? MY_EYE_OFF : MY_EYE; eye.title = on ? tr('set.hide') : tr('set.show'); };
  eye.onclick = () => reveal(!shown);
  pwi.addEventListener('input', () => { if (shown) return; pwi.type = 'text'; clearTimeout(t); t = setTimeout(() => { if (!shown) pwi.type = 'password'; }, 900); });
  if (gen) gen.onclick = () => { pwi.value = myGenPw(12); reveal(true); pwi.dispatchEvent(new Event('input', { bubbles: true })); };
}

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
      const dotCls = m.phase === 'initializing' ? 'init' : (running ? 'on' : '');
      v.innerHTML = `
        <div class="card" style="margin-bottom:16px">
          <div class="row" style="align-items:center">
            <div style="flex:1">
              <div style="font-size:18px;font-weight:650">${esc(m.engine)} <span class="mut" style="font-size:14px;font-weight:400">${esc(m.version || '')}</span></div>
              <div class="mut" style="font-size:12.5px;margin-top:3px">${tr('my.port')} ${m.port ? m.port : tr('my.port_unmapped')} · <span class="chip ${cls}"><span class="dot-s ${dotCls}"></span>${phase}</span></div>
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
      // Management panel — only meaningful once the server accepts queries.
      if (running && m.ready) myPanel($('myPanel'), m.id, reload);
      else if (running) myInitWait($('myPanel'), reload);
      else $('myPanel').innerHTML = `<div class="empty">${tr('my.not_running')}</div>`;
    }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}
function confirmKeepData() { return new Promise((res) => { modal(tr('my.del_title'), `<p style="margin:0 0 16px">${tr('my.del_desc')}</p><div class="row" style="justify-content:flex-end"><button class="btn sec" id="kdCancel">${tr('common.cancel')}</button><button class="btn sec" id="kdKeep">${tr('my.keep_data')}</button><button class="btn danger" id="kdDrop">${tr('my.drop_with_data')}</button></div>`, (close) => { $('kdCancel').onclick = () => { close(); res(null); }; $('kdKeep').onclick = () => { close(); res(true); }; $('kdDrop').onclick = () => { close(); res(false); }; }); }); }

// Animated "starting up" state shown while the server is running but not yet
// accepting queries (fresh init, or after a port change / version switch). It
// polls `list` and re-renders the whole view once the instance is ready.
function myInitWait(host, reload) {
  host.innerHTML = `<div class="card" style="text-align:center;padding:36px 24px">${loading(tr('my.phase_init'))}<p class="mut" style="margin-top:8px;font-size:12.5px">${tr('my.init_wait_desc')}</p></div>`;
  const tk = setInterval(() => {
    if (!document.body.contains(host)) { clearInterval(tk); return; }
    op('mysql', { op: 'list' }).then((d) => {
      const m = (d.instances || [])[0];
      if (!m || m.ready || !m.running) { clearInterval(tk); reload(); }
    }).catch(() => {});
  }, 2000);
}

function myInstall(reload) {
  // Engine + version are separate selects (default MariaDB 11.4).
  const VER = { mariadb: ['11.4', '10.11', '10.6'], mysql: ['8.4', '8.0', '5.7'] };
  const verOpts = (eng) => VER[eng].map((x, i) => `<option value="${x}"${i === 0 ? ' selected' : ''}>${x}</option>`).join('');
  modal(tr('my.create_db'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('my.engine')}</label><select id="miEngine" class="field"><option value="mariadb" selected>MariaDB</option><option value="mysql">MySQL</option></select></div>
      <div><label class="lbl">${tr('my.version')}</label><select id="miVer" class="field">${verOpts('mariadb')}</select></div>
    </div>
    <div class="formgrid" style="margin-top:12px">
      <div><label class="lbl">${tr('my.username')}</label><input id="miUser" class="field" value="root" autocomplete="off" /></div>
      <div><label class="lbl">${tr('my.password')}</label>${myPwFieldHtml('miPw', myGenPw(12), true)}</div>
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
    myWirePw('miPw');
    const syncExpose = () => { $('miPortWrap').classList.toggle('hidden', !$('miExpose').checked); };
    $('miExpose').onchange = syncExpose; syncExpose();
    $('miGo').onclick = () => {
      const engine = $('miEngine').value, version = $('miVer').value;
      const username = $('miUser').value.trim() || 'root';
      const password = $('miPw').value;
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
// Curated charset → collation options (kept small; works on both MySQL & MariaDB).
const MY_CHARSETS = {
  utf8mb4: ['utf8mb4_unicode_ci', 'utf8mb4_general_ci', 'utf8mb4_bin'],
  utf8: ['utf8_general_ci', 'utf8_unicode_ci', 'utf8_bin'],
  latin1: ['latin1_swedish_ci', 'latin1_general_ci', 'latin1_bin'],
  ascii: ['ascii_general_ci', 'ascii_bin'],
  gbk: ['gbk_chinese_ci', 'gbk_bin'],
  big5: ['big5_chinese_ci', 'big5_bin'],
};
function myColOpts(cs) { return (MY_CHARSETS[cs] || []).map((x, i) => `<option${i === 0 ? ' selected' : ''}>${x}</option>`).join(''); }

// New-database dialog: name + character set + collation.
function myNewDb(id, onDone) {
  const csOpts = Object.keys(MY_CHARSETS).map((c) => `<option${c === 'utf8mb4' ? ' selected' : ''}>${c}</option>`).join('');
  modal(tr('my.new_db'), `
    <div><label class="lbl">${tr('my.db_name')}</label><input id="cdbName" class="field" placeholder="myapp" /></div>
    <div class="formgrid" style="margin-top:12px">
      <div><label class="lbl">${tr('my.charset')}</label><select id="cdbCs" class="field">${csOpts}</select></div>
      <div><label class="lbl">${tr('my.collation')}</label><select id="cdbCol" class="field">${myColOpts('utf8mb4')}</select></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:18px"><button class="btn" id="cdbGo">${tr('my.create')}</button></div>`, (close) => {
    $('cdbCs').onchange = () => { $('cdbCol').innerHTML = myColOpts($('cdbCs').value); };
    const go = () => { const name = $('cdbName').value.trim(); if (!name) return; op('mysql', { op: 'create_database', inst: id, database: name, charset: $('cdbCs').value, collation: $('cdbCol').value }).then(() => { close(); toast(tr('common.created'), 'ok'); onDone(); }).catch((e) => toast(e.message, 'err')); };
    $('cdbGo').onclick = go;
    bindDirty('cdbGo');
    $('cdbName').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  });
}
function myDbList(id) {
  const b = $('myMBody');
  b.innerHTML = `<div class="sechead"><h3>${tr('my.tab_db')}</h3><span class="sp"></span><button class="btn sm" id="myAddDb">${tr('my.new_db')}</button></div><div id="myDbs">${loading()}</div>`;
  $('myAddDb').onclick = () => myNewDb(id, () => myDbList(id));
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
    bindDirty('ecGo');
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
function myPermGrid(dbs, cur, noHead) {
  cur = cur || {};
  const opts = (v) => `<option value="none"${!v ? ' selected' : ''}>${tr('my.priv_none')}</option><option value="ro"${v === 'ro' ? ' selected' : ''}>${tr('my.priv_ro')}</option><option value="all"${v === 'all' ? ' selected' : ''}>${tr('my.priv_all')}</option>`;
  let rows = `<tr><td>${tr('my.all_databases')}</td><td><select class="field perm-sel" data-db="*">${opts(cur['*'])}</select></td></tr>`;
  rows += dbs.map((d) => `<tr><td class="mono">${esc(d)}</td><td><select class="field perm-sel" data-db="${esc(d)}">${opts(cur[d])}</select></td></tr>`).join('');
  const head = noHead ? '' : `<div class="sechead" style="margin-top:6px"><h3>${tr('my.db_access')}</h3></div>`;
  return `${head}<table class="optable permtbl"><tr><th>${tr('my.db_name')}</th><th style="width:160px">${tr('my.permissions')}</th></tr>${rows}</table>`;
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

// New-account form: identity + password on "Basic", per-database access plus
// quick-grant shortcuts on "Permissions", and auth/limits on "Advanced".
function myUserForm(id) {
  Promise.all([op('mysql', { op: 'databases', inst: id }), op('mysql', { op: 'credentials', inst: id })]).then(([dd, cc]) => {
    const dbs = (dd.databases || []).filter((x) => !x.system).map((x) => x.name);
    const engine = cc.engine || 'mysql';
    const plugins = engine === 'mariadb'
      ? [['', tr('my.auth_default')], ['mysql_native_password', 'mysql_native_password'], ['ed25519', 'ed25519']]
      : [['', tr('my.auth_default')], ['caching_sha2_password', 'caching_sha2_password'], ['mysql_native_password', 'mysql_native_password']];
    const plugOpts = plugins.map((p) => `<option value="${p[0]}">${esc(p[1])}</option>`).join('');
    modal(tr('my.new_user'), `
      <div class="subtabs" id="auTabs"><button data-s="basic" class="on">${tr('my.tab_basic')}</button><button data-s="perm">${tr('my.permissions')}</button><button data-s="adv">${tr('my.tab_advanced')}</button></div>
      <div id="auBasic">
        <div class="formgrid">
          <div><label class="lbl">${tr('my.username')}</label><input id="auU" class="field" autocomplete="off" /></div>
          <div><label class="lbl">${tr('my.host_mode')}</label><select id="auHostMode" class="field"><option value="%">${tr('my.host_any')}</option><option value="localhost">${tr('my.host_local')}</option><option value="custom">${tr('my.host_custom')}</option></select></div>
          <div class="full hidden" id="auHostCustomWrap"><label class="lbl">${tr('my.src_host')}</label><input id="auHostCustom" class="field" placeholder="192.168.1.%" /></div>
          <div class="full"><label class="lbl">${tr('my.password')}</label>${myPwFieldHtml('auP', '', true, true)}</div>
        </div>
      </div>
      <div id="auPerm" class="hidden">
        <div class="sechead" style="margin-top:2px"><h3>${tr('my.quick_grant')}</h3></div>
        <label class="switch" style="padding:0;margin-bottom:10px"><input type="checkbox" id="auDedDb" /><span class="swbox"></span><span class="swtxt"><b>${tr('my.dedicated_db')}</b><span>${tr('my.dedicated_db_hint')}</span></span></label>
        <div class="hidden" id="auDedDbWrap" style="margin:0 0 12px 4px"><input id="auDedDbName" class="field" placeholder="myapp" style="max-width:280px" /></div>
        <label class="switch" style="padding:0"><input type="checkbox" id="auPrefix" /><span class="swbox"></span><span class="swtxt"><b>${tr('my.prefix_privs')}</b><span id="auPrefixHint">${tr('my.prefix_privs_hint', { p: '…_' })}</span></span></label>
        <div class="sechead" style="margin-top:16px"><h3>${tr('my.db_access')}</h3></div>
        ${myPermGrid(dbs, {}, true)}
      </div>
      <div id="auAdv" class="hidden">
        <div><label class="lbl">${tr('my.auth_plugin')}</label><select id="auPlugin" class="field" style="max-width:300px">${plugOpts}</select></div>
        <div class="formgrid" style="margin-top:14px">
          <div><label class="lbl">${tr('my.limit_queries')}</label><input id="auMQ" class="field" type="number" min="0" value="0" /></div>
          <div><label class="lbl">${tr('my.limit_conns')}</label><input id="auMC" class="field" type="number" min="0" value="0" /></div>
          <div><label class="lbl">${tr('my.limit_user_conns')}</label><input id="auMUC" class="field" type="number" min="0" value="0" /></div>
          <div style="display:flex;align-items:flex-end"><span class="mut" style="font-size:12px">${tr('my.limit_hint')}</span></div>
        </div>
        <label class="switch" style="padding:0;margin-top:16px"><input type="checkbox" id="auSsl" /><span class="swbox"></span><span class="swtxt">${tr('my.require_ssl')}</span></label>
      </div>
      <div class="row" style="justify-content:flex-end;margin-top:18px"><button class="btn" id="auGo">${tr('my.create')}</button></div>`, (close, root) => {
      myWirePw('auP', true);
      const tabs = root.querySelector('#auTabs');
      tabs.querySelectorAll('button').forEach((btn) => btn.onclick = () => { tabs.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === btn)); ['basic', 'perm', 'adv'].forEach((s) => root.querySelector('#au' + s.charAt(0).toUpperCase() + s.slice(1)).classList.toggle('hidden', btn.dataset.s !== s)); });
      const hostMode = $('auHostMode');
      hostMode.onchange = () => { $('auHostCustomWrap').classList.toggle('hidden', hostMode.value !== 'custom'); };
      const uIn = $('auU');
      const syncPrefix = () => { const u = uIn.value.trim() || '…'; $('auPrefixHint').textContent = tr('my.prefix_privs_hint', { p: u + '_' }); };
      uIn.addEventListener('input', () => { syncPrefix(); if ($('auDedDb').checked && !$('auDedDbName').value.trim()) $('auDedDbName').placeholder = uIn.value.trim() || 'myapp'; });
      syncPrefix();
      $('auDedDb').onchange = () => { $('auDedDbWrap').classList.toggle('hidden', !$('auDedDb').checked); if ($('auDedDb').checked) $('auDedDbName').placeholder = uIn.value.trim() || 'myapp'; };
      $('auGo').onclick = async () => {
        const user = uIn.value.trim();
        const host = hostMode.value === 'custom' ? ($('auHostCustom').value.trim() || '%') : hostMode.value;
        const pwd = $('auP').value;
        if (!user || !pwd) { toast(tr('set.fill_all'), 'err'); return; }
        const body = { op: 'create_user', inst: id, username: user, host, password: pwd };
        if ($('auPlugin').value) body.auth_plugin = $('auPlugin').value;
        body.max_queries = Number($('auMQ').value) || 0;
        body.max_connections = Number($('auMC').value) || 0;
        body.max_user_connections = Number($('auMUC').value) || 0;
        if ($('auSsl').checked) body.require_ssl = true;
        try {
          await op('mysql', body);
          await myApplyPerms(id, user, host, myReadPerms(root), {});
          if ($('auDedDb').checked) {
            const dbName = $('auDedDbName').value.trim() || user;
            await op('mysql', { op: 'create_database', inst: id, database: dbName });
            await op('mysql', { op: 'grant', inst: id, username: user, host, database: dbName, privilege: 'all' });
          }
          if ($('auPrefix').checked) await op('mysql', { op: 'grant', inst: id, username: user, host, privilege: 'all', prefix: true });
          close(); toast(tr('common.created'), 'ok'); myUsers(id);
        } catch (e) { toast(e.message, 'err'); }
      };
      bindDirty('auGo', root);
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

// ---- Settings: connection info (moved here) + engine/version + lifecycle ----
function myMore(id, reload) {
  const b = $('myMBody'); b.innerHTML = loading();
  const VER = { mariadb: ['11.4', '10.11', '10.6'], mysql: ['8.4', '8.0', '5.7'] };
  op('mysql', { op: 'credentials', inst: id }).then((c) => {
    const curEngine = c.engine || 'mysql', curVersion = c.version || '';
    const engOpts = ['mariadb', 'mysql'].map((e) => `<option value="${e}"${e === curEngine ? ' selected' : ''}>${e === 'mariadb' ? 'MariaDB' : 'MySQL'}</option>`).join('');
    const verOpts = (eng, sel) => VER[eng].map((x) => `<option value="${x}"${x === sel ? ' selected' : ''}>${x}</option>`).join('');
    b.innerHTML = `
      <div class="sechead"><h3>${tr('my.conn_info')}</h3></div>
      <table class="kvtbl">
        <tr><th style="width:130px">${tr('my.host')}</th><td class="mono">${esc(c.host || '127.0.0.1')}</td></tr>
        <tr><th>${tr('my.port')}</th><td class="mono">${c.port ? esc(String(c.port)) : `<span class="mut">${tr('my.port_unmapped')}</span>`}</td></tr>
        <tr><th>${tr('my.user')}</th><td class="mono">${esc(c.user || 'root')}</td></tr>
        <tr><th>${tr('my.password')}</th><td><span class="pwline"><span class="mono" id="myPwDisp">••••••••••••</span><button class="kveye" id="myPwEye" title="${tr('set.show')}">${MY_EYE}</button></span></td></tr>
      </table>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.engine_version')}</h3></div>
      <div class="row" style="align-items:center;gap:8px"><select id="mvEngine" class="field" style="max-width:150px">${engOpts}</select><select id="mvVer" class="field" style="max-width:130px">${verOpts(curEngine, curVersion)}</select><button class="btn sec sm" id="mvGo">${tr('my.switch_apply')}</button></div>
      <p class="mut" style="font-size:12px;margin-top:8px">${tr('my.switch_warn')}</p>
      <div class="hidden" id="mvJob" style="margin-top:12px"></div>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.reset_root')}</h3></div><div class="row"><button class="btn sec sm" id="myReset">${tr('my.reset_show')}</button></div>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.port_map')}</h3></div><div class="row" style="align-items:center"><label class="switch" style="padding:0"><input type="checkbox" id="myExpose"${c.exposed ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt">${tr('my.expose_short')}</span></label><div id="myPortWrap" style="display:flex;align-items:center;gap:8px"><label class="lbl" style="margin:0">${tr('my.ext_port_label')}</label><input id="myPort" class="field" type="number" value="${c.port || 3306}" placeholder="3306" style="max-width:130px" /></div><button class="btn sec sm" id="myPortGo">${tr('my.apply_recreate')}</button></div>
      <div class="sechead" style="margin-top:18px"><h3>${tr('my.backup')}</h3></div><div class="row"><button class="btn sec sm" id="myBackup">${tr('my.export_dump')}</button></div>
      <div id="myMoreLine" class="ok" style="margin-top:10px"></div>
      <div class="hidden" id="myBackupJob" style="margin-top:12px"></div>`;
    // Password reveal.
    let shown = false;
    $('myPwEye').onclick = () => { shown = !shown; $('myPwDisp').textContent = shown ? (c.password || '') : '••••••••••••'; $('myPwEye').innerHTML = shown ? MY_EYE_OFF : MY_EYE; $('myPwEye').title = shown ? tr('set.hide') : tr('set.show'); };
    // Engine / version switch.
    $('mvEngine').onchange = () => { $('mvVer').innerHTML = verOpts($('mvEngine').value, ''); };
    $('mvGo').onclick = async () => {
      const engine = $('mvEngine').value, version = $('mvVer').value;
      if (engine === curEngine && version === curVersion) { toast(tr('err.mysql.same_version'), 'err'); return; }
      if (!await confirmDanger(tr('my.switch_warn'))) return;
      $('mvGo').disabled = true; $('mvJob').classList.remove('hidden');
      op('mysql', { op: 'switch_version', inst: id, engine, version }).then((r) => renderJob($('mvJob'), 'mysql', r.op_id, '', { onDone: () => { toast(tr('common.applied'), 'ok'); reload(); }, onError: () => { $('mvGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('mvGo').disabled = false; });
    };
    // Port mapping — Apply only enabled when something actually changed.
    const portRow = () => ({ expose: $('myExpose').checked, port: $('myExpose').checked && $('myPort').value ? Number($('myPort').value) : null });
    const orig = { expose: !!c.exposed, port: c.port || null };
    const syncPort = () => {
      $('myPortWrap').classList.toggle('hidden', !$('myExpose').checked);
      const cur = portRow();
      $('myPortGo').disabled = (cur.expose === orig.expose && (cur.port || null) === (orig.port || null));
    };
    $('myExpose').onchange = syncPort; $('myPort').addEventListener('input', syncPort); syncPort();
    $('myReset').onclick = () => op('mysql', { op: 'reset_password', inst: id }).then((r) => { $('myMoreLine').textContent = tr('my.new_root_pw') + (r.password || ''); }).catch((e) => toast(e.message, 'err'));
    $('myPortGo').onclick = async () => {
      const cur = portRow();
      if (cur.expose === orig.expose && (cur.port || null) === (orig.port || null)) return;
      if (!await confirmDanger(tr('my.recreate_confirm'))) return;
      const body = { op: 'change_port', inst: id, expose: cur.expose };
      if (cur.expose && cur.port) body.port = cur.port;
      op('mysql', body).then(() => { toast(tr('common.applied'), 'ok'); reload(); }).catch((e) => toast(e.message, 'err'));
    };
    $('myBackup').onclick = () => { $('myBackup').disabled = true; $('myBackupJob').classList.remove('hidden'); op('mysql', { op: 'backup', inst: id }).then((r) => renderJob($('myBackupJob'), 'mysql', r.op_id, '', { onDone: () => { toast(tr('my.backup') + ' ✓', 'ok'); $('myBackup').disabled = false; }, onError: () => { $('myBackup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('myBackup').disabled = false; }); };
  }).catch((e) => { b.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
