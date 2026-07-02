// =========================================================================
// File browser (host + container). Reused as a tab and as a Docker modal.
// =========================================================================
function renderFiles(v) {
  v.innerHTML = '<div class="files-page" id="fbCard"></div>';
  // Open at the account's home directory (root's home for the super-admin).
  const home = (Auth.me && Auth.me.home) || '/';
  fileBrowser($('fbCard'), null, home);
}
function openFileBrowser(title, container, startPath, rootPath) {
  modal(title, '<div id="fbModal"></div>', (close, mask) => { fileBrowser(mask.querySelector('#fbModal'), container, startPath || rootPath || '/', rootPath || '/'); }, true);
}

// ---- small helpers ----
// Octal mode string ("755", "1777") → rwxr-xr-x (with setuid/setgid/sticky).
function fbRwx(mode) {
  const n = parseInt(mode, 8);
  if (!mode || isNaN(n)) return '';
  let s = '';
  for (let i = 8; i >= 0; i--) s += (n >> i) & 1 ? 'rwx'[(8 - i) % 3] : '-';
  if (n & 2048) s = s.slice(0, 2) + (s[2] === 'x' ? 's' : 'S') + s.slice(3);
  if (n & 1024) s = s.slice(0, 5) + (s[5] === 'x' ? 's' : 'S') + s.slice(6);
  if (n & 512) s = s.slice(0, 8) + (s[8] === 'x' ? 't' : 'T');
  return s;
}
// Short "YYYY-MM-DD HH:MM" for the mtime column (fmtTsFull minus seconds).
function fbTs(ts) { const t = dn7TsParts(ts); return `${t.Y}-${t.M}-${t.D} ${t.h}:${t.m}`; }

// Click-toggled, body-anchored row-actions menu (reuses the .dk-pop styling).
// Escape is captured on window so it wins over an enclosing modal's handler.
function fbMenu(trigger, items) {
  // Tear down any lingering menu properly (running its cleanup) before opening a
  // new one — a bare .remove() would leak its document/window capture listeners.
  document.querySelectorAll('.dk-pop.fb-menu').forEach((p) => { if (p._cleanup) p._cleanup(); p.remove(); });
  const panel = el('div', { class: 'dk-pop fb-menu', role: 'menu' });
  let cleanup = () => {};
  const hide = (refocus) => { cleanup(); panel.remove(); if (refocus) trigger.focus(); };
  items.forEach((it) => {
    if (it.sep) { panel.appendChild(el('div', { class: 'mi-sep' })); return; }
    const b = el('button', { class: 'mi' + (it.cls ? ' ' + it.cls : ''), role: 'menuitem' });
    b.textContent = it.label;
    b.onclick = () => { hide(false); it.fn(); };
    panel.appendChild(b);
  });
  document.body.appendChild(panel);
  panel.style.visibility = 'hidden'; panel.style.display = 'flex';
  const r = trigger.getBoundingClientRect(), pw = panel.offsetWidth, ph = panel.offsetHeight;
  let left = Math.min(r.right - pw, window.innerWidth - pw - 8); if (left < 8) left = 8;
  let top = r.bottom + 4; if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 4);
  panel.style.left = left + 'px'; panel.style.top = top + 'px'; panel.style.visibility = '';
  const onDoc = (ev) => { if (!panel.contains(ev.target)) hide(false); };
  const onKey = (ev) => { if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); hide(true); } };
  document.addEventListener('mousedown', onDoc, true);
  window.addEventListener('keydown', onKey, true);
  cleanup = () => { document.removeEventListener('mousedown', onDoc, true); window.removeEventListener('keydown', onKey, true); };
  panel._cleanup = cleanup; // so a later fbMenu() can tear this one down before removing it
  const first = panel.querySelector('.mi'); if (first) first.focus();
}

// Render an interactive file browser into `mount`. container=null → host.
// `rootPath` (default '/') is the lowest directory the user can navigate to —
// used to root a volume browser at the volume's mountpoint.
function fileBrowser(mount, container, startPath, rootPath) {
  const root = rootPath || '/';
  let path = startPath || root;
  let entries = [], loadedPath = null; // cached listing → client-side sort/filter + conflict pre-check
  let sortKey = 'name', sortAsc = true, filter = '';
  mount.innerHTML = `
    <div class="fb-toolbar">
      <div class="fb-pathbar" id="fbPath"></div>
      <input class="field fb-filter" id="fbFilter" type="search" placeholder="${esc(tr('files.filter'))}" aria-label="${esc(tr('files.filter'))}" />
      <button class="btn sm sec" id="fbMkdir">${tr('files.mkdir')}</button>
      <label class="btn sm" style="position:relative;overflow:hidden">${tr('files.upload')}<input type="file" id="fbUp" multiple style="position:absolute;inset:0;opacity:0;cursor:pointer" /></label>
      <button class="btn sm sec" id="fbRef">${tr('files.refresh')}</button>
    </div>
    <div class="fb-upq" id="fbUpQ"></div>
    <div class="fb-head" id="fbHead"></div>
    <div class="fb-list fb-scroll" id="fbList">${loading()}</div>`;
  const q = (sel) => mount.querySelector(sel);
  const scope = () => (container ? { container } : {});
  const join = (dir, name) => (dir === '/' ? '' : dir) + '/' + name;
  const nav = (p) => { path = p; load(); };

  // ---- breadcrumbs (real buttons: Tab + Enter work) ----
  const renderPath = () => {
    let rel = path;
    if (root !== '/' && (path === root || path.startsWith(root + '/'))) rel = path.slice(root.length);
    const parts = rel.split('/').filter(Boolean);
    let acc = root === '/' ? '' : root, h = `<button class="seg2" data-p="${esc(root)}">${tr('files.root')}</button>`;
    parts.forEach((seg) => { acc += '/' + seg; h += `<span class="sepc">/</span><button class="seg2" data-p="${esc(acc)}">${esc(seg)}</button>`; });
    q('#fbPath').innerHTML = h;
    q('#fbPath').querySelectorAll('.seg2').forEach((s) => s.onclick = () => nav(s.dataset.p));
  };

  // ---- sortable column header (client-side; dirs always group first) ----
  const renderHead = () => {
    const arrow = (k) => (sortKey === k ? (sortAsc ? ' ▲' : ' ▼') : '');
    q('#fbHead').innerHTML = `
      <button class="fh nm" data-k="name">${tr('files.col_name')}${arrow('name')}</button>
      <span class="fh pm">${tr('files.col_perms')}</span>
      <button class="fh mt" data-k="mtime">${tr('files.col_mtime')}${arrow('mtime')}</button>
      <button class="fh sz" data-k="size">${tr('files.col_size')}${arrow('size')}</button>
      <span class="fh act"></span>`;
    q('#fbHead').querySelectorAll('button.fh').forEach((b) => b.onclick = () => {
      const k = b.dataset.k;
      if (sortKey === k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = k === 'name'; } // size/mtime open descending
      render();
    });
  };
  const FB_CMP = {
    name: (a, b) => a.name.localeCompare(b.name),
    size: (a, b) => (a.size || 0) - (b.size || 0),
    mtime: (a, b) => (a.mtime || 0) - (b.mtime || 0),
  };

  const render = () => {
    renderHead();
    const list = q('#fbList'); list.innerHTML = '';
    if (path !== root) {
      const up = el('div', { class: 'fb-row dir', tabindex: '0', role: 'button' }, `<span class="fbic">↩</span><span class="nm dir">${tr('files.parent')}</span>`);
      const goUp = () => { let par = path.replace(/\/[^/]+\/?$/, '') || '/'; if (root !== '/' && par.length < root.length) par = root; nav(par); };
      up.onclick = goUp;
      up.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); goUp(); } });
      list.appendChild(up);
    }
    const f = filter.trim().toLowerCase();
    const shown = entries.filter((e) => !f || e.name.toLowerCase().includes(f))
      .sort((a, b) => ((b.is_dir ? 1 : 0) - (a.is_dir ? 1 : 0)) || (FB_CMP[sortKey](a, b) * (sortAsc ? 1 : -1)) || a.name.localeCompare(b.name));
    if (!entries.length) list.appendChild(el('div', { class: 'empty' }, esc(tr('files.empty_dir'))));
    else if (!shown.length) list.appendChild(el('div', { class: 'empty' }, esc(tr('files.no_match'))));
    shown.forEach((e) => list.appendChild(rowFor(e)));
  };

  // ---- rows: whole row activates (click / Enter); ⋯ opens the actions menu ----
  const rowFor = (e) => {
    const full = join(path, e.name);
    const row = el('div', { class: 'fb-row' + (e.is_dir ? ' dir' : ''), tabindex: '0', role: 'button' });
    row.innerHTML = `<span class="fbic">${e.is_symlink ? '🔗' : (e.is_dir ? '📁' : '📄')}</span><span class="nm ${e.is_dir ? 'dir' : ''}">${esc(e.name)}</span><span class="pm mono" title="${esc(e.mode || '')}">${esc(fbRwx(e.mode))}</span><span class="mt" title="${e.mtime ? esc(fmtTsFull(e.mtime)) : ''}">${e.mtime ? esc(fbTs(e.mtime)) : ''}</span><span class="sz">${e.is_dir ? '' : fmtBytes(e.size)}</span>`;
    const acts = el('div', { class: 'actions' });
    const mb = el('button', { class: 'btn sm sec', 'aria-haspopup': 'menu', 'aria-label': tr('files.actions'), title: tr('files.actions') }, '⋯');
    mb.onclick = (ev) => { ev.stopPropagation(); rowMenu(mb, e, full); };
    acts.appendChild(mb); row.appendChild(acts);
    const open = () => { if (e.is_dir) nav(full); else viewFile(e, full); };
    row.onclick = (ev) => { if (!ev.target.closest('.actions')) open(); };
    row.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && ev.target === row) { ev.preventDefault(); open(); } });
    return row;
  };
  const rowMenu = (trigger, e, full) => {
    const items = [];
    if (!e.is_dir) items.push({ label: tr('files.download'), fn: () => downloadFile(full, container) });
    items.push({ label: tr('files.rename'), fn: () => renameModal(e, full) });
    items.push({ label: tr('files.move'), fn: () => moveModal(e, full) });
    items.push({ sep: true });
    items.push({ label: tr('files.delete'), cls: 'danger', fn: () => delEntry(e, full) });
    fbMenu(trigger, items);
  };
  const delEntry = async (e, full) => {
    const msg = e.is_dir ? tr('files.confirm_del_dir', { name: e.name }) : tr('files.confirm_del', { name: e.name });
    if (!(await confirmDanger(msg))) return;
    api('/api/files/delete', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) })
      .then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((er) => toast(er.message, 'err'));
  };

  // ---- rename / move (same endpoint; `to` is the full new path) ----
  const doRename = (from, to, close, msgKey) => {
    api('/api/files/rename', { method: 'POST', body: JSON.stringify(Object.assign({ path: from, to }, scope())) })
      .then(() => { close(); toast(tr(msgKey), 'ok'); load(); }).catch((er) => toast(er.message, 'err'));
  };
  const renameModal = (e, full) => {
    modal(tr('files.rename'), `<label class="lbl">${tr('files.new_name')}</label><input id="rnName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="rnGo">${tr('files.rename')}</button></div>`, (close, mask) => {
      const inp = mask.querySelector('#rnName'); inp.value = e.name;
      const go = () => {
        const name = inp.value.trim();
        if (!name || name === e.name) return;
        if (name.includes('/')) { toast(tr('files.bad_name'), 'err'); return; }
        doRename(full, join(path, name), close, 'files.renamed');
      };
      mask.querySelector('#rnGo').onclick = go;
      inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') go(); });
      setTimeout(() => { inp.focus(); inp.select(); }, 30);
    });
  };
  const moveModal = (e, full) => {
    modal(tr('files.move'), `<label class="lbl">${tr('files.move_to')}</label><input id="mvTo" class="field mono" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="mvGo">${tr('files.move')}</button></div>`, (close, mask) => {
      const inp = mask.querySelector('#mvTo'); inp.value = full;
      const go = () => {
        const to = inp.value.trim();
        if (!to || to === full) return;
        if (to[0] !== '/') { toast(tr('files.bad_dest'), 'err'); return; }
        if (root !== '/' && to !== root && !to.startsWith(root + '/')) { toast(tr('files.outside_root'), 'err'); return; }
        doRename(full, to, close, 'files.moved');
      };
      mask.querySelector('#mvGo').onclick = go;
      inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') go(); });
      setTimeout(() => inp.focus(), 30);
    });
  };

  // ---- view / edit (text ≤ 1 MiB; binary or truncated → info + download) ----
  const viewFile = (e, full) => {
    modal(e.name, `<div id="fvBody">${loading()}</div>`, (close, mask) => {
      const body = mask.querySelector('#fvBody');
      api('/api/files/read', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) }).then((b) => {
        const d = b.data || {};
        if (d.binary || d.truncated) {
          body.innerHTML = `<p class="mut" style="margin:0 0 16px">${esc(d.binary ? tr('files.binary_notice') : tr('files.truncated_notice'))}</p><div class="row" style="justify-content:flex-end"><button class="btn" id="fvDl">${tr('files.download')}</button></div>`;
          body.querySelector('#fvDl').onclick = () => downloadFile(full, container);
          return;
        }
        body.innerHTML = `<textarea id="fvTxt" class="field mono confbox" spellcheck="false"></textarea>
          <div class="row" style="justify-content:flex-end;gap:10px;margin-top:14px">
            <button class="btn sec" id="fvDl">${tr('files.download')}</button>
            <button class="btn" id="fvSave">${tr('files.save')}</button>
          </div>`;
        const ta = body.querySelector('#fvTxt'); ta.value = d.content || '';
        body.querySelector('#fvDl').onclick = () => downloadFile(full, container);
        const save = body.querySelector('#fvSave');
        const reset = bindDirty(save, body); // enable-on-change + dismiss guard for free
        save.onclick = () => {
          save.disabled = true;
          api('/api/files/write', { method: 'POST', body: JSON.stringify(Object.assign({ path: full, content: ta.value }, scope())) })
            .then(() => { toast(tr('common.saved'), 'ok'); reset(); load(); })
            .catch((er) => { toast(er.message, 'err'); save.disabled = false; });
        };
      }).catch((er) => { body.innerHTML = `<div class="empty err">${esc(er.message)}</div>`; });
    }, true);
  };

  // ---- uploads: XHR queue with real progress, conflict prompts, drag&drop ----
  const uploadFiles = async (files) => {
    const arr = Array.from(files || []);
    if (!arr.length) return;
    // Snapshot the destination dir + its listing at entry: navigating mid-upload
    // must not redirect later files to the new dir (nor pre-check against it).
    const dest = path;
    const destEntries = entries.slice();
    Busy.inc();
    try {
      for (const f of arr) {
        let ow = false;
        if (destEntries.some((x) => x.name === f.name)) { // known conflict: ask before sending
          if (!(await confirmDanger(tr('files.overwrite_confirm', { name: f.name })))) continue;
          ow = true;
        }
        const res = await sendFile(f, dest, ow);
        if (res === 'exists') { // server 409 backstop (stale listing / race)
          if (await confirmDanger(tr('files.overwrite_confirm', { name: f.name }))) await sendFile(f, dest, true);
        }
      }
    } finally { Busy.dec(); load(); }
  };
  const sendFile = (f, dest, overwrite) => new Promise((resolve) => {
    const row = el('div', { class: 'fb-uprow' });
    row.innerHTML = `<span class="upnm">${esc(f.name)}</span><div class="prog"><i></i></div><span class="pct">0%</span>`;
    const stop = el('button', { class: 'btn sm sec', 'aria-label': tr('common.cancel'), title: tr('common.cancel') }, '×');
    row.appendChild(stop);
    q('#fbUpQ').appendChild(row);
    const bar = row.querySelector('.prog > i'), pct = row.querySelector('.pct');
    const qs = `path=${encodeURIComponent(join(dest, f.name))}` + (container ? `&container=${encodeURIComponent(container)}` : '') + (overwrite ? '&overwrite=1' : '');
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files/upload?' + qs);
    const hs = authHeaders(); for (const k in hs) xhr.setRequestHeader(k, hs[k]);
    stop.onclick = () => xhr.abort();
    xhr.upload.onprogress = (ev) => { if (ev.lengthComputable && ev.total) { const p = Math.round((ev.loaded / ev.total) * 100); bar.style.width = p + '%'; pct.textContent = p + '%'; } };
    const settle = (v) => { row.remove(); resolve(v); };
    xhr.onerror = () => { toast(tr('files.upload_failed'), 'err'); settle('err'); };
    xhr.onabort = () => settle('abort');
    xhr.onload = () => {
      let b = {}; try { b = JSON.parse(xhr.responseText); } catch (er) { b = {}; }
      if (xhr.status === 409 && b.code === 'files.exists') { settle('exists'); return; }
      if (xhr.status === 401) { sessionExpired(); settle('err'); return; }
      if (xhr.status < 200 || xhr.status >= 300 || b.ok === false) { toast(srvMsg(b) || tr('files.upload_failed'), 'err'); settle('err'); return; }
      toast(tr('files.uploaded_name', { name: f.name }), 'ok'); settle('ok');
    };
    xhr.send(f);
  });
  q('#fbUp').onchange = (ev) => { uploadFiles(ev.target.files); ev.target.value = ''; };
  const listEl = q('#fbList');
  ['dragover', 'dragenter'].forEach((t) => listEl.addEventListener(t, (ev) => { ev.preventDefault(); listEl.classList.add('drop'); }));
  listEl.addEventListener('dragleave', (ev) => { if (!listEl.contains(ev.relatedTarget)) listEl.classList.remove('drop'); });
  listEl.addEventListener('drop', (ev) => { ev.preventDefault(); listEl.classList.remove('drop'); if (ev.dataTransfer && ev.dataTransfer.files.length) uploadFiles(ev.dataTransfer.files); });

  // ---- load ----
  const load = () => {
    renderPath();
    api('/api/files/list', { method: 'POST', body: JSON.stringify(Object.assign({ path }, scope())) }).then((b) => {
      entries = b.data.entries || []; path = b.data.path || path;
      if (loadedPath !== path) { filter = ''; q('#fbFilter').value = ''; } // navigating clears the filter
      loadedPath = path;
      renderPath(); render();
    }).catch((e) => { q('#fbList').innerHTML = `<div class="empty err">${esc(e.message)}</div>`; });
  };
  q('#fbFilter').addEventListener('input', (ev) => { filter = ev.target.value; render(); });
  q('#fbRef').onclick = load;
  q('#fbMkdir').onclick = () => modal(tr('files.mkdir'), `<label class="lbl">${tr('files.dirname')}</label><input id="mkName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="mkGo">${tr('files.create')}</button></div>`, (close, mask) => {
    const inp = mask.querySelector('#mkName');
    const go = () => { const name = inp.value.trim(); if (!name) return; api('/api/files/mkdir', { method: 'POST', body: JSON.stringify(Object.assign({ path: join(path, name) }, scope())) }).then(() => { close(); toast(tr('common.created'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); };
    mask.querySelector('#mkGo').onclick = go;
    inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') go(); });
    setTimeout(() => inp.focus(), 30);
  });
  load();
}
function downloadFile(full, container) {
  ticket('download').then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&path=${encodeURIComponent(full)}` + (container ? `&container=${encodeURIComponent(container)}` : '');
    const a = el('a', { href: '/api/files/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}
