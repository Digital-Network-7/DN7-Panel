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
// Render an interactive file browser into `mount`. container=null → host.
// `rootPath` (default '/') is the lowest directory the user can navigate to —
// used to root a volume browser at the volume's mountpoint.
function fileBrowser(mount, container, startPath, rootPath) {
  const root = rootPath || '/';
  let path = startPath || root;
  mount.innerHTML = `
    <div class="fb-toolbar">
      <div class="fb-pathbar" id="fbPath"></div>
      <button class="btn sm sec" id="fbMkdir">${tr('files.mkdir')}</button>
      <label class="btn sm" style="position:relative;overflow:hidden">${tr('files.upload')}<input type="file" id="fbUp" style="position:absolute;inset:0;opacity:0;cursor:pointer" /></label>
      <button class="btn sm sec" id="fbRef">${tr('files.refresh')}</button>
    </div>
    <div class="fb-list fb-scroll" id="fbList">${loading()}</div>`;
  const scope = () => (container ? { container } : {});
  const renderPath = () => {
    let rel = path;
    if (root !== '/' && (path === root || path.startsWith(root + '/'))) rel = path.slice(root.length);
    const parts = rel.split('/').filter(Boolean);
    let acc = root === '/' ? '' : root, h = `<span class="seg2" data-p="${esc(root)}">${tr('files.root')}</span>`;
    parts.forEach((seg) => { acc += '/' + seg; h += `<span class="sepc">/</span><span class="seg2" data-p="${esc(acc)}">${esc(seg)}</span>`; });
    $('fbPath').innerHTML = h;
    document.querySelectorAll('#fbPath .seg2').forEach((s) => s.onclick = () => { path = s.dataset.p; load(); });
  };
  const load = () => {
    renderPath();
    api('/api/files/list', { method: 'POST', body: JSON.stringify(Object.assign({ path }, scope())) }).then((b) => {
      const entries = b.data.entries || []; path = b.data.path || path; renderPath();
      const list = $('fbList'); list.innerHTML = '';
      if (path !== root) { const up = el('div', { class: 'fb-row' }, `<span class="fbic">↩</span><span class="nm dir">${tr('files.parent')}</span>`); up.querySelector('.nm').onclick = () => { let par = path.replace(/\/[^/]+\/?$/, '') || '/'; if (root !== '/' && par.length < root.length) par = root; path = par; load(); }; list.appendChild(up); }
      if (!entries.length && path === '/') { /* keep up row only */ }
      entries.forEach((e) => {
        const row = el('div', { class: 'fb-row' });
        const full = (path === '/' ? '' : path) + '/' + e.name;
        row.innerHTML = `<span class="fbic">${e.is_dir ? '📁' : '📄'}</span><span class="nm ${e.is_dir ? 'dir' : ''}">${esc(e.name)}</span><span class="sz">${e.is_dir ? '' : fmtBytes(e.size)}</span>`;
        const acts = el('div', { class: 'actions', style: 'margin-left:10px' });
        if (e.is_dir) { row.querySelector('.nm').onclick = () => { path = full; load(); }; }
        else { const dl = el('button', { class: 'btn sm sec' }, tr('files.download')); dl.onclick = () => downloadFile(full, container); acts.appendChild(dl); }
        const del = el('button', { class: 'btn sm danger' }, tr('files.delete')); del.onclick = async () => { const msg = e.is_dir ? tr('files.confirm_del_dir', { name: e.name }) : tr('files.confirm_del', { name: e.name }); if (await confirmDanger(msg)) api('/api/files/delete', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((er) => toast(er.message, 'err')); };
        acts.appendChild(del); row.appendChild(acts); list.appendChild(row);
      });
    }).catch((e) => { $('fbList').innerHTML = `<div class="empty err">${esc(e.message)}</div>`; });
  };
  $('fbRef').onclick = load;
  $('fbMkdir').onclick = () => modal(tr('files.mkdir'), `<label class="lbl">${tr('files.dirname')}</label><input id="mkName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="mkGo">${tr('files.create')}</button></div>`, (close) => { $('mkGo').onclick = () => { const name = $('mkName').value.trim(); if (!name) return; const full = (path === '/' ? '' : path) + '/' + name; api('/api/files/mkdir', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) }).then(() => { close(); toast(tr('common.created'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); }; });
  $('fbUp').onchange = (ev) => {
    const f = ev.target.files[0]; if (!f) return;
    const full = (path === '/' ? '' : path) + '/' + f.name;
    const qs = `path=${encodeURIComponent(full)}` + (container ? `&container=${encodeURIComponent(container)}` : '');
    toast(tr('files.uploading'));
    fetch('/api/files/upload?' + qs, { method: 'POST', headers: authHeaders(), body: f })
      .then(async (r) => { const b = await r.json().catch(() => ({})); if (!r.ok || b.ok === false) throw new Error(b.error || tr('files.upload_failed')); })
      .then(() => { toast(tr('files.uploaded'), 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
    ev.target.value = '';
  };
  load();
}
function downloadFile(full, container) {
  ticket().then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&path=${encodeURIComponent(full)}` + (container ? `&container=${encodeURIComponent(container)}` : '');
    const a = el('a', { href: '/api/files/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}
