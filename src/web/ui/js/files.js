// =========================================================================
// File browser (host + container). Reused as a tab and as a Docker modal.
// =========================================================================
function renderFiles(v) {
  v.innerHTML = '<div class="files-page" id="fbCard"></div>';
  fileBrowser($('fbCard'), null, '/');
}
function openFileBrowser(title, container) {
  modal(title, '<div id="fbModal"></div>', (close, mask) => { fileBrowser(mask.querySelector('#fbModal'), container, '/'); }, true);
}
// Render an interactive file browser into `mount`. container=null → host.
function fileBrowser(mount, container, startPath) {
  let path = startPath || '/';
  mount.innerHTML = `
    <div class="fb-toolbar">
      <div class="fb-pathbar" id="fbPath"></div>
      <button class="btn sm sec" id="fbMkdir">新建目录</button>
      <label class="btn sm" style="position:relative;overflow:hidden">上传<input type="file" id="fbUp" style="position:absolute;inset:0;opacity:0;cursor:pointer" /></label>
      <button class="btn sm sec" id="fbRef">刷新</button>
    </div>
    <div class="fb-list fb-scroll" id="fbList">${loading()}</div>`;
  const scope = () => (container ? { container } : {});
  const renderPath = () => {
    const parts = path.split('/').filter(Boolean);
    let acc = '', h = `<span class="seg2" data-p="/">根目录</span>`;
    parts.forEach((seg) => { acc += '/' + seg; h += `<span class="sepc">/</span><span class="seg2" data-p="${esc(acc)}">${esc(seg)}</span>`; });
    $('fbPath').innerHTML = h;
    document.querySelectorAll('#fbPath .seg2').forEach((s) => s.onclick = () => { path = s.dataset.p; load(); });
  };
  const load = () => {
    renderPath();
    api('/api/files/list', { method: 'POST', body: JSON.stringify(Object.assign({ path }, scope())) }).then((b) => {
      const entries = b.data.entries || []; path = b.data.path || path; renderPath();
      const list = $('fbList'); list.innerHTML = '';
      if (path !== '/') { const up = el('div', { class: 'fb-row' }, `<span class="fbic">↩</span><span class="nm dir">上级目录</span>`); up.querySelector('.nm').onclick = () => { path = path.replace(/\/[^/]+\/?$/, '') || '/'; load(); }; list.appendChild(up); }
      if (!entries.length && path === '/') { /* keep up row only */ }
      entries.forEach((e) => {
        const row = el('div', { class: 'fb-row' });
        const full = (path === '/' ? '' : path) + '/' + e.name;
        row.innerHTML = `<span class="fbic">${e.is_dir ? '📁' : '📄'}</span><span class="nm ${e.is_dir ? 'dir' : ''}">${esc(e.name)}</span><span class="sz">${e.is_dir ? '' : fmtBytes(e.size)}</span>`;
        const acts = el('div', { class: 'actions', style: 'margin-left:10px' });
        if (e.is_dir) { row.querySelector('.nm').onclick = () => { path = full; load(); }; }
        else { const dl = el('button', { class: 'btn sm sec' }, '下载'); dl.onclick = () => downloadFile(full, container); acts.appendChild(dl); }
        const del = el('button', { class: 'btn sm danger' }, '删除'); del.onclick = async () => { if (await confirmDanger(`删除 ${e.name}？`)) api('/api/files/delete', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) }).then(() => { toast('已删除', 'ok'); load(); }).catch((er) => toast(er.message, 'err')); };
        acts.appendChild(del); row.appendChild(acts); list.appendChild(row);
      });
    }).catch((e) => { $('fbList').innerHTML = `<div class="empty err">${esc(e.message)}</div>`; });
  };
  $('fbRef').onclick = load;
  $('fbMkdir').onclick = () => modal('新建目录', '<label class="lbl">目录名</label><input id="mkName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="mkGo">创建</button></div>', (close) => { $('mkGo').onclick = () => { const name = $('mkName').value.trim(); if (!name) return; const full = (path === '/' ? '' : path) + '/' + name; api('/api/files/mkdir', { method: 'POST', body: JSON.stringify(Object.assign({ path: full }, scope())) }).then(() => { close(); toast('已创建', 'ok'); load(); }).catch((e) => toast(e.message, 'err')); }; });
  $('fbUp').onchange = (ev) => {
    const f = ev.target.files[0]; if (!f) return;
    const full = (path === '/' ? '' : path) + '/' + f.name;
    const qs = `path=${encodeURIComponent(full)}` + (container ? `&container=${encodeURIComponent(container)}` : '');
    toast('上传中…');
    fetch('/api/files/upload?' + qs, { method: 'POST', headers: { 'Authorization': 'Bearer ' + S.token }, body: f })
      .then(async (r) => { const b = await r.json().catch(() => ({})); if (!r.ok || b.ok === false) throw new Error(b.error || '上传失败'); })
      .then(() => { toast('已上传', 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
    ev.target.value = '';
  };
  load();
}
function downloadFile(full, container) {
  const qs = `token=${encodeURIComponent(S.token)}&path=${encodeURIComponent(full)}` + (container ? `&container=${encodeURIComponent(container)}` : '');
  const a = el('a', { href: '/api/files/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
}
