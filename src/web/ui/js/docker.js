// =========================================================================
// Docker management
// =========================================================================

// Attach a host-path autocomplete dropdown to an input. As the user types an
// absolute path, we query the (read-only) docker `list_dirs` op for matching
// subdirectories and show them in a floating panel. Clicking a suggestion fills
// the value and drills deeper. Used by the volumes-tab host-path inputs.
function attachPathSuggest(input) {
  if (!input || input._pathSug) return;
  input._pathSug = true;
  let box = null, timer = null, seq = 0;
  const hide = () => { if (box) { box.remove(); box = null; } };
  const place = () => {
    if (!box) return;
    const r = input.getBoundingClientRect();
    box.style.left = r.left + 'px';
    box.style.width = Math.max(r.width, 180) + 'px';
    // Flip up if not enough room below.
    const want = Math.min(box.scrollHeight || 240, 240);
    if (r.bottom + want > window.innerHeight - 8 && r.top > want) {
      box.style.top = (r.top - want - 2) + 'px';
    } else {
      box.style.top = (r.bottom + 2) + 'px';
    }
  };
  const render = (dirs) => {
    hide();
    if (!dirs || !dirs.length) return;
    box = el('div', { class: 'pathsug' });
    dirs.forEach((d) => {
      const it = el('div', { class: 'pathsug-it' });
      it.textContent = d;
      it.onmousedown = (e) => {
        e.preventDefault();
        input.value = d;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.focus();
        query();
      };
      box.appendChild(it);
    });
    document.body.appendChild(box);
    place();
  };
  const query = () => {
    const v = input.value.trim();
    if (!v.startsWith('/')) { hide(); return; }
    const my = ++seq;
    op('docker', { op: 'list_dirs', path: v }).then((d) => {
      if (my !== seq || document.activeElement !== input) return;
      render(d && d.dirs);
    }).catch(() => {});
  };
  const debounced = () => { clearTimeout(timer); timer = setTimeout(query, 180); };
  input.addEventListener('input', debounced);
  input.addEventListener('focus', debounced);
  input.addEventListener('blur', () => setTimeout(hide, 150));
  window.addEventListener('scroll', () => { if (box) place(); }, true);
}

function renderDocker(v) {
  v.innerHTML = `<div style="padding:8px">${loading(tr('dk.detecting'))}</div>`;
  // If an install job is still running (user left + came back), re-attach.
  if (getJob('docker:install')) {
    v.innerHTML = `<div class="card"><h3>${tr('dk.installing')}</h3><div id="dkInstallJob"></div></div>`;
    reattachJob($('dkInstallJob'), 'docker:install', { onDone: () => setTimeout(() => renderDocker(v), 800) });
    return;
  }
  op('docker', { op: 'info' }).then((info) => {
    if (!info.installed) {
      v.innerHTML = `<div class="card" style="max-width:520px"><h3>Docker</h3><p class="mut">${tr('dk.not_found')}</p>
        <label class="lbl">${tr('dk.install_method')}</label>
        <select id="dkChannel" class="field" style="margin-bottom:10px">
          <option value="distro">${tr('dk.ch_distro')}</option>
          <option value="ce">${tr('dk.ch_ce')}</option>
        </select>
        <label class="lbl">${tr('dk.network_region')}</label>
        <select id="dkRegion" class="field" style="margin-bottom:14px">
          <option value="auto">${tr('dk.rg_auto')}</option>
          <option value="cn">${tr('dk.rg_cn')}</option>
          <option value="global">${tr('dk.rg_global')}</option>
        </select>
        <button class="btn" id="dkInstall">${tr('dk.install_btn')}</button>
        <div id="dkInstallJob" class="hidden" style="margin-top:14px"></div></div>`;
      $('dkInstall').onclick = () => {
        $('dkInstall').disabled = true; $('dkInstallJob').classList.remove('hidden');
        const body = { op: 'install', channel: $('dkChannel').value, region: $('dkRegion').value };
        op('docker', body).then((r) => renderJob($('dkInstallJob'), 'docker', r.op_id, 'docker:install', { onDone: () => setTimeout(() => renderDocker(v), 800), onError: () => { $('dkInstall').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('dkInstall').disabled = false; });
      };
      return;
    }
    v.innerHTML = `
      <div class="subtabs" id="dkTabs">
        <button data-t="containers" class="on">${tr('dk.tab_containers')}</button>
        <button data-t="images">${tr('dk.tab_images')}</button>
        <button data-t="volumes">${tr('dk.tab_volumes')}</button>
        <button data-t="networks">${tr('dk.tab_networks')}</button>
        <button data-t="settings">${tr('dk.tab_settings')}</button>
      </div>
      <div class="row" style="margin-bottom:14px"><span class="chip">Docker ${esc(info.server_version || '')}</span><span class="chip">API ${esc(info.client_version || '')}</span><span class="sp" style="flex:1"></span></div>
      <div id="dkBody"></div>`;
    const tabs = $('dkTabs');
    const sel = (t) => { tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); if (t === 'containers') dkContainers(); else if (t === 'images') dkImages(info); else if (t === 'volumes') dkVolumes(); else if (t === 'settings') dkSettings(); else dkNetworks(); };
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
    sel('containers');
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}

function dkContainers() {
  document.querySelectorAll('.dk-pop').forEach((p) => p.remove());
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_containers')}</h3><span class="sp"></span><button class="btn sm" id="dkNew">${tr('dk.create_container')}</button><button class="btn sec sm" id="dkRefC">${tr('dk.refresh')}</button></div><div id="dkCList">` + loading() + '</div>';
  $('dkRefC').onclick = dkContainers;
  $('dkNew').onclick = () => dkCreateForm();
  op('docker', { op: 'list_containers' }).then((d) => {
    const list = d.containers || [];
    if (!list.length) { $('dkCList').innerHTML = `<div class="empty">${tr('dk.no_containers')}</div>`; return; }
    let h = `<table class="optable ctntbl">`
      + `<colgroup><col style="width:190px"><col style="width:210px"><col style="width:120px">`
      + `<col style="width:140px"><col style="width:210px"><col style="width:230px"><col style="width:120px"><col style="width:200px"></colgroup>`
      + `<tr>`
      + `<th>${tr('dk.col_name')}</th><th>${tr('dk.col_image')}</th><th>${tr('dk.col_status')}</th>`
      + `<th>${tr('dk.col_ip')}</th><th>${tr('dk.col_ports')}</th><th>${tr('dk.col_desc')}</th>`
      + `<th>${tr('dk.col_uptime')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    list.forEach((c) => {
      const running = c.state === 'running';
      const ports = (c.ports || '').split(',').map((p) => p.trim()).filter(Boolean);
      const portCell = ports.length ? ports.map((p) => `<span class="portlbl">${esc(p)}</span>`).join(' ') : '<span class="mut">-</span>';
      const desc = c.description ? esc(c.description) : '<span class="mut">-</span>';
      const uptime = running && c.uptime ? esc(c.uptime.replace(/^Up\s+/i, '')) : '<span class="mut">-</span>';
      const builtin = c.managed ? ` <span class="chip">${tr('dk.builtin')}</span>` : '';
      h += `<tr>
        <td data-tip="${esc(c.name)}"><div class="clamp1"><b>${esc(c.name)}</b>${builtin}</div><div class="clamp1 mut mono" style="font-size:11px">${esc(c.id)}</div></td>
        <td data-tip="${esc(c.image)}"><div class="clamp2 mono" style="font-size:12px">${esc(c.image)}</div></td>
        <td><span class="statuswrap" data-id="${esc(c.id)}" data-name="${esc(c.name)}" data-state="${esc(c.state)}" data-managed="${c.managed ? 1 : 0}">${ctnStateChip(c.state)}</span></td>
        <td><div class="clamp2 mono" style="font-size:12px">${c.ip ? esc(c.ip) : '<span class="mut">-</span>'}</div></td>
        <td data-tip="${esc((c.ports || '').replace(/,\s*/g, '\n'))}"><div class="clamp2 portcell">${portCell}</div></td>
        <td data-tip="${esc(c.description || '')}"><div class="clamp2 mut" style="font-size:12px">${desc}</div></td>
        <td><div class="clamp2 mut" style="font-size:12px">${uptime}</div></td>
        <td class="act"><div class="actions" data-id="${esc(c.id)}" data-name="${esc(c.name)}" data-shell="${c.has_shell ? 1 : 0}" data-state="${esc(c.state)}" data-managed="${c.managed ? 1 : 0}"></div></td>
      </tr>`;
    });
    $('dkCList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkCList .actions').forEach((a) => buildContainerActions(a, dkContainers));
    document.querySelectorAll('#dkCList .statuswrap').forEach((s) => buildStatusControls(s, dkContainers));
    wireStickyShadows($('dkCList').querySelector('.tablewrap'));
    wireCellTips($('dkCList'));
  }).catch((e) => { $('dkCList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Toggle scroll-aware frozen-column shadows on the container table wrapper.
function wireStickyShadows(wrap) {
  if (!wrap) return;
  const upd = () => {
    wrap.classList.toggle('scl', wrap.scrollLeft > 1);
    wrap.classList.toggle('scr', wrap.scrollLeft + wrap.clientWidth < wrap.scrollWidth - 1);
  };
  wrap.addEventListener('scroll', upd, { passive: true });
  upd();
  setTimeout(upd, 60);
}

// A styled hover tooltip for clamped cells (full content) — nicer than the
// native title and reliable over clamped/ellipsised text.
function dkTipBox() {
  let t = $('dkTipBox');
  if (!t) { t = el('div', { id: 'dkTipBox', class: 'dk-tip' }); document.body.appendChild(t); }
  return t;
}
function wireCellTips(scope) {
  scope.querySelectorAll('[data-tip]').forEach((c) => {
    c.addEventListener('mouseenter', () => {
      const txt = c.getAttribute('data-tip'); if (!txt || !txt.trim()) return;
      const t = dkTipBox(); t.textContent = txt; t.style.display = 'block';
      const r = c.getBoundingClientRect();
      const tw = t.offsetWidth, th = t.offsetHeight;
      let left = Math.min(r.left, window.innerWidth - tw - 8); if (left < 8) left = 8;
      let top = r.bottom + 6; if (top + th > window.innerHeight - 8) top = Math.max(8, r.top - th - 6);
      t.style.left = left + 'px'; t.style.top = top + 'px';
    });
    c.addEventListener('mouseleave', () => { const t = $('dkTipBox'); if (t) t.style.display = 'none'; });
  });
}

// A clean state chip (decoupled from the long status text, which now feeds the
// uptime column). Colour + label reflect the lifecycle state.
function ctnStateChip(state) {
  let cls = 'off', dot = '', key = 'dk.st_stopped';
  if (state === 'running') { cls = 'on'; dot = ' on'; key = 'dk.st_running'; }
  else if (state === 'paused') { cls = 'warn'; key = 'dk.st_paused'; }
  else if (state === 'restarting') { cls = 'warn'; dot = ' init'; key = 'dk.st_restarting'; }
  else if (state === 'created') { cls = ''; key = 'dk.st_created'; }
  return `<span class="chip ${cls}"><span class="dot-s${dot}"></span>${tr(key)}</span>`;
}

// Build the lifecycle controls (start/stop/restart/force/pause/resume) shown on
// a hover panel under the status chip. Buttons depend on the container state.
function buildStatusControls(holder, reload) {
  if (holder.dataset.managed === '1') return;
  const id = holder.dataset.id, state = holder.dataset.state;
  const items = [];
  if (state === 'running') {
    items.push({ label: tr('dk.stop'), fn: () => doCAction('stop_container', id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
    items.push({ label: tr('dk.pause'), fn: () => doCAction('pause_container', id, reload) });
    items.push({ label: tr('dk.force_stop'), cls: 'danger', fn: async () => { if (await confirmDanger(tr('dk.confirm_force', { name: holder.dataset.name }))) doCAction('kill_container', id, reload); } });
  } else if (state === 'paused') {
    items.push({ label: tr('dk.resume'), cls: '', fn: () => doCAction('unpause_container', id, reload) });
    items.push({ label: tr('dk.stop'), fn: () => doCAction('stop_container', id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  } else {
    items.push({ label: tr('dk.start'), cls: '', fn: () => doCAction('start_container', id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  }
  if (!items.length) return;
  holder.style.cursor = 'pointer';
  holder.insertAdjacentHTML('beforeend', '<span class="c-caret">▾</span>');
  mkHoverPanel(holder, items);
}

function buildContainerActions(holder, reload) {
  const id = holder.dataset.id, name = holder.dataset.name, hasShell = holder.dataset.shell === '1';
  const state = holder.dataset.state, running = state === 'running';
  const managed = holder.dataset.managed === '1';
  const mk = (label, cls, fn) => { const b = el('button', { class: 'btn sm ' + (cls || 'sec') }, label); b.onclick = fn; holder.appendChild(b); };
  // DN7 Panel-managed service containers (nginx / mysql): lifecycle/edit/delete/
  // logs belong to their own pages. Only safe read-only observe actions show
  // here — Terminal, Files, Monitor — and each only when it actually applies.
  if (managed) {
    if (running && hasShell) mk(tr('dk.terminal'), '', () => openTerminalModal(tr('dk.ctn_term') + name, () => ticket().then((t) => `/api/container/terminal?ticket=${encodeURIComponent(t)}&container=${encodeURIComponent(id)}`)));
    if (running) mk(tr('dk.files'), 'sec', () => openFileBrowser(tr('dk.ctn_files') + name, id));
    if (running) mk(tr('dk.monitor'), 'sec', () => dkMonitor(id, name));
    return;
  }
  // Outermost: terminal, files, advanced (logs/networks moved into Advanced /
  // the create-edit tabs respectively).
  if (running && hasShell) mk(tr('dk.terminal'), '', () => openTerminalModal(tr('dk.ctn_term') + name, () => ticket().then((t) => `/api/container/terminal?ticket=${encodeURIComponent(t)}&container=${encodeURIComponent(id)}`)));
  if (running) mk(tr('dk.files'), 'sec', () => openFileBrowser(tr('dk.ctn_files') + name, id));
  // Advanced menu (the button itself does nothing; items show on hover).
  const adv = el('button', { class: 'btn sm sec' }, tr('dk.advanced') + ' ▾');
  holder.appendChild(adv);
  const items = [
    { label: tr('dk.logs'), fn: () => dkLogs(id, name) },
    { label: tr('dk.edit'), fn: () => dkEditForm(id, name) },
    { label: tr('dk.upgrade'), fn: () => dkUpgradeForm(id, name) },
  ];
  if (running) items.push({ label: tr('dk.monitor'), fn: () => dkMonitor(id, name) });
  items.push({ label: tr('dk.backup'), fn: () => dkBackups(id, name) });
  items.push({ label: tr('dk.rename'), fn: () => dkRenameForm(id, name, reload) });
  items.push({ label: tr('dk.commit'), fn: () => dkCommitForm(id, name) });
  items.push({ sep: true });
  items.push({ label: tr('dk.delete'), cls: 'danger', fn: async () => { if (await confirmDanger(tr('dk.confirm_rm_ctn', { name }))) doCAction('remove_container', id, reload); } });
  mkHoverPanel(adv, items);
}

// Create a body-anchored hover menu for `trigger`. Body-anchored (position:
// fixed) so it isn't clipped by the scrollable table wrapper. Items render as
// clean menu rows; `{ sep:true }` inserts a divider.
function mkHoverPanel(trigger, items) {
  const panel = el('div', { class: 'dk-pop' });
  items.forEach((it) => {
    if (it.sep) { panel.appendChild(el('div', { class: 'mi-sep' })); return; }
    const b = el('button', { class: 'mi' + (it.cls === 'danger' ? ' danger' : '') }, it.label);
    b.onclick = () => { hide(); it.fn(); };
    panel.appendChild(b);
  });
  let timer;
  const place = () => {
    document.body.appendChild(panel);
    panel.style.visibility = 'hidden'; panel.style.display = 'flex';
    const r = trigger.getBoundingClientRect();
    const pw = panel.offsetWidth, ph = panel.offsetHeight;
    let left = Math.min(r.left, window.innerWidth - pw - 8); if (left < 8) left = 8;
    // Prefer below the trigger; flip above when there isn't room at the bottom.
    let top = r.bottom + 4;
    if (top + ph > window.innerHeight - 8) {
      const above = r.top - ph - 4;
      top = above >= 8 ? above : Math.max(8, window.innerHeight - ph - 8);
    }
    panel.style.top = top + 'px';
    panel.style.left = left + 'px';
    panel.style.visibility = 'visible';
  };
  const show = () => { clearTimeout(timer); place(); };
  const hide = () => { timer = setTimeout(() => { panel.style.display = 'none'; }, 130); };
  trigger.addEventListener('mouseenter', show);
  trigger.addEventListener('mouseleave', hide);
  panel.addEventListener('mouseenter', () => clearTimeout(timer));
  panel.addEventListener('mouseleave', hide);
}

function doCAction(o, id, reload) { op('docker', { op: o, ref: id }).then(() => { toast(tr('dk.op_ok'), 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); }

function dkLogs(id, name) {
  modal(tr('dk.logs_title') + name, '<div id="dkLogWrap">' + loading() + '</div>', () => {
    op('docker', { op: 'logs', ref: id, tail: 400 }).then((d) => { $('dkLogWrap').innerHTML = '<pre class="out" id="dkLogOut" style="max-height:64vh"></pre>'; $('dkLogOut').textContent = d.logs || tr('dk.empty_log'); $('dkLogOut').scrollTop = $('dkLogOut').scrollHeight; }).catch((e) => { $('dkLogWrap').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

function dkImages(info) {
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_images')}</h3><span class="sp"></span><button class="btn sm" id="dkPull">${tr('dk.pull_image')}</button><button class="btn sm" id="dkImport">${tr('dk.img_import')}</button><button class="btn sec sm" id="dkRefI">${tr('dk.refresh')}</button></div><div id="dkIList">` + loading() + '</div>';
  $('dkRefI').onclick = () => dkImages(info);
  $('dkPull').onclick = dkPullForm;
  $('dkImport').onclick = () => dkImportForm(info);
  op('docker', { op: 'list_images' }).then((d) => {
    const list = d.images || [];
    if (!list.length) { $('dkIList').innerHTML = `<div class="empty">${tr('dk.no_images')}</div>`; return; }
    let h = `<table class="optable"><tr><th>${tr('dk.col_image')}</th><th>${tr('dk.col_size')}</th><th>${tr('dk.col_created')}</th><th>${tr('dk.img_referenced')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    list.forEach((im) => {
      const ref = im.in_use
        ? `<span class="chip on"><span class="dot-s on"></span>${tr('ng.yes')}</span>`
        : `<span class="chip">${tr('ng.no')}</span>`;
      const delBtn = im.managed
        ? `<button class="btn sm danger" data-rmbuiltin="1">${tr('dk.delete')}</button>`
        : im.in_use
          ? `<button class="btn sm danger" data-rmused="1">${tr('dk.delete')}</button>`
          : `<button class="btn sm danger" data-rm="${esc(im.name)}">${tr('dk.delete')}</button>`;
      const acts = `<div class="actions"><button class="btn sm sec" data-dl="${esc(im.name)}">${tr('dk.img_download')}</button>${delBtn}</div>`;
      h += `<tr><td class="mono" style="font-size:12px">${esc(im.name)}</td><td>${esc(im.size)}</td><td class="mut">${esc(im.created)}</td><td>${ref}</td>
        <td class="act">${acts}</td></tr>`;
    });
    $('dkIList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkIList [data-dl]').forEach((b) => b.onclick = () => dkImageDownload(b.dataset.dl));
    document.querySelectorAll('#dkIList [data-rmbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.img_builtin_block'), 'err'));
    document.querySelectorAll('#dkIList [data-rmused]').forEach((b) => b.onclick = () => toast(tr('dk.img_in_use_block'), 'err'));
    document.querySelectorAll('#dkIList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_img', { name: b.dataset.rm }))) op('docker', { op: 'remove_image', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkImages(info); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkIList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Trigger an image export (`docker save`) download via a one-time ticket.
function dkImageDownload(name) {
  ticket().then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&kind=image&ref=${encodeURIComponent(name)}`;
    const a = el('a', { href: '/api/docker/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}

// Import a local image archive (the output of `docker save`, optionally gzipped)
// by uploading it straight into the daemon's load API.
function dkImportForm(info) {
  modal(tr('dk.img_import'), `
    <label class="lbl">${tr('dk.img_import_label')}</label>
    <input id="iiFile" type="file" accept=".tar,.tar.gz,.tgz,.gz" class="field" />
    <p class="formnote" style="margin-top:6px">${tr('dk.img_import_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="iiGo">${tr('dk.img_import_btn')}</button></div>
    <div class="hidden" id="iiJob" style="margin-top:12px"></div>`, (close) => {
    $('iiGo').onclick = async () => {
      const f = $('iiFile').files[0]; if (!f) return toast(tr('dk.img_need_file'), 'err');
      $('iiGo').disabled = true; $('iiJob').classList.remove('hidden'); $('iiJob').innerHTML = `<div class="mut">${tr('dk.img_importing')}</div>`;
      try {
        const headers = S.token ? { Authorization: 'Bearer ' + S.token } : {};
        const r = await fetch('/api/docker/image-upload', { method: 'POST', headers, body: f });
        const b = await r.json().catch(() => ({}));
        if (!r.ok || (b && b.ok === false)) throw new Error(srvMsg(b) || ('HTTP ' + r.status));
        toast(tr('dk.img_imported'), 'ok'); close(); dkImages(info);
      } catch (e) { toast(e.message, 'err'); $('iiGo').disabled = false; $('iiJob').innerHTML = ''; }
    };
    bindDirty('iiGo');
  });
}

function dkPullForm() {
  modal(tr('dk.pull_image'), `
    <label class="lbl">${tr('dk.img_name_label')}</label>
    <div class="row" style="gap:8px;margin-bottom:12px"><select id="plReg" class="field" style="max-width:180px"><option value="">Docker Hub</option></select><input id="plImg" class="field" placeholder="nginx:latest" style="flex:1" /></div>
    <div id="plMirrorWrap"><label class="lbl">${tr('dk.mirror_label')}</label>
    <select id="plMirror" class="field" style="margin-bottom:16px"><option value="">${tr('dk.mirror_none')}</option></select></div>
    <div class="row" style="justify-content:flex-end"><button class="btn" id="plGo">${tr('dk.pull_start')}</button></div>
    <div class="hidden" id="plJob" style="margin-top:14px"></div>`, (close) => {
    // Load configured mirrors + private registries.
    op('docker', { op: 'get_settings' }).then((s) => {
      (s.mirrors || []).forEach((m) => { const o = document.createElement('option'); o.value = m; o.textContent = m; $('plMirror').appendChild(o); });
      (s.registries || []).forEach((r) => { const o = document.createElement('option'); o.value = r; o.textContent = r; $('plReg').appendChild(o); });
    }).catch(() => {});
    // Mirrors only apply to Docker Hub; hide them when a private registry is picked.
    $('plReg').onchange = () => $('plMirrorWrap').classList.toggle('hidden', !!$('plReg').value);
    $('plGo').onclick = () => {
      const image = $('plImg').value.trim(); if (!image) return toast(tr('dk.need_image_name'), 'err');
      const registry = $('plReg').value || undefined;
      const mirror = registry ? undefined : ($('plMirror').value || undefined);
      $('plGo').disabled = true; $('plJob').classList.remove('hidden');
      op('docker', { op: 'pull_image', image, mirror, registry }).then((r) => renderJob($('plJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.pull_done'), 'ok'); close(); if (S.tab === 'docker') renderDocker($('view')); }, onError: () => { $('plGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('plGo').disabled = false; });
    };
    bindDirty('plGo');
  });
}

// ---- Volumes tab ----
function dkVolumes() {
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_volumes')}</h3><span class="sp"></span><button class="btn sm" id="dkVolNew">${tr('dk.vol_new')}</button><button class="btn sec sm" id="dkRefV">${tr('dk.refresh')}</button></div><div id="dkVList">${loading()}</div>`;
  $('dkRefV').onclick = dkVolumes;
  $('dkVolNew').onclick = () => modal(tr('dk.vol_new'), `<label class="lbl">${tr('dk.vol_name')}</label><input id="dvName" class="field" placeholder="myapp-data" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="dvGo">${tr('dk.create')}</button></div>`, (close) => { $('dvGo').onclick = () => { const name = $('dvName').value.trim(); if (!name) return; op('docker', { op: 'create_volume', name }).then(() => { close(); toast(tr('common.created'), 'ok'); dkVolumes(); }).catch((e) => toast(e.message, 'err')); }; bindDirty('dvGo'); });
  op('docker', { op: 'list_volumes' }).then((d) => {
    const list = d.volumes || [];
    if (!list.length) { $('dkVList').innerHTML = `<div class="empty">${tr('dk.no_volumes')}</div>`; return; }
    let h = `<table class="optable"><tr><th>${tr('dk.vol_name')}</th><th>${tr('dk.col_size')}</th><th>${tr('dk.vol_refs')}</th><th>${tr('dk.vol_mount')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    list.forEach((v) => {
      const act = v.managed ? `<span class="chip">${tr('dk.builtin')}</span>` : `<div class="actions"><button class="btn sm danger" data-rm="${esc(v.name)}">${tr('dk.delete')}</button></div>`;
      h += `<tr><td><b>${esc(v.name)}</b></td><td>${esc(v.size)}</td><td class="mut">${v.refs >= 0 ? v.refs : '-'}</td><td class="mono mut" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(v.mountpoint)}">${esc(v.mountpoint)}</td><td class="act">${act}</td></tr>`;
    });
    $('dkVList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkVList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_vol', { name: b.dataset.rm }))) op('docker', { op: 'remove_volume', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkVolumes(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkVList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function dkCreateForm() {
  // Fetch host capacity (CPU/mem caps), networks and volumes up front so the
  // Resources / Network / Volumes tabs can be populated.
  Promise.all([
    op('docker', { op: 'info' }).catch(() => ({})),
    op('docker', { op: 'list_networks' }).catch(() => ({ networks: [] })),
    op('docker', { op: 'list_volumes' }).catch(() => ({ volumes: [] })),
  ]).then(([info, nd, vd]) => dkCreateModal(info || {}, (nd && nd.networks) || [], { volumes: (vd && vd.volumes) || [] }));
}

function dkCreateModal(info, networks, opts) {
  opts = opts || {};
  const prefill = opts.prefill || null;
  const hostCpus = Number(info.host_cpus) || 0;
  const hostMem = Number(info.host_mem_bytes) || 0;
  const cpuMax = hostCpus > 0 ? hostCpus : 2;
  const memMaxMb = hostMem > 0 ? (hostMem / 1048576) : 0;
  const memMaxTxt = memMaxMb > 0 ? memMaxMb.toFixed(2) + 'MB' : '';
  const vols = opts.volumes || [];
  // Eligible networks (bridge included once; host/none excluded). A container
  // can join several, but never the same network twice — selects only offer
  // networks not already chosen by another row.
  const netList = networks.filter((n) => n.name !== 'host' && n.name !== 'none')
    .map((n) => ({ name: n.name, subnet: n.subnet || '' }));
  const volOpts = `<option value="">${tr('dk.vol_pick')}</option>` + vols.map((v) => `<option value="${esc(v.name)}">${esc(v.name)}</option>`).join('');
  modal(opts.title || tr('dk.create_container'), `
    <div class="subtabs" id="ccTabs">
      <button data-s="basic" class="on">${tr('dk.tab_basic')}</button>
      <button data-s="net">${tr('dk.tab_networks')}</button>
      <button data-s="ports">${tr('dk.tab_ports')}</button>
      <button data-s="vol">${tr('dk.tab_volumes')}</button>
      <button data-s="res">${tr('dk.tab_resources')}</button>
      <button data-s="env">${tr('dk.tab_env')}</button>
    </div>
    <div id="ccBasic">
      <div class="formgrid">
        <div class="full"><label class="lbl">${tr('dk.image')}</label><select id="ccImg" class="field"><option value="">${tr('dk.image_ph')}</option></select></div>
        <div><label class="lbl">${tr('dk.ctn_name')}</label><input id="ccName" class="field" placeholder="my-app" /></div>
        <div><label class="lbl">${tr('dk.restart_policy')}</label><select id="ccRestart" class="field"><option value="unless-stopped">unless-stopped</option><option value="always">always</option><option value="no">no</option></select></div>
        <div class="full"><label class="lbl">${tr('dk.start_cmd')}</label><input id="ccCmd" class="field" placeholder="${tr('dk.cmd_ph')}" /></div>
      </div>
      <div class="switchrow" style="margin-top:10px">
        <label class="switch"><input type="checkbox" id="ccStdin" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.alloc_stdin')}</b><span>${tr('dk.alloc_stdin_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccTty" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.alloc_tty')}</b><span>${tr('dk.alloc_tty_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccStart" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.start_after')}</b><span>${tr('dk.start_after_d')}</span></span></label>
      </div>
      <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="ccGo">${opts.submitLabel || tr('dk.create')}</button></div>
      <div class="hidden" id="ccJob" style="margin-top:14px"></div>
    </div>
    <div id="ccNet" class="hidden">
      <label class="lbl">${tr('dk.net_join')}</label>
      <div class="kvlist" id="ccNets"></div>
      <button type="button" class="kvadd" id="ccNetAdd">${tr('dk.net_add')}</button>
      <p class="formnote" style="margin-top:8px">${tr('dk.net_static_hint')}</p>
      <div class="formgrid" style="margin-top:16px">
        <div><label class="lbl">${tr('dk.hostname')}</label><input id="ccHost" class="field" placeholder="web-01" /></div>
        <div><label class="lbl">${tr('dk.domainname')}</label><input id="ccDomain" class="field" placeholder="example.com" /></div>
        <div class="full"><label class="lbl">${tr('dk.dns')}</label><input id="ccDns" class="field mono" placeholder="1.1.1.1 8.8.8.8" /><p class="formnote" style="margin-top:5px">${tr('dk.dns_hint')}</p></div>
      </div>
    </div>
    <div id="ccPortsT" class="hidden">
      <label class="lbl">${tr('dk.port_map')}</label><div class="kvlist" id="ccPorts"></div><button type="button" class="kvadd" id="ccPortsAdd">${tr('dk.add_port')}</button>
    </div>
    <div id="ccVolT" class="hidden">
      <label class="lbl">${tr('dk.volumes')}</label><div class="kvlist" id="ccVol"></div><button type="button" class="kvadd" id="ccVolAdd">${tr('dk.add_vol')}</button>
    </div>
    <div id="ccRes" class="hidden">
      <div class="formgrid res3">
        <div><label class="lbl">${tr('dk.cpu_weight')}</label><input id="ccCpuShares" class="field" type="number" min="0" value="1024" /><p class="formnote" style="margin-top:5px">${tr('dk.cpu_weight_hint')}</p></div>
        <div><label class="lbl">${tr('dk.cpu_limit')}</label><div class="field-suffix"><input id="ccCpus" class="field" type="number" min="0" max="${cpuMax}" step="0.1" value="0" /><span class="suffix-tag">${tr('dk.unit_core')}</span></div><p class="formnote" style="margin-top:5px">${tr('dk.cpu_limit_hint', { n: cpuMax })}</p></div>
        <div><label class="lbl">${tr('dk.mem_limit')}</label><div class="field-suffix"><input id="ccMem" class="field" type="number" min="0" value="0" /><button type="button" class="suffix-btn" id="ccMemUnit">MB</button></div><p class="formnote" style="margin-top:5px" id="ccMemHint"></p></div>
      </div>
      <label class="switch" style="margin-top:12px"><input type="checkbox" id="ccPriv" /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.privileged')}</b><span>${tr('dk.privileged_d')}</span></span></label>
    </div>
    <div id="ccEnvT" class="hidden">
      <label class="lbl">${tr('dk.env')}</label><div class="kvlist" id="ccEnv"></div><button type="button" class="kvadd" id="ccEnvAdd">${tr('dk.add_env')}</button>
    </div>`, (close, root) => {
    loadImageOptions(prefill ? prefill.image : undefined);    // Tab switching.
    const panes = { basic: 'ccBasic', net: 'ccNet', ports: 'ccPortsT', vol: 'ccVolT', res: 'ccRes', env: 'ccEnvT' };
    const tabs = root.querySelector('#ccTabs');
    tabs.querySelectorAll('button').forEach((btn) => btn.onclick = () => {
      tabs.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === btn));
      Object.keys(panes).forEach((s) => root.querySelector('#' + panes[s]).classList.toggle('hidden', btn.dataset.s !== s));
    });
    // Dynamic row helpers.
    const portRow = (v) => kvRow('ccPorts', [
      { ph: tr('dk.host_port'), val: v && v.h }, { sep: '→' }, { ph: tr('dk.container_port'), val: v && v.c },
    ], { proto: true, protoVal: v && v.proto, ipv6: true, ipv6Val: v && v.ipv6 });
    const envRow = (v) => kvRow('ccEnv', [
      { ph: 'KEY', val: v && v.k, flex: '0 0 34%' }, { sep: '=' }, { ph: 'VALUE', val: v && v.v, flex: '1 1 auto' },
    ]);
    // Volume row: source is a host path or a docker named volume (toggle), then
    // the container path.
    const volRow = (v) => {
      const row = el('div', { class: 'kvrow volrow' });
      row.innerHTML = `<select class="vr-type field"><option value="host">${tr('dk.vol_src_host')}</option><option value="vol">${tr('dk.vol_src_vol')}</option></select>`
        + `<input class="vr-host field" placeholder="/data/app" />`
        + `<select class="vr-vol field hidden">${volOpts}</select>`
        + `<span class="sep">→</span>`
        + `<input class="vr-ctn field" placeholder="/app" />`
        + `<label class="ro"><input type="checkbox" class="vr-ro" /> ${tr('dk.readonly')}</label>`
        + `<button type="button" class="rm">×</button>`;
      const type = row.querySelector('.vr-type'), host = row.querySelector('.vr-host'), vsel = row.querySelector('.vr-vol');
      const syncType = () => { const isVol = type.value === 'vol'; host.classList.toggle('hidden', isVol); vsel.classList.toggle('hidden', !isVol); };
      type.onchange = syncType;
      if (v) {
        const isVol = v.host && !v.host.startsWith('/');
        type.value = isVol ? 'vol' : 'host';
        if (isVol) vsel.value = v.host; else host.value = v.host || '';
        row.querySelector('.vr-ctn').value = v.container || '';
        if (v.readonly) row.querySelector('.vr-ro').checked = true;
      }
      syncType();
      attachPathSuggest(host);
      row.querySelector('.rm').onclick = () => row.remove();
      $('ccVol').appendChild(row);
    };
    const readVolumes = () => Array.from($('ccVol').querySelectorAll('.volrow')).map((r) => {
      const isVol = r.querySelector('.vr-type').value === 'vol';
      const src = isVol ? r.querySelector('.vr-vol').value : r.querySelector('.vr-host').value.trim();
      return { host: src, container: r.querySelector('.vr-ctn').value.trim(), readonly: r.querySelector('.vr-ro').checked };
    }).filter((vv) => vv.host && vv.container);
    $('ccPortsAdd').onclick = () => portRow();
    $('ccEnvAdd').onclick = () => envRow();
    $('ccVolAdd').onclick = () => volRow();
    // Network tab: a container can join several networks (never the same one
    // twice). Each row is a network pick + optional MAC (auto-random) + optional
    // static IPv4 (auto from the chosen network's subnet). The random generators
    // sit inside the inputs.
    const usedNets = () => Array.from($('ccNets').querySelectorAll('.nr-net')).map((s) => s.value);
    // Re-prune every select so it only offers networks not chosen elsewhere, and
    // hide the add button once every eligible network is taken.
    const refreshNetUI = () => {
      const used = usedNets();
      Array.from($('ccNets').querySelectorAll('.netrow')).forEach((row) => {
        const sel = row.querySelector('.nr-net');
        const cur = sel.value;
        sel.innerHTML = netList.filter((n) => n.name === cur || !used.includes(n.name))
          .map((n) => `<option value="${esc(n.name)}" data-subnet="${esc(n.subnet)}">${esc(n.name)}</option>`).join('');
        sel.value = cur;
      });
      const remaining = netList.filter((n) => !used.includes(n.name));
      $('ccNetAdd').style.display = remaining.length ? '' : 'none';
    };
    const netRow = (v) => {
      const used = usedNets();
      const def = (v && v.network) || ((netList.find((n) => !used.includes(n.name)) || netList[0] || {}).name) || '';
      const row = el('div', { class: 'netrow' });
      const allOpts = netList.map((n) => `<option value="${esc(n.name)}" data-subnet="${esc(n.subnet)}">${esc(n.name)}</option>`).join('');
      row.innerHTML = `<select class="nr-net field">${allOpts}</select>`
        + `<div class="ifield"><input class="nr-mac field mono" placeholder="${tr('dk.mac_addr')}" /><button type="button" class="ifield-btn nr-macgen" title="${tr('dk.gen_random')}">${MY_DICE}</button></div>`
        + `<div class="ifield"><input class="nr-ip field mono" placeholder="${tr('dk.ipv4_addr')}" /><button type="button" class="ifield-btn nr-ipgen" title="${tr('dk.gen_random')}">${MY_DICE}</button></div>`
        + `<button type="button" class="rm">×</button>`;
      const sel = row.querySelector('.nr-net'), mac = row.querySelector('.nr-mac'), ip = row.querySelector('.nr-ip');
      if (def) sel.value = def;
      mac.value = (v && v.mac) || randMac();
      const subnet = () => { const o = sel.options[sel.selectedIndex]; return o ? (o.dataset.subnet || '') : ''; };
      if (v && v.ipv4) ip.value = v.ipv4;
      else if (v && v.genip) { const g = randIpFromSubnet(subnet()); if (g) ip.value = g; }
      sel.onchange = () => { if (!ip.value) { const g = randIpFromSubnet(subnet()); if (g) ip.value = g; } refreshNetUI(); };
      row.querySelector('.nr-macgen').onclick = () => { mac.value = randMac(); mac.dispatchEvent(new Event('input', { bubbles: true })); };
      row.querySelector('.nr-ipgen').onclick = () => { const g = randIpFromSubnet(subnet()); if (g) { ip.value = g; ip.dispatchEvent(new Event('input', { bubbles: true })); } else toast(tr('dk.ipv4_need_subnet'), 'err'); };
      row.querySelector('.rm').onclick = () => { row.remove(); refreshNetUI(); };
      $('ccNets').appendChild(row);
      refreshNetUI();
    };
    $('ccNetAdd').onclick = () => netRow();
    const readNetworks = () => Array.from($('ccNets').querySelectorAll('.netrow')).map((r) => ({
      network: r.querySelector('.nr-net').value,
      mac: r.querySelector('.nr-mac').value.trim() || undefined,
      ipv4: r.querySelector('.nr-ip').value.trim() || undefined,
    })).filter((n) => n.network);
    // Memory unit (MB/GB) toggle.
    let memUnit = 'MB';
    const updMemHint = () => {
      const max = memMaxMb > 0 ? (memUnit === 'GB' ? (memMaxMb / 1024).toFixed(2) + 'GB' : memMaxMb.toFixed(0) + 'MB') : '';
      $('ccMemHint').textContent = max ? tr('dk.mem_limit_hint', { n: max }) : tr('dk.mem_limit_off');
    };
    $('ccMemUnit').onclick = () => { memUnit = memUnit === 'MB' ? 'GB' : 'MB'; $('ccMemUnit').textContent = memUnit; updMemHint(); $('ccMem').dispatchEvent(new Event('input', { bubbles: true })); };
    updMemHint();
    // Pre-fill from an existing container (edit / upgrade).
    if (prefill) {
      const cfg = prefill;
      const applyImg = () => {
        const sel = $('ccImg');
        if (cfg.image && !Array.from(sel.options).some((o) => o.value === cfg.image)) {
          const o = document.createElement('option'); o.value = cfg.image; o.textContent = cfg.image; sel.appendChild(o);
        }
        if (cfg.image) sel.value = cfg.image;
      };
      applyImg(); setTimeout(applyImg, 80);
      $('ccName').value = cfg.name || '';
      $('ccRestart').value = cfg.restart || 'unless-stopped';
      $('ccCmd').value = cfg.command || '';
      $('ccTty').checked = !!cfg.tty;
      $('ccStdin').checked = !!cfg.interactive;
      $('ccStart').checked = true;
      (cfg.ports || []).forEach((p) => portRow({ h: p.host, c: p.container, proto: p.proto, ipv6: p.ipv6 }));
      (cfg.env || []).forEach((e) => { const i = e.indexOf('='); envRow({ k: i >= 0 ? e.slice(0, i) : e, v: i >= 0 ? e.slice(i + 1) : '' }); });
      (cfg.volumes || []).forEach((v) => volRow({ host: v.host, container: v.container, readonly: v.readonly }));
      (cfg.networks || []).forEach((n) => netRow(n));
      $('ccHost').value = cfg.hostname || '';
      $('ccDomain').value = cfg.domainname || '';
      $('ccDns').value = (cfg.dns || []).join(' ');
      $('ccCpuShares').value = cfg.cpu_shares ? cfg.cpu_shares : 1024;
      $('ccCpus').value = cfg.cpus ? Number(cfg.cpus) : 0;
      $('ccMem').value = cfg.memory ? Math.round(Number(cfg.memory) / 1048576) : 0;
      $('ccPriv').checked = !!cfg.privileged;
    } else {
      // New container: pre-add the default bridge network with a random MAC and
      // a random IPv4 so the row reflects Docker's default attachment.
      netRow({ network: 'bridge', genip: true });
    }
    const doSubmit = () => {
      const image = $('ccImg').value.trim(); if (!image) return toast(tr('dk.need_image'), 'err');
      const ports = readKv('ccPorts').map((r) => ({ host: Number(r[0]), container: Number(r[1]), proto: r.proto || 'tcp', ipv6: r.ipv6 || undefined })).filter((p) => p.host && p.container);
      const env = readKv('ccEnv').map((r) => (r[0] ? r[0] + '=' + (r[1] || '') : '')).filter(Boolean);
      const volumes = readVolumes();
      const networks = readNetworks();
      const dns = $('ccDns').value.trim().split(/[\s,]+/).filter(Boolean);
      const cpuShares = Number($('ccCpuShares').value) || 0;
      const cpusV = Number($('ccCpus').value) || 0;
      const memV = Number($('ccMem').value) || 0;
      const body = {
        op: 'create_container', image, name: $('ccName').value.trim() || undefined, restart: $('ccRestart').value,
        ports, env, volumes, command: $('ccCmd').value.trim() || undefined, tty: $('ccTty').checked, interactive: $('ccStdin').checked, start: $('ccStart').checked,
        networks,
        hostname: $('ccHost').value.trim() || undefined, domainname: $('ccDomain').value.trim() || undefined,
        dns: dns.length ? dns : undefined, cpu_shares: cpuShares || undefined,
        cpus: cpusV > 0 ? String(cpusV) : undefined, memory: memV > 0 ? memV + (memUnit === 'GB' ? 'g' : 'm') : undefined,
        privileged: $('ccPriv').checked || undefined,
      };
      if (opts.replaceName) body.replace = opts.replaceName;
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden');
      op('docker', body).then((r) => renderJob($('ccJob'), 'docker', r.op_id, '', { onDone: () => { toast(opts.doneMsg || tr('dk.ctn_created'), 'ok'); close(); switchTab('docker'); }, onError: () => { $('ccGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ccGo').disabled = false; });
    };
    $('ccGo').onclick = () => {
      if (opts.confirmMsg) { confirmDanger(opts.confirmMsg).then((ok) => { if (ok) doSubmit(); }); } else doSubmit();
    };
    bindDirty('ccGo', root);
  }, true);
}

// Generate a locally-administered random unicast MAC (02:xx:xx:xx:xx:xx).
function randMac() {
  const h = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  return ['02', h(), h(), h(), h(), h()].join(':');
}

// Suggest a random host address inside an IPv4 subnet (last octet 2–251).
// Editable by the user; only a convenience for user-defined networks.
function randIpFromSubnet(subnet) {
  if (!subnet || subnet.indexOf('/') < 0) return '';
  const base = subnet.split('/')[0].split('.');
  if (base.length !== 4) return '';
  base[3] = String(2 + Math.floor(Math.random() * 250));
  return base.join('.');
}

// Human-readable byte size + epoch-second timestamp helpers (monitor/backups).
function dkHuman(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + u[i];
}
function dkFmtTime(secs) { return secs ? new Date(secs * 1000).toLocaleString() : '-'; }

// ---- Edit (recreate with new config) ----
function dkEditForm(id, name) {
  Promise.all([
    op('docker', { op: 'info' }).catch(() => ({})),
    op('docker', { op: 'list_networks' }).catch(() => ({ networks: [] })),
    op('docker', { op: 'list_volumes' }).catch(() => ({ volumes: [] })),
    op('docker', { op: 'get_container_config', ref: id }),
  ]).then(([info, nd, vd, cd]) => {
    dkCreateModal(info || {}, (nd && nd.networks) || [], {
      volumes: (vd && vd.volumes) || [],
      prefill: cd.config || {}, replaceName: name,
      title: tr('dk.edit') + ' · ' + name, submitLabel: tr('dk.save'),
      confirmMsg: tr('dk.edit_confirm'), doneMsg: tr('dk.edited'),
    });
  }).catch((e) => toast(e.message, 'err'));
}

// ---- Upgrade (recreate keeping config, only the image changes) ----
function dkUpgradeForm(id, name) {
  op('docker', { op: 'get_container_config', ref: id }).then((d) => {
    const cfg = d.config || {};
    modal(tr('dk.upgrade') + ' · ' + name, `
      <p class="mut" style="margin:0 0 12px">${tr('dk.upgrade_cur')}: <span class="mono">${esc(cfg.image || '')}</span></p>
      <label class="lbl">${tr('dk.upgrade_target')}</label>
      <select id="ugImg" class="field" style="margin-bottom:8px"></select>
      <input id="ugImgText" class="field mono" placeholder="nginx:latest" style="margin-bottom:6px" />
      <p class="formnote">${tr('dk.upgrade_hint')}</p>
      <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="ugGo">${tr('dk.upgrade')}</button></div>
      <div class="hidden" id="ugJob" style="margin-top:12px"></div>`, (close) => {
      op('docker', { op: 'list_images' }).then((im) => {
        const names = (im.images || []).map((x) => x.name).filter((n) => n && n !== '<none>:<none>');
        $('ugImg').innerHTML = `<option value="">${tr('dk.upgrade_pick')}</option>` + names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
      }).catch(() => {});
      $('ugImg').onchange = () => { if ($('ugImg').value) $('ugImgText').value = $('ugImg').value; $('ugImgText').dispatchEvent(new Event('input', { bubbles: true })); };
      $('ugGo').onclick = () => {
        const target = $('ugImgText').value.trim() || $('ugImg').value.trim();
        if (!target) return toast(tr('dk.need_image'), 'err');
        confirmDanger(tr('dk.upgrade_confirm')).then((ok) => {
          if (!ok) return;
          const body = Object.assign({}, cfg, { op: 'create_container', image: target, name, replace: name, start: true });
          $('ugGo').disabled = true; $('ugJob').classList.remove('hidden');
          op('docker', body).then((r) => renderJob($('ugJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.upgraded'), 'ok'); close(); switchTab('docker'); }, onError: () => { $('ugGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ugGo').disabled = false; });
        });
      };
      bindDirty('ugGo');
    });
  }).catch((e) => toast(e.message, 'err'));
}

// ---- Rename ----
function dkRenameForm(id, name, reload) {
  modal(tr('dk.rename') + ' · ' + name, `<label class="lbl">${tr('dk.new_name')}</label><input id="rnName" class="field" value="${esc(name)}" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="rnGo">${tr('dk.rename')}</button></div>`, (close) => {
    $('rnGo').onclick = () => { const nn = $('rnName').value.trim(); if (!nn) return; op('docker', { op: 'rename_container', ref: id, new_name: nn }).then(() => { close(); toast(tr('dk.renamed'), 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); };
    bindDirty('rnGo');
  });
}

// ---- Commit container to image ----
function dkCommitForm(id, name) {
  modal(tr('dk.commit') + ' · ' + name, `
    <div class="formgrid">
      <div><label class="lbl">${tr('dk.commit_repo')}</label><input id="cmRepo" class="field" placeholder="my-image" value="${esc(name)}" /></div>
      <div><label class="lbl">${tr('dk.commit_tag')}</label><input id="cmTag" class="field" placeholder="latest" value="latest" /></div>
    </div>
    <p class="formnote" style="margin-top:8px">${tr('dk.commit_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="cmGo">${tr('dk.commit')}</button></div>`, (close) => {
    $('cmGo').onclick = () => {
      const repo = $('cmRepo').value.trim(); if (!repo) return toast(tr('dk.need_image_name'), 'err');
      op('docker', { op: 'commit_container', ref: id, repo, tag: $('cmTag').value.trim() || 'latest' }).then((r) => { close(); toast(tr('dk.committed', { image: r.image || '' }), 'ok'); }).catch((e) => toast(e.message, 'err'));
    };
  });
}

// ---- Monitor (live CPU / memory / network / block IO) ----
function dkMonitor(id, name) {
  modal(tr('dk.monitor') + ' · ' + name, `<div id="monBody">${loading()}</div>`, (close, root) => {
    let stop = false;
    const renderMon = (s) => {
      const cpu = s.cpu_pct || 0;
      const memPct = s.mem_limit > 0 ? (s.mem_used / s.mem_limit * 100) : 0;
      $('monBody').innerHTML = `
        <div class="mongrid">
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_cpu')}</div>
            <div class="mon-big">${cpu.toFixed(1)}<span class="mon-unit">%</span></div>
            <div class="mon-sub">${tr('dk.mon_cores', { n: s.cpu_online || 1 })}</div>
            <div class="mon-bar ${cpu > 85 ? 'warn' : ''}"><i style="width:${Math.min(100, cpu).toFixed(1)}%"></i></div>
          </div>
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_mem')}</div>
            <div class="mon-big">${dkHuman(s.mem_used)}<span class="mon-pct">${memPct.toFixed(1)}%</span></div>
            <div class="mon-sub">/ ${dkHuman(s.mem_limit)}</div>
            <div class="mon-bar ${memPct > 85 ? 'warn' : ''}"><i style="width:${Math.min(100, memPct).toFixed(1)}%"></i></div>
          </div>
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_net')}</div>
            <div class="mon-duo">
              <div><div class="mon-io-k"><span class="mon-arrow dn">↓</span>${tr('dk.mon_rx')}</div><div class="mon-io-v">${dkHuman(s.net_rx)}</div></div>
              <div><div class="mon-io-k"><span class="mon-arrow up">↑</span>${tr('dk.mon_tx')}</div><div class="mon-io-v">${dkHuman(s.net_tx)}</div></div>
            </div>
          </div>
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_blk')}</div>
            <div class="mon-duo">
              <div><div class="mon-io-k">${tr('dk.mon_read')}</div><div class="mon-io-v">${dkHuman(s.blk_read)}</div></div>
              <div><div class="mon-io-k">${tr('dk.mon_write')}</div><div class="mon-io-v">${dkHuman(s.blk_write)}</div></div>
            </div>
          </div>
        </div>
        <p class="formnote" style="margin-top:14px">${tr('dk.mon_hint')}</p>`;
    };
    const tick = () => {
      if (stop || !document.body.contains(root)) { stop = true; return; }
      op('docker', { op: 'container_stats', ref: id }).then(renderMon).catch((e) => { if ($('monBody')) $('monBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; })
        .finally(() => { if (!stop && document.body.contains(root)) setTimeout(tick, 2000); });
    };
    tick();
  });
}

// ---- Backups (commit + save to tar.gz; history, download, restore) ----
function dkBackups(id, name) {
  modal(tr('dk.backup') + ' · ' + name, `
    <div class="sechead" style="margin-top:0"><h3>${tr('dk.bk_history')}</h3><span class="sp"></span><button class="btn sm" id="bkNew">${tr('dk.bk_create')}</button></div>
    <div class="hidden" id="bkJob" style="margin:0 0 12px"></div>
    <div id="bkList">${loading()}</div>`, (close, root) => {
    const load = () => op('docker', { op: 'list_backups', name }).then((d) => {
      const list = d.backups || [];
      if (!list.length) { $('bkList').innerHTML = `<div class="empty">${tr('dk.bk_none')}</div>`; return; }
      let h = `<table class="optable"><tr><th>${tr('dk.bk_file')}</th><th>${tr('dk.col_size')}</th><th>${tr('dk.bk_time')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
      list.forEach((b) => { h += `<tr><td class="mono" style="font-size:12px">${esc(b.file)}</td><td>${dkHuman(b.size)}</td><td class="mut">${dkFmtTime(b.created)}</td><td class="act"><div class="actions"><button class="btn sm sec" data-dl="${esc(b.file)}">${tr('dk.bk_download')}</button><button class="btn sm" data-rs="${esc(b.file)}">${tr('dk.bk_restore')}</button><button class="btn sm danger" data-del="${esc(b.file)}">${tr('dk.delete')}</button></div></td></tr>`; });
      $('bkList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#bkList [data-dl]').forEach((b) => b.onclick = () => dkBackupDownload(name, b.dataset.dl));
      document.querySelectorAll('#bkList [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.bk_confirm_del', { file: b.dataset.del }))) op('docker', { op: 'delete_backup', name, backup: b.dataset.del }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
      document.querySelectorAll('#bkList [data-rs]').forEach((b) => b.onclick = async () => { if (!await confirmDanger(tr('dk.bk_confirm_restore'))) return; $('bkJob').classList.remove('hidden'); op('docker', { op: 'restore_backup', name, backup: b.dataset.rs }).then((r) => renderJob($('bkJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.bk_restored'), 'ok'); switchTab('docker'); } })).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('bkList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    $('bkNew').onclick = () => { $('bkJob').classList.remove('hidden'); op('docker', { op: 'backup_container', ref: id, name }).then((r) => renderJob($('bkJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.bk_done'), 'ok'); load(); } })).catch((e) => toast(e.message, 'err')); };
    load();
  }, true);
}
function dkBackupDownload(name, file) {
  ticket().then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&kind=backup&name=${encodeURIComponent(name)}&backup=${encodeURIComponent(file)}`;
    const a = el('a', { href: '/api/docker/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}

// Populate the create-form image dropdown with all local images (built-in ones
// included). Pre-selects `preselect` when given.
function loadImageOptions(preselect) {
  const sel = $('ccImg'); if (!sel) return;
  op('docker', { op: 'list_images' }).then((d) => {
    const names = (d.images || []).map((im) => im.name).filter((n) => n && n !== '<none>:<none>');
    if (!names.length) { sel.innerHTML = `<option value="">${tr('dk.no_images_pull')}</option>`; return; }
    sel.innerHTML = names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    if (preselect && names.includes(preselect)) sel.value = preselect;
  }).catch(() => {});
}

// Append a dynamic key/value row to list `id`. `cells` is an array of either
// { ph, val, grow } (an input) or { sep } (a literal separator). `opts` adds a
// proto select (ports) or a readonly checkbox (volumes).
function kvRow(id, cells, opts) {
  opts = opts || {};
  const wrap = $(id);
  const row = el('div', { class: 'kvrow' });
  cells.forEach((c) => {
    if (c.sep != null) { row.appendChild(el('span', { class: 'sep' }, c.sep)); return; }
    const i = el('input', { class: 'field' + (c.grow ? ' grow' : ''), placeholder: c.ph || '' });
    if (c.flex) i.style.flex = c.flex;
    else if (c.grow) i.style.flex = '1';
    if (c.val != null) i.value = c.val;
    row.appendChild(i);
  });
  if (opts.proto) {
    const sel = el('select', { class: 'field', style: 'flex:0 0 78px' });
    sel.innerHTML = '<option value="tcp">TCP</option><option value="udp">UDP</option>';
    if (opts.protoVal === 'udp') sel.value = 'udp';
    sel._proto = true;
    row.appendChild(sel);
  }
  if (opts.ipv6) {
    const lab = el('label', { class: 'ro' });
    lab.innerHTML = '<input type="checkbox" /> IPv6';
    const cb = lab.querySelector('input'); cb._ipv6 = true;
    if (opts.ipv6Val) cb.checked = true;
    lab.title = tr('dk.ipv6_hint');
    row.appendChild(lab);
  }
  if (opts.ro) {
    const lab = el('label', { class: 'ro' });
    lab.innerHTML = `<input type="checkbox" /> ${tr('dk.readonly')}`;
    lab.querySelector('input')._ro = true;
    row.appendChild(lab);
  }
  const rm = el('button', { class: 'rm', type: 'button' }, '×');
  rm.onclick = () => row.remove();
  row.appendChild(rm);
  wrap.appendChild(row);
}
// Read a dynamic kv list back: array of [v0, v1, ...] with .proto / .ro extras.
function readKv(id) {
  return Array.from($(id).querySelectorAll('.kvrow')).map((row) => {
    const vals = Array.from(row.querySelectorAll('input[type="text"], input:not([type])')).map((i) => i.value.trim());
    const out = vals;
    const proto = row.querySelector('select');
    if (proto && proto._proto) out.proto = proto.value;
    row.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
      if (cb._ro) out.ro = cb.checked;
      if (cb._ipv6) out.ipv6 = cb.checked;
    });
    return out;
  });
}

function dkNetworks() {
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_networks')}</h3><span class="sp"></span><button class="btn sm" id="dkNetNew">${tr('dk.create_network')}</button><button class="btn sec sm" id="dkRefN">${tr('dk.refresh')}</button></div><div id="dkNList">` + loading() + '</div>';
  $('dkRefN').onclick = dkNetworks;
  $('dkNetNew').onclick = () => modal(tr('dk.create_network'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('dk.net_name')}</label><input id="nnName" class="field" placeholder="my-net" /></div>
      <div><label class="lbl">${tr('dk.net_mode')}</label><select id="nnDriver" class="field"><option value="bridge">bridge</option><option value="macvlan">macvlan</option><option value="ipvlan">ipvlan</option><option value="overlay">overlay</option></select></div>
      <div><label class="lbl">${tr('dk.net_subnet')}</label><input id="nnSubnet" class="field mono" placeholder="172.20.0.0/16" /></div>
      <div><label class="lbl">${tr('dk.net_gateway')}</label><input id="nnGateway" class="field mono" placeholder="172.20.0.1" /></div>
      <div class="full"><label class="lbl">${tr('dk.net_iprange')}</label><input id="nnRange" class="field mono" placeholder="172.20.5.0/24" /></div>
    </div>
    <p class="formnote" style="margin-top:8px">${tr('dk.net_ipam_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="nnGo">${tr('dk.create')}</button></div>`, (close) => {
    $('nnGo').onclick = () => op('docker', {
      op: 'create_network', name: $('nnName').value.trim(), driver: $('nnDriver').value,
      subnet: $('nnSubnet').value.trim() || undefined, gateway: $('nnGateway').value.trim() || undefined, ip_range: $('nnRange').value.trim() || undefined,
    }).then(() => { close(); toast(tr('common.created'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err'));
    bindDirty('nnGo');
  });
  op('docker', { op: 'list_networks' }).then((d) => {
    let h = `<table class="optable"><tr><th>${tr('dk.col_name')}</th><th>${tr('dk.col_driver')}</th><th>${tr('dk.col_scope')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    (d.networks || []).forEach((n) => { h += `<tr><td>${esc(n.name)}</td><td class="mut">${esc(n.driver)}</td><td class="mut">${esc(n.scope)}</td><td class="act">${['bridge', 'host', 'none'].includes(n.name) ? `<span class="mut" style="font-size:12px">${tr('dk.builtin')}</span>` : `<button class="btn sm danger" data-rm="${esc(n.name)}">${tr('dk.delete')}</button>`}</td></tr>`; });
    $('dkNList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkNList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_net', { name: b.dataset.rm }))) op('docker', { op: 'remove_network', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkNList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ---- Settings tab (mirror/registry lists + daemon.json knobs) ----
function dkSettings() {
  const body = $('dkBody');
  body.innerHTML = loading();
  op('docker', { op: 'get_settings' }).then((s) => {
    const cg = s.cgroup_driver || 'systemd';
    body.innerHTML = `
      <div style="max-width:580px">
        <div class="sechead" style="margin-top:0"><h3>${tr('dk.set_mirrors')}</h3></div>
        <p class="mut" style="font-size:12.5px;margin:0 0 8px">${tr('dk.set_mirrors_d')}</p>
        <textarea id="dkMirrors" class="field mono" rows="4" spellcheck="false" placeholder="docker.m.daocloud.io">${esc((s.mirrors || []).join('\n'))}</textarea>

        <div class="sechead" style="margin-top:18px"><h3>${tr('dk.set_registries')}</h3></div>
        <p class="mut" style="font-size:12.5px;margin:0 0 8px">${tr('dk.set_registries_d')}</p>
        <textarea id="dkRegs" class="field mono" rows="3" spellcheck="false" placeholder="registry.example.com:5000">${esc((s.registries || []).join('\n'))}</textarea>
        <div class="row" style="align-items:center;gap:12px;margin-top:12px"><button class="btn sm" id="dkSaveLists">${tr('ng.save')}</button><span class="err ok" id="dkListMsg"></span></div>

        <div class="sechead" style="margin-top:26px"><h3>${tr('dk.set_daemon')}</h3></div>
        <p class="mut" style="font-size:12.5px;margin:0 0 12px">${tr('dk.set_daemon_d')}</p>
        <div class="formgrid">
          <div><label class="lbl">${tr('dk.set_cgroup')}</label><select id="dkCgroup" class="field"><option value="systemd"${cg === 'systemd' ? ' selected' : ''}>systemd</option><option value="cgroupfs"${cg === 'cgroupfs' ? ' selected' : ''}>cgroupfs</option></select></div>
          <div><label class="lbl">${tr('dk.set_socket')}</label><input id="dkSocket" class="field mono" value="${esc(s.socket_path || '/var/run/docker.sock')}" /></div>
          <div><label class="lbl">${tr('dk.set_logsize')}</label><input id="dkLogSize" class="field" value="${esc(s.log_max_size || '10m')}" placeholder="10m" /></div>
          <div><label class="lbl">${tr('dk.set_logfile')}</label><input id="dkLogFile" class="field" type="number" min="1" value="${esc(String(s.log_max_file != null ? s.log_max_file : 3))}" /></div>
        </div>
        <label class="switch" style="padding:0;margin-top:14px"><input type="checkbox" id="dkLogRotate" ${s.log_rotate ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_logrotate')}</b><span>${tr('dk.set_logrotate_d')}</span></span></label>
        <label class="switch" style="padding:0;margin-top:10px"><input type="checkbox" id="dkGzip6" ${s.ipv6 ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_ipv6')}</b><span>${tr('dk.set_ipv6_d')}</span></span></label>
        <label class="switch" style="padding:0;margin-top:10px"><input type="checkbox" id="dkIptables" ${s.iptables ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_iptables')}</b><span>${tr('dk.set_iptables_d')}</span></span></label>
        <label class="switch" style="padding:0;margin-top:10px"><input type="checkbox" id="dkLiveRestore" ${s.live_restore ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_live')}</b><span>${tr('dk.set_live_d')}</span></span></label>
        <div class="row" style="align-items:center;gap:12px;margin-top:16px"><button class="btn sm danger" id="dkSaveDaemon">${tr('dk.set_apply')}</button><span class="err ok" id="dkDaemonMsg"></span></div>
        <p class="formnote" style="margin-top:10px">${tr('dk.set_daemon_warn')}</p>
      </div>`;

    const linesOf = (id) => $(id).value.split('\n').map((x) => x.trim()).filter(Boolean);
    const collect = () => ({
      mirrors: linesOf('dkMirrors'),
      registries: linesOf('dkRegs'),
      ipv6: $('dkGzip6').checked,
      iptables: $('dkIptables').checked,
      live_restore: $('dkLiveRestore').checked,
      cgroup_driver: $('dkCgroup').value,
      log_rotate: $('dkLogRotate').checked,
      log_max_size: $('dkLogSize').value.trim(),
      log_max_file: Number($('dkLogFile').value) || 3,
      socket_path: $('dkSocket').value.trim(),
    });
    // Saving just the lists doesn't restart docker (mirror/registry are panel-side).
    $('dkSaveLists').onclick = () => {
      const m = $('dkListMsg'); $('dkSaveLists').disabled = true;
      op('docker', { op: 'set_settings', settings: collect() }).then(() => { m.className = 'err ok'; m.textContent = tr('common.saved'); dkSettingsReset(); }).catch((e) => { m.className = 'err'; m.textContent = e.message; $('dkSaveLists').disabled = false; });
    };
    $('dkSaveDaemon').onclick = async () => {
      if (!await confirmDanger(tr('dk.set_restart_confirm'))) return;
      const m = $('dkDaemonMsg'); m.className = 'err ok'; m.textContent = tr('dk.set_applying'); $('dkSaveDaemon').disabled = true;
      op('docker', { op: 'set_settings', settings: collect() }).then(() => { m.className = 'err ok'; m.textContent = tr('common.saved'); dkSettingsReset(); }).catch((e) => { m.className = 'err'; m.textContent = e.message; $('dkSaveDaemon').disabled = false; });
    };
    const dkSettingsReset = () => { if ($('dkSaveLists')._dirtyReset) $('dkSaveLists')._dirtyReset(); if ($('dkSaveDaemon')._dirtyReset) $('dkSaveDaemon')._dirtyReset(); };
    bindDirty('dkSaveLists', 'dkBody');
    bindDirty('dkSaveDaemon', 'dkBody');
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
