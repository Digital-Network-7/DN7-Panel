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
  const onScroll = () => { if (box) place(); };
  input.addEventListener('input', debounced);
  input.addEventListener('focus', () => { window.addEventListener('scroll', onScroll, true); debounced(); });
  input.addEventListener('blur', () => setTimeout(() => { hide(); window.removeEventListener('scroll', onScroll, true); }, 150));
}

// Docker engine + API version chips shown in each list tab's header (in place
// of a redundant title). Populated by renderDocker from the `info` response.
let DK_INFO = {};
function dkVerChips() {
  return `<span class="chip">Docker ${esc(DK_INFO.server_version || '')}</span><span class="chip">API ${esc(DK_INFO.client_version || '')}</span>`;
}
// Actions-column width: English/Japanese labels are wider than CJK, so the
// frozen Actions column needs more room or buttons overflow it. `base` is the
// compact (zh) width; widen it for the longer-label languages.
function ngActW(base) {
  const l = (typeof curLang === 'function') ? curLang() : 'en';
  return (l === 'en' || l === 'ja') ? base + 64 : base;
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
      <div id="dkBody"></div>`;
    DK_INFO = info;
    const tabs = $('dkTabs');
    const sel = (t) => { tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); if (t === 'containers') dkContainers(); else if (t === 'images') dkImages(info); else if (t === 'volumes') dkVolumes(); else if (t === 'settings') dkSettings(); else dkNetworks(); };
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
    sel('containers');
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}

function dkContainers() {
  document.querySelectorAll('.dk-pop').forEach((p) => p.remove());
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead">${dkVerChips()}<span class="sp"></span><button class="btn sm" id="dkNew">${tr('dk.create_container')}</button><button class="btn sec sm" id="dkRefC">${tr('dk.refresh')}</button></div><div id="dkCList">` + loading() + '</div>';
  $('dkRefC').onclick = dkContainers;
  $('dkNew').onclick = () => dkCreateForm();
  op('docker', { op: 'list_containers' }).then((d) => {
    const list = d.containers || [];
    if (!list.length) { $('dkCList').innerHTML = `<div class="empty">${tr('dk.no_containers')}</div>`; return; }
    let h = `<table class="optable frztbl ctntbl">`
      + `<colgroup><col style="width:190px"><col style="width:210px"><col style="width:120px">`
      + `<col style="width:200px"><col style="width:210px"><col style="width:230px"><col style="width:120px"><col style="width:${ngActW(200)}px"></colgroup>`
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
        <td data-tip="${esc((c.ips || []).join('\n'))}"><div class="clamp2 mono" style="font-size:12px">${(c.ips && c.ips.length) ? c.ips.map((x) => esc(x)).join('<br>') : '<span class="mut">-</span>'}</div></td>
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
function updateStickyShadows(wrap) {
  if (!wrap) return;
  wrap.classList.toggle('scl', wrap.scrollLeft > 1);
  wrap.classList.toggle('scr', wrap.scrollLeft + wrap.clientWidth < wrap.scrollWidth - 1);
}
function stickyShadowWraps() {
  if (!wireStickyShadows._wraps) wireStickyShadows._wraps = new Set();
  return wireStickyShadows._wraps;
}
function cleanupStickyShadowWraps() {
  const wraps = stickyShadowWraps();
  wraps.forEach((w) => {
    if (!document.body.contains(w)) {
      if (wireStickyShadows._ro) wireStickyShadows._ro.unobserve(w);
      wraps.delete(w);
    }
  });
}
function wireStickyShadows(wrap) {
  if (!wrap) return;
  const upd = () => updateStickyShadows(wrap);
  wrap.addEventListener('scroll', upd, { passive: true });
  cleanupStickyShadowWraps();
  stickyShadowWraps().add(wrap);
  // Recompute on viewport resize — a wider window may stop the table from
  // overflowing (so the right shadow must hide) and vice-versa. Bind the window
  // listener once and re-resolve the current wrapper each time to avoid leaks.
  if (!wireStickyShadows._bound) {
    wireStickyShadows._bound = true;
    window.addEventListener('resize', () => {
      cleanupStickyShadowWraps();
      stickyShadowWraps().forEach(updateStickyShadows);
    });
  }
  // Also react to layout changes that don't fire window resize (sidebar toggle).
  if (window.ResizeObserver) {
    if (!wireStickyShadows._ro) {
      wireStickyShadows._ro = new ResizeObserver((entries) => {
        cleanupStickyShadowWraps();
        entries.forEach((e) => updateStickyShadows(e.target));
      });
    }
    wireStickyShadows._ro.observe(wrap);
  }
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
  else if (state === 'paused') { cls = 'amber'; dot = ' amber'; key = 'dk.st_paused'; }
  else if (state === 'restarting') { cls = 'amber'; dot = ' init'; key = 'dk.st_restarting'; }
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
    items.push({ label: tr('dk.stop'), fn: () => doStopAction(id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
    items.push({ label: tr('dk.pause'), fn: () => doCAction('pause_container', id, reload) });
    items.push({ label: tr('dk.force_stop'), cls: 'danger', fn: async () => { if (await confirmDanger(tr('dk.confirm_force', { name: holder.dataset.name }))) doCAction('kill_container', id, reload); } });
  } else if (state === 'paused') {
    items.push({ label: tr('dk.resume'), cls: '', fn: () => doCAction('unpause_container', id, reload) });
    items.push({ label: tr('dk.stop'), fn: () => doStopAction(id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  } else {
    items.push({ label: tr('dk.start'), cls: '', fn: () => doCAction('start_container', id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  }
  if (!items.length) return;
  holder.style.cursor = 'pointer';
  mkHoverPanel(holder, items);
}

// Resolve the WebSocket path for a container terminal, minting a fresh ticket
// per (re)connect. For a privileged / host-namespaced container (exec into
// which grants effective host root) it first runs a step-up re-auth and rides
// the resulting single-use token in the `stepup` query param; the common,
// non-privileged case stays frictionless. Re-evaluated on every reconnect, so a
// privileged session re-prompts (its step-up token is single-use).
async function ctnTermPath(id) {
  let stepupQ = '';
  let priv = false;
  try {
    const b = await api('/api/container/privileged', { method: 'POST', body: JSON.stringify({ container: id }) });
    priv = !!(b.data && b.data.privileged);
  } catch (_) { /* probe failed → treat as non-privileged; the WS gate is authoritative */ }
  if (priv) {
    const tok = await stepUp(tr('stepup.msg_exec'));
    if (!tok) throw new Error(tr('stepup.cancelled'));
    stepupQ = '&stepup=' + encodeURIComponent(tok);
  }
  const t = await ticket('terminal');
  return `/api/container/terminal?ticket=${encodeURIComponent(t)}&container=${encodeURIComponent(id)}${stepupQ}`;
}

function buildContainerActions(holder, reload) {
  const id = holder.dataset.id, name = holder.dataset.name, hasShell = holder.dataset.shell === '1';
  const state = holder.dataset.state, running = state === 'running';
  const managed = holder.dataset.managed === '1';
  const mk = (label, cls, fn) => { const b = el('button', { class: 'btn sm ' + (cls || 'sec') }, label); b.onclick = fn; holder.appendChild(b); };
  // DN7 Panel-managed service containers (the managed MySQL service): lifecycle/edit/delete/
  // logs belong to their own pages. Only safe read-only observe actions show
  // here — Terminal, Files, and an Advanced menu carrying Monitor.
  if (managed) {
    if (running && hasShell) mk(tr('dk.terminal'), '', () => openTerminalModal(tr('dk.ctn_term') + name, () => ctnTermPath(id)));
    if (running) mk(tr('dk.files'), 'sec', () => openFileBrowser(tr('dk.ctn_files') + name, id));
    const mitems = [];
    if (running) mitems.push({ label: tr('dk.monitor'), fn: () => dkMonitor(id, name) });
    if (mitems.length) {
      const advm = el('button', { class: 'btn sm sec' }, tr('dk.advanced') + ' ▾');
      holder.appendChild(advm);
      mkHoverPanel(advm, mitems);
    }
    return;
  }
  // Outermost: terminal, files, advanced (logs/networks moved into Advanced /
  // the create-edit tabs respectively).
  if (running && hasShell) mk(tr('dk.terminal'), '', () => openTerminalModal(tr('dk.ctn_term') + name, () => ctnTermPath(id)));
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
  panel.setAttribute('role', 'menu');
  items.forEach((it) => {
    if (it.sep) { panel.appendChild(el('div', { class: 'mi-sep' })); return; }
    const b = el('button', { class: 'mi' + (it.cls === 'danger' ? ' danger' : '') }, it.label);
    b.setAttribute('role', 'menuitem');
    b.onclick = () => { hide(); it.fn(); };
    panel.appendChild(b);
  });
  let timer, open = false, mounted = false, docHandler = null;
  // The Advanced menu's trigger is a <button> (Enter/Space fire a native click);
  // the status chip is a <span>, so make it focusable + announce the popup.
  const isButton = trigger.tagName === 'BUTTON';
  if (!isButton) {
    if (!trigger.hasAttribute('tabindex')) trigger.setAttribute('tabindex', '0');
    trigger.setAttribute('role', 'button');
  }
  trigger.setAttribute('aria-haspopup', 'menu');
  trigger.setAttribute('aria-expanded', 'false');
  const place = () => {
    if (!mounted) { document.body.appendChild(panel); mounted = true; }
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
    trigger.setAttribute('aria-expanded', 'true');
  };
  const show = () => { clearTimeout(timer); place(); };
  const hide = () => {
    clearTimeout(timer);
    panel.style.display = 'none';
    open = false;
    trigger.setAttribute('aria-expanded', 'false');
    if (docHandler) { document.removeEventListener('mousedown', docHandler); docHandler = null; }
  };
  // Delayed close lets the cursor cross the gap from trigger to panel, but a
  // click-pinned (`open`) menu stays put until it's explicitly dismissed.
  const hideSoon = () => { timer = setTimeout(() => { if (!open) hide(); }, 130); };
  // Hover — progressive enhancement for mouse users (unchanged behaviour).
  trigger.addEventListener('mouseenter', show);
  trigger.addEventListener('mouseleave', hideSoon);
  panel.addEventListener('mouseenter', () => clearTimeout(timer));
  panel.addEventListener('mouseleave', hideSoon);
  // Click / touch / keyboard — the primary, accessible open path (was missing,
  // so the whole menu was dead on touch and keyboard).
  const toggle = (e) => {
    if (e) { e.preventDefault(); e.stopPropagation(); }
    if (open) { hide(); return; }
    open = true; show();
    // Dismiss on any outside press; registered only while open so it can't leak.
    docHandler = (ev) => { if (!trigger.contains(ev.target) && !panel.contains(ev.target)) hide(); };
    document.addEventListener('mousedown', docHandler);
  };
  trigger.addEventListener('click', toggle);
  trigger.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { hide(); trigger.focus(); }
    // A <button> already synthesises a click on Enter/Space; only fake it for the
    // non-button trigger so a button doesn't toggle twice (net no-op).
    else if (!isButton && (e.key === 'Enter' || e.key === ' ')) toggle(e);
  });
  panel.addEventListener('keydown', (e) => { if (e.key === 'Escape') { hide(); trigger.focus(); } });
}

function doCAction(o, id, reload) { op('docker', { op: o, ref: id }).then(() => { toast(tr('dk.op_ok'), 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); }

// Stopping takes a while (docker waits for the container to exit). Give instant
// feedback that the command was sent, then confirm completion — but only if the
// user is still on the Docker page when it finishes.
function doStopAction(id, reload) {
  toast(tr('dk.stop_sent'));
  op('docker', { op: 'stop_container', ref: id }).then(() => {
    if (UI.tab === 'docker') { toast(tr('dk.stop_done'), 'ok'); reload && reload(); }
  }).catch((e) => toast(e.message, 'err'));
}

function dkLogs(id, name) {
  modal(tr('dk.logs_title') + name, '<div id="dkLogWrap">' + loading() + '</div>', () => {
    op('docker', { op: 'logs', ref: id, tail: 400 }).then((d) => { $('dkLogWrap').innerHTML = '<pre class="out" id="dkLogOut" style="max-height:64vh"></pre>'; $('dkLogOut').textContent = d.logs || tr('dk.empty_log'); $('dkLogOut').scrollTop = $('dkLogOut').scrollHeight; }).catch((e) => { $('dkLogWrap').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}
