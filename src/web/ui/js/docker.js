// =========================================================================
// Docker management
// =========================================================================

// Display form of an image reference: drop the implicit Docker Hub registry
// (`registry-1.docker.io/` or `docker.io/`) and the official `library/`
// namespace, matching how `docker images` prints short names — e.g.
// `registry-1.docker.io/library/alpine:latest` → `alpine:latest`. The full ref
// is still used for every operation (pull/tag/delete); this is display-only.
function dockerShortRef(ref) {
  let s = String(ref == null ? '' : ref);
  s = s.replace(/^(registry-1\.docker\.io|docker\.io|index\.docker\.io)\//, '');
  s = s.replace(/^library\//, '');
  return s;
}

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

// Actions-column width: English/Japanese labels are wider than CJK, so the
// frozen Actions column needs more room or buttons overflow it. `base` is the
// compact (zh) width; widen it for the longer-label languages.
function ngActW(base) {
  const l = (typeof curLang === 'function') ? curLang() : 'en';
  return (l === 'en' || l === 'ja') ? base + 64 : base;
}

function renderDocker(v) {
  v.innerHTML = `<div style="padding:8px">${loading()}</div>`;
  op('docker', { op: 'info' }).then((info) => {
    // The active runtime ("dn7" in-house / "docker" bollard) rides the `info`
    // arg into every sub-tab (dkImages/dkVolumes/dkNetworks/dkCreateModal),
    // which consult it to hide dn7-unsupported controls.
    v.innerHTML = `
      <div class="subtabs" id="dkTabs">
        <button data-t="containers" class="on">${tr('dk.tab_containers')}</button>
        <button data-t="images">${tr('dk.tab_images')}</button>
        <button data-t="volumes">${tr('dk.tab_volumes')}</button>
        <button data-t="networks">${tr('dk.tab_networks')}</button>
      </div>
      <div id="dkBody"></div>`;
    const tabs = $('dkTabs');
    const sel = (t) => { tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); if (t === 'containers') dkContainers(); else if (t === 'images') dkImages(info); else if (t === 'volumes') dkVolumes(info); else dkNetworks(info); };
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
    sel('containers');
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}

function dkContainers() {
  document.querySelectorAll('.dk-pop').forEach((p) => p.remove());
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><input id="dkFilter" class="field" placeholder="${esc(tr('dk.filter_ph'))}" value="${esc(dkContainers._q || '')}" style="max-width:240px" /><span class="sp"></span><button class="btn sm" id="dkNew">${tr('dk.create_container')}</button><button class="btn sec sm" id="dkRefC">${tr('dk.refresh')}</button></div><div id="dkCJobs"></div><div id="dkCList">` + loading() + '</div>';
  $('dkRefC').onclick = () => dkLoadContainers(true);
  $('dkNew').onclick = () => dkCreateForm();
  $('dkFilter').oninput = () => { dkContainers._q = $('dkFilter').value; dkApplyFilter(); };
  dkReattachJobs();
  dkLoadContainers(true);
}

// Re-attach persisted docker background jobs (create/upgrade/restore/backup
// whose modal is gone) so returning to the tab re-shows their progress.
function dkReattachJobs() {
  const host = $('dkCJobs'); if (!host) return;
  ['docker:create', 'docker:upgrade', 'docker:restore', 'docker:backup'].forEach((slot) => {
    if (!getJob(slot)) return;
    // Tag the card with its slot so a modal that shares the slot (backups) can
    // tell the list card is already polling and skip a re-attach that would
    // otherwise steal the poll loop and freeze this card.
    const d = el('div', { class: 'card', 'data-jobslot': slot, style: 'margin:0 0 12px' });
    host.appendChild(d);
    reattachJob(d, slot, { onDone: () => { toast(tr('dk.op_ok'), 'ok'); d.remove(); if ($('dkCList')) dkLoadContainers(); } });
  });
}

// Client-side substring filter over name / image / state (row dataset.f).
function dkApplyFilter() {
  const q = (dkContainers._q || '').trim().toLowerCase();
  document.querySelectorAll('#dkCList tr[data-f]').forEach((r) => { r.style.display = (!q || r.dataset.f.indexOf(q) !== -1) ? '' : 'none'; });
}

// Lifecycle states that resolve on their own keep the list live-polling.
const DK_TRANSIENT = /^(restarting|removing|starting|stopping)$/;

// Fetch + render the container list into #dkCList (leaves the toolbar alone so
// the filter input keeps focus/value). `first` shows the loading skeleton.
function dkLoadContainers(first) {
  const seq = (dkLoadContainers._seq = (dkLoadContainers._seq || 0) + 1);
  clearTimeout(dkLoadContainers._t);
  if (first && $('dkCList')) $('dkCList').innerHTML = loading();
  apiInflight('docker:list', () => op('docker', { op: 'list_containers' })).then((d) => {
    if (seq !== dkLoadContainers._seq || !$('dkCList')) return;
    const list = d.containers || [];
    dkRenderCtnList(list);
    // Auto-refresh (2s) while any container is in a transitional state.
    if (list.some((c) => DK_TRANSIENT.test(c.state))) dkLoadContainers._t = setTimeout(dkCtnTick, 2000);
  }).catch((e) => { if (seq === dkLoadContainers._seq && $('dkCList')) $('dkCList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// One transitional-poll tick: wait (without fetching) while the browser tab is
// hidden or a lifecycle menu is open; stop for good once the list unmounts.
function dkCtnTick() {
  if (UI.tab !== 'docker' || !$('dkCList')) return;
  const menuOpen = Array.from(document.querySelectorAll('.dk-pop')).some((p) => p.style.display === 'flex');
  if (document.hidden || menuOpen) { dkLoadContainers._t = setTimeout(dkCtnTick, 2000); return; }
  dkLoadContainers();
}

// A row's change signature: any difference re-renders that row in place.
function dkCtnRowSig(c) {
  return [c.state, c.status, c.name, c.image, (c.ips || []).join(';'), c.ports || '',
    c.description || '', c.uptime || '', c.has_shell ? 1 : 0, c.managed ? 1 : 0,
    c.oom_killed ? 1 : 0].join('\u0001');
}

// The <td> cells for one container row (everything inside its <tr>).
function dkCtnRowCells(c) {
  const running = c.state === 'running';
  const ports = (c.ports || '').split(',').map((p) => p.trim()).filter(Boolean);
  const portCell = ports.length ? ports.map((p) => `<span class="portlbl">${esc(p)}</span>`).join(' ') : '<span class="mut">-</span>';
  const desc = c.description ? esc(c.description) : '<span class="mut">-</span>';
  // Uptime column: localized "Up …" while running; exit context ("2 hours
  // ago") for exited containers — the raw status rides the cell tooltip.
  const exi = !running ? dkExitInfo(c.status) : null;
  let uptime = '<span class="mut">-</span>';
  if (running && c.uptime) uptime = esc(dkUptimeTr(c.uptime));
  else if (exi && exi.ago) uptime = esc(tr('dk.ago', { t: dkDurTr(exi.ago) }));
  const builtin = c.managed ? ` <span class="chip">${tr('dk.builtin')}</span>` : '';
  return `
      <td data-tip="${esc(c.name)}"><div class="clamp1"><b>${esc(c.name)}</b>${builtin}</div><div class="clamp1 mut mono" style="font-size:11px">${esc(c.id)}</div></td>
      <td data-tip="${esc(c.image)}"><div class="clamp2 mono" style="font-size:12px">${esc(dockerShortRef(c.image))}</div></td>
      <td><span class="statuswrap" data-id="${esc(c.id)}" data-name="${esc(c.name)}" data-state="${esc(c.state)}" data-managed="${c.managed ? 1 : 0}">${ctnStateChip(c.state, c.status, c.oom_killed)}</span></td>
      <td data-tip="${esc((c.ips || []).join('\n'))}"><div class="clamp2 mono" style="font-size:12px">${(c.ips && c.ips.length) ? c.ips.map((x) => esc(x)).join('<br>') : '<span class="mut">-</span>'}</div></td>
      <td data-tip="${esc((c.ports || '').replace(/,\s*/g, '\n'))}"><div class="clamp2 portcell">${portCell}</div></td>
      <td data-tip="${esc(c.description || '')}"><div class="clamp2 mut" style="font-size:12px">${desc}</div></td>
      <td data-tip="${esc(c.status || '')}"><div class="clamp2 mut" style="font-size:12px">${uptime}</div></td>
      <td class="act"><div class="actions" data-id="${esc(c.id)}" data-name="${esc(c.name)}" data-shell="${c.has_shell ? 1 : 0}" data-state="${esc(c.state)}" data-managed="${c.managed ? 1 : 0}"></div></td>`;
}

// Wire the dynamic bits of a freshly-(re)rendered row.
function dkWireCtnRow(row) {
  const a = row.querySelector('.actions');
  if (a) buildContainerActions(a, dkContainers);
  wireCellTips(row);
}

function dkRenderCtnList(list) {
  // Incremental path: same containers in the same order → patch only the rows
  // whose signature changed. The table (and its scroll position, focus, hover
  // and tooltip listeners) survives the 2s transitional poll instead of being
  // torn down — the list no longer jumps to the top mid-restart.
  const wrap = $('dkCList').querySelector('.tablewrap');
  const rows = wrap ? Array.from(wrap.querySelectorAll('tr[data-cid]')) : [];
  if (list.length && rows.length === list.length
      && list.every((c, i) => rows[i].dataset.cid === c.id)) {
    list.forEach((c, i) => {
      const row = rows[i], sig = dkCtnRowSig(c);
      // A lifecycle op is in flight — keep the optimistic transitional chip and
      // disabled buttons; the op's own settle callback refreshes when it's done.
      if (dkPending.has(c.id)) return;
      if (row.dataset.sig === sig) return;
      row.dataset.sig = sig;
      row.dataset.f = (c.name + ' ' + c.image + ' ' + c.state).toLowerCase();
      row.innerHTML = dkCtnRowCells(c);
      dkWireCtnRow(row);
    });
    dkApplyFilter();
    return;
  }

  document.querySelectorAll('.dk-pop').forEach((p) => p.remove());
  if (!list.length) { $('dkCList').innerHTML = `<div class="empty">${tr('dk.no_containers')}</div>`; return; }
  let h = `<table class="optable frztbl ctntbl">`
    + `<colgroup><col style="width:190px"><col style="width:210px"><col style="width:120px">`
    + `<col style="width:200px"><col style="width:210px"><col style="width:230px"><col style="width:120px"><col style="width:${ngActW(200)}px"></colgroup>`
    + `<tr>`
    + `<th>${tr('dk.col_name')}</th><th>${tr('dk.col_image')}</th><th>${tr('dk.col_status')}</th>`
    + `<th>${tr('dk.col_ip')}</th><th>${tr('dk.col_ports')}</th><th>${tr('dk.col_desc')}</th>`
    + `<th>${tr('dk.col_uptime')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
  list.forEach((c) => {
    h += `<tr data-cid="${esc(c.id)}" data-sig="${esc(dkCtnRowSig(c))}" data-f="${esc((c.name + ' ' + c.image + ' ' + c.state).toLowerCase())}">${dkCtnRowCells(c)}
    </tr>`;
  });
  $('dkCList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
  document.querySelectorAll('#dkCList tr[data-cid]').forEach((r) => dkWireCtnRow(r));
  wireStickyShadows($('dkCList').querySelector('.tablewrap'));
  dkApplyFilter();
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

// The server formats durations in English only ("2 hours", "About a minute");
// re-render the known formats through i18n, falling back to the raw string.
function dkDurTr(s) {
  s = String(s || '').trim();
  const m = s.match(/^(\d+)\s+(second|minute|hour|day|week|month|year)s?$/i);
  // Key built outside the tr() call so check_i18n.js doesn't read a prefix
  // literal; the dk.up_<unit> keys all exist in the dictionaries.
  if (m) { const k = 'dk.up_' + m[2].toLowerCase(); return tr(k, { n: m[1] }); }
  if (/^about a minute$/i.test(s)) return tr('dk.up_minute', { n: 1 });
  if (/^about an hour$/i.test(s)) return tr('dk.up_hour', { n: 1 });
  if (/^less than a second$/i.test(s)) return tr('dk.up_lt_sec');
  return s;
}
// Uptime column text: strip the "Up " prefix, localize the duration, keep any
// trailing health/paused annotation as-is.
function dkUptimeTr(s) {
  s = String(s || '').replace(/^Up\s+/i, '').trim();
  const m = s.match(/^(.*?)(\s*\(.*\))?$/);
  return m ? dkDurTr(m[1]) + (m[2] || '') : s;
}
// Exit context from a status line ("Exited (1) 3 hours ago" / dn7's
// "Exited (1)"). Returns { code, ago } or null when it isn't an exit status.
function dkExitInfo(status) {
  const m = String(status || '').match(/^Exited\s*\((-?\d+)\)\s*(.*)$/i);
  if (!m) return null;
  return { code: parseInt(m[1], 10), ago: m[2].replace(/\s*ago\s*$/i, '').trim() };
}

// A clean state chip (decoupled from the long status text, which now feeds the
// uptime column). Colour + label reflect the lifecycle state; an exited
// container shows its exit code, err-tinted for a non-zero (crash) exit.
function ctnStateChip(state, status, oom) {
  let cls = 'off', dot = '', label = tr('dk.st_stopped');
  if (state === 'running') { cls = 'on'; dot = ' on'; label = tr('dk.st_running'); }
  else if (state === 'paused') { cls = 'amber'; dot = ' amber'; label = tr('dk.st_paused'); }
  else if (state === 'restarting') { cls = 'amber'; dot = ' init'; label = tr('dk.st_restarting'); }
  else if (state === 'starting') { cls = 'amber'; dot = ' init'; label = tr('dk.st_starting'); }
  else if (state === 'stopping') { cls = 'amber'; dot = ' init'; label = tr('dk.st_stopping'); }
  else if (state === 'removing') { cls = 'amber'; dot = ' init'; label = tr('dk.st_removing'); }
  else if (state === 'created') { cls = ''; label = tr('dk.st_created'); }
  else {
    const exi = dkExitInfo(status);
    if (exi) {
      label = oom ? tr('dk.st_oom', { code: exi.code }) : tr('dk.st_exited', { code: exi.code });
      if (exi.code !== 0) { cls = 'err'; dot = ' err'; }
    }
  }
  return `<span class="chip ${cls}"><span class="dot-s${dot}"></span>${esc(label)}</span>`;
}

// Build the lifecycle controls (start/stop/restart/force/pause/resume) shown on
// a hover panel under the status chip. Buttons depend on the container state.
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
    const mitems = [];
    if (running) mitems.push({ label: tr('dk.files'), fn: () => openFileBrowser(tr('dk.ctn_files') + name, id) });
    if (running) mitems.push({ label: tr('dk.monitor'), fn: () => dkMonitor(id, name) });
    if (mitems.length) {
      const advm = el('button', { class: 'btn sm sec' }, tr('dk.advanced') + ' ▾');
      holder.appendChild(advm);
      mkHoverPanel(advm, mitems);
    }
    return;
  }
  // Primary lifecycle control (moved out of the status chip): Stop / Resume /
  // Start depending on the current state.
  if (running) mk(tr('dk.stop'), '', () => doStopAction(id, reload));
  else if (state === 'paused') mk(tr('dk.resume'), '', () => doCAction('unpause_container', id, reload));
  else mk(tr('dk.start'), '', () => doCAction('start_container', id, reload));
  if (running && hasShell) mk(tr('dk.terminal'), 'sec', () => openTerminalModal(tr('dk.ctn_term') + name, () => ctnTermPath(id)));
  // Advanced menu (the button itself does nothing; items show on hover).
  const adv = el('button', { class: 'btn sm sec' }, tr('dk.advanced') + ' ▾');
  holder.appendChild(adv);
  // Secondary lifecycle controls first, then the rest.
  const items = [];
  if (running) {
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
    items.push({ label: tr('dk.pause'), fn: () => doCAction('pause_container', id, reload) });
    items.push({ label: tr('dk.force_stop'), cls: 'danger', fn: async () => { if (await confirmDanger(tr('dk.confirm_force', { name }))) doCAction('kill_container', id, reload); } });
  } else if (state === 'paused') {
    items.push({ label: tr('dk.stop'), fn: () => doStopAction(id, reload) });
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  } else {
    items.push({ label: tr('dk.restart'), fn: () => doCAction('restart_container', id, reload) });
  }
  items.push({ sep: true });
  items.push({ label: tr('dk.logs'), fn: () => dkLogs(id, name) });
  if (running) items.push({ label: tr('dk.files'), fn: () => openFileBrowser(tr('dk.ctn_files') + name, id) });
  items.push({ label: tr('dk.edit'), fn: () => dkEditForm(id, name) });
  items.push({ label: tr('dk.upgrade'), fn: () => dkUpgradeForm(id, name) });
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

// The optimistic transitional state a lifecycle verb puts its row into the
// moment it is sent (before the server confirms).
const DK_OP_TRANS = {
  start_container: 'starting', restart_container: 'restarting',
  stop_container: 'stopping', kill_container: 'stopping', remove_container: 'removing',
};

// Containers with a lifecycle op in flight. While an id is here, background
// polls leave its row alone (keep the optimistic transitional chip) instead of
// overwriting it with the still-`running` backend state — that overwrite is what
// made a graceful stop flash running → stopping → running → exited.
const dkPending = new Set();
function dkSettle(id, reload) {
  dkPending.delete(id);
  if (reload) reload();
}

// Optimistic row feedback: flip the status chip to the transitional state and
// disable the row's buttons immediately, then poll for the real state. The
// cleared signature forces the next poll to redraw the row either way.
function dkMarkTransient(id, state) {
  if (!state || !$('dkCList')) return;
  dkPending.add(id);
  const sel = (window.CSS && CSS.escape) ? CSS.escape(id) : id;
  const act = document.querySelector(`#dkCList .actions[data-id="${sel}"]`);
  const row = act && act.closest('tr');
  if (!row) return;
  const wrap = row.querySelector('.statuswrap');
  if (wrap) { wrap.dataset.state = state; wrap.innerHTML = ctnStateChip(state, ''); }
  row.querySelectorAll('.actions button').forEach((b) => { b.disabled = true; });
  row.dataset.sig = '';
  clearTimeout(dkLoadContainers._t);
  dkLoadContainers._t = setTimeout(dkCtnTick, 700);
}

function doCAction(o, id, reload) {
  dkMarkTransient(id, DK_OP_TRANS[o]);
  op('docker', { op: o, ref: id }).then(() => { toast(tr('dk.op_ok'), 'ok'); dkSettle(id, reload); })
    .catch((e) => { toast(e.message, 'err'); dkSettle(id, $('dkCList') ? dkLoadContainers : null); });
}

// Stopping takes a while (docker waits for the container to exit). Give instant
// feedback that the command was sent, then confirm completion — but only if the
// user is still on the Docker page when it finishes.
function doStopAction(id, reload) {
  toast(tr('dk.stop_sent'));
  dkMarkTransient(id, 'stopping');
  op('docker', { op: 'stop_container', ref: id }).then(() => {
    if (UI.tab === 'docker') toast(tr('dk.stop_done'), 'ok');
    dkSettle(id, UI.tab === 'docker' ? reload : null);
  }).catch((e) => { toast(e.message, 'err'); dkSettle(id, $('dkCList') ? dkLoadContainers : null); });
}

// Render log text with ANSI SGR colors as safe HTML. `st.open` carries the
// active style classes across chunks so a color started in one follow poll
// continues in the next. Only SGR survives server sanitization, so this only
// needs the `ESC [ … m` grammar.
function dkAnsiToHtml(text, st) {
  const CLS = { 1: 'lg-b', 3: 'lg-i', 4: 'lg-u' };
  const openSpan = () => (st.open.length ? `<span class="${st.open.join(' ')}">` : '');
  const parts = String(text).split('\u001b[');
  // Resume the style carried over from the previous chunk, if any.
  let html = openSpan() + esc(parts[0]);
  for (let i = 1; i < parts.length; i++) {
    const m = parts[i].match(/^([0-9;]*)m/);
    if (!m) { html += esc(parts[i]); continue; }
    if (st.open.length) html += '</span>';
    const codes = (m[1] || '0').split(';').map((n) => parseInt(n, 10) || 0);
    for (let j = 0; j < codes.length; j++) {
      const c = codes[j];
      if (c === 0) st.open = [];
      else if (CLS[c]) st.open.push(CLS[c]);
      else if (c === 22 || c === 23 || c === 24) st.open = st.open.filter((k) => k !== CLS[{ 22: 1, 23: 3, 24: 4 }[c]]);
      else if ((c >= 30 && c <= 37) || (c >= 90 && c <= 97)) { st.open = st.open.filter((k) => !k.startsWith('lg-f')); st.open.push('lg-f' + (c >= 90 ? c - 90 + 8 : c - 30)); }
      else if ((c >= 40 && c <= 47) || (c >= 100 && c <= 107)) { st.open = st.open.filter((k) => !k.startsWith('lg-g')); st.open.push('lg-g' + (c >= 100 ? c - 100 + 8 : c - 40)); }
      else if (c === 39) st.open = st.open.filter((k) => !k.startsWith('lg-f'));
      else if (c === 49) st.open = st.open.filter((k) => !k.startsWith('lg-g'));
      else if (c === 38 || c === 48) { // 256/truecolor: skip the argument codes, keep default.
        j += codes[j + 1] === 5 ? 2 : codes[j + 1] === 2 ? 4 : 0;
      }
    }
    st.open = [...new Set(st.open)];
    html += openSpan() + esc(parts[i].slice(m[0].length));
  }
  if (st.open.length) html += '</span>';
  return html;
}

function dkLogs(id, name) {
  // Tail sizes match the server clamp (max 2000 lines).
  const tails = [400, 1000, 2000];
  modal(tr('dk.logs_title') + name, `
    <div class="row" style="margin-bottom:10px">
      <label class="tgl"><input type="checkbox" id="dkLogFollow" checked /><span class="tglbox"></span><span class="tgltxt">${tr('dk.log_follow')}</span></label>
      <span class="sp" style="flex:1"></span>
      <select id="dkLogTail" class="field" style="width:auto">${tails.map((n) => `<option value="${n}">${esc(tr('dk.log_lines', { n }))}</option>`).join('')}</select>
      <button class="btn sec sm" id="dkLogRef">${tr('dk.refresh')}</button>
      <button class="btn sec sm" id="dkLogDl">${tr('dk.log_download')}</button>
    </div>
    <div id="dkLogWrap">${loading()}</div>`, (close, root) => {
    let timer = null;
    // Byte offset for incremental follow (dn7 runtime); null = backend doesn't
    // report offsets (bollard) → follow falls back to full re-tails.
    let nextOffset = null;
    const sgr = { open: [] };
    const ensureOut = () => {
      if (!$('dkLogOut')) $('dkLogWrap').innerHTML = '<pre class="out" id="dkLogOut" style="max-height:64vh"></pre>';
      return $('dkLogOut');
    };
    const stickBottom = (out) => out.scrollHeight - out.scrollTop - out.clientHeight < 30;
    const showErr = (e) => { if (document.body.contains(root) && $('dkLogWrap')) $('dkLogWrap').innerHTML = `<p class="err">${esc(e.message)}</p>`; };
    const load = () => op('docker', { op: 'logs', ref: id, tail: parseInt($('dkLogTail').value, 10) || 400 }).then((d) => {
      if (!document.body.contains(root)) return;
      const prev = $('dkLogOut');
      const stick = !prev || stickBottom(prev);
      const out = ensureOut();
      sgr.open = [];
      if (d.logs) { out.innerHTML = dkAnsiToHtml(d.logs, sgr); out.dataset.empty = ''; }
      else { out.textContent = tr('dk.empty_log'); out.dataset.empty = '1'; }
      nextOffset = typeof d.next_offset === 'number' ? d.next_offset : null;
      if (stick) out.scrollTop = out.scrollHeight;
    }).catch(showErr);
    // Incremental follow poll: fetch only the bytes appended since the last
    // poll and append them in place (no flicker, scroll preserved).
    const poll = () => {
      if (nextOffset === null) return load();
      return op('docker', { op: 'logs', ref: id, offset: nextOffset }).then((d) => {
        if (!document.body.contains(root)) return;
        nextOffset = typeof d.next_offset === 'number' ? d.next_offset : null;
        if (!d.logs) return;
        const out = ensureOut();
        const stick = stickBottom(out);
        if (out.dataset.empty === '1') { out.textContent = ''; out.dataset.empty = ''; }
        out.insertAdjacentHTML('beforeend', dkAnsiToHtml(d.logs, sgr));
        // Bound the DOM in a long follow session: re-tail from scratch.
        if (out.innerHTML.length > 3000000) return load();
        if (stick) out.scrollTop = out.scrollHeight;
      }).catch(showErr);
    };
    // Follow: poll every 2s while the modal is open (paused while the browser
    // tab is hidden so a background console doesn't keep polling).
    const tick = () => {
      if (!document.body.contains(root) || !$('dkLogFollow').checked) return;
      (document.hidden ? Promise.resolve() : poll()).finally(() => {
        if (document.body.contains(root) && $('dkLogFollow').checked) timer = setTimeout(tick, 2000);
      });
    };
    $('dkLogFollow').onchange = () => { clearTimeout(timer); if ($('dkLogFollow').checked) tick(); };
    $('dkLogTail').onchange = load;
    $('dkLogRef').onclick = load;
    $('dkLogDl').onclick = () => {
      const txt = ($('dkLogOut') && $('dkLogOut').textContent) || '';
      const url = URL.createObjectURL(new Blob([txt], { type: 'text/plain' }));
      const a = el('a', { href: url, download: name + '.log' });
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    };
    load().finally(() => { if (document.body.contains(root) && $('dkLogFollow').checked) timer = setTimeout(tick, 2000); });
  });
}
