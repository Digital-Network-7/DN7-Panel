// =========================================================================
// Self-update — version modal (manual / auto), dual-source (GitHub + dn7.cn).
// Opened from the sidebar version line; talks to /api/update/*. Every
// /api/update/* endpoint is admin-gated (config writes + apply are super),
// so the entry point is role-gated too.
// =========================================================================
const UPD = { polling: null, active: false, failedVers: [] };

// Passive check on login: light up the sidebar dot when a newer build exists.
// Invoked by the shell for admins only (the endpoint 403s everyone else).
function updateBadge() {
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    if (d.has_update && $('verLine')) $('verLine').title = tr('upd.has_update', { latest: d.latest });
  }).catch(() => {});
}

// The sidebar version line is click-bound for every account (boot.js), but
// updates are admin-only: strip the affordance (pointer + hover hint) once
// the role is known, and restore it for a later admin login on the same page.
function updGateVerLine() {
  const vl = $('verLine'); if (!vl) return;
  const admin = Auth.isAdmin();
  vl.style.cursor = admin ? 'pointer' : 'default';
  if (admin) { if (!vl.title) vl.title = tr('shell.update_hint'); }
  else vl.removeAttribute('title');
}
(function () {
  let tries = 0;
  const armed = () => document.documentElement.getAttribute('data-auth') === 'in';
  const gate = () => {
    if (Auth.me) updGateVerLine();
    else if (++tries < 60) setTimeout(gate, 500); // /api/me still in flight
  };
  new MutationObserver(() => { if (armed()) { tries = 0; gate(); } })
    .observe(document.documentElement, { attributes: true, attributeFilter: ['data-auth'] });
  if (armed()) gate();
})();

function openUpdate() {
  if (!Auth.isAdmin()) {
    updGateVerLine();
    if (Auth.me) toast(tr('upd.admin_only'), 'warn'); // role unknown yet → ignore the click
    return;
  }
  // Update Settings write endpoints require super — hide the section for
  // plain admins instead of serving toggles that 403 on change.
  const isSuper = Auth.isSuper();
  const body = `
    <div class="upd">
      <div class="upd-hero">
        <div class="upd-appicon">
          <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>
        </div>
        <div class="upd-ver" id="uCur">…</div>
        <div class="upd-state" id="uState">${tr('upd.checking')}</div>
        <div class="upd-cta" id="uCta"></div>
        <button class="upd-recheck" id="uCheck">${tr('upd.check')}</button>
      </div>
      <div id="uNotice"></div>
      <div id="uProg" class="upd-prog hidden">
        <div class="prog"><i></i></div>
        <div class="job-line" id="uProgTxt"></div>
      </div>
      <div id="uChangelog"></div>
      ${isSuper ? `
      <div class="upd-sec">
        <div class="upd-sec-h">${tr('upd.settings')}</div>
        <div class="upd-group">
          <div class="upd-row">
            <div class="upd-row-t"><b>${tr('upd.auto')}</b><span>${tr('upd.auto_d')}</span></div>
            <label class="switch" style="padding:0"><input type="checkbox" id="uAuto"/><span class="swbox"></span></label>
          </div>
          <div class="upd-row">
            <div class="upd-row-t"><b>${tr('upd.source')}</b><span>${tr('upd.source_d')}</span></div>
            <div class="segbtns" id="uSrc"><button type="button" data-v="dn7">${tr('upd.src_dn7')}</button><button type="button" data-v="github">${tr('upd.src_github')}</button></div>
          </div>
        </div>
      </div>` : ''}
    </div>`;
  modal(tr('upd.title'), body, (close) => {
    UPD.close = close;
    if (isSuper) {
      const setSrc = (val) => $('uSrc').querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.v === val));
      UPD.setSrc = setSrc;
      // Last-persisted config: powers the optimistic revert + the step-up
      // decision (enabling auto or changing source needs re-auth server-side).
      UPD.cfg = { auto: false, source: 'dn7' };
      setSrc('dn7');
      api('/api/update/config').then((b) => {
        UPD.cfg = { auto: !!b.data.auto, source: b.data.source_pref === 'github' ? 'github' : 'dn7' };
        $('uAuto').checked = UPD.cfg.auto;
        setSrc(UPD.cfg.source);
      }).catch(() => {});
      $('uAuto').onchange = () => saveUpdCfg();
      $('uSrc').querySelectorAll('button').forEach((x) => x.onclick = () => { setSrc(x.dataset.v); saveUpdCfg().then((ok) => { if (ok) runUpdCheck(); }); });
    }
    $('uCheck').onclick = runUpdCheck;
    // Decide the initial view from whether an update is already running, so
    // re-opening the modal mid-update shows live progress — not the "update
    // now" CTA plus a dead, empty bar. Check status first; runUpdCheck() still
    // fills in the version line + changelog but suppresses the apply CTA while
    // an update is active (see UPD.active). The same status response carries
    // the rollback/boot-verify state (renderUpdNotice).
    api('/api/update/status').then((b) => {
      const d = b.data || {};
      renderUpdNotice(d);
      if (d.in_progress) {
        UPD.active = true;
        resetUpdProg();
        $('uProg').classList.remove('hidden');
        setUpdBar(0, 'indet');
        updTxt(tr('upd.starting'));
        runUpdCheck();
        pollUpdStatus();
      } else {
        UPD.active = false;
        runUpdCheck();
      }
    }).catch(() => { UPD.active = false; runUpdCheck(); });
  });
}

// Rollback / boot-verify state from /api/update/status (fields may be absent
// on older backends → falsy). A rollback renders a prominent warn instead of
// letting the hero silently claim "up to date" at the version the operator
// just tried to leave; failed versions also badge their changelog entries.
function renderUpdNotice(d) {
  UPD.failedVers = (d && d.failed_versions) || [];
  const host = $('uNotice'); if (!host || !d) return;
  if (d.rolled_back || d.rollback_from) {
    host.innerHTML = `<div class="warn">${tr('upd.rolled_back', { from: esc(d.rollback_from || '?'), to: esc(d.current || '?') })}</div>`;
  } else if (d.update_pending_verify) {
    host.innerHTML = `<div class="warn">${tr('upd.pending_verify')}</div>`;
  } else host.innerHTML = '';
}

// Persist the auto/source config. The backend requires a step-up re-auth when
// enabling auto (auto:true) or switching source, so grab a token first for
// those transitions — otherwise the POST 403s and the segmented control (which
// flipped optimistically) desyncs from the server. On step-up cancel or a
// failed POST we revert the control back to the last-persisted state (UPD.cfg).
// Returns a promise that resolves true only when the save succeeds.
async function saveUpdCfg() {
  const on = $('uSrc') && $('uSrc').querySelector('button.on');
  const source = on ? on.dataset.v : 'dn7';
  const auto = !!($('uAuto') && $('uAuto').checked);
  const prev = UPD.cfg || { auto: false, source: 'dn7' };
  const autoChanged = auto !== prev.auto;
  const sourceChanged = source !== prev.source;
  if (!autoChanged && !sourceChanged) return true; // no-op
  const revert = () => {
    if ($('uAuto')) $('uAuto').checked = prev.auto;
    if (UPD.setSrc) UPD.setSrc(prev.source);
  };
  // Send `auto` only when it actually changed so a source-only save with auto
  // already on doesn't trip the backend's enables_auto step-up gate.
  const body = { source_pref: source };
  if (autoChanged) body.auto = auto;
  const needsStepup = (autoChanged && auto) || sourceChanged;
  const headers = {};
  if (needsStepup) {
    const tok = await stepUp(tr('stepup.msg_update'));
    if (!tok) { revert(); return false; }
    headers['X-DN7-Stepup'] = tok;
  }
  try {
    await api('/api/update/config', { method: 'POST', headers, body: JSON.stringify(body) });
    UPD.cfg = { auto, source };
    toast(tr('upd.saved'));
    return true;
  } catch (e) {
    revert();
    toast(e.message, 'err');
    return false;
  }
}

function runUpdCheck() {
  const state = $('uState'); if (!state) return;
  const cur = $('uCur'), cta = $('uCta');
  state.textContent = tr('upd.checking'); state.className = 'upd-state';
  if (cta) cta.innerHTML = '';
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    if (cur) cur.textContent = 'v' + d.current;
    // While an update is actually running, the progress UI is the live state:
    // show the running version + changelog, but never the "update now" CTA
    // (re-opening the modal mid-update used to show a misleading "update now").
    if (UPD.active) {
      state.className = 'upd-state';
      state.textContent = tr('upd.in_progress');
      loadChangelog();
      return;
    }
    if (d.has_update) {
      state.className = 'upd-state avail';
      state.textContent = tr('upd.avail', { latest: d.latest });
      cta.innerHTML = `<button class="btn" id="uApply">${tr('upd.apply_to', { latest: esc(d.latest) })}</button>`;
      $('uApply').onclick = applyUpdate;
    } else if (d.latest) {
      state.className = 'upd-state ok';
      state.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>${esc(tr('upd.uptodate'))}`;
    } else {
      state.className = 'upd-state err';
      state.textContent = tr('upd.no_source');
    }
    loadChangelog();
  }).catch((e) => { state.className = 'upd-state err'; state.textContent = e.message; });
}

// Fetch + render the version history ("what's new"): release notes for the
// current build and every past version, newest first. The newest entry is
// expanded; older ones collapse behind a "view all" toggle. The entry matching
// the running build is tagged; versions that failed to boot and were rolled
// back (skiplist) are badged too. A fetch failure degrades to a quiet hint.
function loadChangelog() {
  const host = $('uChangelog'); if (!host) return;
  api('/api/update/changelog').then((b) => {
    const entries = (b.data && b.data.entries) || [];
    const current = (b.data && b.data.current) || '';
    if (!entries.length) { host.innerHTML = ''; return; }
    const failed = UPD.failedVers || [];
    // notes is a per-language map { lang: paragraph }; show the current language
    // (fall back to English, then any). codename + build → "Phanes 27.0.0 (build 1)"
    // title, else "v…".
    const noteFor = (e) => { const n = (e.notes && typeof e.notes === 'object') ? e.notes : {}; return n[curLang()] || n.en || Object.values(n)[0] || ''; };
    const verLabel = (e) => {
      const bd = (e.build && String(e.build) !== '0') ? ` (build ${esc(String(e.build))})` : '';
      return e.codename ? `${esc(e.codename)} ${esc(e.version)}${bd}` : `v${esc(e.version)}`;
    };
    const entry = (e) => {
      const note = noteFor(e);
      return `<div class="cl-entry"><div class="cl-ver">${verLabel(e)}${e.version === current ? `<span class="cl-cur">${tr('upd.current')}</span>` : ''}${failed.includes(e.version) ? `<span class="cl-cur cl-fail">${tr('upd.failed_badge')}</span>` : ''}${e.date ? '<span class="cl-date">' + esc(e.date) + '</span>' : ''}</div>`
        + (note ? `<div class="cl-note">${esc(note)}</div>` : `<div class="cl-empty mut">${tr('upd.no_notes')}</div>`)
        + '</div>';
    };
    let html = entry(entries[0]);
    if (entries.length > 1) {
      html += `<div id="uClMore" class="hidden">${entries.slice(1).map(entry).join('')}</div>`;
      html += `<button class="cl-toggle" id="uClToggle">${tr('upd.view_all', { n: entries.length })}</button>`;
    }
    host.innerHTML = `<div class="upd-sec"><div class="upd-sec-h">${tr('upd.changelog')}</div><div class="upd-group upd-cl">${html}</div></div>`;
    if (entries.length > 1) {
      $('uClToggle').onclick = () => {
        const more = $('uClMore'); const closed = more.classList.contains('hidden');
        more.classList.toggle('hidden');
        $('uClToggle').textContent = closed ? tr('upd.collapse') : tr('upd.view_all', { n: entries.length });
      };
    }
  }).catch(() => { host.innerHTML = `<div class="mut" style="font-size:12px;margin-top:10px">${tr('upd.cl_unavailable')}</div>`; });
}

function applyUpdate() {
  const btn = $('uApply');
  // Applying an update replaces the running binary and restarts the panel —
  // require a fresh step-up re-auth (also serves as the confirmation) so a
  // stolen/idle session can't push a new build on its own.
  stepUp(tr('stepup.msg_update')).then((tok) => {
    if (!tok) return;
    if (btn) { btn.disabled = true; btn.textContent = tr('upd.starting'); }
    resetUpdProg();
    UPD.active = true;
    api('/api/update/apply', { method: 'POST', headers: { 'X-DN7-Stepup': tok } }).then((b) => {
      if (b.data && b.data.started === false) toast(tr('upd.in_progress'));
      // Show the progress immediately (indeterminate until the first byte count),
      // so a fast download still gives visible feedback.
      setUpdBar(0, 'indet');
      updTxt(tr('upd.starting'));
      pollUpdStatus();
    }).catch((e) => { toast(e.message, 'err'); if (btn) { btn.disabled = false; btn.textContent = tr('upd.retry'); } });
  });
}

// Progress is presented in three phases mapped onto one bar:
//   1) download → 0–100% driven by real byte progress (indeterminate when the
//      source sends no content-length)
//   2) install  → indeterminate; the swap is atomic and reports no real
//      progress, so no percentage is fabricated. A confirmation (the panel
//      restarting, i.e. the status request failing) moves to phase 3
//   3) done     → 100%, a short countdown, then reload onto the new build.
function setUpdBar(pct, cls) {
  const prog = $('uProg'); if (!prog) return;
  prog.classList.remove('hidden');
  const bar = prog.querySelector('.prog'), pi = prog.querySelector('.prog > i');
  if (!bar) return;
  bar.classList.remove('indet', 'done', 'err');
  if (cls) bar.classList.add(cls);
  if (pi && pct != null) pi.style.width = Math.max(0, Math.min(100, pct)) + '%';
}
function updTxt(s) { const t = $('uProgTxt'); if (t) t.textContent = s; }
function resetUpdProg() {
  if (UPD.cd) { clearInterval(UPD.cd); UPD.cd = null; }
  UPD.refreshing = false;
}
function enterRefreshState() {
  if (UPD.refreshing) return;
  UPD.refreshing = true;
  if (UPD.polling) { clearInterval(UPD.polling); UPD.polling = null; }
  setUpdBar(100, 'done');
  let n = 3;
  updTxt(tr('upd.refresh_in', { n }));
  UPD.cd = setInterval(() => {
    n--;
    if (n <= 0) { clearInterval(UPD.cd); UPD.cd = null; updTxt(tr('upd.restarting')); waitForRestart(); }
    else updTxt(tr('upd.refresh_in', { n }));
  }, 1000);
}

function pollUpdStatus() {
  if (UPD.polling) clearInterval(UPD.polling);
  const mb = (n) => (n / 1048576).toFixed(1);
  const tick = () => {
    api('/api/update/status').then((b) => {
      const d = b.data;
      if (!$('uProg')) { clearInterval(UPD.polling); UPD.polling = null; return; }
      if (UPD.refreshing) return;
      if (d.phase === 'downloading') {
        if (d.total_bytes) setUpdBar(d.progress || 0, '');
        else setUpdBar(null, 'indet');
        updTxt(tr('upd.downloading', { pct: d.progress }) + (d.total_bytes ? ` (${mb(d.done_bytes)}/${mb(d.total_bytes)} MB)` : ''));
      } else if (d.phase === 'installing') {
        // Atomic verify+swap: no real progress exists, so show honest
        // indeterminate motion instead of a fabricated ramp that can sit at a
        // full bar while still installing.
        setUpdBar(null, 'indet');
        updTxt(tr('upd.installing'));
      } else if (d.phase === 'error') {
        setUpdBar(100, 'err');
        updTxt(tr('upd.error'));
        clearInterval(UPD.polling); UPD.polling = null;
        UPD.active = false;
        renderUpdNotice(d);
        const btn = $('uApply');
        if (btn) { btn.disabled = false; btn.textContent = tr('upd.retry'); }
        else runUpdCheck(); // re-attached view has no CTA yet — rebuild it
      } else {
        // idle / checking / not-yet-started: show an indeterminate bar so a
        // re-attached view never shows a dead, empty bar. Keep polling.
        setUpdBar(null, 'indet'); updTxt(tr('upd.starting'));
      }
    }).catch(() => {
      // Server unreachable → install finished and the panel is restarting onto
      // the new build. Move to the final phase: fill, count down, then reload.
      enterRefreshState();
    });
  };
  tick();
  UPD.polling = setInterval(tick, 700);
}

// ---- Restart overlay ----
// While the panel restarts the whole shell is a dead UI (every click errors):
// mask it with a full-screen blocking overlay instead of leaving it clickable.
// Shared by the self-update flow and a (future) needs_restart settings save.
function restartMaskShow(msg) {
  let m = $('restartMask');
  if (!m) {
    m = el('div', { id: 'restartMask', class: 'restart-mask' });
    m.innerHTML = '<div class="spin"></div><div class="rm-msg" id="rmMsg"></div><div id="rmAct"></div>';
    document.body.appendChild(m);
  }
  m.classList.remove('failed');
  $('rmMsg').textContent = msg;
  $('rmAct').innerHTML = '';
}
function restartMaskFail() {
  const m = $('restartMask'); if (!m) return;
  m.classList.add('failed');
  $('rmMsg').textContent = tr('upd.restart_timeout');
  $('rmAct').innerHTML = `<button class="btn sec" id="rmReload">${tr('common.reload')}</button>`;
  $('rmReload').onclick = () => location.reload();
}

// After the panel exits to restart, poll a public endpoint until it answers
// again, then reload. When the retry budget runs out, say so (a stale
// "restarting…" that hangs forever reads as success) and offer a manual reload.
function waitForRestart(msg) {
  if (UPD.reloading) return;
  UPD.reloading = true;
  restartMaskShow(msg || tr('upd.restarting'));
  let tries = 0;
  const ping = () => {
    tries++;
    fetch('/api/login/challenge', { cache: 'no-store' })
      .then((r) => { if (r.ok) location.reload(); else next(); })
      .catch(next);
  };
  const next = () => {
    if (tries < 150) setTimeout(ping, 1000);
    else { UPD.reloading = false; restartMaskFail(); }
  };
  setTimeout(ping, 1500);
}
