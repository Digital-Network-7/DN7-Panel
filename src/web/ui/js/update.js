// =========================================================================
// Self-update — version modal (manual / auto), dual-source (GitHub + dn7.cn).
// Opened from the sidebar version line; talks to /api/update/*.
// =========================================================================
const UPD = { polling: null, active: false };

// Passive check on login: light up the sidebar dot when a newer build exists.
function updateBadge() {
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    if (d.has_update && $('verLine')) $('verLine').title = tr('upd.has_update', { latest: d.latest });
  }).catch(() => {});
}

function openUpdate() {
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
      <div id="uProg" class="upd-prog hidden">
        <div class="prog"><i></i></div>
        <div class="job-line" id="uProgTxt"></div>
      </div>
      <div id="uChangelog"></div>
      <div class="upd-sec">
        <div class="upd-sec-h">${tr('upd.settings')}</div>
        <div class="upd-group">
          <div class="upd-row">
            <div class="upd-row-t"><b>${tr('upd.auto')}</b><span>${tr('upd.auto_d')}</span></div>
            <label class="switch" style="padding:0"><input type="checkbox" id="uAuto"/><span class="swbox"></span></label>
          </div>
          <div class="upd-row">
            <div class="upd-row-t"><b>${tr('upd.beta')}</b><span>${tr('upd.beta_d')}</span></div>
            <label class="switch" style="padding:0"><input type="checkbox" id="uBeta"/><span class="swbox"></span></label>
          </div>
        </div>
      </div>
    </div>`;
  modal(tr('upd.title'), body, (close) => {
    UPD.close = close;
    api('/api/update/config').then((b) => {
      $('uAuto').checked = !!b.data.auto;
      $('uBeta').checked = b.data.source_pref === 'github';
    }).catch(() => {});
    $('uCheck').onclick = runUpdCheck;
    $('uAuto').onchange = saveUpdCfg;
    $('uBeta').onchange = () => { saveUpdCfg(); runUpdCheck(); };
    // Decide the initial view from whether an update is already running, so
    // re-opening the modal mid-update shows live progress — not the "update
    // now" CTA plus a dead, empty bar. Check status first; runUpdCheck() still
    // fills in the version line + changelog but suppresses the apply CTA while
    // an update is active (see UPD.active).
    api('/api/update/status').then((b) => {
      if (b.data && b.data.in_progress) {
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

function saveUpdCfg() {
  api('/api/update/config', { method: 'POST', body: JSON.stringify({ auto: $('uAuto').checked, source_pref: $('uBeta').checked ? 'github' : 'dn7' }) })
    .then(() => toast(tr('upd.saved'))).catch((e) => toast(e.message, 'err'));
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
// the running build is tagged. A fetch failure degrades to a quiet hint.
function loadChangelog() {
  const host = $('uChangelog'); if (!host) return;
  api('/api/update/changelog').then((b) => {
    const entries = (b.data && b.data.entries) || [];
    const current = (b.data && b.data.current) || '';
    if (!entries.length) { host.innerHTML = ''; return; }
    const entry = (e) => `<div class="cl-entry"><div class="cl-ver">v${esc(e.version)}${e.version === current ? `<span class="cl-cur">${tr('upd.current')}</span>` : ''}${e.date ? '<span class="cl-date">' + esc(e.date) + '</span>' : ''}</div>`
      + (e.notes && e.notes.length ? '<ul class="cl-notes">' + e.notes.map((n) => `<li>${esc(n)}</li>`).join('') + '</ul>' : `<div class="cl-empty mut">${tr('upd.no_notes')}</div>`)
      + '</div>';
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
//   1) download → 0–60% (driven by real byte progress)
//   2) install  → 60–100% (auto-ramps +5%/s, full in ~8s) while we wait for the
//      backend to confirm; a confirmation (the panel restarting, i.e. the
//      status request failing) jumps straight to phase 3
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
  if (UPD.ramp) { clearInterval(UPD.ramp); UPD.ramp = null; }
  if (UPD.cd) { clearInterval(UPD.cd); UPD.cd = null; }
  UPD.refreshing = false;
}
function startInstallRamp() {
  if (UPD.ramp || UPD.refreshing) return;
  UPD.rampPct = 60;
  setUpdBar(60, '');
  updTxt(tr('upd.installing'));
  UPD.ramp = setInterval(() => {
    if (UPD.refreshing) { clearInterval(UPD.ramp); UPD.ramp = null; return; }
    UPD.rampPct = Math.min(100, UPD.rampPct + 1); // +5%/s (the 40% install span fills in ~8s)
    setUpdBar(UPD.rampPct, '');
    if (UPD.rampPct >= 100) { clearInterval(UPD.ramp); UPD.ramp = null; }
  }, 200);
}
function enterRefreshState() {
  if (UPD.refreshing) return;
  UPD.refreshing = true;
  if (UPD.ramp) { clearInterval(UPD.ramp); UPD.ramp = null; }
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
        if (UPD.ramp) { clearInterval(UPD.ramp); UPD.ramp = null; }
        if (d.total_bytes) setUpdBar((d.progress || 0) * 0.6, '');
        else setUpdBar(null, 'indet');
        updTxt(tr('upd.downloading', { pct: d.progress }) + (d.total_bytes ? ` (${mb(d.done_bytes)}/${mb(d.total_bytes)} MB)` : ''));
      } else if (d.phase === 'installing') {
        startInstallRamp();
      } else if (d.phase === 'error') {
        if (UPD.ramp) { clearInterval(UPD.ramp); UPD.ramp = null; }
        setUpdBar(100, 'err');
        updTxt(tr('upd.error'));
        clearInterval(UPD.polling); UPD.polling = null;
        UPD.active = false;
        const btn = $('uApply');
        if (btn) { btn.disabled = false; btn.textContent = tr('upd.retry'); }
        else runUpdCheck(); // re-attached view has no CTA yet — rebuild it
      } else {
        // idle / checking / not-yet-started: show an indeterminate bar so a
        // re-attached view never shows a dead, empty bar. Keep polling.
        if (!UPD.ramp) { setUpdBar(null, 'indet'); updTxt(tr('upd.starting')); }
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

// After the panel exits to restart on the new build, poll a public endpoint
// until it answers again, then reload so the UI runs the new version.
function waitForRestart() {
  if (UPD.reloading) return;
  UPD.reloading = true;
  let tries = 0;
  const ping = () => {
    tries++;
    fetch('/api/login/challenge', { cache: 'no-store' })
      .then((r) => { if (r.ok) location.reload(); else if (tries < 150) setTimeout(ping, 1000); })
      .catch(() => { if (tries < 150) setTimeout(ping, 1000); });
  };
  setTimeout(ping, 1500);
}
