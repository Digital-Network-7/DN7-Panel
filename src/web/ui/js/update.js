// =========================================================================
// Self-update — version modal (manual / auto), dual-source (GitHub + dn7.cn).
// Opened from the sidebar version line; talks to /api/update/*.
// =========================================================================
const UPD = { polling: null };

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
            <div class="upd-row-t"><b>${tr('upd.source')}</b></div>
            <select id="uSource" class="field" style="width:auto;min-width:172px">
              <option value="auto">${tr('upd.src_auto')}</option>
              <option value="github">GitHub</option>
              <option value="dn7">Digital Network 7</option>
            </select>
          </div>
        </div>
      </div>
    </div>`;
  modal(tr('upd.title'), body, (close) => {
    UPD.close = close;
    api('/api/update/config').then((b) => {
      $('uAuto').checked = !!b.data.auto;
      $('uSource').value = b.data.source_pref || 'auto';
    }).catch(() => {});
    $('uCheck').onclick = runUpdCheck;
    $('uAuto').onchange = saveUpdCfg;
    $('uSource').onchange = saveUpdCfg;
    runUpdCheck();
    pollUpdStatus(); // re-attach progress if a download is already running
  });
}

function saveUpdCfg() {
  api('/api/update/config', { method: 'POST', body: JSON.stringify({ auto: $('uAuto').checked, source_pref: $('uSource').value }) })
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
      + (e.notes && e.notes.length ? '<ul class="cl-notes">' + e.notes.map((n) => `<li>${esc(n)}</li>`).join('') + '</ul>' : '')
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
  const btn = $('uApply'); if (btn) { btn.disabled = true; btn.textContent = tr('upd.starting'); }
  api('/api/update/apply', { method: 'POST' }).then((b) => {
    if (b.data && b.data.started === false) toast(tr('upd.in_progress'));
    $('uProg').classList.remove('hidden');
    pollUpdStatus();
  }).catch((e) => { toast(e.message, 'err'); if (btn) { btn.disabled = false; btn.textContent = tr('upd.retry'); } });
}

function pollUpdStatus() {
  if (UPD.polling) clearInterval(UPD.polling);
  UPD.polling = setInterval(() => {
    api('/api/update/status').then((b) => {
      const d = b.data, prog = $('uProg');
      if (!prog) { clearInterval(UPD.polling); return; }
      const pi = prog.querySelector('.prog > i'), txt = $('uProgTxt');
      if (d.phase === 'downloading') {
        prog.classList.remove('hidden');
        pi.style.width = d.progress + '%';
        const mb = (n) => (n / 1048576).toFixed(1);
        txt.textContent = tr('upd.downloading', { pct: d.progress }) + (d.total_bytes ? ` (${mb(d.done_bytes)}/${mb(d.total_bytes)} MB)` : '');
      } else if (d.phase === 'installing') {
        prog.classList.remove('hidden');
        pi.style.width = '100%';
        txt.textContent = tr('upd.installing');
      } else if (d.phase === 'error') {
        txt.textContent = tr('upd.error');
        clearInterval(UPD.polling);
      } else if (!d.in_progress) {
        clearInterval(UPD.polling);
      }
    }).catch(() => {
      // The panel restarts after install → requests fail; that's success.
      const txt = $('uProgTxt');
      if (txt) txt.textContent = tr('upd.restarting');
      clearInterval(UPD.polling);
    });
  }, 1000);
}
