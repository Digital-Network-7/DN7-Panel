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
    <div class="row" style="justify-content:space-between;align-items:center">
      <div>${tr('upd.current')} <b id="uCur">…</b></div>
      <button class="btn sec sm" id="uCheck">${tr('upd.check')}</button>
    </div>
    <div id="uResult" style="margin-top:14px"></div>
    <div id="uProg" class="hidden" style="margin-top:14px">
      <div class="prog"><i></i></div>
      <div class="job-line" id="uProgTxt"></div>
    </div>
    <div class="card" style="margin-top:16px;background:var(--panel2)">
      <h3>${tr('upd.settings')}</h3>
      <label class="switch"><input type="checkbox" id="uAuto"/><span class="swbox"></span><span class="swtxt"><b>${tr('upd.auto')}</b><span>${tr('upd.auto_d')}</span></span></label>
      <label class="lbl" style="margin-top:10px">${tr('upd.source')}</label>
      <select id="uSource" class="field">
        <option value="auto">${tr('upd.src_auto')}</option>
        <option value="github">GitHub</option>
        <option value="dn7">Digital Network 7</option>
      </select>
    </div>`;
  modal(tr('upd.title'), body, (close) => {
    UPD.close = close;
    api('/api/update/config').then((b) => {
      $('uAuto').checked = !!b.data.auto;
      $('uSource').value = b.data.source_pref || 'auto';
    }).catch(() => {});
    api('/api/update/status').then((b) => { $('uCur').textContent = 'v' + b.data.current; }).catch(() => {});
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

function srcLabel(name) { return name === 'dn7' ? 'Digital Network 7' : 'GitHub'; }

function runUpdCheck() {
  const r = $('uResult'); if (!r) return;
  r.innerHTML = loading(tr('upd.checking'), 2);
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    let html = '';
    if (d.has_update) {
      html += `<div class="ok" style="font-size:14px;margin-bottom:10px">${tr('upd.found', { latest: esc(d.latest), current: esc(d.current) })}</div>`;
      html += `<button class="btn" id="uApply">${tr('upd.apply_to', { latest: esc(d.latest) })}</button>`;
      html += '<div id="uChangelog"></div>';
    } else if (d.latest) {
      html += `<div class="mut" style="margin-bottom:6px">${tr('upd.latest', { current: esc(d.current) })}</div>`;
    } else {
      html += `<div class="err" style="margin-bottom:6px">${tr('upd.no_source')}</div>`;
    }
    html += '<div style="margin-top:12px">' + (d.sources || []).map((s) => {
      const tag = s.ok ? `<span class="chip on">${tr('upd.kbps', { n: s.kbps })}</span>` : `<span class="chip warn">${tr('upd.conn_fail')}</span>`;
      const star = (s.name === d.source) ? ` <span style="color:var(--cy)">${tr('upd.cur_src')}</span>` : '';
      return `<div class="row" style="justify-content:space-between;padding:6px 0;border-top:1px solid var(--line)"><span>${srcLabel(s.name)}${star}</span>${tag}</div>`;
    }).join('') + '</div>';
    r.innerHTML = html;
    if (d.has_update) { $('uApply').onclick = applyUpdate; loadChangelog(); }
  }).catch((e) => { r.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Fetch + render "what's new": the notes for every version this update brings
// (newest first). Shows the latest version expanded; the rest collapse behind a
// "view all" toggle. Works from whichever source (GitHub / Digital Network 7)
// is reachable; a fetch failure degrades to a quiet hint.
function loadChangelog() {
  const host = $('uChangelog'); if (!host) return;
  api('/api/update/changelog').then((b) => {
    const entries = (b.data && b.data.entries) || [];
    if (!entries.length) { host.innerHTML = ''; return; }
    const entry = (e) => `<div class="cl-entry"><div class="cl-ver">v${esc(e.version)}${e.date ? ' · ' + esc(e.date) : ''}</div>`
      + (e.notes && e.notes.length ? '<ul class="cl-notes">' + e.notes.map((n) => `<li>${esc(n)}</li>`).join('') + '</ul>' : '')
      + '</div>';
    let html = `<div class="cl-title">${tr('upd.changelog')}</div>` + entry(entries[0]);
    if (entries.length > 1) {
      html += `<div id="uClMore" class="hidden">${entries.slice(1).map(entry).join('')}</div>`;
      html += `<button class="cl-toggle" id="uClToggle">${tr('upd.view_all', { n: entries.length })}</button>`;
    }
    host.innerHTML = `<div class="upd-cl">${html}</div>`;
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
