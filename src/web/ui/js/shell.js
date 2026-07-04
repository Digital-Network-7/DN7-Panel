// =========================================================================
// Shell + tabs
// =========================================================================
// Monochrome line/solid icons (inherit currentColor). Kept inline so the
// console stays a single self-contained file with no icon-font/CDN dependency.
const IC = {
  dash: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M3 12h3l2.5 6 4-13L18 12h3"/></svg>',
  term: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><path d="M13 15h4"/></svg>',
  // Containers: a neutral 3D box/package outline (vendor-neutral container mark).
  docker: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>',
  // Website: a neutral globe (web), vendor-neutral — not an "N"/nginx mark.
  website: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14.5 14.5 0 0 1 0 18 14.5 14.5 0 0 1 0-18"/></svg>',
  files: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" style="vertical-align:-3px"><path d="M3 6.5C3 5.7 3.7 5 4.5 5H9l2 2h8.5c.8 0 1.5.7 1.5 1.5v9c0 .8-.7 1.5-1.5 1.5h-15C3.7 19 3 18.3 3 17.5v-11Z"/></svg>',
  settings: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>',
  users: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  logs: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M5 3h9l5 5v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M8 12h8M8 16h8M8 8h2"/></svg>',
};
// `admin: true` → visible only to admin (sudo) accounts; `sup: true` → only the
// super-admin. Unflagged tabs are available to every authenticated user.
const TABS = [
  { key: 'dash', tkey: 'tab.dash', ic: IC.dash },
  { key: 'term', tkey: 'tab.term', ic: IC.term },
  { key: 'docker', tkey: 'tab.docker', ic: IC.docker, admin: true },
  { key: 'website', tkey: 'tab.website', ic: IC.website, admin: true },
  { key: 'files', tkey: 'tab.files', ic: IC.files },
  { key: 'users', tkey: 'tab.users', ic: IC.users, admin: true },
  { key: 'settings', tkey: 'tab.settings', ic: IC.settings, sup: true },
  { key: 'logs', tkey: 'tab.logs', ic: IC.logs, sup: true },
];
// Whether the current account may see/use a tab.
function tabAllowed(t) {
  const me = Auth.me || {};
  if (t.sup) return !!me.is_super;
  if (t.admin) return !!me.is_admin;
  return true;
}
// A tab's display label: translated when it has a key, else the literal brand.
function tabLabel(t) { return t.tkey ? tr(t.tkey) : (t.label || ''); }

function showApp() {
  document.documentElement.setAttribute('data-auth', 'in');
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  api('/api/me').then((b) => {
    Auth.me = b.data || {};
    renderNav();
    setUser(Auth.me.nickname || Auth.me.username || 'admin', Auth.me.avatar);
    if (Auth.me.must_setup) forceAccountSetup(Auth.me.username, () => { logout(); });
    // Deep link: an initial #tab in the URL wins over the saved tab.
    const hk = location.hash.slice(1);
    if (hk && TABS.some((x) => x.key === hk)) UI.setTab(hk);
    // If the saved tab isn't allowed for this account, fall back to dashboard.
    const t = TABS.find((x) => x.key === UI.tab);
    if (!t || !tabAllowed(t)) UI.setTab('dash');
    switchTab(UI.tab);
    // Update badge is admin-only; gate on the real role (Auth.me is only set here).
    if (window.updateBadge && Auth.me.is_admin) updateBadge();
  }).catch(() => {});
  api('/api/info').then((b) => {
    // "<codename> <version>", e.g. "Phanes 27.0.0" (codename "dev" on local builds).
    const cn = b.data.codename ? b.data.codename + ' ' : '';
    $('panelVer').textContent = cn + (b.data.version || '?');
    if (b.data.hostname) $('panelVer').title = b.data.hostname;
  }).catch(() => {});
  if (window.updateJobsBadge) updateJobsBadge();
}
// Build the sidebar nav from the tabs the current account may access.
function renderNav() {
  const nav = $('nav'); nav.innerHTML = '';
  nav.setAttribute('aria-label', tr('nav.label'));
  TABS.filter(tabAllowed).forEach((t) => {
    // title doubles as the tooltip for the <=720px icon rail (labels hidden).
    const b = el('button', { 'data-k': t.key, title: tabLabel(t) });
    b.className = UI.tab === t.key ? 'active' : '';
    if (UI.tab === t.key) b.setAttribute('aria-current', 'page');
    b.innerHTML = `<span class="ic">${t.ic}</span><span class="t">${tabLabel(t)}</span>`;
    b.onclick = () => switchTab(t.key, 'nav');
    nav.appendChild(b);
  });
}
function setUser(name, avatar) {
  $('whoName').textContent = name;
  const av = $('userAv');
  if (avatar) { av.innerHTML = `<img src="${esc(avatar)}" alt="" />`; av.classList.add('hasimg'); }
  else { av.textContent = (name[0] || 'A').toUpperCase(); av.classList.remove('hasimg'); }
}

function stopTab() {
  if (S.timer) { clearInterval(S.timer); S.timer = null; }
  if (S.ws) { try { S.ws.close(); } catch (e) {} S.ws = null; }
  if (window._dashCleanup) { try { window._dashCleanup(); } catch (e) {} window._dashCleanup = null; }
  if (window._logsCleanup) { try { window._logsCleanup(); } catch (e) {} window._logsCleanup = null; }
  if (window._termCleanup) { try { window._termCleanup(); } catch (e) {} window._termCleanup = null; }
  if (window._modalTermCleanup) { try { window._modalTermCleanup(); } catch (e) {} window._modalTermCleanup = null; }
  // Close any open modal (and its live sockets) when leaving a tab. Route
  // through closeAllModals() (forced, non-guarded teardown) rather than wiping
  // #modalRoot directly: the latter bypasses modal()'s close(), leaking the
  // per-modal keydown listener and stranding onDismiss promises (confirmDanger/
  // stepUp/sessionExpired → Busy stuck, AUTH_EXPIRED latched). Persisted
  // background jobs survive this: their pollers self-stop once detached
  // (jobs.js checks host.isConnected) and re-attach from the localStorage slot.
  if (typeof closeAllModals === 'function') closeAllModals();
  const root = $('modalRoot'); if (root) root.innerHTML = ''; // belt-and-suspenders
}

// `src`: 'nav' = user nav click (pushes a history entry), 'pop' = back/forward
// (history already moved), anything else = programmatic/guard (replaces).
function switchTab(k, src) {
  const t = TABS.find((x) => x.key === k);
  if (t && !tabAllowed(t)) { k = 'dash'; src = 'guard'; } // deny tabs above the account's role
  UI.setTab(k);
  if (src !== 'pop') {
    const push = src === 'nav' && location.hash !== '#' + k;
    try { history[push ? 'pushState' : 'replaceState'](null, '', '#' + k); } catch (e) {}
  }
  const paint = () => {
    stopTab();
    document.querySelectorAll('#nav button').forEach((b) => {
      const on = b.dataset.k === k;
      b.className = on ? 'active' : '';
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    $('title').textContent = tabLabel(TABS.find((x) => x.key === k) || {});
    const v = $('view'); v.innerHTML = '';
    // The dashboard + terminal + files + logs are fixed one-screen layouts (no
    // body scroll); other tabs scroll normally. (Logs fits its table to the
    // available height and paginates, so it must own the viewport.)
    const fill = (k === 'dash' || k === 'term' || k === 'files' || k === 'logs');
    v.classList.toggle('fill', fill);
    document.querySelector('.content').classList.toggle('fillmode', fill);
    if (k === 'dash') renderDash(v);
    else if (k === 'term') renderTerm(v);
    else if (k === 'docker') renderDocker(v);
    else if (k === 'website') renderWebsite(v);
    else if (k === 'files') renderFiles(v);
    else if (k === 'users') renderUsers(v);
    else if (k === 'settings') renderSettings(v);
    else if (k === 'logs') renderLogs(v);
  };
  // Cross-fade the swap via the View Transitions API when available (CSS in
  // app.css); plain repaint when unsupported or reduced motion is requested.
  if (document.startViewTransition && !matchMedia('(prefers-reduced-motion: reduce)').matches) document.startViewTransition(paint);
  else paint();
}

// Back/forward navigates tabs (repaint only — never push another entry).
window.addEventListener('popstate', () => {
  if (document.documentElement.getAttribute('data-auth') !== 'in') return;
  const k = location.hash.slice(1) || 'dash';
  if (TABS.some((x) => x.key === k) && k !== UI.tab) switchTab(k, 'pop');
});

// =========================================================================
// Topbar running-jobs indicator + sidebar help
// =========================================================================
// Spinner iconbtn injected next to #langBtn; hidden unless the persisted job
// store (jobs.js) has active slots. The '?' help button joins the sidebar foot.
(function initTopbarExtras() {
  const lang = $('langBtn');
  if (lang && !$('jobsBtn')) {
    const b = el('button', { class: 'iconbtn hidden', id: 'jobsBtn', title: tr('jobs.running'), 'aria-label': tr('jobs.running') });
    b.innerHTML = '<span class="jobs-spin" aria-hidden="true"></span>';
    b.onclick = toggleJobsPop;
    lang.parentNode.insertBefore(b, lang);
  }
  const foot = document.querySelector('aside .foot');
  if (foot && !$('helpBtn')) {
    const h = el('button', { class: 'iconbtn helpbtn', id: 'helpBtn', title: tr('help.title'), 'aria-label': tr('help.title') });
    h.innerHTML = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.2-3 3.7"/><path d="M12 17h.01"/></svg>';
    h.onclick = openHelp;
    foot.appendChild(h);
  }
})();
// Show/hide the spinner from the persisted-job slot count (jobs.js calls this
// on every saveJob so the indicator tracks job starts/finishes live).
function updateJobsBadge() {
  const b = $('jobsBtn'); if (!b || typeof loadJobs !== 'function') return;
  b.classList.toggle('hidden', !Object.keys(loadJobs()).length);
}
function toggleJobsPop() {
  const old = document.querySelector('.jobs-pop');
  if (old) { old.remove(); return; }
  const jobs = (typeof loadJobs === 'function') ? loadJobs() : {};
  // Own class only (NOT 'selx-pop'): selxClose() removes every .selx-pop and
  // selx's window-scroll handler would close this popup even on scrolls inside
  // its own overflow list. The jobs popup owns its full lifecycle here; its
  // chrome (position/z-index/background/border/radius/shadow/max-height/overflow)
  // is declared in the scratchpad fix CSS.
  const pop = el('div', { class: 'jobs-pop' });
  const keys = Object.keys(jobs);
  if (!keys.length) pop.innerHTML = `<div class="mut jobs-empty">${tr('jobs.none')}</div>`;
  keys.forEach((slot) => {
    const info = jobs[slot] || {};
    const p0 = slot.split(':')[0];
    const t = TABS.find((x) => x.key === p0);
    const row = el('div', { class: 'jobs-row' });
    row.innerHTML = `<div class="jobs-name"><b>${esc(t ? tabLabel(t) : p0)}</b><span class="mut">${esc(slot.split(':').slice(1).join(':') || info.kind || '')}</span></div>
      <div class="prog indet"><i></i></div><div class="job-line"></div>`;
    if (t && tabAllowed(t)) { row.style.cursor = 'pointer'; row.onclick = () => { pop.remove(); switchTab(p0, 'nav'); }; }
    pop.appendChild(row);
    pollJobRow(row, slot, info);
  });
  document.body.appendChild(pop);
  const r = $('jobsBtn').getBoundingClientRect();
  pop.style.minWidth = '260px';
  pop.style.left = Math.max(8, r.right - 280) + 'px';
  pop.style.top = (r.bottom + 4) + 'px';
  const close = (e) => { if (!e.target.closest('.jobs-pop') && !e.target.closest('#jobsBtn')) { pop.remove(); document.removeEventListener('mousedown', close, true); } };
  setTimeout(() => document.addEventListener('mousedown', close, true), 0);
}
// Read-only progress poll for one popup row; stops once the popup is removed.
// Never dismisses the op server-side — the owning page's renderJob does that —
// but does clear a finished slot so the spinner doesn't stick forever.
function pollJobRow(row, slot, info) {
  const bar = row.querySelector('.prog'), line = row.querySelector('.job-line');
  const tick = () => {
    if (!row.isConnected) return;
    op(info.kind, { op: 'op_log', op_id: info.opId }).then((d) => {
      if (!row.isConnected) return;
      const lines = d.lines || [];
      line.textContent = lines.length ? msgLine(lines[lines.length - 1]) : tr('job.processing');
      if (typeof d.pct === 'number' && d.pct >= 0) { bar.classList.remove('indet'); bar.querySelector('i').style.width = Math.min(100, d.pct).toFixed(0) + '%'; }
      if (d.status === 'done' || d.status === 'error' || d.status === 'gone') {
        bar.classList.remove('indet'); bar.classList.add(d.status === 'done' ? 'done' : 'err');
        line.textContent = d.status === 'done' ? tr('job.done') : (d.status === 'error' ? tr('job.failed') + codeMsg(d.error || '') : tr('job.ended'));
        saveJob(slot, null);
        return;
      }
      setTimeout(tick, 1200);
    }).catch(() => setTimeout(tick, 1800));
  };
  tick();
}
// '?' help: key panel concepts + the matching dn7 host-CLI entry points.
function openHelp() {
  const body = `<ul class="help-list">${['stepup', 'cli', 'pwsync', 'update', 'logs', 'docs']
    .map((k) => `<li>${esc(tr('help.body_' + k))}</li>`).join('')}</ul>`;
  modal(tr('help.title'), body);
}
