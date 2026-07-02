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
    // If the saved tab isn't allowed for this account, fall back to dashboard.
    const t = TABS.find((x) => x.key === UI.tab);
    if (!t || !tabAllowed(t)) UI.setTab('dash');
    switchTab(UI.tab);
  }).catch(() => {});
  api('/api/info').then((b) => {
    $('panelVer').textContent = 'v' + (b.data.version || '?');
    if (b.data.hostname) $('panelVer').title = b.data.hostname;
  }).catch(() => {});
  if (window.updateBadge && (Auth.me ? Auth.me.is_admin : true)) updateBadge();
}
// Build the sidebar nav from the tabs the current account may access.
function renderNav() {
  const nav = $('nav'); nav.innerHTML = '';
  TABS.filter(tabAllowed).forEach((t) => {
    const b = el('button', { 'data-k': t.key });
    b.className = UI.tab === t.key ? 'active' : '';
    b.innerHTML = `<span class="ic">${t.ic}</span><span class="t">${tabLabel(t)}</span>`;
    b.onclick = () => switchTab(t.key);
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
  if (window._termCleanup) { try { window._termCleanup(); } catch (e) {} window._termCleanup = null; }
  if (window._modalTermCleanup) { try { window._modalTermCleanup(); } catch (e) {} window._modalTermCleanup = null; }
  // Close any open modal (and its live sockets) when leaving a tab.
  const root = $('modalRoot'); if (root) root.innerHTML = '';
}

function switchTab(k) {
  const t = TABS.find((x) => x.key === k);
  if (t && !tabAllowed(t)) k = 'dash'; // guard: deny tabs above the account's role
  UI.setTab(k);
  stopTab();
  document.querySelectorAll('#nav button').forEach((b) => b.className = b.dataset.k === k ? 'active' : '');
  $('title').textContent = tabLabel(TABS.find((t) => t.key === k) || {});
  const v = $('view'); v.innerHTML = '';
  // The dashboard + terminal + files are fixed one-screen layouts (no body
  // scroll); other tabs scroll normally.
  const fill = (k === 'dash' || k === 'term' || k === 'files');
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
}
