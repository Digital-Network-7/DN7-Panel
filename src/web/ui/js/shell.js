// =========================================================================
// Shell + tabs
// =========================================================================
// Monochrome line/solid icons (inherit currentColor). Kept inline so the
// console stays a single self-contained file with no icon-font/CDN dependency.
const IC = {
  dash: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M3 12h3l2.5 6 4-13L18 12h3"/></svg>',
  term: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><path d="M13 15h4"/></svg>',
  // Docker: the stacked containers + whale-back silhouette, simplified, solid.
  docker: '<svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor" style="vertical-align:-3px"><path d="M4 10h2.4v2.2H4V10Zm2.9 0h2.4v2.2H6.9V10Zm2.9 0h2.4v2.2H9.8V10Zm2.9 0h2.4v2.2h-2.4V10ZM6.9 7.1h2.4v2.2H6.9V7.1Zm2.9 0h2.4v2.2H9.8V7.1Zm2.9 0h2.4v2.2h-2.4V7.1Zm0-2.9h2.4v2.2h-2.4V4.2Z"/><path d="M22 11.2c-.5-.35-1.7-.48-2.6-.3-.12-.83-.6-1.55-1.43-2.2l-.48-.32-.32.48c-.42.64-.56 1.7-.13 2.42.18.3.46.55.8.72-.4.22-1.18.3-1.36.3H2.5c-.36 2 .26 4.5 1.86 6 1.5 1.42 3.74 2.1 6.66 2.1 6.33 0 11.02-2.92 13.2-8.24.86.02 2.02-.01 2.62-1.16l.16-.3-.28-.2c-.62-.4-1.62-.5-2.38-.3Z" transform="translate(-1.5 0)"/></svg>',
  // Nginx: stylized "N" inside a rounded square (official wordmark feel).
  nginx: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" style="vertical-align:-3px"><rect x="3" y="3" width="18" height="18" rx="4"/><path d="M8.5 16V8.5l7 7V8" stroke-linecap="round"/></svg>',
  // MySQL: a database cylinder (clean, monochrome).
  mysql: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><ellipse cx="12" cy="5.5" rx="7" ry="2.8"/><path d="M5 5.5v13c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8v-13"/><path d="M5 12c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8"/></svg>',
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
  { key: 'docker', label: 'Docker', ic: IC.docker, admin: true },
  { key: 'nginx', tkey: 'tab.website', ic: IC.nginx, admin: true },
  { key: 'mysql', tkey: 'tab.databases', ic: IC.mysql, admin: true },
  { key: 'files', tkey: 'tab.files', ic: IC.files },
  { key: 'users', tkey: 'tab.users', ic: IC.users, admin: true },
  { key: 'settings', tkey: 'tab.settings', ic: IC.settings, sup: true },
  { key: 'logs', tkey: 'tab.logs', ic: IC.logs, sup: true },
];
// Whether the current account may see/use a tab.
function tabAllowed(t) {
  const me = S.me || {};
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
    S.me = b.data || {};
    renderNav();
    setUser(S.me.nickname || S.me.username || 'admin', S.me.avatar);
    if (S.me.must_setup) forceAccountSetup(S.me.username, () => { logout(); });
    // If the saved tab isn't allowed for this account, fall back to dashboard.
    const t = TABS.find((x) => x.key === S.tab);
    if (!t || !tabAllowed(t)) S.tab = 'dash';
    switchTab(S.tab);
  }).catch(() => {});
  api('/api/info').then((b) => {
    $('panelVer').textContent = 'v' + (b.data.version || '?');
    if (b.data.hostname) $('panelVer').title = b.data.hostname;
  }).catch(() => {});
  if (window.updateBadge && (S.me ? S.me.is_admin : true)) updateBadge();
}
// Build the sidebar nav from the tabs the current account may access.
function renderNav() {
  const nav = $('nav'); nav.innerHTML = '';
  TABS.filter(tabAllowed).forEach((t) => {
    const b = el('button', { 'data-k': t.key });
    b.className = S.tab === t.key ? 'active' : '';
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
  if (window._termCleanup) { try { window._termCleanup(); } catch (e) {} window._termCleanup = null; }
  if (window._modalTermCleanup) { try { window._modalTermCleanup(); } catch (e) {} window._modalTermCleanup = null; }
  // Close any open modal (and its live sockets) when leaving a tab.
  const root = $('modalRoot'); if (root) root.innerHTML = '';
}

function switchTab(k) {
  const t = TABS.find((x) => x.key === k);
  if (t && !tabAllowed(t)) k = 'dash'; // guard: deny tabs above the account's role
  S.tab = k;
  try { localStorage.setItem('dn7_tab', k); } catch (e) {}
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
  else if (k === 'nginx') renderNginx(v);
  else if (k === 'mysql') renderMysql(v);
  else if (k === 'files') renderFiles(v);
  else if (k === 'users') renderUsers(v);
  else if (k === 'settings') renderSettings(v);
  else if (k === 'logs') renderLogs(v);
}
