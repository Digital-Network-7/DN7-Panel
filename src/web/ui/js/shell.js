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
};
const TABS = [
  { key: 'dash', label: '监控', ic: IC.dash },
  { key: 'term', label: '终端', ic: IC.term },
  { key: 'docker', label: 'Docker', ic: IC.docker },
  { key: 'nginx', label: 'Nginx', ic: IC.nginx },
  { key: 'mysql', label: 'MySQL', ic: IC.mysql },
  { key: 'files', label: '文件', ic: IC.files },
  { key: 'settings', label: '设置', ic: IC.settings },
];

function showApp() {
  document.documentElement.setAttribute('data-auth', 'in');
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  const nav = $('nav'); nav.innerHTML = '';
  TABS.forEach((t) => {
    const b = el('button', { 'data-k': t.key });
    b.className = S.tab === t.key ? 'active' : '';
    b.innerHTML = `<span class="ic">${t.ic}</span><span class="t">${t.label}</span>`;
    b.onclick = () => switchTab(t.key);
    nav.appendChild(b);
  });
  api('/api/info').then((b) => {
    $('panelVer').textContent = 'v' + (b.data.version || '?');
    if (b.data.hostname) $('panelVer').title = b.data.hostname;
  }).catch(() => {});
  api('/api/settings').then((b) => { setUser(b.data.username || 'admin'); }).catch(() => {});
  if (window.updateBadge) updateBadge();
  switchTab(S.tab);
}
function setUser(name) { $('whoName').textContent = name; $('userAv').textContent = (name[0] || 'A').toUpperCase(); }

function stopTab() {
  if (S.timer) { clearInterval(S.timer); S.timer = null; }
  if (S.ws) { try { S.ws.close(); } catch (e) {} S.ws = null; }
  if (window._termCleanup) { try { window._termCleanup(); } catch (e) {} window._termCleanup = null; }
  if (window._modalTermCleanup) { try { window._modalTermCleanup(); } catch (e) {} window._modalTermCleanup = null; }
  // Close any open modal (and its live sockets) when leaving a tab.
  const root = $('modalRoot'); if (root) root.innerHTML = '';
}

function switchTab(k) {
  S.tab = k;
  try { localStorage.setItem('dn7_tab', k); } catch (e) {}
  stopTab();
  document.querySelectorAll('#nav button').forEach((b) => b.className = b.dataset.k === k ? 'active' : '');
  $('title').textContent = (TABS.find((t) => t.key === k) || {}).label || '';
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
  else if (k === 'settings') renderSettings(v);
}
