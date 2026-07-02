// =========================================================================
// Command palette (Cmd/Ctrl+K): type-to-jump between tabs + quick actions
// (theme/density/language, new container, add site, updates, help, sign out).
// Built on the existing registries — TABS/tabAllowed/switchTab (shell.js),
// LANGS/setLang (i18n.js) — so role gating and labels stay single-sourced.
// Deliberately NOT modal(): the palette owns its keyboard handling (its
// window-capture handler runs before modal's document-capture Escape).
// =========================================================================
const PAL = { mask: null, prev: null, cmds: [], rows: [], active: 0 };

// Extra action icons in the shell.js house style (16px, stroke 2, currentColor).
const PAL_IC = {
  density: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="vertical-align:-3px"><path d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>',
  update: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>',
  help: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.2-3 3.7"/><path d="M12 17h.01"/></svg>',
  logout: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>',
};

// Poll for a lazily-rendered button (target tabs render after an info fetch)
// and click it — degrades to a plain tab switch when it never appears. The
// first check is deferred past the switchTab repaint so a same-tab rerun
// can't click the outgoing DOM's button before stopTab() clears #modalRoot.
function palClickWhen(id, tries) {
  setTimeout(function poll() {
    const b = $(id);
    if (b) { b.click(); return; }
    if (--tries > 0) setTimeout(poll, 150);
  }, 120);
}

function palAllowedTab(k) { const t = TABS.find((x) => x.key === k); return !!(t && tabAllowed(t)); }

// Snapshot the command list at open time so labels reflect the live language,
// theme, density and role state. Each: { id, icon, label, hint, run }.
function palCommands() {
  const list = [];
  const add = (id, icon, label, run, hint) => list.push({ id, icon: icon || '', label, run, hint: hint || '' });
  TABS.filter(tabAllowed).forEach((t) => add('tab:' + t.key, t.ic, tabLabel(t), () => switchTab(t.key, 'nav')));
  // Quick actions: switch to the owning tab, then press its real toolbar
  // button once the tab has rendered (the buttons appear after an info fetch).
  if (palAllowedTab('docker')) add('act:new_container', IC.docker, tr('pal.new_container'), () => { switchTab('docker', 'nav'); palClickWhen('dkNew', 20); });
  if (palAllowedTab('website')) add('act:add_site', IC.website, tr('pal.add_site'), () => { switchTab('website', 'nav'); palClickWhen('ngAdd', 20); });
  const tm = localStorage.getItem('dn7_theme') || themeDefault();
  add('act:theme', THEME_ICONS[tm] || THEME_ICONS.auto, tr('pal.theme', { mode: tr('theme.' + tm) }), cycleTheme);
  const dm = getDensity() === 'compact' ? 'acct.den_compact' : 'acct.den_comfort';
  add('act:density', PAL_IC.density, tr('pal.density', { mode: tr(dm) }), () => setDensity(getDensity() === 'compact' ? '' : 'compact'));
  // One command per switchable language (the active one would be a no-op).
  LANGS.filter((c) => c !== curLang()).forEach((code) => add('lang:' + code, langIcon(code), tr('pal.lang', { name: LANG_FULL[code] }), () => setLang(code)));
  // Update check is admin-gated like the topbar badge (shell.js showApp).
  if (Auth.me && Auth.me.is_admin && typeof openUpdate === 'function') add('act:update', PAL_IC.update, tr('pal.update'), openUpdate);
  if (typeof openHelp === 'function') add('act:help', PAL_IC.help, tr('pal.help'), openHelp);
  if (typeof logout === 'function') add('act:logout', PAL_IC.logout, tr('pal.logout'), logout);
  return list;
}

// ---- Recents (last 5 run command ids; rank first while the query is empty) ----
function palRecent() {
  try { const a = JSON.parse(localStorage.getItem('dn7_pal_recent') || '[]'); return Array.isArray(a) ? a : []; }
  catch (e) { return []; }
}
function palRemember(id) {
  const a = [id].concat(palRecent().filter((x) => x !== id)).slice(0, 5);
  try { localStorage.setItem('dn7_pal_recent', JSON.stringify(a)); } catch (e) {}
}

// ---- Fuzzy match over the translated label. Substring beats subsequence;
// earlier + tighter matches rank higher. Returns -1 for "no match". ----
function palScore(q, s) {
  q = q.toLowerCase(); s = s.toLowerCase();
  if (!q) return 0;
  const idx = s.indexOf(q);
  if (idx >= 0) return 1000 - idx * 2 - (s.length - q.length);
  let i = 0, j = 0, first = -1, last = -1;
  while (i < q.length && j < s.length) {
    if (q[i] === s[j]) { if (first < 0) first = j; last = j; i++; }
    j++;
  }
  if (i < q.length) return -1;
  return 500 - first * 2 - (last - first) - (s.length - q.length);
}

function palSetActive(i, scroll) {
  PAL.active = i;
  const opts = PAL.mask ? PAL.mask.querySelectorAll('.pal-opt') : [];
  opts.forEach((o, j) => { o.classList.toggle('active', j === i); o.setAttribute('aria-selected', j === i ? 'true' : 'false'); });
  if (scroll && opts[i]) opts[i].scrollIntoView({ block: 'nearest' });
  const inp = $('palIn');
  if (inp) { if (opts[i]) inp.setAttribute('aria-activedescendant', 'palOpt' + i); else inp.removeAttribute('aria-activedescendant'); }
}

function palRender() {
  const q = $('palIn').value.trim();
  let rows;
  if (!q) {
    // Empty query: everything, recently-run first (in recency order).
    const rec = palRecent();
    const rank = (c) => { const r = rec.indexOf(c.id); return r < 0 ? rec.length : r; };
    rows = PAL.cmds.slice().sort((a, b) => rank(a) - rank(b)); // stable → registry order among non-recents
  } else {
    rows = PAL.cmds.map((c) => ({ c, s: palScore(q, c.label) })).filter((x) => x.s >= 0)
      .sort((a, b) => b.s - a.s).map((x) => x.c);
  }
  PAL.rows = rows;
  const listEl = $('palList');
  if (!rows.length) {
    listEl.innerHTML = `<div class="pal-empty mut">${esc(tr('pal.no_match'))}</div>`;
    palSetActive(0, false);
    return;
  }
  // Icons come from the static IC/THEME_ICONS/flag sets (trusted markup);
  // labels/hints are dynamic strings and go through esc().
  listEl.innerHTML = rows.map((c, i) =>
    `<div class="selx-opt pal-opt" role="option" id="palOpt${i}" aria-selected="false" data-i="${i}">` +
    `<span class="ic">${c.icon}</span><span class="pal-t">${esc(c.label)}</span>` +
    `${c.hint ? `<kbd class="pal-hint">${esc(c.hint)}</kbd>` : ''}</div>`).join('');
  listEl.querySelectorAll('.pal-opt').forEach((o) => {
    o.addEventListener('mousedown', (e) => { e.preventDefault(); palRun(Number(o.dataset.i)); });
    o.addEventListener('mousemove', () => { if (PAL.active !== Number(o.dataset.i)) palSetActive(Number(o.dataset.i), false); });
  });
  palSetActive(0, false);
}

function palRun(i) {
  const c = PAL.rows[i];
  if (!c) return;
  palRemember(c.id);
  palClose();
  c.run();
}

// Palette-local keys. On `window` in the capture phase so it runs BEFORE
// modal()'s document-capture Escape handler — stopPropagation keeps a modal
// underneath (or selx) from also reacting to the same keystroke.
function palOnKey(e) {
  if (!PAL.mask) return;
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); palClose(); return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault(); e.stopPropagation();
    if (!PAL.rows.length) return;
    const d = e.key === 'ArrowDown' ? 1 : -1;
    palSetActive((PAL.active + d + PAL.rows.length) % PAL.rows.length, true);
    return;
  }
  if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); palRun(PAL.active); return; }
  // Single-field dialog: focus stays in the input (and stopPropagation keeps
  // an underlying modal()'s Tab focus-trap from pulling focus out).
  if (e.key === 'Tab') { e.preventDefault(); e.stopPropagation(); }
}

function palOpen() {
  if (PAL.mask) { palClose(); return; }
  PAL.prev = document.activeElement;
  PAL.cmds = palCommands();
  const mask = el('div', { class: 'mask pal-mask' });
  mask.innerHTML = `<div class="pal" role="dialog" aria-modal="true" aria-label="${esc(tr('pal.title'))}">
    <input id="palIn" class="pal-in" type="text" role="combobox" aria-expanded="true" aria-controls="palList" aria-autocomplete="list"
      autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="${esc(tr('pal.placeholder'))}" />
    <div id="palList" class="pal-list" role="listbox" aria-label="${esc(tr('pal.title'))}"></div>
  </div>`;
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) palClose(); });
  document.body.appendChild(mask);
  PAL.mask = mask;
  window.addEventListener('keydown', palOnKey, true);
  $('palIn').addEventListener('input', palRender);
  palRender();
  $('palIn').focus();
}

function palClose() {
  if (!PAL.mask) return;
  window.removeEventListener('keydown', palOnKey, true);
  PAL.mask.remove();
  PAL.mask = null; PAL.rows = []; PAL.active = 0;
  const p = PAL.prev; PAL.prev = null;
  if (p && p.focus && document.contains(p)) p.focus();
}

// Global toggle: Cmd+K (mac) / Ctrl+K. Window-capture so it wins over
// element handlers, BUT it must never steal Ctrl+K from the web terminal:
// vterm's textarea handler (vterm.js) preventDefaults without stopPropagation,
// and its keydown fires after this capture listener — so skip by target
// (.vt-in input proxy, .vterm screen, anything inside a .term-wrap) as well
// as honoring e.defaultPrevented. Post-login only ('/' deliberately unbound).
window.addEventListener('keydown', (e) => {
  if ((e.key !== 'k' && e.key !== 'K') || !(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
  if (e.defaultPrevented) return;
  if (document.documentElement.getAttribute('data-auth') !== 'in') return;
  const t = e.target;
  if (t && t.closest && (t.closest('.vt-in') || t.closest('.vterm') || t.closest('.term-wrap'))) return;
  e.preventDefault(); e.stopPropagation();
  if (PAL.mask) palClose(); else palOpen();
}, true);

// Discoverability: a subtle ⌘K/Ctrl K chip next to the topbar language button
// (desktop only — hidden ≤720px in CSS). Same injection pattern as #jobsBtn.
(function initPalTip() {
  const lang = $('langBtn');
  if (!lang || $('palTip')) return;
  const mac = /Mac|iP(hone|ad|od)/.test(navigator.platform || '');
  const b = el('button', { class: 'iconbtn pal-tip', id: 'palTip', title: tr('pal.open_tip'), 'aria-label': tr('pal.open_tip') });
  b.innerHTML = `<kbd>${mac ? '⌘K' : 'Ctrl K'}</kbd>`;
  b.onclick = () => { if (PAL.mask) palClose(); else palOpen(); };
  lang.parentNode.insertBefore(b, lang);
})();
