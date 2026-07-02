// =========================================================================
// Theme: auto (follow OS) | light | dark — single icon cycles the 3 states.
// Also owns the density preference (comfortable | compact, html[data-density]).
// =========================================================================
// Inline SVGs in the shell.js icon house style (16px, stroke 2, currentColor):
// auto = half-circle, light = sun, dark = moon.
const THEME_ICONS = {
  auto: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg>',
  light: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  dark: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
};
function themeLabel(m) { return tr('theme.' + m); }
function themeDefault() { return (window.__BRAND__ && window.__BRAND__.theme) || 'auto'; }
// The visible theme button (topbar post-login, .login-corner pre-login) — the
// circular reveal expands from its center.
function themeBtnVisible() {
  const a = $('themeBtn'), b = $('loginThemeBtn');
  return (a && a.offsetParent) ? a : ((b && b.offsetParent) ? b : null);
}
function applyTheme() {
  const m = localStorage.getItem('dn7_theme') || themeDefault();
  let eff = m;
  if (m === 'auto') eff = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  const de = document.documentElement;
  const apply = () => { de.setAttribute('data-theme', eff); de.setAttribute('data-mode', m); };
  const src = themeBtnVisible();
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (de.getAttribute('data-theme') !== eff && src && document.startViewTransition && !reduced) {
    // Circular reveal from the theme button (CSS keyframe vt-reveal reads
    // --vtx/--vty; html.vt-theme scopes it to theme swaps only).
    const r = src.getBoundingClientRect();
    de.style.setProperty('--vtx', (r.left + r.width / 2) + 'px');
    de.style.setProperty('--vty', (r.top + r.height / 2) + 'px');
    de.classList.add('vt-theme');
    const t = document.startViewTransition(apply);
    (t.finished || Promise.resolve()).finally(() => de.classList.remove('vt-theme'));
  } else apply();
  [$('themeBtn'), $('loginThemeBtn')].forEach((btn) => {
    if (btn) { btn.innerHTML = THEME_ICONS[m] || THEME_ICONS.auto; btn.title = tr('theme.tip') + themeLabel(m); }
  });
}
function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  const m = localStorage.getItem('dn7_theme') || themeDefault();
  const next = order[(order.indexOf(m) + 1) % order.length];
  localStorage.setItem('dn7_theme', next);
  applyTheme();
}
// Density: '' (comfortable) | 'compact'; persisted like the theme and applied
// pre-paint by prepaint.js.
function setDensity(m) {
  m = m === 'compact' ? 'compact' : '';
  try { localStorage.setItem('dn7_dens', m); } catch (e) {}
  if (m) document.documentElement.setAttribute('data-density', m);
  else document.documentElement.removeAttribute('data-density');
}
function getDensity() {
  return document.documentElement.getAttribute('data-density') === 'compact' ? 'compact' : '';
}
if (window.matchMedia) {
  const mq = window.matchMedia('(prefers-color-scheme: light)');
  (mq.addEventListener ? mq.addEventListener.bind(mq, 'change') : mq.addListener.bind(mq))(() => {
    if ((localStorage.getItem('dn7_theme') || themeDefault()) === 'auto') applyTheme();
  });
}
applyTheme();
