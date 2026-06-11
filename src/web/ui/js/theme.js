// =========================================================================
// Theme: auto (follow OS) | light | dark — single icon cycles the 3 states.
// =========================================================================
const THEME_ICONS = { auto: '◑', light: '☀', dark: '☾' };
function themeLabel(m) { return tr('theme.' + m); }
function themeDefault() { return (window.__BRAND__ && window.__BRAND__.theme) || 'auto'; }
function applyTheme() {
  const m = localStorage.getItem('dn7_theme') || themeDefault();
  let eff = m;
  if (m === 'auto') eff = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', eff);
  document.documentElement.setAttribute('data-mode', m);
  const btn = $('themeBtn');
  if (btn) { btn.textContent = THEME_ICONS[m]; btn.title = tr('theme.tip') + themeLabel(m); }
}
function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  const m = localStorage.getItem('dn7_theme') || themeDefault();
  const next = order[(order.indexOf(m) + 1) % order.length];
  localStorage.setItem('dn7_theme', next);
  applyTheme();
}
if (window.matchMedia) {
  const mq = window.matchMedia('(prefers-color-scheme: light)');
  (mq.addEventListener ? mq.addEventListener.bind(mq, 'change') : mq.addListener.bind(mq))(() => {
    if ((localStorage.getItem('dn7_theme') || themeDefault()) === 'auto') applyTheme();
  });
}
applyTheme();
