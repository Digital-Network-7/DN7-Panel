// =========================================================================
// Custom select dropdown — replaces the native OS <select> popup (which looks
// out of place, especially in dark mode) with a themed list, app-wide. The
// real <select> stays the source of truth: we intercept its dropdown, render
// our own popup, then write the chosen value back and fire a `change` event so
// every existing handler keeps working. Works for dynamically-added selects too
// via event delegation.
// =========================================================================
const SELX = { sel: null, pop: null };
function selxClose() {
  // Remove the tracked popup AND any stray ones (defensive against desync).
  document.querySelectorAll('.selx-pop').forEach((p) => p.remove());
  SELX.pop = null;
  SELX.sel = null;
}
function selxOpen(sel) {
  selxClose();
  if (sel.disabled || !sel.options.length) return;
  SELX.sel = sel;
  const pop = el('div', { class: 'selx-pop' });
  Array.from(sel.options).forEach((o, i) => {
    const opt = el('div', { class: 'selx-opt' + (i === sel.selectedIndex ? ' sel' : '') + (o.disabled ? ' dis' : '') }, esc(o.textContent));
    if (!o.disabled) {
      opt.addEventListener('mousedown', (e) => {
        e.preventDefault();
        if (sel.selectedIndex !== i) { sel.selectedIndex = i; sel.dispatchEvent(new Event('change', { bubbles: true })); }
        selxClose();
      });
    }
    pop.appendChild(opt);
  });
  document.body.appendChild(pop);
  SELX.pop = pop;
  // Position under (or above, if no room) the select, matching its width.
  const r = sel.getBoundingClientRect();
  pop.style.left = r.left + 'px';
  pop.style.width = r.width + 'px';
  const below = window.innerHeight - r.bottom;
  if (below < 280 && r.top > below) { pop.style.bottom = (window.innerHeight - r.top + 4) + 'px'; }
  else { pop.style.top = (r.bottom + 4) + 'px'; }
  // Scroll the selected option into view within the popup only.
  const selOpt = pop.querySelector('.selx-opt.sel');
  if (selOpt) selOpt.scrollIntoView({ block: 'nearest' });
}
// Intercept native dropdown on pointerdown (capture) for any <select>.
document.addEventListener('mousedown', (e) => {
  const sel = e.target.closest && e.target.closest('select');
  if (sel) {
    e.preventDefault(); // suppress the native OS dropdown
    if (SELX.sel === sel) { selxClose(); } else { sel.focus(); selxOpen(sel); }
    return;
  }
  if (SELX.pop && !e.target.closest('.selx-pop')) selxClose();
}, true);
// Keyboard: open on Enter/Space/Arrow when focused; navigate + select in popup.
document.addEventListener('keydown', (e) => {
  const a = document.activeElement;
  if (a && a.tagName === 'SELECT' && !SELX.pop && (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
    e.preventDefault(); selxOpen(a); return;
  }
  if (!SELX.pop) return;
  if (e.key === 'Escape') { e.preventDefault(); selxClose(); return; }
  const opts = Array.from(SELX.pop.querySelectorAll('.selx-opt:not(.dis)'));
  if (!opts.length) return;
  let cur = opts.findIndex((o) => o.classList.contains('active'));
  if (cur < 0) cur = opts.findIndex((o) => o.classList.contains('sel'));
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    cur = e.key === 'ArrowDown' ? Math.min(opts.length - 1, cur + 1) : Math.max(0, cur - 1);
    opts.forEach((o) => o.classList.remove('active'));
    opts[cur].classList.add('active'); opts[cur].scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter' && cur >= 0) {
    e.preventDefault(); opts[cur].dispatchEvent(new MouseEvent('mousedown'));
  }
}, true);
// Reposition/close on scroll or resize (popup is fixed-position). Ignore scroll
// events originating inside the popup itself (long option lists scroll).
window.addEventListener('scroll', (e) => { if (SELX.pop && e.target && e.target.closest && e.target.closest('.selx-pop')) return; selxClose(); }, true);
window.addEventListener('resize', selxClose);
