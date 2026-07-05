// =========================================================================
// Bootstrap
// =========================================================================

// ---- Crash safety net: an uncaught exception or unhandled rejection shows
// one persistent banner with a reload affordance instead of leaving a
// silently blank/half-drawn pane. Errors still reach the console. ----
function showCrashBar() {
  if (document.querySelector('.crashbar')) return; // one banner max
  const bar = el('div', { class: 'crashbar', role: 'alert' });
  bar.innerHTML = `<span class="cb-msg">${esc(tr('common.crash_msg'))}</span><button class="btn sm sec">${esc(tr('common.reload'))}</button>`;
  bar.querySelector('button').onclick = () => location.reload();
  document.body.appendChild(bar);
}
window.addEventListener('error', (e) => {
  if (/ResizeObserver loop/.test(String(e.message || ''))) return; // benign
  console.error(e.error || e.message);
  // try/catch: a throw here would re-fire 'error' and loop.
  try { showCrashBar(); } catch (_) { /* helpers unavailable — console only */ }
});
window.addEventListener('unhandledrejection', (e) => {
  console.error(e.reason);
  try { showCrashBar(); } catch (_) { /* helpers unavailable — console only */ }
});

// Wire the static-markup controls here (instead of inline `onclick=` handlers)
// so the Content-Security-Policy can drop `script-src 'unsafe-inline'`.
// The <form> submit makes Enter work from every login field (user/pw/2FA).
if ($('loginForm')) $('loginForm').addEventListener('submit', (e) => { e.preventDefault(); doLogin(); });
else {
  // Fallback for markup without the form wrapper.
  $('loginBtn').addEventListener('click', doLogin);
  $('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
}
if ($('loginThemeBtn')) $('loginThemeBtn').addEventListener('click', cycleTheme);
if ($('loginLangBtn')) $('loginLangBtn').addEventListener('click', () => toggleLangMenu('loginLangBtn'));
$('themeBtn').addEventListener('click', cycleTheme);
$('verLine').addEventListener('click', openUpdate);
$('userBox').addEventListener('click', toggleAccountMenu);

// A live session → straight to the app. Otherwise ask the server whether setup
// is still pending: the UI-custom deploy mode serves a token-gated first-run
// wizard (bootInit renders it), and every other case just shows the login form.
if (Auth.token) showApp();
else {
  bootInit().then((wizard) => {
    if (!wizard && $('user')) $('user').focus();
  });
}
