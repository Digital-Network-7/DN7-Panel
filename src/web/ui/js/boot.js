// =========================================================================
// Bootstrap
// =========================================================================

// Wire the static-markup controls here (instead of inline `onclick=` handlers)
// so the Content-Security-Policy can drop `script-src 'unsafe-inline'`.
$('loginBtn').addEventListener('click', doLogin);
$('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
$('themeBtn').addEventListener('click', cycleTheme);
$('verLine').addEventListener('click', openUpdate);
$('userBox').addEventListener('click', toggleAccountMenu);

// First-run setup is done via the CLI before the panel ever serves, so the
// console always shows login (or the app, when a session token is present).
if (Auth.token) showApp();
