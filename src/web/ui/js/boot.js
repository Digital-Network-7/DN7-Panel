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

if (Auth.token) showApp();
