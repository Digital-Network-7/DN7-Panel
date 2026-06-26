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

// While the panel is uninitialized, the first-run wizard owns the screen
// (instead of login). Otherwise fall through to the normal login/app path.
bootInit().then((wizard) => {
  if (wizard) return;
  if (Auth.token) showApp();
});
