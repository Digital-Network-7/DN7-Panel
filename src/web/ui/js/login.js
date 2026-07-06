// =========================================================================
// Login
// =========================================================================

// One attempt in flight max: the submit button swaps to a spinner + label so
// the challenge round-trips and the chunked KDF read as busy, not frozen.
let loginBusy = false;
function setLoginBusy(on) {
  const btn = $('loginBtn');
  if (!btn) return;
  loginBusy = on;
  btn.disabled = on;
  if (on) btn.innerHTML = `<span class="spin" aria-hidden="true"></span>${esc(tr('login.signing_in'))}`;
  else btn.textContent = tr('login.submit');
}

// Show/hide password (.pwf eye). Also called from logout() to re-mask.
function setPwVisible(show) {
  const eye = $('pwEye'), pw = $('pw');
  if (!eye || !pw) return;
  const A = 'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  pw.type = show ? 'text' : 'password';
  eye.innerHTML = show
    ? `<svg viewBox="0 0 24 24" width="16" height="16" ${A}><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
    : `<svg viewBox="0 0 24 24" width="16" height="16" ${A}><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>`;
  const lbl = tr(show ? 'login.hide_pw' : 'login.show_pw');
  eye.title = lbl;
  eye.setAttribute('aria-label', lbl);
}

function doLogin() {
  if (loginBusy) return; // double-submit guard (Enter spam, re-click)
  const username = $('user').value.trim();
  const password = $('pw').value;
  const code = $('loginCode') ? $('loginCode').value.trim() : '';
  const errBox = $('loginErr');
  errBox.textContent = '';
  // Empty fields fail locally — no challenge round-trip, no KDF burn.
  if (!username || !password) {
    errBox.textContent = tr('login.err_empty');
    (!username ? $('user') : $('pw')).focus();
    return;
  }
  setLoginBusy(true);
  // Fetch a one-time nonce + the account's salt + KDF scheme, then send
  // deriveVerifier(salt, password, kdf) — a hash, never the cleartext password.
  // The server checks it against the stored Argon2id credential. A TOTP code is
  // added when the account requires 2FA.
  fetch('/api/login/challenge?username=' + encodeURIComponent(username))
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('challenge'))))
    .then((c) => {
      if (!c || !c.nonce) throw new Error('challenge');
      // Chunked KDF: yields to the event loop so the pending button paints.
      return deriveVerifierAsync(c.salt, password, c.kdf).then((verifier) => {
        const body = { username, nonce: c.nonce, verifier, code };
        return fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      });
    })
    .then(async (r) => { const b = await r.json().catch(() => ({})); if (!r.ok && !b.need_totp) throw new Error(srvMsg(b) || tr('login.err_fail')); return b; })
    .then((b) => {
      if (b.need_totp) {
        // Password verified; reveal the 2FA field (it carries its own hint —
        // the red #loginErr slot stays reserved for actual failures).
        setLoginBusy(false);
        $('loginTotpWrap').classList.remove('hidden');
        $('loginCode').focus();
        return;
      }
      Auth.setToken(b.token);
      showApp();
      // Reset the form behind the app so nothing lingers for the next login.
      setLoginBusy(false);
      setPwVisible(false);
      $('pw').value = '';
      if ($('loginCode')) $('loginCode').value = '';
      $('loginTotpWrap').classList.add('hidden');
    })
    .catch((e) => {
      setLoginBusy(false);
      // The 'challenge' sentinel and raw fetch network failures (TypeError,
      // browser-English "Failed to fetch") both localize to err_conn.
      const conn = (e && e.message === 'challenge') || e instanceof TypeError;
      errBox.textContent = conn ? tr('login.err_conn') : (e && e.message) || tr('login.err_fail');
    });
}

function logout() {
  if (Auth.token) api('/api/logout', { method: 'POST' }).catch(() => {});
  Auth.clear();
  document.documentElement.setAttribute('data-auth', 'out');
  stopTab();
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
  // Leave no credentials or 2FA state behind for the next person at the keyboard.
  setPwVisible(false);
  $('pw').value = '';
  if ($('loginCode')) $('loginCode').value = '';
  $('loginTotpWrap').classList.add('hidden');
  const errBox = $('loginErr');
  errBox.textContent = '';
  errBox.classList.remove('info');
  setLoginBusy(false);
  $('user').focus();
}

// Legacy post-login credential nag: shown after logging in while the account is
// still named "admin" (the residual `must_setup` heuristic). A non-dismissible
// overlay that requires a new account name (not "admin") and a new password,
// then saves both via /api/settings. The token-gated first-run wizard now sets a
// real account + password at init, so this rarely triggers.
function forceAccountSetup(currentUser, onDone) {
  const root = $('modalRoot');
  if (document.getElementById('suGo')) return; // already open
  const mask = el('div', { class: 'mask' });
  mask.innerHTML = `<div class="modal" style="width:460px">
    <div class="modal-h"><h3>${tr('setup.title')}</h3></div>
    <div class="modal-b">
      <p class="mut" style="margin:0 0 16px;font-size:13px;line-height:1.6">${tr('setup.intro')}</p>
      <label class="lbl">${tr('set.account')}</label>
      <input id="suUser" class="field" style="margin-bottom:12px" autocomplete="username" placeholder="${tr('setup.account_ph')}" />
      <label class="lbl">${tr('setup.new_pw')}</label>
      <input id="suPw" class="field" type="password" autocomplete="new-password" style="margin-bottom:12px" />
      <label class="lbl">${tr('setup.confirm_pw')}</label>
      <input id="suPw2" class="field" type="password" autocomplete="new-password" />
      <button class="btn" id="suGo" style="margin-top:18px;width:100%">${tr('setup.submit')}</button>
      <div class="err" id="suErr" style="margin-top:10px"></div>
    </div>
  </div>`;
  root.appendChild(mask);
  if (currentUser && currentUser.toLowerCase() !== 'admin') $('suUser').value = currentUser;
  const submit = () => {
    const err = $('suErr'); err.textContent = '';
    const un = $('suUser').value.trim();
    const pw = $('suPw').value, pw2 = $('suPw2').value;
    if (un.length < 2 || un.length > 32 || !/^[A-Za-z0-9_-]+$/.test(un)) { err.textContent = tr('err.settings.username_format'); return; }
    if (un.toLowerCase() === 'admin') { err.textContent = tr('err.settings.username_reserved'); return; }
    if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
    if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
    const go = $('suGo'); go.disabled = true;
    // Need the current salt to prove the new password differs from the default.
    fetch('/api/login/challenge')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(tr('login.err_conn')))))
      .then((c) => {
        const salt = randHex(16);
        // Chunked KDF (×2) so the disabled button paints instead of freezing.
        return deriveVerifierAsync(salt, pw, newKdf()).then((pwHash) =>
          // pw_check proves the new password differs from the current default —
          // computed with the CURRENT account's salt + KDF so the server can
          // compare it to the stored verifier.
          deriveVerifierAsync(c.salt, pw, c.kdf).then((pwCheck) => {
            const body = { username: un, pw_salt: salt, pw_hash: pwHash, pw_kdf: newKdf(), pw_check: pwCheck };
            return api('/api/settings', { method: 'POST', body: JSON.stringify(body) });
          }));
      })
      .then(() => { mask.remove(); toast(tr('setup.done'), 'ok'); if (onDone) onDone(un); })
      .catch((e) => { err.textContent = e.message; go.disabled = false; });
  };
  $('suGo').onclick = submit;
  $('suPw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  // Null-safe: the overlay could be gone by the time this fires (a tab switch
  // clears #modalRoot); never let a stray focus() crash the page.
  setTimeout(() => { const u = $('suUser'); if (u) u.focus(); }, 30);
}

// ---- Static login markup wiring (scripts load at the end of <body>, so the
// DOM exists; boot.js owns the rest of the pre-login controls). ----
if ($('pwEye')) {
  $('pwEye').addEventListener('click', () => setPwVisible($('pw').type === 'password'));
  setPwVisible(false); // seed the eye icon + localized label
}
