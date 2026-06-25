// =========================================================================
// Login
// =========================================================================
function doLogin() {
  const username = $('user').value.trim();
  const password = $('pw').value;
  const code = $('loginCode') ? $('loginCode').value.trim() : '';
  $('loginErr').textContent = '';
  // Fetch a one-time nonce + the account's salt + KDF scheme, then send
  // deriveVerifier(salt, password, kdf) — a hash, never the cleartext password.
  // The server checks it against the stored Argon2id credential. A TOTP code is
  // added when the account requires 2FA.
  fetch('/api/login/challenge?username=' + encodeURIComponent(username))
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('challenge'))))
    .then((c) => {
      if (!c || !c.nonce) throw new Error('challenge');
      const verifier = deriveVerifier(c.salt, password, c.kdf);
      const body = { username, nonce: c.nonce, verifier, code };
      return fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    })
    .then(async (r) => { const b = await r.json().catch(() => ({})); if (!r.ok && !b.need_totp) throw new Error(srvMsg(b) || tr('login.err_fail')); return b; })
    .then((b) => {
      if (b.need_totp) {
        // Password verified; reveal the 2FA field and prompt for the code.
        $('loginTotpWrap').classList.remove('hidden');
        $('loginCode').focus();
        $('loginErr').textContent = tr('tfa.login_prompt');
        return;
      }
      Auth.setToken(b.token); showApp();
    })
    .catch((e) => { $('loginErr').textContent = e.message === 'challenge' ? tr('login.err_conn') : e.message; });
}

function logout() {
  if (Auth.token) api('/api/logout', { method: 'POST' }).catch(() => {});
  Auth.clear();
  document.documentElement.setAttribute('data-auth', 'out');
  stopTab();
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
}

// First-run forced credential setup: shown after logging in while still on the
// default account ("admin") or the auto-generated default password. A
// non-dismissible overlay that requires a new account name (not "admin") and a
// new password (not the default), then saves both via /api/settings.
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
        const body = {
          username: un,
          pw_salt: salt,
          pw_hash: deriveVerifier(salt, pw, newKdf()),
          pw_kdf: newKdf(),
          // pw_check proves the new password differs from the current default —
          // computed with the CURRENT account's salt + KDF so the server can
          // compare it to the stored verifier.
          pw_check: deriveVerifier(c.salt, pw, c.kdf),
        };
        return api('/api/settings', { method: 'POST', body: JSON.stringify(body) });
      })
      .then(() => { mask.remove(); toast(tr('setup.done'), 'ok'); if (onDone) onDone(un); })
      .catch((e) => { err.textContent = e.message; go.disabled = false; });
  };
  $('suGo').onclick = submit;
  $('suPw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  setTimeout(() => $('suUser').focus(), 30);
}
