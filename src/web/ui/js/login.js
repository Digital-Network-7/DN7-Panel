// =========================================================================
// Login
// =========================================================================
function doLogin() {
  const username = $('user').value.trim();
  const password = $('pw').value;
  $('loginErr').textContent = '';
  // Challenge-response: fetch a one-time nonce, send sha256(nonce:password) so
  // the cleartext password never travels over the (plaintext-HTTP) wire. Falls
  // back to plain password only if the challenge endpoint is unavailable.
  fetch('/api/login/challenge')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('challenge'))))
    .then((c) => {
      const body = c && c.nonce
        ? { username, nonce: c.nonce, proof: sha256Hex(c.nonce + ':' + password) }
        : { username, password };
      return fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    })
    .then(async (r) => { const b = await r.json().catch(() => ({})); if (!r.ok) throw new Error(b.error || '登录失败'); return b; })
    .then((b) => { S.token = b.token; localStorage.setItem('dn7_web_token', S.token); showApp(); })
    .catch((e) => { $('loginErr').textContent = e.message === 'challenge' ? '无法连接服务' : e.message; });
}

function logout() {
  if (S.token) api('/api/logout', { method: 'POST' }).catch(() => {});
  S.token = ''; localStorage.removeItem('dn7_web_token');
  document.documentElement.setAttribute('data-auth', 'out');
  stopTab();
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
}
