// =========================================================================
// Login
// =========================================================================
function doLogin() {
  const username = $('user').value.trim();
  const password = $('pw').value;
  $('loginErr').textContent = '';
  // Challenge-response: fetch a one-time nonce + the per-install salt, then send
  // sha256(nonce ":" sha256(salt ":" password)). The cleartext password never
  // travels over the (plaintext-HTTP) wire, and the server stores only the
  // irreversible verifier sha256(salt ":" password).
  fetch('/api/login/challenge')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('challenge'))))
    .then((c) => {
      if (!c || !c.nonce) throw new Error('challenge');
      const verifier = sha256Hex((c.salt || '') + ':' + password);
      const body = { username, nonce: c.nonce, proof: sha256Hex(c.nonce + ':' + verifier) };
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
