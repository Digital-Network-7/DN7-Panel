// =========================================================================
// API client
// =========================================================================
// The single network layer: attaches the bearer token from the Auth store,
// normalizes the panel's { ok, code, error } envelope into a thrown Error
// (localized via srvMsg), and signs the user out on a 401. Page scripts call
// api()/op()/ticket() and never build fetch headers or parse the envelope
// themselves.
function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (Auth.token) opts.headers['Authorization'] = 'Bearer ' + Auth.token;
  return fetch(path, opts).then(async (r) => {
    if (r.status === 401) { logout(); throw new Error(tr('common.unauthorized')); }
    const txt = await r.text();
    let body; try { body = JSON.parse(txt); } catch (e) { body = txt; }
    if (!r.ok || (body && body.ok === false)) throw new Error(srvMsg(body) || ('HTTP ' + r.status));
    return body;
  });
}

// Capability op (docker/website/mysql): POST {op,...} → data.
function op(kind, obj) { return api('/api/' + kind, { method: 'POST', body: JSON.stringify(obj) }).then((b) => b.data); }

// Mint a one-time, short-lived ticket SCOPED to a purpose ('terminal' or
// 'download') for a WebSocket upgrade or a download link — the session token
// must never travel in a URL (history/proxy logs), and a ticket minted for one
// purpose can't be replayed against the other.
function ticket(purpose) { return api('/api/ticket?purpose=' + encodeURIComponent(purpose), { method: 'POST' }).then((b) => b.data.ticket); }

// Authorization header object for raw fetch() calls (file/image/static uploads
// that send a body the api() JSON wrapper can't). Empty when not signed in.
function authHeaders() { return Auth.token ? { Authorization: 'Bearer ' + Auth.token } : {}; }
