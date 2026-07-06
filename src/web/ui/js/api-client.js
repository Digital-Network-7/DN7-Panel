// =========================================================================
// API client
// =========================================================================
// The single network layer: attaches the bearer token from the Auth store,
// normalizes the panel's { ok, code, error } envelope into a thrown Error
// (localized via srvMsg), and surfaces session expiry on a 401. Page scripts
// call api()/op()/ticket() and never build fetch headers or parse the envelope
// themselves.

// One 'session expired' dialog per expiry: any open form stays intact behind
// the mask until the user acknowledges (no pre-wipe) — only then logout().
let AUTH_EXPIRED = false;
function sessionExpired() {
  if (AUTH_EXPIRED || !Auth.token) return; // already prompted / already signed out
  AUTH_EXPIRED = true;
  const done = () => { AUTH_EXPIRED = false; logout(); };
  modal(tr('auth.expired_title'),
    `<p style="margin:0 0 18px">${esc(tr('auth.expired_msg'))}</p>
     <div class="row" style="justify-content:flex-end"><button class="btn" id="axOk">${tr('common.ok')}</button></div>`,
    (close) => { $('axOk').onclick = () => { close(); done(); }; },
    { onDismiss: done });
}

// The security entry path (obscurity front door) is echoed as `X-DN7-Entry` on
// every request so the server's entry gate passes even for non-navigation fetches.
// Visiting the front door set a readable `dn7_entry` cookie; mirror it here.
function entryHeaders() {
  const m = document.cookie.match(/(?:^|;\s*)dn7_entry=([^;]+)/);
  return m ? { 'X-DN7-Entry': decodeURIComponent(m[1]) } : {};
}

function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, entryHeaders(), opts.headers || {});
  if (Auth.token) opts.headers['Authorization'] = 'Bearer ' + Auth.token;
  return fetch(path, opts).then(async (r) => {
    if (r.status === 401) { sessionExpired(); throw new Error(tr('common.unauthorized')); }
    const txt = await r.text();
    let body; try { body = JSON.parse(txt); } catch (e) { body = txt; }
    if (!r.ok || (body && body.ok === false)) throw new Error(srvMsg(body) || tr('common.request_failed', { status: r.status }));
    return body;
  });
}

// In-flight coalescing for page polls: while `key` has a pending call, return
// its promise instead of stacking another request (slow links / 2s pollers).
const API_INFLIGHT = {};
function apiInflight(key, fn) {
  if (API_INFLIGHT[key]) return API_INFLIGHT[key];
  const p = Promise.resolve().then(fn);
  API_INFLIGHT[key] = p;
  const clear = () => { if (API_INFLIGHT[key] === p) delete API_INFLIGHT[key]; };
  p.then(clear, clear);
  return p;
}

// Capability op (docker/website): POST {op,...} → data.
function op(kind, obj) { return api('/api/' + kind, { method: 'POST', body: JSON.stringify(obj) }).then((b) => b.data); }

// Mint a one-time, short-lived ticket SCOPED to a purpose ('terminal' or
// 'download') for a WebSocket upgrade or a download link — the session token
// must never travel in a URL (history/proxy logs), and a ticket minted for one
// purpose can't be replayed against the other.
function ticket(purpose) { return api('/api/ticket?purpose=' + encodeURIComponent(purpose), { method: 'POST' }).then((b) => b.data.ticket); }

// Authorization header object for raw fetch() calls (file/image/static uploads
// that send a body the api() JSON wrapper can't). Empty when not signed in.
function authHeaders() { return Object.assign(entryHeaders(), Auth.token ? { Authorization: 'Bearer ' + Auth.token } : {}); }
