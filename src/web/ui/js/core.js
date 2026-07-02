// =========================================================================
// Core helpers + runtime handles
// =========================================================================
// `S` now holds only transient runtime handles (the active polling timer and
// websocket). Persistent app state lives in dedicated stores: Auth (token +
// current user, auth-state.js), UI (active tab, ui-state.js), and the jobs
// store (jobs.js). The network layer is in api-client.js.
const S = { timer: null, ws: null };

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function $(id) { return document.getElementById(id); }
function el(tag, attrs, html) { const e = document.createElement(tag); if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]); if (html != null) e.innerHTML = html; return e; }

// Global unsaved-work guards. `Dirty` counts roots bindDirty currently flags
// as changed (recounted from the live DOM, so a removed modal drops out);
// `Busy` counts in-flight transfers (upload/import code calls inc()/dec()).
// One beforeunload handler warns while either is non-zero.
window.Dirty = 0;
function syncDirtyCount() { window.Dirty = document.querySelectorAll('[data-dirty="1"]').length; }
window.Busy = { n: 0, inc() { this.n++; }, dec() { if (this.n > 0) this.n--; } };
window.addEventListener('beforeunload', (e) => {
  syncDirtyCount();
  if (window.Dirty > 0 || window.Busy.n > 0) { e.preventDefault(); e.returnValue = ''; }
});

// Gate a save/apply/confirm button on "the form actually changed". The button
// starts disabled; it enables only when a control inside `root` differs from
// its initial value (so create forms enable once something is entered, and edit
// forms enable only after a real change). Returns a `reset()` that re-baselines
// (call it after a successful in-place save so the button disables again).
// Also flags `root` with data-dirty="1"/"0" live — modal() consults it before
// dismissing, and the beforeunload guard counts flagged roots.
function bindDirty(btn, root) {
  btn = typeof btn === 'string' ? $(btn) : btn;
  root = typeof root === 'string' ? $(root) : root;
  if (!btn) return () => {};
  if (!root) root = btn.closest('.modal-b') || btn.parentElement;
  if (!root) return () => {};
  const snap = () => Array.from(root.querySelectorAll('input,select,textarea'))
    .map((c) => (c.type === 'checkbox' || c.type === 'radio') ? (c.checked ? '1' : '0') : (c.value == null ? '' : c.value))
    .join('\u0001');
  let base = snap();
  const sync = () => {
    const dirty = snap() !== base;
    btn.disabled = !dirty;
    root.dataset.dirty = dirty ? '1' : '0';
    syncDirtyCount();
  };
  const reset = () => { base = snap(); sync(); };
  root.addEventListener('input', sync);
  root.addEventListener('change', sync);
  sync();
  btn._dirtyReset = reset;
  return reset;
}

// A friendly skeleton loading indicator (shimmer rows + optional caption),
// reused everywhere in place of a bare spinner / "加载中…" string.
function loading(text, rows) {
  const n = rows || 4;
  let s = '<div class="skel-list">';
  for (let i = 0; i < n; i++) s += '<div class="skel"></div>';
  s += '</div>';
  if (text) s += `<div class="skel-cap">${esc(text)}</div>`;
  return s;
}

// Pure-JS SHA-256 (hex). window.crypto.subtle is unavailable on insecure
// origins (plain HTTP), so we can't rely on it for the login proof.
function sha256Hex(ascii) {
  function rrot(x, n) { return (x >>> n) | (x << (32 - n)); }
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
    h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  // UTF-8 encode.
  const bytes = [];
  for (let i = 0; i < ascii.length; i++) {
    let c = ascii.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else { bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
  }
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, i * 8)) & 0xff);
  const w = new Array(64);
  for (let off = 0; off < bytes.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = (bytes[off + i * 4] << 24) | (bytes[off + i * 4 + 1] << 16) | (bytes[off + i * 4 + 2] << 8) | bytes[off + i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
  }
  const toHex = (n) => ('00000000' + (n >>> 0).toString(16)).slice(-8);
  return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4) + toHex(h5) + toHex(h6) + toHex(h7);
}

// Derive the login verifier from the password per the account's KDF scheme,
// which /api/login/challenge returns as `kdf`. '' or 'sha256' = legacy single
// salted SHA-256; 's256:N' = N salted-SHA-256 iterations — a key-stretch that
// makes a leaked verifier N times costlier to brute-force offline. Pure-JS (so
// it works on insecure origins, where crypto.subtle is unavailable) and
// deterministic, so the value set at password-change time and the value
// recomputed at login time always agree. The s256:N loop is chunked (~2000
// rounds per setTimeout(0) slice) so a just-set pending state (disabled button
// / spinner) can paint instead of freezing the tab.
// NOTE: the former synchronous deriveVerifier() was removed after the async
// migration (all call sites use this). login.js:46's comment still names it.
function deriveVerifierAsync(salt, password, kdf) {
  const s = String(salt || '');
  const pw = String(password);
  const k = String(kdf || '');
  if (k.slice(0, 5) !== 's256:') return Promise.resolve(sha256Hex(s + ':' + pw));
  let n = parseInt(k.slice(5), 10);
  if (!(n > 0)) n = 1;
  if (n > 5000000) n = 5000000; // sanity clamp against a hostile/garbled value
  return new Promise((resolve) => {
    let h = pw, i = 0;
    const step = () => {
      const end = Math.min(n, i + 2000);
      for (; i < end; i++) h = sha256Hex(s + ':' + h);
      if (i < n) setTimeout(step, 0); else resolve(h);
    };
    setTimeout(step, 0); // defer even the first slice so pending UI paints
  });
}

// KDF scheme stamped on every newly-set / changed password. Existing accounts
// keep their stored scheme (legacy '') and migrate to this the next time their
// password changes. Stored alongside the salt so login recomputes the same
// verifier. A function (not a top-level const) so it's reliably shared across
// the separately-loaded <script> files.
function newKdf() { return 's256:30000'; }

// Random hex string of `n` bytes (uses the CSPRNG; getRandomValues works on
// insecure origins too). Used to salt a client-side password hash.
function randHex(n) {
  const a = new Uint8Array(n);
  if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a);
  else for (let i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
  return Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fmtBytes(n) {
  n = Number(n) || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? (n < 10 ? 2 : 1) : 0) + ' ' + u[i];
}

// Timezone the console displays times in (operator-set at init; empty = the
// viewer's local browser time). Injected server-side into __BRAND__.timezone.
function dn7Tz() { return (window.__BRAND__ && window.__BRAND__.timezone) || ''; }

// Split a unix-seconds timestamp into zero-padded {Y,M,D,h,m,s} in the configured
// display timezone, falling back to the browser's local time (or on a bad tz).
function dn7TsParts(ts) {
  const d = new Date((Number(ts) || 0) * 1000);
  const tz = dn7Tz();
  if (tz) {
    try {
      const o = {};
      new Intl.DateTimeFormat('en-CA', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
        .formatToParts(d).forEach((x) => { o[x.type] = x.value; });
      if (o.year) return { Y: o.year, M: o.month, D: o.day, h: o.hour, m: o.minute, s: o.second };
    } catch (e) { /* invalid tz → fall through to local */ }
  }
  const p = (n) => String(n).padStart(2, '0');
  return { Y: String(d.getFullYear()), M: p(d.getMonth() + 1), D: p(d.getDate()), h: p(d.getHours()), m: p(d.getMinutes()), s: p(d.getSeconds()) };
}

// "YYYY-MM-DD HH:MM:SS" in the configured display timezone.
function fmtTsFull(ts) { const t = dn7TsParts(ts); return `${t.Y}-${t.M}-${t.D} ${t.h}:${t.m}:${t.s}`; }
// Toast notification. `kind`: 'ok' | 'err' | 'warn' | 'info' (default 'info').
// Each kind gets its own accent colour + icon so success/info/warnings don't
// all read as errors.
const TOAST_ICONS = {
  ok: '<path d="M20 6 9 17l-5-5"/>',
  err: '<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>',
  warn: '<path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/>',
};
// `opts`: { duration, action: { label, onClick } }. Errors/warnings linger 6s
// (ok/info 2.6s); hovering pauses the timer, leaving resumes what's left
// (1.5s minimum). The .timed class + --tms var drive the CSS countdown bar
// (paused on :hover in CSS).
function toast(msg, kind, opts) {
  const k = (kind === 'ok' || kind === 'err' || kind === 'warn') ? kind : 'info';
  const o = opts || {};
  let wrap = $('toastWrap');
  if (!wrap) { wrap = el('div', { id: 'toastWrap', class: 'toast-wrap', 'aria-live': 'polite' }); document.body.appendChild(wrap); }
  const t = el('div', { class: 'toast ' + k + ' timed' });
  t.innerHTML = `<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${TOAST_ICONS[k]}</svg><span class="tx"></span>`;
  t.querySelector('.tx').textContent = msg;
  const ms = o.duration || ((k === 'err' || k === 'warn') ? 6000 : 2600);
  t.style.setProperty('--tms', ms + 'ms');
  let timer = null, deadline = 0, remain = ms, gone = false;
  const dispose = () => { if (gone) return; gone = true; clearTimeout(timer); t.style.transition = 'opacity .3s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 300); };
  const arm = (d) => { deadline = Date.now() + d; timer = setTimeout(dispose, d); };
  if (o.action && o.action.label) {
    const b = el('button', { class: 'btn sm sec toast-act' });
    b.textContent = o.action.label;
    b.onclick = () => { dispose(); if (o.action.onClick) o.action.onClick(); };
    t.appendChild(b);
  }
  t.addEventListener('mouseenter', () => { if (timer) { clearTimeout(timer); timer = null; remain = Math.max(0, deadline - Date.now()); } });
  t.addEventListener('mouseleave', () => { if (!gone && !timer) arm(Math.max(1500, remain)); });
  wrap.appendChild(t);
  arm(ms);
}
function confirmDanger(msg) { return new Promise((res) => { modal(tr('common.confirm'), `<p style="margin:0 0 18px">${esc(msg)}</p><div class="row" style="justify-content:flex-end"><button class="btn sec" id="cdNo">${tr('common.cancel')}</button><button class="btn danger" id="cdYes">${tr('common.ok')}</button></div>`, (close) => { $('cdNo').onclick = () => { close(); res(false); }; $('cdYes').onclick = () => { close(); res(true); }; }, { onDismiss: () => res(false) }); }); }

// Step-up re-authentication for the highest-risk actions (self-update, panel
// access/settings changes, exec into a privileged container). Prompts for the
// current account's password (and a 2FA code if the server asks), exchanges it
// for a single-use step-up token via /api/stepup using the same challenge-
// response proof as login (the cleartext password never crosses the wire), and
// resolves to that token. Resolves to null if the user cancels. The caller
// attaches the token to the privileged request — header `X-DN7-Stepup` for HTTP
// calls, a `stepup` query param for the (header-less) WebSocket exec upgrade.
// Uses raw fetch (not api()) so the `need_totp` reply can reveal the 2FA field
// instead of being thrown as an error.
function stepUp(message) {
  return new Promise((resolve) => {
    const username = (Auth.me && Auth.me.username) || '';
    const body = `
      ${message ? `<p class="mut" style="margin:0 0 14px;font-size:13px;line-height:1.5">${esc(message)}</p>` : ''}
      <label class="lbl">${tr('stepup.password')}</label>
      <input id="suPw" class="field" type="password" autocomplete="current-password" />
      <div id="suCodeWrap" class="hidden" style="margin-top:12px">
        <label class="lbl">${tr('tfa.code')}</label>
        <input id="suCode" class="field" inputmode="numeric" autocomplete="one-time-code" maxlength="6" />
      </div>
      <p class="err" id="suErr" style="margin-top:10px"></p>
      <div class="row" style="justify-content:flex-end;gap:10px;margin-top:4px">
        <button class="btn sec" id="suNo">${tr('common.cancel')}</button>
        <button class="btn danger" id="suGo">${tr('stepup.confirm')}</button>
      </div>`;
    let settled = false;
    modal(tr('stepup.title'), body, (close) => {
      const err = $('suErr');
      const finish = (val) => { if (settled) return; settled = true; close(); resolve(val); };
      $('suNo').onclick = () => finish(null);
      const submit = () => {
        const pw = $('suPw').value;
        const code = $('suCode') ? $('suCode').value.trim() : '';
        if (!pw) { err.textContent = tr('stepup.need_pw'); return; }
        err.textContent = ''; $('suGo').disabled = true;
        fetch('/api/login/challenge?username=' + encodeURIComponent(username))
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error(tr('login.err_conn')))))
          .then((c) => {
            if (!c || !c.nonce) throw new Error(tr('login.err_conn'));
            // Chunked KDF so the disabled confirm button paints during derivation.
            return deriveVerifierAsync(c.salt, pw, c.kdf).then((verifier) => {
              const payload = { nonce: c.nonce, verifier, code };
              return fetch('/api/stepup', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()), body: JSON.stringify(payload) });
            });
          })
          .then(async (r) => {
            const txt = await r.text(); let b; try { b = JSON.parse(txt); } catch (_) { b = txt; }
            if (b && b.need_totp) { $('suCodeWrap').classList.remove('hidden'); const ci = $('suCode'); if (ci) ci.focus(); err.textContent = tr('stepup.need_code'); $('suGo').disabled = false; return; }
            if (!r.ok || (b && b.ok === false)) throw new Error(srvMsg(b) || ('HTTP ' + r.status));
            finish((b && b.data && b.data.token) || null);
          })
          .catch((e) => { err.textContent = e.message; $('suGo').disabled = false; });
      };
      $('suGo').onclick = submit;
      $('suPw').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') submit(); });
      const cc = $('suCode'); if (cc) cc.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') submit(); });
      setTimeout(() => $('suPw').focus(), 30);
    }, { onDismiss: () => { if (!settled) { settled = true; resolve(null); } } });
  });
}


// ---- Modal ----
// Registry of every open mask, in stacking order. modal() pushes on open and
// close() splices on teardown, so a forced teardown (stopTab leaving a tab)
// can route through closeAllModals() instead of wiping #modalRoot — which would
// bypass close() and leak the per-modal keydown listener + strand onDismiss
// promises (confirmDanger/stepUp/sessionExpired).
const OPEN_MODALS = [];
// Force-close every open modal (topmost first). Used by stopTab(): this is a
// non-guarded teardown — it still runs each modal's cleanup + fires onDismiss so
// promise-based dialogs settle, but skips the dirty-discard confirm because the
// tab has already switched. Iterates a snapshot since close() mutates the list.
function closeAllModals() {
  OPEN_MODALS.slice().forEach((m) => { try { m._close(true); } catch (e) {} });
}

// 4th arg: boolean `big` (legacy) or { big, onDismiss }. A dismiss (X /
// backdrop / Escape — not the programmatic close()) first consults the dirty
// guard: forms flagged [data-dirty="1"] by bindDirty require a discard
// confirmation, then `onDismiss` fires so promise-based dialogs can settle.
// Escape and the Tab focus-trap address only the topmost mask in #modalRoot,
// so stacked dialogs (stepUp over the update modal) behave.
function modal(title, bodyHtml, onMount, opts) {
  const o = (opts && typeof opts === 'object') ? opts : { big: !!opts };
  const root = $('modalRoot');
  const prev = document.activeElement;
  const mask = el('div', { class: 'mask' });
  mask.innerHTML = `<div class="modal ${o.big ? 'big' : ''}" role="dialog" aria-modal="true"><div class="modal-h"><h3>${esc(title)}</h3><button class="x" aria-label="${esc(tr('common.close'))}">&times;</button></div><div class="modal-b">${bodyHtml}</div></div>`;
  root.appendChild(mask);
  OPEN_MODALS.push(mask);
  const focusables = () => Array.from(mask.querySelectorAll('button,input,select,textarea,a[href],[tabindex]'))
    .filter((n) => !n.disabled && n.tabIndex !== -1 && n.offsetParent !== null);
  let closed = false;
  // Teardown. `silent` (used by closeAllModals on a forced tab switch) fires
  // onDismiss so promise-based dialogs settle, but callers that dismiss the
  // modal normally already ran onDismiss via dismiss(), so it isn't double-fired.
  const close = (silent) => {
    if (closed) return;
    closed = true;
    const i = OPEN_MODALS.indexOf(mask);
    if (i !== -1) OPEN_MODALS.splice(i, 1);
    document.removeEventListener('keydown', onKey, true);
    mask.remove();
    if (prev && prev.focus && document.contains(prev)) prev.focus();
    if (silent === true && o.onDismiss) o.onDismiss();
  };
  // closeAllModals() reaches every open mask through this stored handle.
  mask._close = close;
  const dismiss = () => {
    if (closed) return;
    const go = () => { close(); if (o.onDismiss) o.onDismiss(); };
    if (mask.querySelector('[data-dirty="1"]')) confirmDanger(tr('common.discard_confirm')).then((yes) => { if (yes) go(); });
    else go();
  };
  const onKey = (e) => {
    const all = root.querySelectorAll('.mask');
    if (closed || all[all.length - 1] !== mask) return; // only the topmost mask reacts
    if (e.key === 'Escape') {
      if (e.defaultPrevented) return; // an inner widget (selx popup) consumed it
      e.preventDefault(); dismiss();
    } else if (e.key === 'Tab') {
      const f = focusables();
      if (!f.length) { e.preventDefault(); return; }
      const cur = document.activeElement;
      if (e.shiftKey && (cur === f[0] || !mask.contains(cur))) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && (cur === f[f.length - 1] || !mask.contains(cur))) { e.preventDefault(); f[0].focus(); }
    }
  };
  document.addEventListener('keydown', onKey, true);
  mask.querySelector('.x').onclick = dismiss;
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) dismiss(); });
  if (onMount) onMount(close, mask);
  if (!mask.contains(document.activeElement)) {
    const f = focusables();
    const first = f.find((n) => !n.classList.contains('x')) || f[0];
    if (first) first.focus();
  }
  return close;
}
