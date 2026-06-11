// =========================================================================
// Core state + helpers
// =========================================================================
const S = { token: localStorage.getItem('dn7_web_token') || '', tab: localStorage.getItem('dn7_tab') || 'dash', timer: null, ws: null };

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function $(id) { return document.getElementById(id); }
function el(tag, attrs, html) { const e = document.createElement(tag); if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]); if (html != null) e.innerHTML = html; return e; }

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

function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (S.token) opts.headers['Authorization'] = 'Bearer ' + S.token;
  return fetch(path, opts).then(async (r) => {
    if (r.status === 401) { logout(); throw new Error('未授权'); }
    const txt = await r.text();
    let body; try { body = JSON.parse(txt); } catch (e) { body = txt; }
    if (!r.ok || (body && body.ok === false)) throw new Error((body && body.error) || body || ('HTTP ' + r.status));
    return body;
  });
}
// Capability op (docker/nginx/mysql): POST {op,...} → data.
function op(kind, obj) { return api('/api/' + kind, { method: 'POST', body: JSON.stringify(obj) }).then((b) => b.data); }

// Mint a one-time, short-lived ticket for a WebSocket upgrade or a download
// link — the session token must never travel in a URL (history/proxy logs).
function ticket() { return api('/api/ticket', { method: 'POST' }).then((b) => b.data.ticket); }

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
function toast(msg, kind) {
  const t = el('div', { style: 'position:fixed;left:50%;top:22px;transform:translateX(-50%);z-index:99;padding:10px 18px;border-radius:10px;font-size:13px;box-shadow:var(--shadow);background:var(--panel-solid);border:1px solid var(--line2);color:var(--fg)' });
  if (kind === 'err') t.style.borderColor = 'var(--err)';
  if (kind === 'ok') t.style.borderColor = 'var(--ok)';
  t.textContent = msg; document.body.appendChild(t);
  setTimeout(() => { t.style.transition = 'opacity .3s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 2200);
}
function confirmDanger(msg) { return new Promise((res) => { modal(tr('common.confirm'), `<p style="margin:0 0 18px">${esc(msg)}</p><div class="row" style="justify-content:flex-end"><button class="btn sec" id="cdNo">${tr('common.cancel')}</button><button class="btn danger" id="cdYes">${tr('common.ok')}</button></div>`, (close) => { $('cdNo').onclick = () => { close(); res(false); }; $('cdYes').onclick = () => { close(); res(true); }; }); }); }

// ---- Modal ----
function modal(title, bodyHtml, onMount, big) {
  const root = $('modalRoot');
  const mask = el('div', { class: 'mask' });
  mask.innerHTML = `<div class="modal ${big ? 'big' : ''}"><div class="modal-h"><h3>${esc(title)}</h3><button class="x">&times;</button></div><div class="modal-b">${bodyHtml}</div></div>`;
  root.appendChild(mask);
  const close = () => { mask.remove(); };
  mask.querySelector('.x').onclick = close;
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
  if (onMount) onMount(close, mask);
  return close;
}
