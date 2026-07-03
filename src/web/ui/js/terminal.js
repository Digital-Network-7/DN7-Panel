// =========================================================================
// Terminal tab (host shell) + reusable terminal launcher
// The HOST terminal session (WS + VTerm screen buffer) lives in a module-level
// store and survives tab switches: _termCleanup only detaches the DOM; coming
// back re-attaches and repaints from the buffer. Container-exec modals stay
// session-per-modal (torn down on close).
// =========================================================================
let HostTerm = null; // { hostEl, h } — h is the mountTerminal handle

// Logout (data-auth flips to 'out') must kill the persistent session — a
// logged-out browser may not keep a live shell, nor hand it to the next login.
new MutationObserver(() => {
  if (document.documentElement.getAttribute('data-auth') !== 'out' || !HostTerm) return;
  const s = HostTerm;
  HostTerm = null;
  window._termCleanup = null;
  s.h.cleanup();
  if (s.hostEl.parentNode) s.hostEl.remove();
}).observe(document.documentElement, { attributes: true, attributeFilter: ['data-auth'] });

function hostTermPath() { return ticket('terminal').then((t) => `/api/terminal?ticket=${encodeURIComponent(t)}`); }

function createHostTerm() {
  // Pass a path *provider* (fresh one-time ticket per connection) so the
  // terminal can transparently reconnect without a page reload.
  const hostEl = el('div', { class: 'vterm' });
  return { hostEl, h: mountTerminal(hostEl, null, hostTermPath) };
}

function renderTerm(v) {
  v.innerHTML = `<div class="term-page"><div class="term-wrap" style="flex:1;min-height:0"><div class="term-bar"><span class="dot-s" id="tStatus"></span><span id="tLabel">${tr('term.host')}</span><span class="term-state" id="tState"></span><span class="sp"></span><button class="term-tool" id="tFontDn" title="${tr('term.font_smaller')}">A&minus;</button><button class="term-tool" id="tFontUp" title="${tr('term.font_larger')}">A+</button><button class="term-tool" id="tDisc">${tr('term.disconnect')}</button></div><div class="term-body" id="termBody"></div></div></div>`;
  const body = $('termBody');
  if (!body) return;
  if (!HostTerm) HostTerm = createHostTerm();
  attachHostTerm(body);
  $('tFontDn').onclick = () => bumpTermFont(-1);
  $('tFontUp').onclick = () => bumpTermFont(1);
  $('tDisc').onclick = () => {
    if (!HostTerm) return;
    const s = HostTerm;
    HostTerm = null;
    window._termCleanup = null;
    s.h.cleanup();
    if (s.hostEl.parentNode) s.hostEl.remove();
    const dot = $('tStatus'); if (dot) dot.className = 'dot-s';
    const stEl = $('tState'); if (stEl) { stEl.textContent = tr('term.disconnected'); stEl.classList.remove('is-off'); stEl.onclick = null; }
    body.innerHTML = `<div class="term-off"><span class="mut">${tr('term.disconnected')}</span><button class="btn sm sec" id="tRe">${tr('term.reconnect')}</button></div>`;
    $('tRe').onclick = () => { body.innerHTML = ''; HostTerm = createHostTerm(); attachHostTerm(body); };
  };
}

// Re-attach the persistent host session into the tab: hand it the status dot
// + state text, repaint from the retained buffer, refit and focus.
function attachHostTerm(body) {
  const s = HostTerm;
  body.appendChild(s.hostEl);
  const stEl = $('tState');
  const paintState = (st) => {
    if (!stEl) return;
    stEl.textContent = tr(st === 'on' ? 'term.connected' : st === 'connecting' ? 'term.connecting' : 'term.disconnected');
    stEl.classList.toggle('is-off', st === 'off'); // off → clickable reconnect affordance
    stEl.title = st === 'off' ? tr('term.reconnect') : '';
  };
  s.h.onState = paintState;
  s.h.setStatusEl($('tStatus'));
  paintState(s.h.getState());
  if (stEl) stEl.onclick = () => { if (s.h.getState() === 'off') s.h.reconnect(); };
  setTimeout(() => {
    if (HostTerm !== s || !s.hostEl.isConnected) return;
    s.h.term.fit();
    s.h.term.redraw();
    // redraw() is rAF-batched; render() paints then, but computes atBottom
    // from the (still top-anchored) scroll pos and won't pin. Force the
    // scroll to the prompt on the next frame, once the paint has landed.
    requestAnimationFrame(() => { if (HostTerm === s && s.hostEl.isConnected) s.h.term.scrollToBottom(); });
    s.h.term.focus();
  }, 30);
  // Tab switch detaches the DOM only — the WS + screen buffer live on.
  window._termCleanup = () => {
    s.h.onState = null;
    s.h.setStatusEl(null);
    if (s.hostEl.parentNode) s.hostEl.remove();
  };
}

// A-/A+ in the term-bar: persisted font size, reflow (fit) after the change.
function bumpTermFont(d) {
  if (!HostTerm) return;
  const cur = parseInt(localStorage.getItem('dn7_term_fs') || '', 10) || 13;
  const fs = Math.max(10, Math.min(24, cur + d));
  try { localStorage.setItem('dn7_term_fs', String(fs)); } catch (e) {}
  HostTerm.hostEl.style.fontSize = fs + 'px';
  HostTerm.h.term.fit();
  HostTerm.h.term.redraw();
  HostTerm.h.term.focus();
}

// Open a terminal in the given host element against a WS path; returns a
// handle { term, cleanup, reconnect, setStatusEl, getState, onState }.
// `pathProvider` is a WS path string or a function returning a (possibly
// async) path — the latter lets us mint a fresh ticket on every (re)connect.
function mountTerminal(hostEl, statusDot, pathProvider) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const dec = new TextDecoder();
  let ws = null;
  let disposed = false;
  let reconnectArmed = false;
  let statusEl = statusDot;
  let state = 'off';
  const handle = { onState: null };
  const setState = (s) => {
    state = s;
    if (statusEl) statusEl.className = s === 'on' ? 'dot-s on' : s === 'connecting' ? 'dot-s init' : 'dot-s';
    if (handle.onState) handle.onState(s);
  };

  // VTerm keeps capturing keystrokes after the socket closes; route them to the
  // live socket, or use the first keystroke to trigger a reconnect.
  const onInput = (s) => {
    if (ws && ws.readyState === 1) { ws.send(s); return; }
    if (reconnectArmed && s.indexOf('"type":"data"') !== -1) { reconnectArmed = false; connect(); }
  };
  // Persisted font size (shared with the host tab's A-/A+ control).
  const fs = parseInt(localStorage.getItem('dn7_term_fs') || '', 10);
  if (fs) hostEl.style.fontSize = Math.max(10, Math.min(24, fs)) + 'px';
  const term = VTerm(hostEl, onInput);

  let rzT = 0; // debounce drag-resizes so we don't storm the PTY with resizes
  const onResize = () => { clearTimeout(rzT); rzT = setTimeout(() => term.fit(), 120); };
  window.addEventListener('resize', onResize);

  const resolvePath = () => Promise.resolve(typeof pathProvider === 'function' ? pathProvider() : pathProvider);

  function connect() {
    if (disposed) return;
    setState('connecting');
    resolvePath().then((wsPath) => {
      if (disposed) return;
      ws = new WebSocket(`${proto}://${location.host}${wsPath}`);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => { setState('on'); setTimeout(() => { term.fit(); term.syncSize(); term.focus(); }, 30); };
      ws.onmessage = (e) => { term.feed(typeof e.data === 'string' ? e.data : dec.decode(e.data, { stream: true })); };
      ws.onclose = () => {
        if (disposed) return;
        setState('off');
        term.feed('\r\n\x1b[90m' + tr('term.closed') + '  \x1b[36m' + tr('term.reconnect_hint') + '\x1b[0m\r\n');
        reconnectArmed = true;
      };
      ws.onerror = () => { if (!disposed) setState('off'); };
    }).catch((e) => {
      if (disposed) return;
      setState('off');
      term.feed('\r\n\x1b[91m' + (e && e.message ? e.message : tr('term.conn_failed')) + '  \x1b[36m' + tr('term.reconnect_hint') + '\x1b[0m\r\n');
      reconnectArmed = true;
    });
  }

  handle.term = term;
  handle.cleanup = () => { disposed = true; clearTimeout(rzT); window.removeEventListener('resize', onResize); term.dispose(); try { if (ws) ws.close(); } catch (e) {} };
  handle.reconnect = () => { if (!disposed && (!ws || ws.readyState > 1)) { reconnectArmed = false; connect(); } };
  handle.setStatusEl = (elx) => { statusEl = elx; setState(state); };
  handle.getState = () => state;
  connect();
  return handle;
}

// Open a container/exec terminal as a centered modal over a dark backdrop —
// just the terminal, with a close (×) button in the top-right of the bar.
// No Esc-to-close: Esc belongs to the shell (vim/less) — the vterm forwards
// it as \x1b. Close via the × button or a backdrop click.
// `pathProvider` is a WS path string or a function returning a (possibly
// async) path (used to mint a fresh ticket per connection, enabling reconnect).
function openTerminalModal(title, pathProvider) {
  const root = $('modalRoot');
  const mask = el('div', { class: 'mask term-mask' });
  const panel = el('div', { class: 'term-overlay' });
  panel.innerHTML = `<div class="term-wrap" style="height:100%"><div class="term-bar"><span class="dot-s" id="mtStatus"></span><span>${esc(title)}</span><span class="sp"></span><button class="term-x" title="${tr('term.close')}">&times;</button></div><div class="vterm" id="mvterm"></div></div>`;
  mask.appendChild(panel);
  root.appendChild(mask);
  const h = mountTerminal(panel.querySelector('#mvterm'), panel.querySelector('#mtStatus'), pathProvider);
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    h.cleanup();
    mask.remove();
    window._modalTermCleanup = null;
  };
  // A tab switch closes the modal session too (via stopTab).
  window._modalTermCleanup = close;
  panel.querySelector('.term-x').addEventListener('click', close);
  // Click on the dark backdrop (outside the panel) closes it.
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
}
