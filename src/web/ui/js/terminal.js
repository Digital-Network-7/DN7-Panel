// =========================================================================
// Terminal tab (host shell) + reusable terminal launcher
// =========================================================================
function renderTerm(v) {
  v.innerHTML = `<div class="term-page"><div class="term-wrap" style="flex:1;min-height:0"><div class="term-bar"><span class="dot-s on" id="tStatus"></span><span id="tLabel">${tr('term.host')}</span><span class="sp"></span><span class="mut">${tr('term.hint')}</span></div><div class="vterm" id="vterm"></div></div></div>`;
  const host = $('vterm');
  if (!host) return;
  // Pass a path *provider* (fresh one-time ticket per connection) so the
  // terminal can transparently reconnect without a page reload.
  mountTerminal(host, $('tStatus'), () => ticket('terminal').then((t) => `/api/terminal?ticket=${encodeURIComponent(t)}`));
}

// Open a terminal in the given host element against a WS path; returns cleanup.
// `pathProvider` is a WS path string or a function returning a (possibly async)
// path — the latter lets us mint a fresh ticket on every (re)connect.
function mountTerminal(hostEl, statusDot, pathProvider) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const dec = new TextDecoder();
  let ws = null;
  let disposed = false;
  let reconnectArmed = false;

  // VTerm keeps capturing keystrokes after the socket closes; route them to the
  // live socket, or use the first keystroke to trigger a reconnect.
  const onInput = (s) => {
    if (ws && ws.readyState === 1) { ws.send(s); return; }
    if (reconnectArmed && s.indexOf('"type":"data"') !== -1) { reconnectArmed = false; connect(); }
  };
  const term = VTerm(hostEl, onInput);

  const onResize = () => term.fit();
  window.addEventListener('resize', onResize);
  hostEl.addEventListener('click', () => term.focus());

  const resolvePath = () => Promise.resolve(typeof pathProvider === 'function' ? pathProvider() : pathProvider);

  function connect() {
    if (disposed) return;
    if (statusDot) statusDot.className = 'dot-s';
    resolvePath().then((wsPath) => {
      if (disposed) return;
      ws = new WebSocket(`${proto}://${location.host}${wsPath}`);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => { if (statusDot) statusDot.className = 'dot-s on'; setTimeout(() => { term.fit(); term.focus(); }, 30); };
      ws.onmessage = (e) => { term.feed(typeof e.data === 'string' ? e.data : dec.decode(e.data, { stream: true })); };
      ws.onclose = () => {
        if (disposed) return;
        if (statusDot) statusDot.className = 'dot-s';
        term.feed('\r\n\x1b[90m' + tr('term.closed') + '  \x1b[36m' + tr('term.reconnect_hint') + '\x1b[0m\r\n');
        reconnectArmed = true;
      };
      ws.onerror = () => { if (statusDot) statusDot.className = 'dot-s'; };
    }).catch((e) => {
      if (disposed) return;
      if (statusDot) statusDot.className = 'dot-s';
      term.feed('\r\n\x1b[91m' + (e && e.message ? e.message : 'connection failed') + '  \x1b[36m' + tr('term.reconnect_hint') + '\x1b[0m\r\n');
      reconnectArmed = true;
    });
  }

  const cleanup = () => { disposed = true; window.removeEventListener('resize', onResize); term.dispose(); try { if (ws) ws.close(); } catch (e) {} };
  window._termCleanup = cleanup;
  connect();
  return cleanup;
}

// Open a container/exec terminal as a centered modal over a dark backdrop —
// just the terminal, with a close (×) button in the top-right of the bar where
// the hint text used to be. Click the backdrop or press Esc to close.
// `pathProvider` is a WS path string or a function returning a (possibly async)
// path (used to mint a fresh ticket per connection, enabling reconnect).
function openTerminalModal(title, pathProvider) {
  const root = $('modalRoot');
  const mask = el('div', { class: 'mask term-mask' });
  const panel = el('div', { class: 'term-overlay' });
  panel.innerHTML = `<div class="term-wrap" style="height:100%"><div class="term-bar"><span class="dot-s" id="mtStatus"></span><span>${esc(title)}</span><span class="sp"></span><button class="term-x" title="${tr('term.close')}">&times;</button></div><div class="vterm" id="mvterm"></div></div>`;
  mask.appendChild(panel);
  root.appendChild(mask);
  const cleanup = mountTerminal(panel.querySelector('#mvterm'), panel.querySelector('#mtStatus'), pathProvider);
  // Use a panel-local cleanup hook (so a tab switch closes it too via stopTab).
  window._termCleanup = null;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey, true);
    cleanup();
    mask.remove();
    window._modalTermCleanup = null;
  };
  window._modalTermCleanup = close;
  panel.querySelector('.term-x').addEventListener('click', close);
  // Click on the dark backdrop (outside the panel) closes it.
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
  // Esc closes the terminal panel.
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey, true);
}
