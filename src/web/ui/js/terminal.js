// =========================================================================
// Terminal tab (host shell) + reusable terminal launcher
// =========================================================================
function renderTerm(v) {
  v.innerHTML = `<div class="term-page"><div class="term-wrap" style="flex:1;min-height:0"><div class="term-bar"><span class="dot-s on" id="tStatus"></span><span id="tLabel">主机终端</span><span class="sp"></span><span class="mut">点击下方区域即可输入</span></div><div class="vterm" id="vterm"></div></div></div>`;
  mountTerminal($('vterm'), $('tStatus'), `/api/terminal?token=${encodeURIComponent(S.token)}`);
}
// Open a terminal in the given host element against a WS path; returns cleanup.
function mountTerminal(hostEl, statusDot, wsPath) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}${wsPath}`);
  ws.binaryType = 'arraybuffer';
  const dec = new TextDecoder();
  const term = VTerm(hostEl, (s) => { if (ws.readyState === 1) ws.send(s); });
  ws.onopen = () => { if (statusDot) statusDot.className = 'dot-s on'; setTimeout(() => { term.fit(); term.focus(); }, 30); };
  ws.onmessage = (e) => { term.feed(typeof e.data === 'string' ? e.data : dec.decode(e.data, { stream: true })); };
  ws.onclose = () => { if (statusDot) statusDot.className = 'dot-s'; term.feed('\r\n\x1b[90m[连接已关闭]\x1b[0m\r\n'); };
  ws.onerror = () => { if (statusDot) statusDot.className = 'dot-s'; };
  hostEl.addEventListener('click', () => term.focus());
  const onResize = () => term.fit();
  window.addEventListener('resize', onResize);
  const cleanup = () => { window.removeEventListener('resize', onResize); term.dispose(); try { ws.close(); } catch (e) {} };
  window._termCleanup = cleanup;
  return cleanup;
}
// Open a container/exec terminal as a centered modal over a dark backdrop —
// just the terminal, with a close (×) button in the top-right of the bar where
// the hint text used to be. Click the backdrop or press Esc to close.
function openTerminalModal(title, wsPath) {
  const root = $('modalRoot');
  const mask = el('div', { class: 'mask term-mask' });
  const panel = el('div', { class: 'term-overlay' });
  panel.innerHTML = `<div class="term-wrap" style="height:100%"><div class="term-bar"><span class="dot-s" id="mtStatus"></span><span>${esc(title)}</span><span class="sp"></span><button class="term-x" title="关闭">&times;</button></div><div class="vterm" id="mvterm"></div></div>`;
  mask.appendChild(panel);
  root.appendChild(mask);
  const cleanup = mountTerminal(panel.querySelector('#mvterm'), panel.querySelector('#mtStatus'), wsPath);
  // Use a panel-local cleanup hook (so a tab switch closes it too via stopTab).
  window._termCleanup = null;
  window._modalTermCleanup = () => { cleanup(); mask.remove(); };
  const close = () => { cleanup(); mask.remove(); window._modalTermCleanup = null; };
  panel.querySelector('.term-x').addEventListener('click', close);
  // Click on the dark backdrop (outside the panel) closes it.
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
  // Esc closes the terminal panel.
  const onKey = (e) => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey, true); } };
  document.addEventListener('keydown', onKey, true);
}
