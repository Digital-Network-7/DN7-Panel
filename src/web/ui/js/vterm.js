// =========================================================================
// VTerm — a compact VT100/ANSI terminal emulator that renders to a focusable
// <div>. Click the screen to type directly (no separate input box). Handles
// backspace/erase, cursor movement, colors (SGR), scroll region, and the
// alt-screen so full-screen apps (top/vim) behave. Encodes keystrokes to the
// proper byte sequences and sends them via the supplied `send(str)`.
// =========================================================================
function VTerm(host, send) {
  const COLORS = ['#1c2533', '#fb7185', '#34d399', '#fbbf24', '#60a5fa', '#c084fc', '#22d3ee', '#dbe6f5',
                  '#5b6b86', '#fda4af', '#6ee7b7', '#fde68a', '#93c5fd', '#d8b4fe', '#67e8f9', '#ffffff'];
  const DEF_FG = 7, DEF_BG = -1;
  let cols = 80, rows = 24;
  const blank = () => ({ ch: ' ', fg: DEF_FG, bg: DEF_BG, bold: false, inv: false });
  let grid, alt = null, cx = 0, cy = 0, sgr = { fg: DEF_FG, bg: DEF_BG, bold: false, inv: false };
  let top = 0, bot = rows - 1, curVisible = true;
  let saved = null;

  function makeGrid() { const g = []; for (let r = 0; r < rows; r++) { const row = []; for (let c = 0; c < cols; c++) row.push(blank()); g.push(row); } return g; }
  grid = makeGrid();

  function resizeTo(nc, nr) {
    nc = Math.max(8, Math.min(400, nc)); nr = Math.max(4, Math.min(200, nr));
    if (nc === cols && nr === rows) return;
    cols = nc; rows = nr; top = 0; bot = rows - 1;
    grid = makeGrid(); if (alt) alt = makeGrid();
    cx = Math.min(cx, cols - 1); cy = Math.min(cy, rows - 1);
    send(JSON.stringify({ type: 'resize', cols, rows }));
    schedule();
  }

  function scrollUp(n) { for (let k = 0; k < n; k++) { grid.splice(top, 1); const row = []; for (let c = 0; c < cols; c++) row.push(blank()); grid.splice(bot, 0, row); } }
  function lineFeed() { if (cy === bot) scrollUp(1); else cy = Math.min(rows - 1, cy + 1); }
  function putChar(ch) {
    if (cx >= cols) { cx = 0; lineFeed(); }
    const cell = grid[cy][cx];
    cell.ch = ch; cell.fg = sgr.fg; cell.bg = sgr.bg; cell.bold = sgr.bold; cell.inv = sgr.inv;
    cx++;
  }
  function eraseInLine(mode) {
    const row = grid[cy];
    if (mode === 0) for (let c = cx; c < cols; c++) row[c] = blank();
    else if (mode === 1) for (let c = 0; c <= cx && c < cols; c++) row[c] = blank();
    else for (let c = 0; c < cols; c++) row[c] = blank();
  }
  function eraseInDisplay(mode) {
    if (mode === 2 || mode === 3) { grid = makeGrid(); cx = 0; cy = 0; return; }
    if (mode === 0) { eraseInLine(0); for (let r = cy + 1; r < rows; r++) grid[r] = grid[r].map(blank); }
    else if (mode === 1) { for (let r = 0; r < cy; r++) grid[r] = grid[r].map(blank); eraseInLine(1); }
  }
  function applySGR(params) {
    if (params.length === 0) params = [0];
    for (let i = 0; i < params.length; i++) {
      const p = params[i];
      if (p === 0) { sgr = { fg: DEF_FG, bg: DEF_BG, bold: false, inv: false }; }
      else if (p === 1) sgr.bold = true;
      else if (p === 22) sgr.bold = false;
      else if (p === 7) sgr.inv = true;
      else if (p === 27) sgr.inv = false;
      else if (p >= 30 && p <= 37) sgr.fg = p - 30;
      else if (p === 39) sgr.fg = DEF_FG;
      else if (p >= 40 && p <= 47) sgr.bg = p - 40;
      else if (p === 49) sgr.bg = DEF_BG;
      else if (p >= 90 && p <= 97) sgr.fg = p - 90 + 8;
      else if (p >= 100 && p <= 107) sgr.bg = p - 100 + 8;
      else if (p === 38 || p === 48) {
        // 256/truecolor — collapse to nearest basic for our 16-color palette.
        const target = p === 38 ? 'fg' : 'bg';
        if (params[i + 1] === 5) { const idx = params[i + 2] || 0; sgr[target] = idx < 16 ? idx : DEF_FG; i += 2; }
        else if (params[i + 1] === 2) { sgr[target] = DEF_FG; i += 4; }
      }
    }
  }

  // ---- ANSI parser state machine ----
  let st = 'gnd', buf = '', oscBuf = '';
  function feed(bytes) {
    for (let i = 0; i < bytes.length; i++) {
      const ch = bytes[i], code = ch.charCodeAt(0);
      if (st === 'gnd') {
        if (code === 0x1b) { st = 'esc'; }
        else if (ch === '\r') cx = 0;
        else if (ch === '\n') lineFeed();
        else if (ch === '\b') { cx = Math.max(0, cx - 1); }
        else if (ch === '\t') { cx = Math.min(cols - 1, (Math.floor(cx / 8) + 1) * 8); }
        else if (code === 7) { /* bell */ }
        else if (code >= 32) putChar(ch);
      } else if (st === 'esc') {
        if (ch === '[') { buf = ''; st = 'csi'; }
        else if (ch === ']') { oscBuf = ''; st = 'osc'; }
        else if (ch === '(' || ch === ')') { st = 'charset'; }
        else if (ch === '=' || ch === '>') { st = 'gnd'; }
        else if (ch === 'M') { if (cy === top) { grid.splice(bot, 1); const row = []; for (let c = 0; c < cols; c++) row.push(blank()); grid.splice(top, 0, row); } else cy = Math.max(0, cy - 1); st = 'gnd'; }
        else if (ch === '7') { saved = { cx, cy, sgr: Object.assign({}, sgr) }; st = 'gnd'; }
        else if (ch === '8') { if (saved) { cx = saved.cx; cy = saved.cy; sgr = Object.assign({}, saved.sgr); } st = 'gnd'; }
        else st = 'gnd';
      } else if (st === 'charset') { st = 'gnd'; }
      else if (st === 'csi') {
        if ((code >= 0x40 && code <= 0x7e)) { handleCSI(ch, buf); st = 'gnd'; }
        else buf += ch;
      } else if (st === 'osc') {
        if (code === 7) { st = 'gnd'; }
        else if (code === 0x1b) { st = 'oscEsc'; }
        else oscBuf += ch;
      } else if (st === 'oscEsc') { st = 'gnd'; }
    }
    schedule();
  }

  function handleCSI(final, raw) {
    let priv = '';
    if (raw[0] === '?' || raw[0] === '>') { priv = raw[0]; raw = raw.slice(1); }
    const params = raw.split(';').map((x) => (x === '' ? 0 : parseInt(x, 10)));
    const p0 = params[0] || 0;
    switch (final) {
      case 'A': cy = Math.max(top, cy - Math.max(1, p0)); break;
      case 'B': cy = Math.min(bot, cy + Math.max(1, p0)); break;
      case 'C': cx = Math.min(cols - 1, cx + Math.max(1, p0)); break;
      case 'D': cx = Math.max(0, cx - Math.max(1, p0)); break;
      case 'E': cx = 0; cy = Math.min(bot, cy + Math.max(1, p0)); break;
      case 'F': cx = 0; cy = Math.max(top, cy - Math.max(1, p0)); break;
      case 'G': cx = Math.min(cols - 1, Math.max(0, (p0 || 1) - 1)); break;
      case 'H': case 'f': cy = Math.min(rows - 1, Math.max(0, (params[0] || 1) - 1)); cx = Math.min(cols - 1, Math.max(0, (params[1] || 1) - 1)); break;
      case 'J': eraseInDisplay(p0); break;
      case 'K': eraseInLine(p0); break;
      case 'L': { const n = Math.max(1, p0); for (let k = 0; k < n; k++) { grid.splice(bot, 1); const row = []; for (let c = 0; c < cols; c++) row.push(blank()); grid.splice(cy, 0, row); } break; }
      case 'M': { const n = Math.max(1, p0); for (let k = 0; k < n; k++) { grid.splice(cy, 1); const row = []; for (let c = 0; c < cols; c++) row.push(blank()); grid.splice(bot, 0, row); } break; }
      case 'P': { const n = Math.max(1, p0); const row = grid[cy]; row.splice(cx, n); while (row.length < cols) row.push(blank()); break; }
      case '@': { const n = Math.max(1, p0); const row = grid[cy]; for (let k = 0; k < n; k++) row.splice(cx, 0, blank()); row.length = cols; break; }
      case 'X': { const n = Math.max(1, p0); for (let c = cx; c < cx + n && c < cols; c++) grid[cy][c] = blank(); break; }
      case 'd': cy = Math.min(rows - 1, Math.max(0, (p0 || 1) - 1)); break;
      case 'm': applySGR(params); break;
      case 'r': top = Math.max(0, (params[0] || 1) - 1); bot = Math.min(rows - 1, (params[1] || rows) - 1); cx = 0; cy = top; break;
      case 'h': case 'l': handleMode(priv, params, final === 'h'); break;
      case 's': saved = { cx, cy, sgr: Object.assign({}, sgr) }; break;
      case 'u': if (saved) { cx = saved.cx; cy = saved.cy; sgr = Object.assign({}, saved.sgr); } break;
      default: break;
    }
  }
  function handleMode(priv, params, set) {
    if (priv !== '?') return;
    for (const p of params) {
      if (p === 25) curVisible = set;
      else if (p === 1049 || p === 1047 || p === 47) {
        if (set && !alt) { alt = grid; grid = makeGrid(); saved = { cx, cy, sgr: Object.assign({}, sgr) }; cx = 0; cy = 0; }
        else if (!set && alt) { grid = alt; alt = null; if (saved) { cx = saved.cx; cy = saved.cy; sgr = Object.assign({}, saved.sgr); } }
      }
    }
  }

  // ---- Render (rAF-batched) ----
  let raf = 0;
  function schedule() { if (!raf) raf = requestAnimationFrame(render); }
  function render() {
    raf = 0;
    let html = '';
    for (let r = 0; r < rows; r++) {
      const row = grid[r];
      let line = '', curStyle = null, span = '';
      const flush = () => { if (span) { line += `<span style="${curStyle}">${span}</span>`; span = ''; } };
      for (let c = 0; c < cols; c++) {
        const cell = row[c];
        const isCur = curVisible && r === cy && c === cx;
        let fg = cell.fg < 0 ? DEF_FG : cell.fg, bg = cell.bg;
        if (cell.inv) { const t = fg; fg = bg < 0 ? DEF_BG : bg; bg = t < 0 ? DEF_FG : t; }
        let style = `color:${isCur ? '#05080f' : (COLORS[fg] || COLORS[DEF_FG])}`;
        const bgc = isCur ? '#cfe3ff' : (bg >= 0 ? COLORS[bg] : '');
        if (bgc) style += `;background:${bgc}`;
        if (cell.bold) style += ';font-weight:700';
        if (style !== curStyle) { flush(); curStyle = style; }
        span += cell.ch === ' ' ? '\u00a0' : esc(cell.ch);
      }
      flush();
      html += line + '\n';
    }
    host.innerHTML = html;
  }

  // ---- Input ----
  function keyToBytes(e) {
    const k = e.key;
    if (e.altKey && k.length === 1) return '\x1b' + k;
    if (e.ctrlKey && k.length === 1) {
      const u = k.toUpperCase();
      if (u >= 'A' && u <= 'Z') return String.fromCharCode(u.charCodeAt(0) - 64);
      if (k === ' ') return '\x00';
    }
    switch (k) {
      case 'Enter': return '\r';
      case 'Backspace': return '\x7f';
      case 'Tab': return '\t';
      case 'Escape': return '\x1b';
      case 'ArrowUp': return '\x1b[A'; case 'ArrowDown': return '\x1b[B';
      case 'ArrowRight': return '\x1b[C'; case 'ArrowLeft': return '\x1b[D';
      case 'Home': return '\x1b[H'; case 'End': return '\x1b[F';
      case 'PageUp': return '\x1b[5~'; case 'PageDown': return '\x1b[6~';
      case 'Insert': return '\x1b[2~'; case 'Delete': return '\x1b[3~';
      default: return k.length === 1 ? k : '';
    }
  }
  const onKey = (e) => {
    if (e.metaKey && (e.key === 'c' || e.key === 'v')) return; // allow copy/paste
    const bytes = keyToBytes(e);
    if (bytes !== '') { e.preventDefault(); send(JSON.stringify({ type: 'data', data: bytes })); }
  };
  const onPaste = (e) => { e.preventDefault(); const t = (e.clipboardData || window.clipboardData).getData('text'); if (t) send(JSON.stringify({ type: 'data', data: t })); };
  host.setAttribute('tabindex', '0');
  host.addEventListener('keydown', onKey);
  host.addEventListener('paste', onPaste);

  // Measure char cell to fit cols/rows to the element.
  function fit() {
    const probe = el('span', { style: 'visibility:hidden;position:absolute;white-space:pre' }, 'M'.repeat(10));
    host.appendChild(probe);
    const cw = probe.getBoundingClientRect().width / 10 || 8;
    probe.remove();
    const styles = getComputedStyle(host);
    const lh = parseFloat(styles.lineHeight) || 17;
    const padX = parseFloat(styles.paddingLeft) + parseFloat(styles.paddingRight);
    const padY = parseFloat(styles.paddingTop) + parseFloat(styles.paddingBottom);
    const nc = Math.floor((host.clientWidth - padX) / cw);
    const nr = Math.floor((host.clientHeight - padY) / lh);
    if (nc > 0 && nr > 0) resizeTo(nc, nr);
  }

  render();
  return {
    feed,
    fit,
    focus: () => host.focus(),
    dispose: () => { host.removeEventListener('keydown', onKey); host.removeEventListener('paste', onPaste); if (raf) cancelAnimationFrame(raf); },
  };
}
