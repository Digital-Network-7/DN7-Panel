// =========================================================================
// VTerm — a compact VT100/ANSI terminal emulator that renders to a <div>.
// Input goes through a hidden <textarea> proxy inside the screen (the
// xterm.js pattern): printable text and IME composition arrive via input/
// composition events (CJK typing + mobile soft keyboards work), special keys
// (arrows, Ctrl-*, Esc, F-keys) via keydown, and paste via the textarea's
// native paste event (Ctrl+V / right-click paste work on every OS). Handles
// erase, cursor movement, 16/256/truecolor SGR, wide (CJK) glyphs, scroll
// region, bracketed paste and the alt-screen so full-screen apps (top/vim)
// behave. Encodes keystrokes to byte sequences sent via `send(str)`.
// =========================================================================
function VTerm(host, send) {
  const COLORS = ['#1c2533', '#fb7185', '#34d399', '#fbbf24', '#60a5fa', '#c084fc', '#22d3ee', '#dbe6f5',
                  '#5b6b86', '#fda4af', '#6ee7b7', '#fde68a', '#93c5fd', '#d8b4fe', '#67e8f9', '#ffffff'];
  const DEF_FG = 7, DEF_BG = -1, SCREEN_BG = '#05080f', CUR_BG = '#cfe3ff';
  let cols = 80, rows = 24;
  const blank = () => ({ ch: ' ', fg: DEF_FG, bg: DEF_BG, bold: false, inv: false, w: 1 });
  let grid, alt = null, cx = 0, cy = 0, sgr = { fg: DEF_FG, bg: DEF_BG, bold: false, inv: false };
  let top = 0, bot = rows - 1, curVisible = true;
  let saved = null;
  let bracketed = false; // DECSET 2004 (bracketed paste), set by the app
  let appCursor = false; // DECSET 1 (application cursor keys, vim/less)
  // Scrollback: lines that scroll off the top of the main screen are kept here
  // so the user can wheel/scroll up to review past output.
  let scrollback = [];
  const SCROLLBACK_MAX = 1000;

  // DOM: a render target + the hidden input proxy (kept out of innerHTML wipes).
  const screen = el('div', { class: 'vt-screen' });
  const ta = el('textarea', { class: 'vt-in', autocapitalize: 'off', autocomplete: 'off',
    autocorrect: 'off', spellcheck: 'false', 'aria-label': tr('tab.term') });
  host.appendChild(screen);
  host.appendChild(ta);

  function makeGrid() { const g = []; for (let r = 0; r < rows; r++) { const row = []; for (let c = 0; c < cols; c++) row.push(blank()); g.push(row); } return g; }
  grid = makeGrid();

  // ---- Wide (CJK/fullwidth/emoji) glyphs: 2 cells ----
  const WIDE = [[0x1100, 0x115f], [0x2e80, 0x303e], [0x3041, 0x33ff], [0x3400, 0x4dbf], [0x4e00, 0x9fff],
                [0xa000, 0xa4cf], [0xa960, 0xa97f], [0xac00, 0xd7a3], [0xf900, 0xfaff], [0xfe10, 0xfe19],
                [0xfe30, 0xfe6f], [0xff00, 0xff60], [0xffe0, 0xffe6], [0x1f300, 0x1f9ff], [0x20000, 0x3fffd]];
  function chWidth(cp) {
    if (cp < 0x1100) return 1;
    for (let i = 0; i < WIDE.length; i++) if (cp >= WIDE[i][0] && cp <= WIDE[i][1]) return 2;
    return 1;
  }

  function resizeTo(nc, nr) {
    nc = Math.max(8, Math.min(400, nc)); nr = Math.max(4, Math.min(200, nr));
    if (nc === cols && nr === rows) return;
    // Reflow instead of wiping: pad/truncate each row to the new width, trim
    // blank rows below the cursor first, then spill/pull top rows through the
    // scrollback (main screen only) so visible content survives a resize.
    const padRow = (row) => { if (row.length > nc) row.length = nc; else while (row.length < nc) row.push(blank()); return row; };
    const isBlankRow = (row) => row.every((c) => (c.ch === ' ' || c.ch === '') && c.bg === DEF_BG);
    const reflow = (g, curY, useSB) => {
      g.forEach(padRow);
      let dy = 0;
      while (g.length > nr) {
        if (g.length - 1 > curY + dy && isBlankRow(g[g.length - 1])) { g.pop(); continue; }
        const rm = g.shift(); dy--;
        if (useSB) { scrollback.push(rm); if (scrollback.length > SCROLLBACK_MAX) scrollback.shift(); }
      }
      while (g.length < nr) {
        if (useSB && scrollback.length) { g.unshift(padRow(scrollback.pop())); dy++; }
        else g.push(padRow([]));
      }
      return dy;
    };
    // `alt` stashes the MAIN screen while the alt screen is live; `grid` is
    // always the active one. Only the main screen exchanges with scrollback.
    cy += reflow(grid, cy, alt === null);
    if (alt) {
      const dy = reflow(alt, saved ? saved.cy : 0, true);
      if (saved) { saved.cy = Math.max(0, Math.min(saved.cy + dy, nr - 1)); saved.cx = Math.min(saved.cx, nc - 1); }
    }
    cols = nc; rows = nr; top = 0; bot = rows - 1;
    cx = Math.min(cx, cols - 1); cy = Math.max(0, Math.min(cy, rows - 1));
    send(JSON.stringify({ type: 'resize', cols, rows }));
    schedule();
  }

  function scrollUp(n) {
    for (let k = 0; k < n; k++) {
      const removed = grid.splice(top, 1)[0];
      // Keep lines leaving the top of the MAIN screen (full-screen scroll only —
      // not a partial DECSTBM region, not the alt screen) as scrollback.
      if (alt === null && top === 0) {
        scrollback.push(removed);
        if (scrollback.length > SCROLLBACK_MAX) scrollback.shift();
      }
      const row = [];
      for (let c = 0; c < cols; c++) row.push(blank());
      grid.splice(bot, 0, row);
    }
  }
  function lineFeed() { if (cy === bot) scrollUp(1); else cy = Math.min(rows - 1, cy + 1); }
  function putChar(ch) {
    const w = chWidth(ch.codePointAt(0));
    if (cx + w > cols) { cx = 0; lineFeed(); }
    const cell = grid[cy][cx];
    cell.ch = ch; cell.fg = sgr.fg; cell.bg = sgr.bg; cell.bold = sgr.bold; cell.inv = sgr.inv; cell.w = w;
    cx++;
    if (w === 2 && cx < cols) { // zero-width filler behind a wide glyph
      const f = grid[cy][cx];
      f.ch = ''; f.w = 0; f.fg = sgr.fg; f.bg = sgr.bg; f.bold = false; f.inv = sgr.inv;
      cx++;
    }
  }
  function eraseInLine(mode) {
    const row = grid[cy];
    if (mode === 0) for (let c = cx; c < cols; c++) row[c] = blank();
    else if (mode === 1) for (let c = 0; c <= cx && c < cols; c++) row[c] = blank();
    else for (let c = 0; c < cols; c++) row[c] = blank();
  }
  function eraseInDisplay(mode) {
    if (mode === 3) scrollback = []; // ED 3 (\e[3J): also clear scrollback
    if (mode === 2 || mode === 3) { grid = makeGrid(); cx = 0; cy = 0; return; }
    if (mode === 0) { eraseInLine(0); for (let r = cy + 1; r < rows; r++) grid[r] = grid[r].map(blank); }
    else if (mode === 1) { for (let r = 0; r < cy; r++) grid[r] = grid[r].map(blank); eraseInLine(1); }
  }
  // xterm 256-color palette: 0-15 semantic (theme COLORS), 16-231 the 6x6x6
  // cube, 232-255 the grayscale ramp — the latter two resolve to CSS strings.
  function xcolor(n) {
    n &= 0xff;
    if (n < 16) return n;
    if (n < 232) { const v = [0, 95, 135, 175, 215, 255], q = n - 16; return `rgb(${v[(q / 36) | 0]},${v[((q / 6) | 0) % 6]},${v[q % 6]})`; }
    const g = 8 + 10 * (n - 232);
    return `rgb(${g},${g},${g})`;
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
        // 256-color (38;5;n) and truecolor (38;2;r;g;b), fg and bg alike.
        const target = p === 38 ? 'fg' : 'bg';
        if (params[i + 1] === 5) { sgr[target] = xcolor(params[i + 2] || 0); i += 2; }
        else if (params[i + 1] === 2) { sgr[target] = `rgb(${params[i + 2] || 0},${params[i + 3] || 0},${params[i + 4] || 0})`; i += 4; }
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
        else if (code >= 32) {
          // Surrogate pair (emoji/rare CJK) → hand the full code point over.
          if (code >= 0xd800 && code <= 0xdbff && i + 1 < bytes.length) { putChar(ch + bytes[i + 1]); i++; }
          else putChar(ch);
        }
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
    // SGR subparameter colons (38:5:n / 38:2::r:g:b) → semicolon form.
    if (final === 'm' && raw.indexOf(':') !== -1) raw = raw.replace(/::/g, ':').replace(/:/g, ';');
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
      else if (p === 1) appCursor = set;
      else if (p === 2004) bracketed = set;
      else if (p === 1049 || p === 1047 || p === 47) {
        if (set && !alt) { alt = grid; grid = makeGrid(); saved = { cx, cy, sgr: Object.assign({}, sgr) }; cx = 0; cy = 0; }
        else if (!set && alt) { grid = alt; alt = null; if (saved) { cx = Math.min(saved.cx, cols - 1); cy = Math.min(saved.cy, rows - 1); sgr = Object.assign({}, saved.sgr); } }
      }
    }
  }

  // ---- Render (rAF-batched) ----
  let raf = 0;
  function schedule() { if (!raf) raf = requestAnimationFrame(render); }
  function renderRow(row, cursorCol) {
    let line = '', curStyle = null, span = '';
    const flush = () => { if (span) { line += `<span style="${curStyle}">${span}</span>`; span = ''; } };
    const cval = (v) => (typeof v === 'string' ? v : (COLORS[v] || COLORS[DEF_FG]));
    for (let c = 0; c < row.length; c++) {
      const cell = row[c];
      if (cell.w === 0) continue; // filler behind a wide glyph
      // Cursor sitting on a filler cell highlights its wide glyph instead.
      const isCur = c === cursorCol ||
        (cursorCol > 0 && cell.w === 2 && c === cursorCol - 1 && row[cursorCol] && row[cursorCol].w === 0);
      let fgc = cval(cell.fg < 0 ? DEF_FG : cell.fg);
      let bgc = cell.bg === DEF_BG ? '' : cval(cell.bg);
      if (cell.inv) { const t = fgc; fgc = bgc || SCREEN_BG; bgc = t; }
      if (isCur) { fgc = SCREEN_BG; bgc = CUR_BG; }
      let style = `color:${fgc}`;
      if (bgc) style += `;background:${bgc}`;
      if (cell.bold) style += ';font-weight:700';
      if (style !== curStyle) { flush(); curStyle = style; }
      span += cell.ch === ' ' ? ' ' : esc(cell.ch);
    }
    flush();
    return line;
  }
  function render() {
    raf = 0;
    if (!host.isConnected) return; // detached (tab away) — redraw() on re-attach
    // Don't destroy an in-progress mouse selection with a repaint; retry soon.
    const sel = window.getSelection ? getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && screen.contains(sel.anchorNode)) { setTimeout(schedule, 300); return; }
    // Keep the view pinned to the bottom unless the user scrolled up to read.
    const atBottom = host.scrollTop + host.clientHeight >= host.scrollHeight - 4;
    let html = '';
    // Scrollback only on the main screen (full-screen apps own the alt screen).
    if (alt === null) {
      for (let r = 0; r < scrollback.length; r++) html += renderRow(scrollback[r], -1) + '\n';
    }
    for (let r = 0; r < rows; r++) {
      html += renderRow(grid[r], curVisible && r === cy ? cx : -1) + '\n';
    }
    screen.innerHTML = html;
    // Anchor the input proxy at the caret so IME candidate windows open there.
    ta.style.top = padT + ((alt === null ? scrollback.length : 0) + cy) * lh + 'px';
    ta.style.left = padL + Math.min(cx * cw, Math.max(0, host.clientWidth - 8)) + 'px';
    if (atBottom) host.scrollTop = host.scrollHeight;
  }

  // ---- Input (hidden textarea proxy) ----
  let composing = false;
  const sendData = (s) => { if (ta.style.width) resetTa(); send(JSON.stringify({ type: 'data', data: s })); };
  function keyToBytes(e) {
    const k = e.key;
    if (e.altKey && !e.ctrlKey && !e.metaKey && k.length === 1) return '\x1b' + k;
    if (e.ctrlKey && !e.altKey && !e.metaKey && k.length === 1) {
      const u = k.toUpperCase();
      if (u >= 'A' && u <= 'Z') return String.fromCharCode(u.charCodeAt(0) - 64);
      if (k === ' ') return '\x00';
      return ''; // other Ctrl chords stay with the browser
    }
    switch (k) {
      case 'Enter': return '\r';
      case 'Backspace': return '\x7f';
      case 'Tab': return '\t';
      case 'ArrowUp': return appCursor ? '\x1bOA' : '\x1b[A';
      case 'ArrowDown': return appCursor ? '\x1bOB' : '\x1b[B';
      case 'ArrowRight': return appCursor ? '\x1bOC' : '\x1b[C';
      case 'ArrowLeft': return appCursor ? '\x1bOD' : '\x1b[D';
      case 'Home': return appCursor ? '\x1bOH' : '\x1b[H';
      case 'End': return appCursor ? '\x1bOF' : '\x1b[F';
      case 'PageUp': return '\x1b[5~'; case 'PageDown': return '\x1b[6~';
      case 'Insert': return '\x1b[2~'; case 'Delete': return '\x1b[3~';
      case 'F1': return '\x1bOP'; case 'F2': return '\x1bOQ'; case 'F3': return '\x1bOR'; case 'F4': return '\x1bOS';
      case 'F5': return '\x1b[15~'; case 'F6': return '\x1b[17~'; case 'F7': return '\x1b[18~'; case 'F8': return '\x1b[19~';
      case 'F9': return '\x1b[20~'; case 'F10': return '\x1b[21~'; case 'F11': return '\x1b[23~'; case 'F12': return '\x1b[24~';
      default: return ''; // plain printable keys flow through the textarea
    }
  }
  const onKey = (e) => {
    if (composing || e.isComposing || e.keyCode === 229) return; // IME owns it
    const k = e.key;
    // Native paste chords (Ctrl+V / Ctrl+Shift+V / Cmd+V / Shift+Insert): let
    // the browser deliver the textarea's paste event — handled in onPaste below.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (k === 'v' || k === 'V')) return;
    if (e.shiftKey && k === 'Insert') return;
    // Copy: Ctrl+Shift+C / Cmd+C copy the screen selection (bare Ctrl+C = SIGINT).
    if (((e.ctrlKey && e.shiftKey) || e.metaKey) && !e.altKey && (k === 'c' || k === 'C')) {
      const s = String(getSelection() || '');
      if (s) { e.preventDefault(); if (navigator.clipboard) navigator.clipboard.writeText(s); return; }
      if (e.metaKey) return;
    }
    // Shift + PageUp/PageDown/Home/End scroll the local scrollback view (mouse
    // wheel works natively); they're not forwarded to the shell.
    if (e.shiftKey && (k === 'PageUp' || k === 'PageDown' || k === 'Home' || k === 'End')) {
      e.preventDefault();
      const page = host.clientHeight * 0.9;
      if (k === 'PageUp') host.scrollTop -= page;
      else if (k === 'PageDown') host.scrollTop += page;
      else if (k === 'Home') host.scrollTop = 0;
      else host.scrollTop = host.scrollHeight;
      return;
    }
    // Esc belongs to the shell (vim/less). preventDefault + stopPropagation so
    // no modal Escape-dismiss handler (they honor defaultPrevented) ever fires.
    if (k === 'Escape') { e.preventDefault(); e.stopPropagation(); sendData('\x1b'); return; }
    const bytes = keyToBytes(e);
    if (bytes !== '') {
      e.preventDefault();
      sendData(bytes);
      host.scrollTop = host.scrollHeight; // typing jumps back to the prompt
    }
  };
  // Printable text (incl. mobile soft keyboards) lands in the textarea.
  const onInput = () => {
    if (composing) return;
    const v = ta.value;
    if (!v) return;
    ta.value = '';
    sendData(v.replace(/\n/g, '\r'));
    host.scrollTop = host.scrollHeight;
  };
  const onCompStart = () => { composing = true; };
  const onCompEnd = (e) => {
    composing = false;
    ta.value = '';
    if (e.data) { sendData(e.data); host.scrollTop = host.scrollHeight; }
  };
  function pasteText(raw) {
    const t = String(raw).replace(/\r\n/g, '\r').replace(/\n/g, '\r');
    if (!t) return;
    if (bracketed) { sendData('\x1b[200~' + t + '\x1b[201~'); host.scrollTop = host.scrollHeight; return; }
    if (t.indexOf('\r') !== -1) {
      // No bracketed paste: every newline executes immediately — confirm first.
      const n = t.split('\r').length - (t.endsWith('\r') ? 1 : 0);
      confirmDanger(tr('term.paste_confirm', { n })).then((yes) => {
        if (yes) { sendData(t); host.scrollTop = host.scrollHeight; }
        ta.focus();
      });
      return;
    }
    sendData(t);
    host.scrollTop = host.scrollHeight;
  }
  const onPaste = (e) => {
    e.preventDefault();
    resetTa();
    const t = (e.clipboardData || window.clipboardData).getData('text');
    if (t) pasteText(t);
  };
  // Right-click: slide the (invisible) textarea under the pointer so the
  // native context menu targets it and offers Paste.
  const placeTa = (e) => {
    const r = host.getBoundingClientRect();
    ta.style.left = (e.clientX - r.left - 12) + 'px';
    ta.style.top = (e.clientY - r.top + host.scrollTop - 12) + 'px';
    ta.style.width = '25px'; ta.style.height = '25px';
    ta.focus();
  };
  const resetTa = () => { ta.style.width = ''; ta.style.height = ''; };
  // A live (non-collapsed) selection sitting inside the rendered screen: the
  // user is copying screen text. Sliding the hidden textarea under the pointer
  // (placeTa) would retarget the native menu at the empty proxy — no Copy — so
  // we leave the selection alone and let the browser's default menu offer Copy.
  const selectionInScreen = () => {
    const sel = window.getSelection ? getSelection() : null;
    return !!(sel && sel.rangeCount && !sel.isCollapsed &&
      ((sel.anchorNode && screen.contains(sel.anchorNode)) ||
       (sel.focusNode && screen.contains(sel.focusNode))));
  };
  const onMouseDown = (e) => { if (e.button === 2 && !selectionInScreen()) placeTa(e); };
  // Keep the native menu on the proxy (for Paste) — unless the user has text
  // selected on screen, in which case the native menu must target that
  // selection so Copy is offered.
  const onCtxMenu = (e) => { if (!selectionInScreen()) placeTa(e); };
  const onHostClick = () => {
    // Don't steal a fresh mouse selection; otherwise focus the input proxy.
    const sel = window.getSelection ? getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && host.contains(sel.anchorNode)) return;
    focusTa();
  };
  function focusTa() { try { ta.focus({ preventScroll: true }); } catch (e) { ta.focus(); } }
  // Fallback copy for mouse users: a browser 'copy' (Ctrl+C or the native menu's
  // Copy) fires against whatever is focused. If the hidden proxy holds focus but
  // the user has text selected on screen, the default would copy the empty
  // proxy. Detect a screen selection and hand the browser that text instead.
  const onCopy = (e) => {
    if (!selectionInScreen()) return; // no screen selection → let default run
    const text = String(getSelection() || '');
    if (!text) return;
    if (e.clipboardData) { e.preventDefault(); e.clipboardData.setData('text/plain', text); }
  };
  ta.addEventListener('keydown', onKey);
  ta.addEventListener('input', onInput);
  ta.addEventListener('compositionstart', onCompStart);
  ta.addEventListener('compositionend', onCompEnd);
  ta.addEventListener('paste', onPaste);
  ta.addEventListener('blur', resetTa);
  host.addEventListener('mousedown', onMouseDown);
  host.addEventListener('contextmenu', onCtxMenu);
  host.addEventListener('click', onHostClick);
  host.addEventListener('copy', onCopy);

  // Measure char cell to fit cols/rows to the element.
  let cw = 7.8, lh = 17, padL = 12, padT = 10; // cached cell metrics (fit updates)
  function fit() {
    const probe = el('span', { style: 'visibility:hidden;position:absolute;white-space:pre' }, 'M'.repeat(10));
    host.appendChild(probe);
    cw = probe.getBoundingClientRect().width / 10 || 8;
    probe.remove();
    const styles = getComputedStyle(host);
    lh = parseFloat(styles.lineHeight) || 17;
    padL = parseFloat(styles.paddingLeft) || 0;
    padT = parseFloat(styles.paddingTop) || 0;
    const padX = padL + (parseFloat(styles.paddingRight) || 0);
    const padY = padT + (parseFloat(styles.paddingBottom) || 0);
    const nc = Math.floor((host.clientWidth - padX) / cw);
    const nr = Math.floor((host.clientHeight - padY) / lh);
    if (nc > 0 && nr > 0) resizeTo(nc, nr);
  }

  schedule();
  return {
    feed,
    fit,
    focus: focusTa,
    redraw: schedule,
    // Pin the scroll container to the live prompt. render() computes
    // atBottom from the current scrollTop, so on re-attach (where the
    // container was scrolled to the top) it won't re-pin on its own —
    // callers force it after a redraw when returning to the tab.
    scrollToBottom: () => { host.scrollTop = host.scrollHeight; },
    // Re-announce the current size (a fresh PTY starts at 80x24; on reconnect
    // the dimensions may be unchanged so resizeTo would skip the frame).
    syncSize: () => send(JSON.stringify({ type: 'resize', cols, rows })),
    dispose: () => {
      if (raf) cancelAnimationFrame(raf);
      ta.removeEventListener('keydown', onKey);
      ta.removeEventListener('input', onInput);
      ta.removeEventListener('compositionstart', onCompStart);
      ta.removeEventListener('compositionend', onCompEnd);
      ta.removeEventListener('paste', onPaste);
      ta.removeEventListener('blur', resetTa);
      host.removeEventListener('mousedown', onMouseDown);
      host.removeEventListener('contextmenu', onCtxMenu);
      host.removeEventListener('click', onHostClick);
      host.removeEventListener('copy', onCopy);
      ta.remove();
      screen.remove();
    },
  };
}
