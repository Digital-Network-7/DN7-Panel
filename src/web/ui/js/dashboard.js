// =========================================================================
// Dashboard — one screen: stat cards + split network throughput + proc table
// =========================================================================
function renderDash(v) {
  v.innerHTML = `
    <div class="dash">
      <div class="statrow" id="cards"></div>
      <div class="card procwrap"><div class="proc-head" id="procHead"></div><div class="scroll" id="procs">${loading()}</div></div>
    </div>`;
  const hist = { rx: [], tx: [] };
  const st = { sort: 'cpu', data: null };
  const refresh = () => {
    api('/api/metrics').then((b) => {
      const m = b.data;
      hist.rx.push(m.net_rx || 0); hist.tx.push(m.net_tx || 0);
      if (hist.rx.length > 40) { hist.rx.shift(); hist.tx.shift(); }
      const coreLabel = m.cpu_virtual ? ' vCPU' : ' 核心';
      $('cards').innerHTML = [
        card('CPU', (m.cpu_usage || 0).toFixed(1) + '%', (m.cpu_cores || 0) + coreLabel, m.cpu_usage),
        card('内存', (m.memory_usage || 0).toFixed(1) + '%', fmtBytes(m.mem_used) + ' / ' + fmtBytes(m.mem_total), m.memory_usage),
        card('磁盘', (m.disk_usage || 0).toFixed(1) + '%', fmtBytes(m.disk_used) + ' / ' + fmtBytes(m.disk_total), m.disk_usage),
        netCard(m.net_rx || 0, m.net_tx || 0, hist),
      ].join('');
    }).catch(() => {});
    api('/api/procs').then((b) => { st.data = b.data; renderProcs(st); }).catch(() => {});
  };
  // Clicking the CPU / 内存 header toggles which ranking is shown.
  $('procHead').addEventListener('click', (e) => {
    const th = e.target.closest('[data-sort]');
    if (!th) return;
    st.sort = th.dataset.sort;
    renderProcs(st);
  });
  refresh(); S.timer = setInterval(refresh, 2000);
}
// Render the process ranking. `st.sort` is 'cpu' | 'mem'; the agent returns both
// pre-sorted lists (by_cpu / by_mem) so switching is instant + accurate. The
// header is a separate (non-scrolling) table from the scrolling body so the
// scrollbar never overlaps the header and the columns never jitter.
const PROC_COLS = '<colgroup><col class="c-pid"/><col class="c-name"/><col class="c-user"/><col class="c-time"/><col class="c-cpu"/><col class="c-mem"/></colgroup>';
function renderProcs(st) {
  if (!st.data) return;
  const rows = ((st.sort === 'mem' ? st.data.by_mem : st.data.by_cpu) || []).slice(0, 30);
  const arrow = (k) => (st.sort === k ? ' <span class="sortar">▼</span>' : '');
  // Header table (fixed, outside the scroll area).
  $('procHead').innerHTML = '<table class="proctable proc-head-tbl">' + PROC_COLS +
    '<tr><th class="num">PID</th><th>进程</th><th>用户</th><th class="num">TIME</th>' +
    `<th class="num sortable" data-sort="cpu">CPU${arrow('cpu')}</th>` +
    `<th class="num sortable" data-sort="mem">内存${arrow('mem')}</th></tr></table>`;
  // Body table (scrolls).
  let h = '<table class="proctable">' + PROC_COLS + '<tbody>';
  rows.forEach((p) => {
    h += `<tr><td class="num mono">${p.pid}</td><td class="mono nm" title="${esc(p.name)}">${esc(p.name)}</td><td class="mut nm" title="${esc(p.user || '')}">${esc(p.user || '-')}</td><td class="num mono">${fmtProcTime(p.time)}</td><td class="num">${(p.cpu || 0).toFixed(1)}%</td><td class="num">${fmtBytes(p.mem)}</td></tr>`;
  });
  const sc = $('procs');
  sc.innerHTML = h + '</tbody></table>';
  // Pad the header by the body's actual scrollbar width so columns stay aligned
  // (and the scrollbar never sits beside the header).
  const sbw = sc.offsetWidth - sc.clientWidth;
  $('procHead').style.paddingRight = (sbw > 0 ? sbw : 0) + 'px';
}
// Format cumulative CPU time (seconds) like top: M:SS, or H:MM:SS past an hour.
function fmtProcTime(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const pad = (n) => (n < 10 ? '0' + n : '' + n);
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}
function card(title, big, sub, pct) {
  const bar = pct == null ? '' : `<div class="bar"><i style="width:${Math.min(100, Math.max(0, pct)).toFixed(0)}%"></i></div>`;
  return `<div class="card"><h3>${title}</h3><div class="big">${big}</div><div class="sub">${sub}</div>${bar}</div>`;
}
// Network throughput as a single stat card (same size as CPU/mem/disk): two
// Network throughput stat card (same footprint as CPU/mem/disk): a left/right
// split — left = 上行 (upload, amber), right = 下行 (download, blue) — each with
// a nice SVG icon, the live value, and its own mini area chart. The two colors
// are deliberately far apart (warm vs cool) so up/down read at a glance.
function netCard(rx, tx, hist) {
  const upIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6 11l6-6 6 6"/><path d="M5 21h14"/></svg>';
  const dnIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v12"/><path d="M6 13l6 6 6-6"/><path d="M5 3h14"/></svg>';
  return `<div class="card netcard"><h3>网络吞吐</h3>
    <div class="netsplit">
      <div class="netcell up">
        <div class="nethdr"><span class="netic">${upIcon}</span><span>上行</span></div>
        <div class="netval">${fmtBytes(tx)}<s>/s</s></div>
        <div class="netchart">${areaChart(hist.tx, 'up')}</div>
      </div>
      <div class="netcell dn">
        <div class="nethdr"><span class="netic">${dnIcon}</span><span>下行</span></div>
        <div class="netval">${fmtBytes(rx)}<s>/s</s></div>
        <div class="netchart">${areaChart(hist.rx, 'dn')}</div>
      </div>
    </div>
  </div>`;
}
// Single-series smooth area chart, normalized to its own recent peak. `kind`
// (up|dn) selects the gradient/stroke colour.
function areaChart(data, kind) {
  const W = 130, H = 34, pad = 3;
  const m = data.length;
  if (m < 2) return '<div style="height:34px"></div>';
  const max = Math.max(1, ...data);
  const xs = (i) => (i * (W / (m - 1)));
  const ys = (val) => (H - pad - (val / max) * (H - pad * 2));
  const pts = data.map((val, i) => [xs(i), ys(val)]);
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  const stroke = kind === 'up' ? '#f59e0b' : '#38bdf8';
  const gid = 'ng_' + kind;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="34" preserveAspectRatio="none">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${stroke}" stop-opacity="0.38"/><stop offset="1" stop-color="${stroke}" stop-opacity="0.02"/></linearGradient></defs>
    <path d="${d} L${W},${H} L0,${H} Z" fill="url(#${gid})"/><path d="${d}" fill="none" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`;
}
