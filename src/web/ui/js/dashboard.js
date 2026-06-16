// =========================================================================
// Dashboard — one screen: live stat cards + a history chart (CPU / 内存 / 网络
// over 15m / 1h / 6h / 1d / 7d), drawn on a plain <canvas> (no chart lib).
// =========================================================================
function renderDash(v) {
  v.innerHTML = `
    <div class="dash">
      <div class="statrow" id="cards"></div>
      <div class="card histcard">
        <div class="hist-head">
          <div class="subtabs hist-metric" id="histMetric">
            <button data-m="cpu" class="on">CPU</button>
            <button data-m="mem">${tr('dash.mem')}</button>
            <button data-m="net">${tr('dash.net')}</button>
          </div>
          <div class="subtabs hist-range" id="histRange">
            <button data-r="15m" class="on">15m</button>
            <button data-r="1h">1h</button>
            <button data-r="6h">6h</button>
            <button data-r="1d">1d</button>
            <button data-r="7d">7d</button>
          </div>
        </div>
        <div class="hist-body">
          <canvas id="histCanvas"></canvas>
          <div class="hist-empty mut" id="histEmpty" style="display:none"></div>
        </div>
      </div>
    </div>`;
  const hist = { rx: [], tx: [] };
  const H = { metric: 'cpu', range: '15m', data: null };

  const doMetrics = () => {
    api('/api/metrics').then((b) => {
      const m = b.data;
      hist.rx.push(m.net_rx || 0); hist.tx.push(m.net_tx || 0);
      if (hist.rx.length > 40) { hist.rx.shift(); hist.tx.shift(); }
      const coreLabel = m.cpu_virtual ? tr('dash.vcpu') : tr('dash.cores');
      $('cards').innerHTML = [
        card('CPU', (m.cpu_usage || 0).toFixed(1) + '%', (m.cpu_cores || 0) + coreLabel, m.cpu_usage),
        card(tr('dash.mem'), (m.memory_usage || 0).toFixed(1) + '%', fmtBytes(m.mem_used) + ' / ' + fmtBytes(m.mem_total), m.memory_usage),
        card(tr('dash.disk'), (m.disk_usage || 0).toFixed(1) + '%', fmtBytes(m.disk_used) + ' / ' + fmtBytes(m.disk_total), m.disk_usage),
        netCard(m.net_rx || 0, m.net_tx || 0, hist),
      ].join('');
    }).catch(() => {});
  };
  const doHistory = () => {
    api('/api/metrics/history?metric=' + H.metric + '&range=' + H.range)
      .then((b) => { H.data = b.data; drawHistory(H); })
      .catch(() => {});
  };

  // Metric / range selectors: highlight the chosen button and reload the chart.
  const pick = (group, attr, key) => (e) => {
    const btn = e.target.closest('button'); if (!btn) return;
    [...$(group).children].forEach((c) => c.classList.toggle('on', c === btn));
    H[key] = btn.dataset[attr];
    doHistory();
  };
  $('histMetric').addEventListener('click', pick('histMetric', 'm', 'metric'));
  $('histRange').addEventListener('click', pick('histRange', 'r', 'range'));
  window.addEventListener('resize', () => drawHistory(H));

  // Poll loop: skip while the tab is hidden. Stat cards refresh every 2s; the
  // history chart is cheap but slower-moving, so refresh it ~every 10s.
  let beat = 0;
  const tick = () => {
    if (document.hidden) return;
    doMetrics();
    if (beat % 5 === 0) doHistory();
    beat++;
  };
  doMetrics(); doHistory();
  beat = 1;
  S.timer = setInterval(tick, 2000);
}

function card(title, big, sub, pct) {
  const bar = pct == null ? '' : `<div class="bar"><i style="width:${Math.min(100, Math.max(0, pct)).toFixed(0)}%"></i></div>`;
  return `<div class="card"><h3>${title}</h3><div class="big">${big}</div><div class="sub">${sub}</div>${bar}</div>`;
}

// ---- History chart (canvas) ----------------------------------------------

// Size the canvas to its container at device-pixel resolution (crisp lines).
// Height tracks the (flex-grown) container so the chart fills the card instead
// of a fixed slice; the canvas is absolutely positioned (see app.css) so its
// own size never feeds back into the container's measured height.
function fitCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const parent = cv.parentElement;
  const w = Math.max(160, parent.clientWidth);
  const hpx = Math.max(180, parent.clientHeight);
  cv.style.width = w + 'px'; cv.style.height = hpx + 'px';
  cv.width = Math.round(w * dpr); cv.height = Math.round(hpx * dpr);
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h: hpx };
}

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

// Local HH:MM (and MM-DD for multi-day ranges) tick label for a unix-second ts.
function histClock(ts, range) {
  const d = new Date(ts * 1000);
  const p = (n) => (n < 10 ? '0' + n : '' + n);
  const hm = p(d.getHours()) + ':' + p(d.getMinutes());
  return (range === '1d' || range === '7d') ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ${hm}` : hm;
}

function drawHistory(H) {
  const cv = $('histCanvas'); if (!cv) return;
  const pts = (H.data && H.data.points) || [];
  const empty = $('histEmpty');
  if (pts.length < 2) {
    cv.style.display = 'none';
    if (empty) { empty.style.display = 'flex'; empty.textContent = tr('dash.no_history'); }
    return;
  }
  cv.style.display = 'block'; if (empty) empty.style.display = 'none';
  const net = H.metric === 'net';
  const { ctx, w, h } = fitCanvas(cv);
  const padL = 52, padR = 14, padT = 14, padB = 24;
  const plotW = w - padL - padR, plotH = h - padT - padB;
  const n = pts.length;
  const x = (i) => padL + (n === 1 ? 0 : (i * plotW) / (n - 1));

  // Y scale: percent metrics are fixed 0..100; network auto-scales to its peak.
  let yMax, fmtY;
  if (net) {
    const peak = Math.max(1, ...pts.map((p) => Math.max(p.rx || 0, p.tx || 0)));
    yMax = peak * 1.15;
    fmtY = (val) => fmtBytes(val) + '/s';
  } else {
    yMax = 100; fmtY = (val) => val.toFixed(0) + '%';
  }
  const y = (val) => padT + plotH - (Math.max(0, Math.min(val, yMax)) / yMax) * plotH;

  const ink = cssVar('--muted', '#94a3b8');
  const grid = cssVar('--border', 'rgba(148,163,184,0.18)');
  ctx.clearRect(0, 0, w, h);
  ctx.font = '11px system-ui, sans-serif';
  ctx.textBaseline = 'middle';

  // Horizontal gridlines + y labels (5 steps).
  ctx.strokeStyle = grid; ctx.fillStyle = ink; ctx.lineWidth = 1;
  for (let k = 0; k <= 4; k++) {
    const val = (yMax * k) / 4, yy = y(val);
    ctx.globalAlpha = 0.5; ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(w - padR, yy); ctx.stroke();
    ctx.globalAlpha = 1; ctx.textAlign = 'right'; ctx.fillText(fmtY(val), padL - 8, yy);
  }
  // X end labels (start + now).
  ctx.textAlign = 'left'; ctx.fillText(histClock(pts[0].t, H.range), padL, h - padB / 2);
  ctx.textAlign = 'right'; ctx.fillText(histClock(pts[n - 1].t, H.range), w - padR, h - padB / 2);

  // Draw one series as an area + line; `key` reads the value off each point.
  const series = (key, color) => {
    ctx.beginPath();
    pts.forEach((p, i) => { const xi = x(i), yi = y(p[key] || 0); i ? ctx.lineTo(xi, yi) : ctx.moveTo(xi, yi); });
    ctx.lineTo(x(n - 1), y(0)); ctx.lineTo(x(0), y(0)); ctx.closePath();
    const g = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    g.addColorStop(0, color + '44'); g.addColorStop(1, color + '08');
    ctx.fillStyle = g; ctx.fill();
    ctx.beginPath();
    pts.forEach((p, i) => { const xi = x(i), yi = y(p[key] || 0); i ? ctx.lineTo(xi, yi) : ctx.moveTo(xi, yi); });
    ctx.strokeStyle = color; ctx.lineWidth = 1.8; ctx.lineJoin = 'round'; ctx.stroke();
  };

  if (net) {
    series('rx', '#38bdf8'); // download (blue)
    series('tx', '#f59e0b'); // upload (amber)
    // Legend.
    ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
    ctx.fillStyle = '#38bdf8'; ctx.fillRect(padL, padT + 2, 10, 3); ctx.fillStyle = ink; ctx.fillText(tr('dash.dn'), padL + 14, padT + 4);
    ctx.fillStyle = '#f59e0b'; ctx.fillRect(padL + 60, padT + 2, 10, 3); ctx.fillStyle = ink; ctx.fillText(tr('dash.up'), padL + 74, padT + 4);
  } else {
    series('v', cssVar('--accent', '#3b82f6'));
  }
  ctx.globalAlpha = 1;
}

// ---- Network throughput stat card (unchanged) ----------------------------
function netCard(rx, tx, hist) {
  const upIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6 11l6-6 6 6"/><path d="M5 21h14"/></svg>';
  const dnIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v12"/><path d="M6 13l6 6 6-6"/><path d="M5 3h14"/></svg>';
  return `<div class="card netcard"><h3>${tr('dash.net')}</h3>
    <div class="netsplit">
      <div class="netcell up">
        <div class="nethdr"><span class="netic">${upIcon}</span><span>${tr('dash.up')}</span></div>
        <div class="netval">${fmtBytes(tx)}<s>/s</s></div>
        <div class="netchart">${areaChart(hist.tx, 'up')}</div>
      </div>
      <div class="netcell dn">
        <div class="nethdr"><span class="netic">${dnIcon}</span><span>${tr('dash.dn')}</span></div>
        <div class="netval">${fmtBytes(rx)}<s>/s</s></div>
        <div class="netchart">${areaChart(hist.rx, 'dn')}</div>
      </div>
    </div>
  </div>`;
}
// Single-series smooth area chart for the net stat card, normalized to its own
// recent peak. `kind` (up|dn) selects the gradient/stroke colour.
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
