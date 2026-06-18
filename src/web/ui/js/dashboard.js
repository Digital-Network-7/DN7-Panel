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
          <div class="hist-tip" id="histTip" style="display:none"></div>
        </div>
      </div>
    </div>`;
  const hist = { rx: [], tx: [] };
  const H = { metric: 'cpu', range: '15m', data: null, hover: null };

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
    H.hover = null;
    doHistory();
  };
  $('histMetric').addEventListener('click', pick('histMetric', 'm', 'metric'));
  $('histRange').addEventListener('click', pick('histRange', 'r', 'range'));
  const onResize = () => drawHistory(H);
  window.addEventListener('resize', onResize);
  $('histCanvas').addEventListener('mousemove', (e) => moveHistoryHover(H, e));
  $('histCanvas').addEventListener('mouseleave', () => { H.hover = null; drawHistory(H); });
  window._dashCleanup = () => window.removeEventListener('resize', onResize);

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

function histFullTime(ts) {
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const HIST_RANGE_SECS = { '15m': 900, '1h': 3600, '6h': 21600, '1d': 86400, '7d': 604800 };
const HIST_PAD = { l: 52, r: 14, t: 14, b: 24 };

function fmtBytesInt(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return Math.round(n) + ' ' + u[i];
}

function histBounds(H) {
  const d = H.data || {};
  const windowSecs = Number(d.window_secs) || HIST_RANGE_SECS[H.range] || HIST_RANGE_SECS['15m'];
  const end = Number(d.now) || Math.floor(Date.now() / 1000);
  const slotSecs = Number(d.slot_secs) || Math.max(1, Math.round(windowSecs / 100));
  return { start: end - windowSecs, end, windowSecs, slotSecs };
}

function histPoints(H) {
  return ((H.data && H.data.points) || [])
    .filter((p) => Number.isFinite(Number(p.t)))
    .slice()
    .sort((a, b) => Number(a.t) - Number(b.t));
}

function histSegments(pts, slotSecs) {
  const maxGap = Math.max(slotSecs * 2.25, slotSecs + 2);
  const segs = [];
  let cur = [];
  pts.forEach((p) => {
    const prev = cur[cur.length - 1];
    if (prev && (Number(p.t) - Number(prev.t)) > maxGap) {
      if (cur.length) segs.push(cur);
      cur = [];
    }
    cur.push(p);
  });
  if (cur.length) segs.push(cur);
  return segs;
}

function drawHistory(H) {
  const cv = $('histCanvas'); if (!cv) return;
  const pts = histPoints(H);
  const bounds = histBounds(H);
  const empty = $('histEmpty');
  const tip = $('histTip');
  cv.style.display = 'block';
  if (empty) { empty.style.display = pts.length ? 'none' : 'flex'; empty.textContent = tr('dash.no_history'); }
  if (tip && !H.hover) tip.style.display = 'none';
  const net = H.metric === 'net';
  const { ctx, w, h } = fitCanvas(cv);
  const padL = HIST_PAD.l, padR = HIST_PAD.r, padT = HIST_PAD.t, padB = HIST_PAD.b;
  const plotW = w - padL - padR, plotH = h - padT - padB;
  const xTime = (ts) => padL + Math.max(0, Math.min(1, (Number(ts) - bounds.start) / bounds.windowSecs)) * plotW;

  // Y scale: percent metrics are fixed 0..100; network auto-scales to its peak.
  let yMax, fmtY;
  if (net) {
    const peak = Math.max(1, ...pts.map((p) => Math.max(p.rx || 0, p.tx || 0)));
    yMax = peak * 1.15;
    fmtY = (val) => fmtBytesInt(val) + '/s';
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
  ctx.textAlign = 'left'; ctx.fillText(histClock(bounds.start, H.range), padL, h - padB / 2);
  ctx.textAlign = 'right'; ctx.fillText(histClock(bounds.end, H.range), w - padR, h - padB / 2);

  // Draw one series as an area + line; `key` reads the value off each point.
  const series = (key, color) => {
    const g = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    g.addColorStop(0, color + '44'); g.addColorStop(1, color + '08');
    histSegments(pts, bounds.slotSecs).forEach((seg) => {
      if (seg.length === 1) {
        ctx.beginPath(); ctx.arc(xTime(seg[0].t), y(seg[0][key] || 0), 2.6, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill();
        return;
      }
      ctx.beginPath();
      seg.forEach((p, i) => { const xi = xTime(p.t), yi = y(p[key] || 0); i ? ctx.lineTo(xi, yi) : ctx.moveTo(xi, yi); });
      ctx.lineTo(xTime(seg[seg.length - 1].t), y(0)); ctx.lineTo(xTime(seg[0].t), y(0)); ctx.closePath();
      ctx.fillStyle = g; ctx.fill();
      ctx.beginPath();
      seg.forEach((p, i) => { const xi = xTime(p.t), yi = y(p[key] || 0); i ? ctx.lineTo(xi, yi) : ctx.moveTo(xi, yi); });
      ctx.strokeStyle = color; ctx.lineWidth = 1.8; ctx.lineJoin = 'round'; ctx.stroke();
    });
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

  const hover = H.hover == null ? null : pts.find((p) => Number(p.t) === H.hover);
  if (hover) {
    const hx = xTime(hover.t);
    ctx.save();
    ctx.strokeStyle = ink; ctx.globalAlpha = 0.75; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(hx, padT); ctx.lineTo(hx, padT + plotH); ctx.stroke();
    ctx.setLineDash([]); ctx.globalAlpha = 1;
    if (net) {
      [['rx', '#38bdf8'], ['tx', '#f59e0b']].forEach(([key, color]) => {
        ctx.beginPath(); ctx.arc(hx, y(hover[key] || 0), 3.2, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill(); ctx.strokeStyle = cssVar('--panel', '#fff'); ctx.lineWidth = 2; ctx.stroke();
      });
      showHistoryTip(H, hover, hx, y(Math.max(hover.rx || 0, hover.tx || 0)), w, h);
    } else {
      const color = cssVar('--accent', '#3b82f6');
      ctx.beginPath(); ctx.arc(hx, y(hover.v || 0), 3.4, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.fill(); ctx.strokeStyle = cssVar('--panel', '#fff'); ctx.lineWidth = 2; ctx.stroke();
      showHistoryTip(H, hover, hx, y(hover.v || 0), w, h);
    }
    ctx.restore();
  } else if (tip) {
    tip.style.display = 'none';
  }
  ctx.globalAlpha = 1;
}

function moveHistoryHover(H, ev) {
  const cv = $('histCanvas'); if (!cv) return;
  const pts = histPoints(H);
  if (!pts.length) { H.hover = null; drawHistory(H); return; }
  const bounds = histBounds(H);
  const rect = cv.getBoundingClientRect();
  const padL = HIST_PAD.l, padR = HIST_PAD.r;
  const plotW = rect.width - padL - padR;
  const mx = ev.clientX - rect.left;
  if (mx < padL || mx > rect.width - padR || plotW <= 0) {
    H.hover = null; drawHistory(H); return;
  }
  const xTime = (ts) => padL + Math.max(0, Math.min(1, (Number(ts) - bounds.start) / bounds.windowSecs)) * plotW;
  let best = null, bestDist = Infinity;
  pts.forEach((p) => {
    const dist = Math.abs(xTime(p.t) - mx);
    if (dist < bestDist) { best = p; bestDist = dist; }
  });
  const maxHit = Math.max(14, Math.min(28, plotW / 36));
  H.hover = best && bestDist <= maxHit ? Number(best.t) : null;
  drawHistory(H);
}

function showHistoryTip(H, p, x, y, w, h) {
  const tip = $('histTip'); if (!tip) return;
  if (H.metric === 'net') {
    tip.innerHTML = `<b>${histFullTime(p.t)}</b><span><i style="background:#38bdf8"></i>${tr('dash.dn')} ${fmtBytes(p.rx || 0)}/s</span><span><i style="background:#f59e0b"></i>${tr('dash.up')} ${fmtBytes(p.tx || 0)}/s</span>`;
  } else {
    const label = H.metric === 'mem' ? tr('dash.mem') : 'CPU';
    tip.innerHTML = `<b>${histFullTime(p.t)}</b><span><i style="background:${cssVar('--accent', '#3b82f6')}"></i>${label} ${(Number(p.v) || 0).toFixed(1)}%</span>`;
  }
  tip.style.display = 'block';
  const tw = tip.offsetWidth || 170, th = tip.offsetHeight || 64;
  let left = x + 12, top = y - th - 10;
  if (left + tw > w - 6) left = x - tw - 12;
  if (top < 6) top = y + 12;
  if (top + th > h - 6) top = h - th - 6;
  tip.style.left = Math.round(Math.max(6, left)) + 'px';
  tip.style.top = Math.round(Math.max(6, top)) + 'px';
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
