// =========================================================================
// Dashboard — bento grid: four live stat tiles (with rolling sparklines), a
// system tile (host identity + per-mount disks) and a history chart hero
// (CPU / 内存 / 网络 over 15m / 1h / 6h / 1d / 7d) drawn on a plain <canvas>
// (no chart lib). Chart selection, last payload and the sparkline buffers
// live at module scope so tab switches don't reset them.
// =========================================================================
const DASH = {
  H: { metric: 'cpu', range: '15m', data: null, hover: null }, // history chart state
  spark: { rx: [], tx: [], cpu: [], mem: [], disk: [] },       // rolling sample buffers
};
const DASH_SPARK_MAX = 40;
const HIST_RX = '#38bdf8', HIST_TX = '#f59e0b'; // download / upload series

// warn ≥80%, err ≥92% — class suffix for bars and big numbers.
function dashSev(pct) { return pct >= 92 ? 'err' : pct >= 80 ? 'warn' : ''; }

// "14d 3h" style uptime from seconds (unit strings are locale keys).
function fmtUptime(s) {
  s = Math.max(0, Number(s) || 0);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return tr('dash.up_d', { d, h });
  if (h) return tr('dash.up_h', { h, m });
  return tr('dash.up_m', { m });
}

function renderDash(v) {
  const H = DASH.H;
  H.hover = null;
  // First-paint skeletons: every tile shimmers until the first poll lands.
  const skel = `
    <div class="skel" style="height:12px;width:42%"></div>
    <div class="skel" style="height:24px;width:58%;margin-top:12px"></div>
    <div class="skel" style="height:12px;width:78%;margin-top:10px"></div>`;
  const stat = (id, cls) => `<div class="card stattile tile-3${cls || ''}" id="${id}">${skel}</div>`;
  v.innerHTML = `
    <div class="dash" id="dashRoot">
      <div class="dash-grid">
        ${stat('dCpu')}${stat('dMem')}${stat('dDisk')}${stat('dNet', ' netcard')}
        <div class="card histcard tile-hero with-side">
          <div class="hist-head">
            <div class="subtabs hist-metric" id="histMetric">
              <button data-m="cpu"${H.metric === 'cpu' ? ' class="on"' : ''}>CPU</button>
              <button data-m="mem"${H.metric === 'mem' ? ' class="on"' : ''}>${tr('dash.mem')}</button>
              <button data-m="net"${H.metric === 'net' ? ' class="on"' : ''}>${tr('dash.net')}</button>
            </div>
            <span class="chip warn" id="dashStale" style="display:none">${tr('dash.unreachable')}</span>
            <div class="subtabs hist-range" id="histRange">
              ${['15m', '1h', '6h', '1d', '7d'].map((r) => `<button data-r="${r}"${H.range === r ? ' class="on"' : ''}>${r}</button>`).join('')}
            </div>
          </div>
          <div class="hist-body" id="histBody">
            <canvas id="histCanvas"></canvas>
            <div class="hist-empty mut" id="histEmpty" style="display:none"></div>
            <div class="hist-tip" id="histTip" style="display:none"></div>
          </div>
        </div>
        <div class="card tile-side" id="dSys">${skel}</div>
      </div>
    </div>`;

  // ---- tile bodies (built ONCE on the first successful poll; later ticks
  // only patch text/width/svg nodes so the .bar width transition can run and
  // text selection survives the 2s refresh) ----
  const statBody = (title) => `<h3>${title}</h3><div class="big">—</div><div class="sub"></div><div class="bar"><i></i></div><div class="cardspark"></div>`;
  const netBody = () => {
    const upIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6 11l6-6 6 6"/><path d="M5 21h14"/></svg>';
    const dnIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v12"/><path d="M6 13l6 6 6-6"/><path d="M5 3h14"/></svg>';
    return `<h3>${tr('dash.net')}</h3>
      <div class="netsplit">
        <div class="netcell up">
          <div class="nethdr"><span class="netic">${upIcon}</span><span>${tr('dash.up')}</span></div>
          <div class="netval"><span id="dNetTx">0 B</span><s>/s</s></div>
          <div class="netchart" id="dNetTxS"></div>
        </div>
        <div class="netcell dn">
          <div class="nethdr"><span class="netic">${dnIcon}</span><span>${tr('dash.dn')}</span></div>
          <div class="netval"><span id="dNetRx">0 B</span><s>/s</s></div>
          <div class="netchart" id="dNetRxS"></div>
        </div>
      </div>`;
  };
  const sysRow = (k, id) => `<div class="sysrow" id="${id}Row" style="display:none"><span class="k">${k}</span><span class="v" id="${id}"></span></div>`;
  const sysBody = () => `<h3>${tr('dash.sys')}</h3>
    <div class="sysrows">
      ${sysRow(tr('dash.host'), 'dSysHost')}
      ${sysRow(tr('dash.os'), 'dSysOs')}
      ${sysRow(tr('dash.uptime'), 'dSysUp')}
      ${sysRow(tr('dash.ip'), 'dSysIp')}
      ${sysRow(tr('dash.cpu_model'), 'dSysCpu')}
    </div>
    <div class="sysmounts" id="dSysMounts"></div>`;

  let N = null; // node refs for incremental updates
  const buildCards = () => {
    $('dCpu').innerHTML = statBody('CPU');
    $('dMem').innerHTML = statBody(tr('dash.mem'));
    $('dDisk').innerHTML = statBody(tr('dash.disk'));
    $('dNet').innerHTML = netBody();
    $('dSys').innerHTML = sysBody();
    const pick3 = (id) => { const c = $(id); return { big: c.querySelector('.big'), sub: c.querySelector('.sub'), bar: c.querySelector('.bar>i'), spark: c.querySelector('.cardspark') }; };
    N = { cpu: pick3('dCpu'), mem: pick3('dMem'), disk: pick3('dDisk'), mountSig: '' };
  };
  const setStat = (n, pct, big, sub, data, kind) => {
    const sev = dashSev(pct || 0);
    n.big.textContent = big;
    n.big.className = 'big' + (sev ? ' ' + sev : '');
    n.sub.textContent = sub;
    n.bar.style.width = Math.min(100, Math.max(0, pct || 0)).toFixed(0) + '%';
    n.bar.className = sev;
    n.spark.innerHTML = areaChart(data, kind);
  };
  // System tile rows hide when the backend omits the field.
  const sysSet = (id, val, wantTitle) => {
    const n = $(id); if (!n) return;
    const row = $(id + 'Row');
    if (row) row.style.display = val ? '' : 'none';
    n.textContent = val || '';
    if (wantTitle) n.title = val || '';
  };
  // Per-mount disk bars: rebuild rows only when the mount set changes shape;
  // otherwise just patch used/width per tick.
  const updMounts = (mounts) => {
    const box = $('dSysMounts'); if (!box) return;
    mounts = Array.isArray(mounts) ? mounts : [];
    const sig = mounts.map((mt) => mt.mount + ':' + mt.total).join('|');
    if (sig !== N.mountSig) {
      N.mountSig = sig;
      box.innerHTML = !mounts.length ? '' : `<div class="mhead">${tr('dash.mounts')}</div>` + mounts.map((mt, i) => `
        <div class="sysmount" id="dMnt${i}">
          <div class="mrow"><b title="${esc(mt.mount + (mt.device ? ' · ' + mt.device : ''))}">${esc(mt.mount)}</b><span class="mv"></span></div>
          <div class="bar"><i></i></div>
        </div>`).join('');
    }
    mounts.forEach((mt, i) => {
      const row = $('dMnt' + i); if (!row) return;
      const pct = mt.total ? ((mt.used || 0) / mt.total) * 100 : 0;
      row.querySelector('.mv').textContent = fmtBytes(mt.used) + ' / ' + fmtBytes(mt.total);
      const bar = row.querySelector('.bar>i');
      bar.style.width = Math.min(100, Math.max(0, pct)).toFixed(0) + '%';
      bar.className = dashSev(pct);
    });
  };
  const update = (m) => {
    if (!N) buildCards();
    const sp = DASH.spark;
    sp.rx.push(m.net_rx || 0); sp.tx.push(m.net_tx || 0);
    sp.cpu.push(m.cpu_usage || 0); sp.mem.push(m.memory_usage || 0); sp.disk.push(m.disk_usage || 0);
    for (const k in sp) if (sp[k].length > DASH_SPARK_MAX) sp[k].splice(0, sp[k].length - DASH_SPARK_MAX);
    const coreLabel = m.cpu_virtual ? tr('dash.vcpu') : tr('dash.cores');
    setStat(N.cpu, m.cpu_usage, (m.cpu_usage || 0).toFixed(1) + '%', (m.cpu_cores || 0) + coreLabel, sp.cpu, 'cpu');
    setStat(N.mem, m.memory_usage, (m.memory_usage || 0).toFixed(1) + '%', fmtBytes(m.mem_used) + ' / ' + fmtBytes(m.mem_total), sp.mem, 'mem');
    setStat(N.disk, m.disk_usage, (m.disk_usage || 0).toFixed(1) + '%', fmtBytes(m.disk_used) + ' / ' + fmtBytes(m.disk_total), sp.disk, 'disk');
    $('dNetTx').textContent = fmtBytes(m.net_tx || 0);
    $('dNetRx').textContent = fmtBytes(m.net_rx || 0);
    $('dNetTxS').innerHTML = areaChart(sp.tx, 'up');
    $('dNetRxS').innerHTML = areaChart(sp.rx, 'dn');
    sysSet('dSysHost', m.hostname);
    sysSet('dSysOs', m.os_version);
    sysSet('dSysUp', m.uptime ? fmtUptime(m.uptime) : '');
    sysSet('dSysIp', m.ip);
    sysSet('dSysCpu', m.cpu_model, true);
    updMounts(m.disk_mounts);
  };

  // ---- polls (apiInflight coalesces overlapping requests on slow links).
  // Failures are NOT silent: after 2 consecutive misses the grid desaturates
  // (.stale) and a warn chip appears until the next success.
  let fails = 0, lastOk = 0;
  const setStale = (on) => {
    const root = $('dashRoot'); if (!root) return;
    root.classList.toggle('stale', on);
    const chip = $('dashStale');
    if (chip) {
      chip.style.display = on ? '' : 'none';
      if (on && lastOk) chip.title = tr('dash.asof', { time: fmtTsFull(lastOk) });
    }
  };
  const doMetrics = () => {
    apiInflight('dash:metrics', () => api('/api/metrics')).then((b) => {
      fails = 0; lastOk = Math.floor(Date.now() / 1000);
      setStale(false);
      update(b.data || {});
    }).catch(() => {
      fails++;
      if (fails >= 2) setStale(true);
    });
  };
  const doHistory = () => {
    const metric = H.metric, range = H.range;
    apiInflight('dash:hist:' + metric + ':' + range,
      () => api('/api/metrics/history?metric=' + metric + '&range=' + range))
      .then((b) => {
        if (metric !== H.metric || range !== H.range) return; // selection changed mid-flight
        H.data = b.data;
        drawHistory(H);
      })
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
  let ro = null;
  if (window.ResizeObserver) { ro = new ResizeObserver(onResize); ro.observe($('histBody')); }
  const cv = $('histCanvas');
  cv.addEventListener('mousemove', (e) => moveHistoryHover(H, e));
  cv.addEventListener('mouseleave', () => { H.hover = null; drawHistory(H); });
  // Touch scrubbing (CSS touch-action:pan-y keeps vertical page scroll alive).
  const scrub = (e) => { if (e.touches && e.touches[0]) moveHistoryHover(H, e.touches[0]); };
  const scrubEnd = () => { H.hover = null; drawHistory(H); };
  cv.addEventListener('touchstart', scrub, { passive: true });
  cv.addEventListener('touchmove', scrub, { passive: true });
  cv.addEventListener('touchend', scrubEnd);
  cv.addEventListener('touchcancel', scrubEnd);
  window._dashCleanup = () => { window.removeEventListener('resize', onResize); if (ro) ro.disconnect(); };

  // Poll loop: skip while the tab is hidden. Stat tiles refresh every 2s; the
  // history chart is cheap but slower-moving, so refresh it ~every 10s.
  let beat = 0;
  const tick = () => {
    if (document.hidden) return;
    doMetrics();
    if (beat % 5 === 0) doHistory();
    beat++;
  };
  if (H.data) drawHistory(H); // instant paint from the persisted payload on revisit
  doMetrics(); doHistory();
  beat = 1;
  S.timer = setInterval(tick, 2000);
}

// ---- History chart (canvas) ----------------------------------------------

// Size the canvas to its container at device-pixel resolution (crisp lines).
// The fitted size is cached on the element: hover/tick redraws skip the
// width/height reassignment (which would reallocate the backing store) and
// only an actual container/dpr change re-fits.
function fitCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const parent = cv.parentElement;
  const w = Math.max(160, parent.clientWidth);
  const hpx = Math.max(180, parent.clientHeight);
  const ctx = cv.getContext('2d');
  if (cv._fw !== w || cv._fh !== hpx || cv._fd !== dpr) {
    cv._fw = w; cv._fh = hpx; cv._fd = dpr;
    cv.style.width = w + 'px'; cv.style.height = hpx + 'px';
    cv.width = Math.round(w * dpr); cv.height = Math.round(hpx * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  return { ctx, w, h: hpx };
}

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

// css color + alpha → a canvas-parsable color: hex fast-path, color-mix for
// token values (oklch()/color-mix strings can't take a hex alpha suffix).
function fadeColor(c, alpha) {
  if (c[0] === '#' && c.length === 7) return c + Math.round(alpha * 255).toString(16).padStart(2, '0');
  return `color-mix(in srgb, ${c} ${Math.round(alpha * 100)}%, transparent)`;
}

// HH:MM (and MM-DD for multi-day ranges) tick label for a unix-second ts, in the
// configured display timezone.
function histClock(ts, range) {
  const t = dn7TsParts(ts);
  const hm = `${t.h}:${t.m}`;
  return (range === '1d' || range === '7d') ? `${t.M}-${t.D} ${hm}` : hm;
}

function histFullTime(ts) { return fmtTsFull(ts); }

const HIST_RANGE_SECS = { '15m': 900, '1h': 3600, '6h': 21600, '1d': 86400, '7d': 604800 };
// Intermediate x-tick step per range (3-5 ticks across the window incl. edges).
const HIST_TICK_SECS = { '15m': 300, '1h': 900, '6h': 7200, '1d': 21600, '7d': 172800 };
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
  // Empty overlay: shimmer skeleton before the FIRST payload, "no history"
  // only once the backend actually answered with zero points.
  if (empty) {
    if (!H.data) {
      if (empty.dataset.mode !== 'skel') { empty.dataset.mode = 'skel'; empty.innerHTML = `<div style="width:min(420px,80%)">${loading()}</div>`; }
      empty.style.display = 'flex';
    } else if (!pts.length) {
      if (empty.dataset.mode !== 'txt') { empty.dataset.mode = 'txt'; empty.textContent = tr('dash.no_history'); }
      empty.style.display = 'flex';
    } else { empty.style.display = 'none'; }
  }
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
  // Intermediate x ticks: faint vertical gridlines at round wall-clock steps,
  // skipping ticks that would collide with the edge labels.
  const step = HIST_TICK_SECS[H.range] || Math.max(60, Math.round(bounds.windowSecs / 4));
  const edgeGap = (H.range === '1d' || H.range === '7d') ? 78 : 42;
  ctx.textAlign = 'center';
  for (let ts = Math.ceil(bounds.start / step) * step; ts < bounds.end; ts += step) {
    const x = xTime(ts);
    if (x < padL + edgeGap || x > w - padR - edgeGap) continue;
    ctx.globalAlpha = 0.3; ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + plotH); ctx.stroke();
    ctx.globalAlpha = 1; ctx.fillText(histClock(ts, H.range), x, h - padB / 2);
  }
  // X end labels (start + now).
  ctx.textAlign = 'left'; ctx.fillText(histClock(bounds.start, H.range), padL, h - padB / 2);
  ctx.textAlign = 'right'; ctx.fillText(histClock(bounds.end, H.range), w - padR, h - padB / 2);

  // Draw one series as an area + line; `key` reads the value off each point.
  const series = (key, color) => {
    const g = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    g.addColorStop(0, fadeColor(color, 0.27)); g.addColorStop(1, fadeColor(color, 0.03));
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
    series('rx', HIST_RX); // download (blue)
    series('tx', HIST_TX); // upload (amber)
    // Legend.
    ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
    ctx.fillStyle = HIST_RX; ctx.fillRect(padL, padT + 2, 10, 3); ctx.fillStyle = ink; ctx.fillText(tr('dash.dn'), padL + 14, padT + 4);
    ctx.fillStyle = HIST_TX; ctx.fillRect(padL + 60, padT + 2, 10, 3); ctx.fillStyle = ink; ctx.fillText(tr('dash.up'), padL + 74, padT + 4);
  } else {
    series('v', cssVar('--accent', '#3b82f6'));
  }

  const hover = H.hover == null ? null : pts.find((p) => Number(p.t) === H.hover);
  if (hover) {
    const hx = xTime(hover.t);
    const ring = cssVar('--panel-solid', '#fff');
    ctx.save();
    ctx.strokeStyle = ink; ctx.globalAlpha = 0.75; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(hx, padT); ctx.lineTo(hx, padT + plotH); ctx.stroke();
    ctx.setLineDash([]); ctx.globalAlpha = 1;
    if (net) {
      [['rx', HIST_RX], ['tx', HIST_TX]].forEach(([key, color]) => {
        ctx.beginPath(); ctx.arc(hx, y(hover[key] || 0), 3.2, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill(); ctx.strokeStyle = ring; ctx.lineWidth = 2; ctx.stroke();
      });
      showHistoryTip(H, hover, hx, y(Math.max(hover.rx || 0, hover.tx || 0)), w, h);
    } else {
      const color = cssVar('--accent', '#3b82f6');
      ctx.beginPath(); ctx.arc(hx, y(hover.v || 0), 3.4, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.fill(); ctx.strokeStyle = ring; ctx.lineWidth = 2; ctx.stroke();
      showHistoryTip(H, hover, hx, y(hover.v || 0), w, h);
    }
    ctx.restore();
  } else if (tip) {
    tip.style.display = 'none';
  }
  ctx.globalAlpha = 1;
}

// Works for both mouse events and Touch points (both expose clientX).
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
    tip.innerHTML = `<b>${histFullTime(p.t)}</b><span><i style="background:${HIST_RX}"></i>${tr('dash.dn')} ${fmtBytes(p.rx || 0)}/s</span><span><i style="background:${HIST_TX}"></i>${tr('dash.up')} ${fmtBytes(p.tx || 0)}/s</span>`;
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

// Single-series smooth area chart for a stat tile, normalized to its own
// recent peak. `kind` (up|dn|cpu|mem|disk) selects the stroke/gradient colour;
// each kind renders in exactly one tile, so gradient ids stay unique.
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
  const stroke = kind === 'up' ? HIST_TX : kind === 'dn' ? HIST_RX
    : kind === 'mem' ? cssVar('--accent-2', '#8b5cf6')
      : kind === 'disk' ? cssVar('--muted', '#94a3b8')
        : cssVar('--accent', '#3b82f6');
  const gid = 'ng_' + kind;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="34" preserveAspectRatio="none">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${stroke}" stop-opacity="0.38"/><stop offset="1" stop-color="${stroke}" stop-opacity="0.02"/></linearGradient></defs>
    <path d="${d} L${W},${H} L0,${H} Z" fill="url(#${gid})"/><path d="${d}" fill="none" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`;
}
