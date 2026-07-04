// =========================================================================
// Audit log (Owner only) — privileged-action history from /api/logs
// =========================================================================

// An action key is "<group>.<op>" (e.g. "website.add_site", "auth.login"). The
// table shows the group and the op in two separate columns:
//
//   logGroup(action) → the module/category label  ("Website", "Auth", …)
//   logOp(action)    → the operation label        ("Add site", "Sign in", …)
//
// Each tries the most specific i18n key and degrades to the raw token so a new
// backend op still renders readably.

function logGrpTok(action) {
  const dot = String(action || '').indexOf('.');
  return dot > 0 ? String(action).slice(0, dot) : '';
}

function logGrpLabel(grp) {
  const gk = 'log.grp.' + grp, gl = tr(gk);
  return gl !== gk ? gl : grp;
}

function logGroup(action) {
  const grp = logGrpTok(action);
  return grp ? logGrpLabel(grp) : '';
}

function logOp(action) {
  // Prefer a full per-action phrase ("Sign in"), then a channel-agnostic op
  // label ("Add site"), then the raw op / action token.
  action = String(action || '');
  const full = 'log.act.' + action;
  const tf = tr(full);
  if (tf !== full) return tf;
  const dot = action.indexOf('.');
  const op = dot > 0 ? action.slice(dot + 1) : action;
  const ok = 'log.op.' + op, ol = tr(ok);
  return ol !== ok ? ol : op;
}

function logFmtTime(ts) {
  if (!ts) return '-';
  return fmtTsFull(ts); // configured display timezone (falls back to local)
}

// Unambiguous UTC form for tooltips/exports (audit rows get correlated against
// server logs and provider dashboards in other timezones).
function logUtcIso(ts) { return ts ? new Date((Number(ts) || 0) * 1000).toISOString() : ''; }

// Rows per page are computed from the height actually available (min 10); the
// row height is measured after the first paint and reused across renders/visits.
let LOG_ROW_H = 42;

// ---- Export (client-side download of the currently filtered entries) ----

function logDownload(name, mime, text) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = el('a', { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

function logExportName(ext) {
  const t = dn7TsParts(Math.floor(Date.now() / 1000));
  return `audit-log-${t.Y}${t.M}${t.D}-${t.h}${t.m}${t.s}.${ext}`;
}

// OWASP CSV-injection mitigation: cells that begin with a formula trigger
// (= + - @ tab CR) are executed by Excel/LibreOffice, and fields like `actor`
// are attacker-controlled (a failed login records the attempted username
// verbatim). Prefix such values with a single quote before quoting.
function logCsvCell(v) {
  const s = String(v == null ? '' : v);
  const g = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return '"' + g.replace(/"/g, '""') + '"';
}

// `note`: truncation warning appended as a final row / field when the server
// cap was hit ('' when the export is complete history).
function logExportCsv(rows, note) {
  const tz = dn7Tz() || tr('log.tz_local');
  const head = [tr('log.time') + ' (' + tz + ')', 'UTC', tr('log.actor'), tr('log.col_module'), tr('log.action'), tr('log.export_col_key'), tr('log.target'), tr('log.col_ip'), tr('log.result'), tr('log.detail')];
  const lines = [head.map(logCsvCell).join(',')];
  rows.forEach((e) => lines.push([
    logFmtTime(e.ts), logUtcIso(e.ts), e.actor || '', logGroup(e.action), logOp(e.action),
    e.action || '', e.target || '', e.ip || '', e.ok ? tr('log.ok') : tr('log.fail'), e.detail || '',
  ].map(logCsvCell).join(',')));
  if (note) lines.push(logCsvCell(note));
  // BOM so spreadsheet apps detect UTF-8 (CJK labels/targets).
  logDownload(logExportName('csv'), 'text/csv;charset=utf-8', '\uFEFF' + lines.join('\r\n'));
}

function logExportJson(rows, note) {
  // Strip the client-side filter caches (_q/_grp/_d) added by prime().
  const clean = rows.map((e) => { const c = {}; for (const k in e) if (k[0] !== '_') c[k] = e[k]; return c; });
  const doc = { generated_utc: new Date().toISOString(), timezone: dn7Tz() || 'local', count: clean.length, entries: clean };
  if (note) doc.note = note;
  logDownload(logExportName('json'), 'application/json', JSON.stringify(doc, null, 2));
}

function renderLogs(v) {
  const tz = dn7Tz() || tr('log.tz_local');
  // No card wrapper: the logs tab owns the viewport (fillmode) and lays out as a
  // flex column — a filter/action bar on top, the table filling the middle, the
  // pager pinned at the bottom. The table's row count is fitted to that middle.
  v.innerHTML = `
    <div class="logspage">
      <div class="logbar">
        <input id="logFilter" class="field sm" placeholder="${tr('log.filter')}" style="max-width:200px" aria-label="${esc(tr('log.filter'))}" />
        <select id="logResult" class="field sm" style="width:auto">
          <option value="all">${tr('log.f_result_all')}</option>
          <option value="ok">${tr('log.ok')}</option>
          <option value="fail">${tr('log.fail')}</option>
        </select>
        <select id="logModule" class="field sm" style="width:auto;max-width:180px">
          <option value="">${tr('log.f_module_all')}</option>
        </select>
        <input id="logFrom" class="field sm" type="date" style="width:auto" title="${esc(tr('log.f_from'))}" aria-label="${esc(tr('log.f_from'))}" />
        <span class="mut">–</span>
        <input id="logTo" class="field sm" type="date" style="width:auto" title="${esc(tr('log.f_to'))}" aria-label="${esc(tr('log.f_to'))}" />
        <span class="sp"></span>
        <button class="btn sec sm" id="logExport">${tr('log.export')}</button>
        <button class="btn sec sm" id="logRefresh">${tr('log.refresh')}</button>
      </div>
      <div id="logBody">${loading()}</div>
      <div id="logPager" class="logpager"></div>
    </div>`;

  // Real (server-side) pagination: each page/filter change is a fresh
  // /api/logs request with an offset+limit and the active filters; the server
  // returns just that window plus the total match count and the module list.
  let page = 1;      // 1-based, current page
  let total = 0;     // matching entries across all pages (from the server)
  let pages = 1;     // ceil(total / pageSize)
  let rows = [];     // the current page's entries
  let pageSize = 12; // rows per page — fitted to the available height (min 10)
  let measured = false; // one-time row-height self-correction after first paint

  // Rows-per-page from the live height of the (flex:1) table area. The toolbar
  // and pager are flex:0 siblings, so their space is already excluded — floor to
  // whole rows, minus one for the header, never below 10.
  const fitSize = () => {
    const body = $('logBody'); if (!body) return pageSize;
    const h = body.clientHeight;
    if (h < 40) return pageSize; // not laid out yet — keep current
    return Math.max(10, Math.floor(h / LOG_ROW_H) - 1);
  };
  const measureRow = () => {
    const body = $('logBody'), trEl = body && body.querySelector('table tr');
    if (trEl) { const rh = trEl.getBoundingClientRect().height; if (rh >= 24 && rh <= 120) LOG_ROW_H = rh; }
  };

  const filterActive = () => !!((($('logFilter').value || '').trim())
    || $('logResult').value !== 'all' || $('logModule').value || $('logFrom').value || $('logTo').value);

  // Build the query string for a window, translating the UI filters into the
  // server's params (date inputs → absolute unix bounds in the display tz).
  const qsFor = (offset, limit) => {
    const p = new URLSearchParams();
    p.set('offset', offset); p.set('limit', limit);
    const res = $('logResult').value;
    if (res === 'ok' || res === 'fail') p.set('result', res);
    const mod = $('logModule').value; if (mod) p.set('module', mod);
    const ft = dn7DayBoundTs($('logFrom').value, false); if (ft != null) p.set('from_ts', ft);
    const tt = dn7DayBoundTs($('logTo').value, true); if (tt != null) p.set('to_ts', tt);
    const q = ($('logFilter').value || '').trim(); if (q) p.set('q', q);
    return p.toString();
  };

  // Module dropdown from the groups the server reports as present (unfiltered,
  // so the option set is stable). Preserve the current selection if still valid.
  const populateModules = (mods) => {
    const sel = $('logModule'), cur = sel.value;
    const sorted = (mods || []).slice().sort((a, b) => logGrpLabel(a).localeCompare(logGrpLabel(b)));
    sel.innerHTML = `<option value="">${tr('log.f_module_all')}</option>` + sorted.map((m) => `<option value="${esc(m)}">${esc(logGrpLabel(m))}</option>`).join('');
    sel.value = sorted.indexOf(cur) >= 0 ? cur : '';
  };

  const resetFilters = () => {
    $('logFilter').value = ''; $('logResult').value = 'all'; $('logModule').value = '';
    $('logFrom').value = ''; $('logTo').value = '';
    page = 1; load();
  };

  const draw = () => {
    if (!total) {
      // Filtered-to-zero gets its own message + reset, so an active filter is
      // never mistaken for an empty audit trail.
      if (filterActive()) {
        $('logBody').innerHTML = `<div class="empty">${esc(tr('log.no_match'))}<div style="margin-top:10px"><button class="btn sec sm" id="logResetF">${tr('log.clear_filters')}</button></div></div>`;
        $('logResetF').onclick = resetFilters;
      } else {
        $('logBody').innerHTML = `<div class="empty">${tr('log.none')}</div>`;
      }
      $('logPager').innerHTML = '';
      return;
    }
    $('logBody').innerHTML = `<table class="optable logtbl">
      <tr><th style="width:150px" title="${esc(tr('log.tz_note', { tz }))}">${tr('log.time')}</th><th style="width:120px">${tr('log.actor')}</th><th style="width:110px">${tr('log.col_module')}</th><th>${tr('log.action')}</th><th style="width:130px">${tr('log.col_ip')}</th><th style="width:92px">${tr('log.result')}</th><th class="act" style="width:88px">${tr('log.col_actions')}</th></tr>` +
      rows.map((e, i) => `<tr class="${e.ok ? '' : 'fail'}">
        <td class="mut mono" style="white-space:nowrap" title="${esc(logUtcIso(e.ts))}">${logFmtTime(e.ts)}</td>
        <td title="${esc(e.actor || '?')}">${esc(e.actor || '?')}</td>
        <td title="${esc(logGroup(e.action))}">${esc(logGroup(e.action))}</td>
        <td title="${esc(logOp(e.action))}">${esc(logOp(e.action))}</td>
        <td class="mono mut" style="white-space:nowrap">${esc(e.ip || '-')}</td>
        <td>${e.ok ? `<span class="chip on"><span class="dot-s on"></span>${tr('log.ok')}</span>` : `<span class="chip err"><span class="dot-s err"></span>${tr('log.fail')}</span>`}</td>
        <td class="act"><button class="btn sec sm" data-idx="${i}">${tr('log.detail_btn')}</button></td>
      </tr>`).join('') + '</table>';
    document.querySelectorAll('#logBody [data-idx]').forEach((b) => b.onclick = () => logDetail(rows[Number(b.dataset.idx)]));
    // Pager: total count + prev/next + a direct page-jump input (Enter/change).
    // Prev/Next/jump each refetch the target page from the server.
    $('logPager').innerHTML = `
      <span class="mut" style="font-size:12.5px">${esc(tr('log.total', { n: total }))}</span>
      <button class="btn sec sm" id="logPrev" ${page <= 1 ? 'disabled' : ''}>${tr('log.prev')}</button>
      <input id="logPage" class="field" type="number" min="1" max="${pages}" value="${page}" aria-label="${esc(tr('log.page_jump'))}" style="width:64px;text-align:center;padding:6px 4px" />
      <span class="mut" style="font-size:12.5px">/ ${pages}</span>
      <button class="btn sec sm" id="logNext" ${page >= pages ? 'disabled' : ''}>${tr('log.next')}</button>`;
    $('logPrev').onclick = () => { if (page > 1) { page--; load(); } };
    $('logNext').onclick = () => { if (page < pages) { page++; load(); } };
    const jump = () => {
      let p = Math.round(Number($('logPage').value));
      if (!(p >= 1)) p = 1;
      if (p > pages) p = pages;
      if (p !== page) { page = p; load(); } else $('logPage').value = page;
    };
    $('logPage').addEventListener('change', jump);
    $('logPage').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') jump(); });
  };

  const load = () => {
    $('logBody').innerHTML = loading();
    api('/api/logs?' + qsFor((page - 1) * pageSize, pageSize)).then((b) => {
      const d = b.data || {};
      rows = d.entries || [];
      total = d.total || 0;
      pages = Math.max(1, Math.ceil(total / pageSize));
      // A filter change can shrink the result past the current page — clamp and
      // refetch the last valid page (bounded: `page` only ever decreases here).
      if (page > pages) { page = pages; return load(); }
      populateModules(d.modules);
      draw();
      // First paint: measure the real row height and, if the fitting page size
      // changed from the estimate, reload once with the corrected size. (After
      // this LOG_ROW_H is accurate, so later fits — and the next visit — match.)
      if (!measured) {
        measured = true;
        measureRow();
        const want = fitSize();
        if (want !== pageSize) { pageSize = want; page = 1; return load(); }
      }
    }).catch((e) => { $('logBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; $('logPager').innerHTML = ''; });
  };

  const applyFilters = () => { page = 1; load(); };
  $('logRefresh').onclick = applyFilters;
  let searchT = null;
  $('logFilter').addEventListener('input', () => { clearTimeout(searchT); searchT = setTimeout(applyFilters, 300); });
  ['logResult', 'logModule', 'logFrom', 'logTo'].forEach((id) => $(id).addEventListener('change', applyFilters));

  $('logExport').onclick = () => {
    if (!total) { toast(tr(filterActive() ? 'log.no_match' : 'log.none'), 'warn'); return; }
    // Export the full filtered set (not just the visible page) — fetch a large
    // window with the same filters. Note it if the server cap clips the history.
    const EXPORT_CAP = 5000;
    api('/api/logs?' + qsFor(0, EXPORT_CAP)).then((b) => {
      const d = b.data || {};
      const all = d.entries || [];
      if (!all.length) { toast(tr('log.none'), 'warn'); return; }
      const note = (d.total || 0) > all.length ? tr('log.export_truncated', { n: all.length }) : '';
      modal(tr('log.export'), `
        <p class="mut" style="margin:0 0 6px;font-size:13px">${esc(tr('log.export_note', { n: all.length }))}</p>
        ${note ? `<p style="margin:0 0 6px;font-size:12.5px;color:var(--warn)">${esc(note)}</p>` : ''}
        <div class="row" style="justify-content:flex-end;gap:10px;margin-top:16px">
          <button class="btn sec" id="lxCsv">${tr('log.export_csv')}</button>
          <button class="btn" id="lxJson">${tr('log.export_json')}</button>
        </div>`, (close) => {
        $('lxCsv').onclick = () => { close(); logExportCsv(all, note); };
        $('lxJson').onclick = () => { close(); logExportJson(all, note); };
      });
    }).catch((e) => toast(e.message, 'err'));
  };

  // Re-fit the page size when the viewport changes; reload only if it changed.
  let rT = null;
  const onResize = () => { clearTimeout(rT); rT = setTimeout(() => {
    const want = fitSize();
    if (want !== pageSize) { pageSize = want; page = 1; load(); }
  }, 200); };
  window.addEventListener('resize', onResize);
  // stopTab() calls this on tab switch — drop the resize listener + timers.
  window._logsCleanup = () => { window.removeEventListener('resize', onResize); clearTimeout(rT); clearTimeout(searchT); };

  pageSize = fitSize(); // initial fit from the (empty but flex-sized) table area
  load();
}

// Detail modal: target (when present), request headers, response, and the
// recorded detail — labelled "Error" on failures, "Detail" on successes —
// each on its own tab.
function logDetail(e) {
  let resp = e.response || '';
  try { if (resp) resp = JSON.stringify(JSON.parse(resp), null, 2); } catch (_) { /* keep raw */ }
  const failed = !e.ok;
  const hasTarget = !!(e.target && String(e.target).trim());
  const hasDetail = !!(e.detail && String(e.detail).trim());
  const grp = logGroup(e.action), op = logOp(e.action);
  const actLabel = grp ? grp + ' · ' + op : op;
  const ids = [];
  const tabs = [];
  if (hasTarget) { tabs.push(`<button data-s="target" class="on">${tr('log.target')}</button>`); ids.push('target'); }
  tabs.push(`<button data-s="headers"${ids.length ? '' : ' class="on"'}>${tr('log.dt_headers')}</button>`); ids.push('headers');
  tabs.push(`<button data-s="response">${tr('log.dt_response')}</button>`); ids.push('response');
  if (failed) { tabs.push(`<button data-s="error">${tr('log.dt_error')}</button>`); ids.push('error'); }
  else if (hasDetail) { tabs.push(`<button data-s="detail">${tr('log.detail')}</button>`); ids.push('detail'); }
  const pane = (id, body, hidden) => `<pre class="out" id="ld_${id}" style="max-height:46vh;margin:0;${hidden ? 'display:none' : ''}">${esc(body || tr('log.dt_empty'))}</pre>`;
  modal(tr('log.detail_title'), `
    <div class="row" style="gap:14px;flex-wrap:wrap;margin-bottom:12px">
      <span class="mut" style="font-size:12.5px" title="${esc(logUtcIso(e.ts))}">${tr('log.time')}: ${logFmtTime(e.ts)}${dn7Tz() ? ' (' + esc(dn7Tz()) + ')' : ''}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.actor')}: ${esc(e.actor || '?')}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.col_ip')}: ${esc(e.ip || '-')}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.action')}: ${esc(actLabel)}</span>
    </div>
    <div class="subtabs" id="ldTabs">${tabs.join('')}</div>
    ${hasTarget ? pane('target', e.target || '') : ''}
    ${pane('headers', e.headers || '', hasTarget)}
    ${pane('response', resp, true)}
    ${failed ? pane('error', e.detail || '', true) : (hasDetail ? pane('detail', e.detail, true) : '')}`, (close, root) => {
    const t = root.querySelector('#ldTabs');
    t.querySelectorAll('button').forEach((btn) => btn.onclick = () => {
      t.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === btn));
      ids.forEach((s) => { const el2 = root.querySelector('#ld_' + s); if (el2) el2.style.display = (s === btn.dataset.s ? 'block' : 'none'); });
    });
  }, true);
}
