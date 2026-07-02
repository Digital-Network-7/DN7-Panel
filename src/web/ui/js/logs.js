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

const LOG_PAGE_SIZE = 15;
const LOG_FETCH_LIMIT = 2000; // ?limit we request — the server returns the newest N only

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
  v.innerHTML = `
    <div class="card">
      <div class="sechead" style="margin-top:0">
        <h3>${tr('tab.logs')}</h3>
        <span class="sp"></span>
        <input id="logFilter" class="field" placeholder="${tr('log.filter')}" style="max-width:220px" />
        <button class="btn sec sm" id="logExport">${tr('log.export')}</button>
        <button class="btn sec sm" id="logRefresh">${tr('log.refresh')}</button>
        <button class="btn danger sm" id="logClear">${tr('log.clear')}</button>
      </div>
      <p class="mut" style="font-size:12.5px;margin:0 0 12px">${tr('log.desc')} · ${esc(tr('log.tz_note', { tz }))}</p>
      <div class="row" style="gap:8px;flex-wrap:wrap;margin:0 0 12px">
        <select id="logResult" class="field" style="width:auto">
          <option value="all">${tr('log.f_result_all')}</option>
          <option value="ok">${tr('log.ok')}</option>
          <option value="fail">${tr('log.fail')}</option>
        </select>
        <select id="logModule" class="field" style="width:auto;max-width:190px">
          <option value="">${tr('log.f_module_all')}</option>
        </select>
        <input id="logFrom" class="field" type="date" style="width:auto" title="${esc(tr('log.f_from'))}" aria-label="${esc(tr('log.f_from'))}" />
        <span class="mut">–</span>
        <input id="logTo" class="field" type="date" style="width:auto" title="${esc(tr('log.f_to'))}" aria-label="${esc(tr('log.f_to'))}" />
      </div>
      <div id="logTrunc"></div>
      <div id="logBody">${loading()}</div>
      <div id="logPager" class="row" style="justify-content:center;gap:14px;margin-top:14px"></div>
    </div>`;
  let all = [];
  let page = 1;
  let truncated = false;

  // Cache, per entry, what the table SHOWS (localized module/action labels,
  // formatted time, OK/Failed word) alongside the raw tokens, so the free-text
  // filter matches the visible text in any language. `_d` is the calendar day
  // in the display timezone for the date-range filter. Recomputed on every
  // load (a language change re-renders the whole tab).
  const prime = () => {
    all.forEach((e) => {
      e._grp = logGrpTok(e.action);
      const t = e.ts ? dn7TsParts(e.ts) : null;
      e._d = t ? `${t.Y}-${t.M}-${t.D}` : '';
      e._q = [e.actor, e.action, logGroup(e.action), logOp(e.action), logFmtTime(e.ts),
        e.ok ? tr('log.ok') : tr('log.fail'), e.target, e.detail, e.ip]
        .map((x) => (x == null ? '' : x)).join(' ').toLowerCase();
    });
  };

  const filterActive = () => !!((($('logFilter').value || '').trim())
    || $('logResult').value !== 'all' || $('logModule').value || $('logFrom').value || $('logTo').value);

  const filtered = () => {
    const q = ($('logFilter').value || '').trim().toLowerCase();
    const res = $('logResult').value, grp = $('logModule').value;
    const from = $('logFrom').value, to = $('logTo').value;
    return all.filter((e) =>
      (!q || e._q.includes(q))
      && (res === 'all' || (res === 'ok') === !!e.ok)
      && (!grp || e._grp === grp)
      && (!from || (e._d && e._d >= from))
      && (!to || (e._d && e._d <= to)));
  };

  const resetFilters = () => {
    $('logFilter').value = ''; $('logResult').value = 'all'; $('logModule').value = '';
    $('logFrom').value = ''; $('logTo').value = '';
    page = 1; draw();
  };

  const draw = () => {
    const rows = filtered();
    const pages = Math.max(1, Math.ceil(rows.length / LOG_PAGE_SIZE));
    if (page > pages) page = pages;
    if (!rows.length) {
      // Filtered-to-zero gets its own message + reset, so an active filter is
      // never mistaken for an empty audit trail.
      if (all.length && filterActive()) {
        $('logBody').innerHTML = `<div class="empty">${esc(tr('log.no_match'))}<div style="margin-top:10px"><button class="btn sec sm" id="logResetF">${tr('log.clear_filters')}</button></div></div>`;
        $('logResetF').onclick = resetFilters;
      } else {
        $('logBody').innerHTML = `<div class="empty">${tr('log.none')}</div>`;
      }
      $('logPager').innerHTML = '';
      return;
    }
    const slice = rows.slice((page - 1) * LOG_PAGE_SIZE, page * LOG_PAGE_SIZE);
    $('logBody').innerHTML = `<div class="tablescroll" style="max-height:none"><table class="optable logtbl">
      <tr><th style="width:150px" title="${esc(tr('log.tz_note', { tz }))}">${tr('log.time')}</th><th style="width:120px">${tr('log.actor')}</th><th style="width:110px">${tr('log.col_module')}</th><th>${tr('log.action')}</th><th style="width:130px">${tr('log.col_ip')}</th><th style="width:92px">${tr('log.result')}</th><th class="act" style="width:88px">${tr('log.col_actions')}</th></tr>` +
      slice.map((e, i) => `<tr class="${e.ok ? '' : 'fail'}">
        <td class="mut mono" style="white-space:nowrap" title="${esc(logUtcIso(e.ts))}">${logFmtTime(e.ts)}</td>
        <td title="${esc(e.actor || '?')}">${esc(e.actor || '?')}</td>
        <td title="${esc(logGroup(e.action))}">${esc(logGroup(e.action))}</td>
        <td title="${esc(logOp(e.action))}">${esc(logOp(e.action))}</td>
        <td class="mono mut" style="white-space:nowrap">${esc(e.ip || '-')}</td>
        <td>${e.ok ? `<span class="chip on"><span class="dot-s on"></span>${tr('log.ok')}</span>` : `<span class="chip err"><span class="dot-s err"></span>${tr('log.fail')}</span>`}</td>
        <td class="act"><button class="btn sec sm" data-idx="${(page - 1) * LOG_PAGE_SIZE + i}">${tr('log.detail_btn')}</button></td>
      </tr>`).join('') + '</table></div>';
    document.querySelectorAll('#logBody [data-idx]').forEach((b) => b.onclick = () => logDetail(rows[Number(b.dataset.idx)]));
    // Pager: prev/next + a direct page-jump input (Enter or change).
    $('logPager').innerHTML = `
      <button class="btn sec sm" id="logPrev" ${page <= 1 ? 'disabled' : ''}>${tr('log.prev')}</button>
      <input id="logPage" class="field" type="number" min="1" max="${pages}" value="${page}" aria-label="${esc(tr('log.page_jump'))}" style="width:64px;text-align:center;padding:6px 4px" />
      <span class="mut" style="font-size:12.5px">/ ${pages}</span>
      <button class="btn sec sm" id="logNext" ${page >= pages ? 'disabled' : ''}>${tr('log.next')}</button>`;
    $('logPrev').onclick = () => { if (page > 1) { page--; draw(); } };
    $('logNext').onclick = () => { if (page < pages) { page++; draw(); } };
    const jump = () => {
      let p = Math.round(Number($('logPage').value));
      if (!(p >= 1)) p = 1;
      if (p > pages) p = pages;
      if (p !== page) { page = p; draw(); } else $('logPage').value = page;
    };
    $('logPage').addEventListener('change', jump);
    $('logPage').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') jump(); });
  };

  const load = () => {
    $('logBody').innerHTML = loading();
    api('/api/logs?limit=' + LOG_FETCH_LIMIT).then((b) => {
      all = (b.data && b.data.entries) || [];
      truncated = all.length >= LOG_FETCH_LIMIT;
      prime();
      // Module filter options from the groups actually present in the data.
      const sel = $('logModule'), cur = sel.value;
      const mods = Array.from(new Set(all.map((e) => e._grp).filter(Boolean)))
        .sort((a, b2) => logGrpLabel(a).localeCompare(logGrpLabel(b2)));
      sel.innerHTML = `<option value="">${tr('log.f_module_all')}</option>` + mods.map((m) => `<option value="${esc(m)}">${esc(logGrpLabel(m))}</option>`).join('');
      if (mods.indexOf(cur) >= 0) sel.value = cur;
      $('logTrunc').innerHTML = truncated ? `<div class="log-trunc">${esc(tr('log.truncated', { n: all.length }))}</div>` : '';
      page = 1; draw();
    }).catch((e) => { $('logBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  };
  $('logRefresh').onclick = load;
  $('logFilter').addEventListener('input', () => { page = 1; draw(); });
  ['logResult', 'logModule', 'logFrom', 'logTo'].forEach((id) => $(id).addEventListener('change', () => { page = 1; draw(); }));
  $('logExport').onclick = () => {
    const rows = filtered();
    if (!rows.length) { toast(tr(all.length ? 'log.no_match' : 'log.none'), 'warn'); return; }
    const note = truncated ? tr('log.export_truncated', { n: all.length }) : '';
    modal(tr('log.export'), `
      <p class="mut" style="margin:0 0 6px;font-size:13px">${esc(tr('log.export_note', { n: rows.length }))}</p>
      ${note ? `<p style="margin:0 0 6px;font-size:12.5px;color:var(--warn)">${esc(note)}</p>` : ''}
      <div class="row" style="justify-content:flex-end;gap:10px;margin-top:16px">
        <button class="btn sec" id="lxCsv">${tr('log.export_csv')}</button>
        <button class="btn" id="lxJson">${tr('log.export_json')}</button>
      </div>`, (close) => {
      $('lxCsv').onclick = () => { close(); logExportCsv(rows, note); };
      $('lxJson').onclick = () => { close(); logExportJson(rows, note); };
    });
  };
  $('logClear').onclick = async () => {
    const n = truncated ? all.length + '+' : String(all.length);
    if (!await confirmDanger(tr('log.clear_confirm_n', { n }))) return;
    // Erasing the trail is the canonical post-compromise move — require a
    // fresh step-up token, like update-apply and settings changes do.
    const tok = await stepUp(tr('stepup.msg_logs'));
    if (!tok) return;
    api('/api/logs/clear', { method: 'POST', headers: { 'X-DN7-Stepup': tok } })
      .then(() => { toast(tr('common.deleted'), 'ok'); load(); })
      .catch((e) => toast(e.message, 'err'));
  };
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
