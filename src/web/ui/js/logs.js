// =========================================================================
// Audit log (Owner only) — privileged-action history from /api/logs
// =========================================================================

// An action key is "<group>.<op>" (e.g. "nginx.add_site", "auth.login"). The
// table shows the group and the op in two separate columns:
//
//   logGroup(action) → the module/category label  ("Website", "Auth", …)
//   logOp(action)    → the operation label        ("Add site", "Sign in", …)
//
// Each tries the most specific i18n key and degrades to the raw token so a new
// backend op still renders readably.

function logGroup(action) {
  const dot = action.indexOf('.');
  if (dot <= 0) return '';
  const grp = action.slice(0, dot);
  const gk = 'log.grp.' + grp, gl = tr(gk);
  return gl !== gk ? gl : grp;
}

function logOp(action) {
  // Prefer a full per-action phrase ("Sign in"), then a channel-agnostic op
  // label ("Add site"), then the raw op / action token.
  const full = 'log.act.' + action;
  const tf = tr(full);
  if (tf !== full) return tf;
  const dot = action.indexOf('.');
  const op = dot > 0 ? action.slice(dot + 1) : action;
  const ok = 'log.op.' + op, ol = tr(ok);
  return ol !== ok ? ol : op;
}

function logFmtTime(ts) {
  const d = new Date((Number(ts) || 0) * 1000);
  if (!ts) return '-';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const LOG_PAGE_SIZE = 15;

function renderLogs(v) {
  v.innerHTML = `
    <div class="card">
      <div class="sechead" style="margin-top:0">
        <h3>${tr('tab.logs')}</h3>
        <span class="sp"></span>
        <input id="logFilter" class="field" placeholder="${tr('log.filter')}" style="max-width:220px;margin-right:8px" />
        <button class="btn sec sm" id="logRefresh">${tr('log.refresh')}</button>
        <button class="btn danger sm" id="logClear" style="margin-left:8px">${tr('log.clear')}</button>
      </div>
      <p class="mut" style="font-size:12.5px;margin:0 0 14px">${tr('log.desc')}</p>
      <div id="logBody">${loading()}</div>
      <div id="logPager" class="row" style="justify-content:center;gap:14px;margin-top:14px"></div>
    </div>`;
  let all = [];
  let page = 1;

  const filtered = () => {
    const q = ($('logFilter').value || '').trim().toLowerCase();
    return q
      ? all.filter((e) => (e.actor + ' ' + e.action + ' ' + e.target + ' ' + (e.detail || '') + ' ' + (e.ip || '')).toLowerCase().includes(q))
      : all;
  };

  const draw = () => {
    const rows = filtered();
    const pages = Math.max(1, Math.ceil(rows.length / LOG_PAGE_SIZE));
    if (page > pages) page = pages;
    if (!rows.length) { $('logBody').innerHTML = `<div class="empty">${tr('log.none')}</div>`; $('logPager').innerHTML = ''; return; }
    const slice = rows.slice((page - 1) * LOG_PAGE_SIZE, page * LOG_PAGE_SIZE);
    $('logBody').innerHTML = `<div class="tablescroll" style="max-height:none"><table class="optable logtbl">
      <tr><th style="width:150px">${tr('log.time')}</th><th style="width:120px">${tr('log.actor')}</th><th style="width:110px">${tr('log.col_module')}</th><th>${tr('log.action')}</th><th style="width:130px">${tr('log.col_ip')}</th><th style="width:92px">${tr('log.result')}</th><th class="act" style="width:88px">${tr('log.col_actions')}</th></tr>` +
      slice.map((e, i) => `<tr>
        <td class="mut mono" style="white-space:nowrap">${logFmtTime(e.ts)}</td>
        <td title="${esc(e.actor || '?')}">${esc(e.actor || '?')}</td>
        <td title="${esc(logGroup(e.action))}">${esc(logGroup(e.action))}</td>
        <td title="${esc(logOp(e.action))}">${esc(logOp(e.action))}</td>
        <td class="mono mut" style="white-space:nowrap">${esc(e.ip || '-')}</td>
        <td>${e.ok ? `<span class="chip on"><span class="dot-s on"></span>${tr('log.ok')}</span>` : `<span class="chip warn"><span class="dot-s"></span>${tr('log.fail')}</span>`}</td>
        <td class="act"><button class="btn sec sm" data-idx="${(page - 1) * LOG_PAGE_SIZE + i}">${tr('log.detail_btn')}</button></td>
      </tr>`).join('') + '</table></div>';
    document.querySelectorAll('#logBody [data-idx]').forEach((b) => b.onclick = () => logDetail(rows[Number(b.dataset.idx)]));
    // Pager.
    $('logPager').innerHTML = `
      <button class="btn sec sm" id="logPrev" ${page <= 1 ? 'disabled' : ''}>${tr('log.prev')}</button>
      <span class="mut" style="font-size:12.5px">${tr('log.page_info', { cur: page, total: pages })}</span>
      <button class="btn sec sm" id="logNext" ${page >= pages ? 'disabled' : ''}>${tr('log.next')}</button>`;
    $('logPrev').onclick = () => { if (page > 1) { page--; draw(); } };
    $('logNext').onclick = () => { if (page < pages) { page++; draw(); } };
  };

  const load = () => {
    $('logBody').innerHTML = loading();
    api('/api/logs?limit=2000').then((b) => { all = (b.data && b.data.entries) || []; page = 1; draw(); }).catch((e) => { $('logBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  };
  $('logRefresh').onclick = load;
  $('logFilter').addEventListener('input', () => { page = 1; draw(); });
  $('logClear').onclick = async () => {
    if (!await confirmDanger(tr('log.clear_confirm'))) return;
    api('/api/logs/clear', { method: 'POST' }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
  };
  load();
}

// Detail modal: target (when present), request headers, response, and (for
// failures) the error — each on its own tab.
function logDetail(e) {
  let resp = e.response || '';
  try { if (resp) resp = JSON.stringify(JSON.parse(resp), null, 2); } catch (_) { /* keep raw */ }
  const failed = !e.ok;
  const hasTarget = !!(e.target && String(e.target).trim());
  const grp = logGroup(e.action), op = logOp(e.action);
  const actLabel = grp ? grp + ' · ' + op : op;
  const ids = [];
  const tabs = [];
  if (hasTarget) { tabs.push(`<button data-s="target" class="on">${tr('log.target')}</button>`); ids.push('target'); }
  tabs.push(`<button data-s="headers"${ids.length ? '' : ' class="on"'}>${tr('log.dt_headers')}</button>`); ids.push('headers');
  tabs.push(`<button data-s="response">${tr('log.dt_response')}</button>`); ids.push('response');
  if (failed) { tabs.push(`<button data-s="error">${tr('log.dt_error')}</button>`); ids.push('error'); }
  const pane = (id, body, hidden) => `<pre class="out" id="ld_${id}" style="max-height:46vh;margin:0;${hidden ? 'display:none' : ''}">${esc(body || tr('log.dt_empty'))}</pre>`;
  modal(tr('log.detail_title'), `
    <div class="row" style="gap:14px;flex-wrap:wrap;margin-bottom:12px">
      <span class="mut" style="font-size:12.5px">${tr('log.time')}: ${logFmtTime(e.ts)}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.actor')}: ${esc(e.actor || '?')}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.col_ip')}: ${esc(e.ip || '-')}</span>
      <span class="mut" style="font-size:12.5px">${tr('log.action')}: ${esc(actLabel)}</span>
    </div>
    <div class="subtabs" id="ldTabs">${tabs.join('')}</div>
    ${hasTarget ? pane('target', e.target || '') : ''}
    ${pane('headers', e.headers || '', hasTarget)}
    ${pane('response', resp, true)}
    ${failed ? pane('error', e.detail || '', true) : ''}`, (close, root) => {
    const t = root.querySelector('#ldTabs');
    t.querySelectorAll('button').forEach((btn) => btn.onclick = () => {
      t.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === btn));
      ids.forEach((s) => { const el2 = root.querySelector('#ld_' + s); if (el2) el2.style.display = (s === btn.dataset.s ? 'block' : 'none'); });
    });
  }, true);
}
