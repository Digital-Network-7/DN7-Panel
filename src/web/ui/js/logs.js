// =========================================================================
// Audit log (Owner only) — privileged-action history from /api/logs
// =========================================================================

// Map a stable action key (e.g. "mysql.install", "auth.login") to a label.
// Channel prefixes get a friendly group name; the op part is shown verbatim
// when it has no dedicated translation, so new backend ops still render.
function logActionLabel(action) {
  const k = 'log.act.' + action;
  const t = tr(k);
  if (t !== k) return t;
  const dot = action.indexOf('.');
  if (dot > 0) {
    const grp = action.slice(0, dot), op = action.slice(dot + 1);
    const gk = 'log.grp.' + grp, gl = tr(gk);
    return (gl !== gk ? gl : grp) + ' · ' + op;
  }
  return action;
}

function logFmtTime(ts) {
  const d = new Date((Number(ts) || 0) * 1000);
  if (!ts) return '-';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

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
    </div>`;
  let all = [];
  const draw = () => {
    const q = ($('logFilter').value || '').trim().toLowerCase();
    const rows = q
      ? all.filter((e) => (e.actor + ' ' + e.action + ' ' + e.target + ' ' + (e.detail || '') + ' ' + (e.ip || '')).toLowerCase().includes(q))
      : all;
    if (!rows.length) { $('logBody').innerHTML = `<div class="empty">${tr('log.none')}</div>`; return; }
    $('logBody').innerHTML = `<div class="tablescroll" style="max-height:none"><table class="optable logtbl">
      <tr><th style="width:150px">${tr('log.time')}</th><th>${tr('log.actor')}</th><th>${tr('log.action')}</th><th>${tr('log.target')}</th><th>${tr('log.result')}</th><th>${tr('log.detail')}</th></tr>` +
      rows.map((e) => `<tr>
        <td class="mut mono" style="white-space:nowrap">${logFmtTime(e.ts)}</td>
        <td>${esc(e.actor || '?')}${e.ip ? ` <span class="mut" style="font-size:11px">${esc(e.ip)}</span>` : ''}</td>
        <td>${esc(logActionLabel(e.action))}</td>
        <td class="mono">${esc(e.target || '')}</td>
        <td>${e.ok ? `<span class="chip on"><span class="dot-s on"></span>${tr('log.ok')}</span>` : `<span class="chip warn"><span class="dot-s init"></span>${tr('log.fail')}</span>`}</td>
        <td class="mut" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.detail || '')}">${esc(e.detail || '')}</td>
      </tr>`).join('') + '</table></div>';
  };
  const load = () => {
    $('logBody').innerHTML = loading();
    api('/api/logs?limit=500').then((b) => { all = (b.data && b.data.entries) || []; draw(); }).catch((e) => { $('logBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  };
  $('logRefresh').onclick = load;
  $('logFilter').addEventListener('input', draw);
  $('logClear').onclick = async () => {
    if (!await confirmDanger(tr('log.clear_confirm'))) return;
    api('/api/logs/clear', { method: 'POST' }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
  };
  load();
}
