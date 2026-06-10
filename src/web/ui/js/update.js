// =========================================================================
// Self-update — version modal (manual / auto), dual-source (GitHub + dn7.cn).
// Opened from the sidebar version line; talks to /api/update/*.
// =========================================================================
const UPD = { polling: null };

// Passive check on login: light up the sidebar dot when a newer build exists.
function updateBadge() {
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    if (d.has_update && $('verLine')) $('verLine').title = '有新版本 v' + d.latest + '，点击更新';
  }).catch(() => {});
}

function openUpdate() {
  const body = `
    <div class="row" style="justify-content:space-between;align-items:center">
      <div>当前版本 <b id="uCur">…</b></div>
      <button class="btn sec sm" id="uCheck">检查更新</button>
    </div>
    <div id="uResult" style="margin-top:14px"></div>
    <div id="uProg" class="hidden" style="margin-top:14px">
      <div class="prog"><i></i></div>
      <div class="job-line" id="uProgTxt"></div>
    </div>
    <div class="card" style="margin-top:16px;background:var(--panel2)">
      <h3>更新设置</h3>
      <label class="switch"><input type="checkbox" id="uAuto"/><span class="swbox"></span><span class="swtxt"><b>自动更新</b><span>发现新版本后每分钟自动检测并更新；关闭则每小时检测，仅提示</span></span></label>
      <label class="lbl" style="margin-top:10px">下载源</label>
      <select id="uSource" class="field">
        <option value="auto">自动（测速择优，并记住最快的源）</option>
        <option value="github">GitHub</option>
        <option value="dn7">dn7.cn</option>
      </select>
    </div>`;
  modal('Panel 更新', body, (close) => {
    UPD.close = close;
    api('/api/update/config').then((b) => {
      $('uAuto').checked = !!b.data.auto;
      $('uSource').value = b.data.source_pref || 'auto';
    }).catch(() => {});
    api('/api/update/status').then((b) => { $('uCur').textContent = 'v' + b.data.current; }).catch(() => {});
    $('uCheck').onclick = runUpdCheck;
    $('uAuto').onchange = saveUpdCfg;
    $('uSource').onchange = saveUpdCfg;
    runUpdCheck();
    pollUpdStatus(); // re-attach progress if a download is already running
  });
}

function saveUpdCfg() {
  api('/api/update/config', { method: 'POST', body: JSON.stringify({ auto: $('uAuto').checked, source_pref: $('uSource').value }) })
    .then(() => toast('已保存')).catch((e) => toast(e.message, 'err'));
}

function srcLabel(name) { return name === 'dn7' ? 'dn7.cn' : 'GitHub'; }

function runUpdCheck() {
  const r = $('uResult'); if (!r) return;
  r.innerHTML = loading('正在检测两个下载源…', 2);
  api('/api/update/check', { method: 'POST' }).then((b) => {
    const d = b.data, dot = $('verDot');
    if (dot) dot.classList.toggle('hidden', !d.has_update);
    let html = '';
    if (d.has_update) {
      html += `<div class="ok" style="font-size:14px;margin-bottom:10px">发现新版本 v${esc(d.latest)}（当前 v${esc(d.current)}）</div>`;
      html += `<button class="btn" id="uApply">立即更新到 v${esc(d.latest)}</button>`;
    } else if (d.latest) {
      html += `<div class="mut" style="margin-bottom:6px">已是最新版本 v${esc(d.current)}</div>`;
    } else {
      html += `<div class="err" style="margin-bottom:6px">无法连接任何下载源，请检查网络。</div>`;
    }
    html += '<div style="margin-top:12px">' + (d.sources || []).map((s) => {
      const tag = s.ok ? `<span class="chip on">${s.kbps} KB/s</span>` : `<span class="chip warn">连接失败</span>`;
      const star = (s.name === d.source) ? ' <span style="color:var(--cy)">★ 当前源</span>' : '';
      return `<div class="row" style="justify-content:space-between;padding:6px 0;border-top:1px solid var(--line)"><span>${srcLabel(s.name)}${star}</span>${tag}</div>`;
    }).join('') + '</div>';
    r.innerHTML = html;
    if (d.has_update) $('uApply').onclick = applyUpdate;
  }).catch((e) => { r.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function applyUpdate() {
  const btn = $('uApply'); if (btn) { btn.disabled = true; btn.textContent = '开始更新…'; }
  api('/api/update/apply', { method: 'POST' }).then((b) => {
    if (b.data && b.data.started === false) toast('更新已在进行中');
    $('uProg').classList.remove('hidden');
    pollUpdStatus();
  }).catch((e) => { toast(e.message, 'err'); if (btn) { btn.disabled = false; btn.textContent = '重试'; } });
}

function pollUpdStatus() {
  if (UPD.polling) clearInterval(UPD.polling);
  UPD.polling = setInterval(() => {
    api('/api/update/status').then((b) => {
      const d = b.data, prog = $('uProg');
      if (!prog) { clearInterval(UPD.polling); return; }
      const pi = prog.querySelector('.prog > i'), txt = $('uProgTxt');
      if (d.phase === 'downloading') {
        prog.classList.remove('hidden');
        pi.style.width = d.progress + '%';
        const mb = (n) => (n / 1048576).toFixed(1);
        txt.textContent = `下载中 ${d.progress}%` + (d.total_bytes ? ` (${mb(d.done_bytes)}/${mb(d.total_bytes)} MB)` : '');
      } else if (d.phase === 'installing') {
        prog.classList.remove('hidden');
        pi.style.width = '100%';
        txt.textContent = '正在安装并重启…';
      } else if (d.phase === 'error') {
        txt.textContent = '更新失败，请稍后重试或更换下载源。';
        clearInterval(UPD.polling);
      } else if (!d.in_progress) {
        clearInterval(UPD.polling);
      }
    }).catch(() => {
      // The agent restarts after install → requests fail; that's success.
      const txt = $('uProgTxt');
      if (txt) txt.textContent = '已安装新版本，正在重启，请稍后刷新页面…';
      clearInterval(UPD.polling);
    });
  }, 1000);
}
