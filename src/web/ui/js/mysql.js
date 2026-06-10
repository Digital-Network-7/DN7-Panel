// =========================================================================
// MySQL management (DN7 Panel-provisioned instances only)
// =========================================================================
function renderMysql(v) {
  v.innerHTML = `<div style="padding:8px">${loading('正在检测环境')}</div>`;
  if (getJob('mysql:install')) {
    v.innerHTML = `<div class="card"><h3>正在创建数据库</h3><div id="myInstallJob"></div></div>`;
    reattachJob($('myInstallJob'), 'mysql:install', { onDone: () => setTimeout(() => renderMysql(v), 800) });
    return;
  }
  op('mysql', { op: 'info' }).then((info) => {
    if (info && info.docker_ok === false) {
      v.innerHTML = '<div class="card"><h3>MySQL</h3><p class="mut">需要先安装并启动 Docker（在 Docker 管理中安装）。数据库由 DN7 Panel 通过容器管理。</p></div>';
      return;
    }
    op('mysql', { op: 'list' }).then((d) => {
      const arr = d.instances || [];
      const m = arr[0];
      if (!m) {
        v.innerHTML = `<div class="card"><h3>MySQL / MariaDB</h3><p class="mut">尚未创建数据库。一台主机由 DN7 Panel 托管一个实例，可在其中创建多个库。</p><button class="btn" id="myNew">创建数据库</button></div>`;
        $('myNew').onclick = () => myInstall(() => renderMysql(v));
        return;
      }
      // Single-instance layout: a header card with status + lifecycle actions,
      // then the management panel (databases / accounts / SQL / settings) inline.
      const running = m.running;
      const phase = m.phase === 'initializing' ? '初始化中' : (running ? '运行中' : '已停止');
      const cls = m.phase === 'initializing' ? 'warn' : (running ? 'on' : 'off');
      v.innerHTML = `
        <div class="card" style="margin-bottom:16px">
          <div class="row" style="align-items:center">
            <div style="flex:1">
              <div style="font-size:18px;font-weight:650">${esc(m.engine)} <span class="mut" style="font-size:14px;font-weight:400">${esc(m.version || '')}</span></div>
              <div class="mut" style="font-size:12.5px;margin-top:3px">端口 ${m.port ? m.port : '未映射'} · <span class="chip ${cls}"><span class="dot-s ${running ? 'on' : ''}"></span>${phase}</span></div>
            </div>
            <div class="actions" id="myLifecycle"></div>
          </div>
        </div>
        <div id="myPanel"></div>`;
      const reload = () => renderMysql(v);
      const lc = $('myLifecycle');
      const mk = (label, klass, fn) => { const b = el('button', { class: 'btn sm ' + (klass || 'sec') }, label); b.onclick = fn; lc.appendChild(b); };
      if (running) {
        mk('停止', 'sec', () => op('mysql', { op: 'stop', inst: m.id }).then(() => { toast('已停止', 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
        mk('重启', 'sec', () => op('mysql', { op: 'restart', inst: m.id }).then(() => { toast('已重启', 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
      } else {
        mk('启动', '', () => op('mysql', { op: 'start', inst: m.id }).then(() => { toast('已启动', 'ok'); reload(); }).catch((e) => toast(e.message, 'err')));
      }
      mk('删除', 'danger', async () => { const keep = await confirmKeepData(); if (keep === null) return; op('mysql', { op: 'remove', inst: m.id, keep_data: keep }).then(() => { toast('已删除', 'ok'); reload(); }).catch((e) => toast(e.message, 'err')); });
      // Management panel — only meaningful when the instance can serve queries.
      if (running) myPanel($('myPanel'), m.id, reload);
      else $('myPanel').innerHTML = '<div class="empty">实例未运行，启动后可管理数据库与账号</div>';
    }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}
function confirmKeepData() { return new Promise((res) => { modal('删除数据库', '<p style="margin:0 0 16px">删除将移除数据库容器。是否保留数据卷（其中的所有库和数据）？</p><div class="row" style="justify-content:flex-end"><button class="btn sec" id="kdCancel">取消</button><button class="btn sec" id="kdKeep">保留数据</button><button class="btn danger" id="kdDrop">连同数据删除</button></div>', (close) => { $('kdCancel').onclick = () => { close(); res(null); }; $('kdKeep').onclick = () => { close(); res(true); }; $('kdDrop').onclick = () => { close(); res(false); }; }); }); }

function myInstall(reload) {
  // Engine+version merged into one picker; default MariaDB 11.4.
  const OPTS = [
    { v: 'mariadb|11.4', label: 'MariaDB 11.4' },
    { v: 'mariadb|10.11', label: 'MariaDB 10.11' },
    { v: 'mariadb|10.6', label: 'MariaDB 10.6' },
    { v: 'mysql|8.4', label: 'MySQL 8.4' },
    { v: 'mysql|8.0', label: 'MySQL 8.0' },
    { v: 'mysql|5.7', label: 'MySQL 5.7' },
  ];
  modal('创建数据库', `
    <div class="formgrid">
      <div><label class="lbl">引擎 / 版本</label><select id="miEv" class="field">${OPTS.map((o) => `<option value="${o.v}"${o.v === 'mariadb|11.4' ? ' selected' : ''}>${o.label}</option>`).join('')}</select></div>
      <div><label class="lbl">对外端口（映射 3306）</label><input id="miPort" class="field" type="number" placeholder="3306" /></div>
      <div style="display:flex;align-items:flex-end"><label style="display:flex;gap:7px;align-items:center"><input type="checkbox" id="miExpose" checked /> 对外映射端口</label></div>
    </div>
    <p class="mut" style="font-size:12px;margin-top:10px">root 密码将自动生成，可在「管理」中查看。创建后可在实例中建立多个数据库。</p>
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="miGo">创建</button></div>
    <div class="hidden" id="miJob" style="margin-top:14px"></div>`, (close) => {
    $('miExpose').onchange = () => { $('miPort').disabled = !$('miExpose').checked; };
    $('miGo').onclick = () => {
      const [engine, version] = $('miEv').value.split('|');
      const body = { op: 'install', engine, version, expose: $('miExpose').checked };
      if (body.expose && $('miPort').value) body.port = Number($('miPort').value);
      $('miGo').disabled = true; $('miJob').classList.remove('hidden');
      op('mysql', body).then((r) => renderJob($('miJob'), 'mysql', r.op_id, 'mysql:install', { onDone: () => { toast('数据库已创建', 'ok'); close(); reload(); }, onError: () => { $('miGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('miGo').disabled = false; });
    };
  });
}

function myPanel(host, id, reload) {
  host.innerHTML = `
    <div class="subtabs" id="myTabs"><button data-t="info" class="on">数据库</button><button data-t="users">账号</button><button data-t="more">设置</button></div>
    <div id="myMBody"></div>`;
  const tabs = host.querySelector('#myTabs');
  const sel = (t) => { tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); if (t === 'info') myInfo(id); else if (t === 'users') myUsers(id); else myMore(id, () => {}, reload); };
  tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
  sel('info');
}
function myInfo(id) {
  const b = $('myMBody'); b.innerHTML = loading();
  op('mysql', { op: 'credentials', inst: id }).then((c) => {
    b.innerHTML = `<table>
      <tr><th style="width:120px">主机</th><td class="mono">${esc(c.host || '127.0.0.1')}</td></tr>
      <tr><th>端口</th><td class="mono">${esc(String(c.port || ''))}</td></tr>
      <tr><th>用户</th><td class="mono">${esc(c.user || 'root')}</td></tr>
      <tr><th>密码</th><td class="mono">${esc(c.password || '')}</td></tr>
    </table>
    <div class="sechead" style="margin-top:18px"><h3>数据库</h3><span class="sp"></span><button class="btn sm" id="myAddDb">新建数据库</button></div><div id="myDbs">${loading()}</div>`;
    $('myAddDb').onclick = () => modal('新建数据库', `<label class="lbl">库名</label><input id="cdbName" class="field" placeholder="myapp" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="cdbGo">创建</button></div>`, (close) => { $('cdbGo').onclick = () => { const name = $('cdbName').value.trim(); if (!name) return; op('mysql', { op: 'create_database', inst: id, database: name }).then(() => { close(); toast('已创建', 'ok'); myInfo(id); }).catch((e) => toast(e.message, 'err')); }; });
    loadMyDbs(id);
  }).catch((e) => { b.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
function loadMyDbs(id) {
  op('mysql', { op: 'databases', inst: id }).then((d) => {
    const arr = d.databases || [];
    if (!arr.length) { $('myDbs').innerHTML = '<div class="empty">无</div>'; return; }
    $('myDbs').innerHTML = '<table class="optable"><tr><th>库名</th><th>表数</th><th>大小</th><th class="act">操作</th></tr>' + arr.map((x) => `<tr><td>${esc(x.name)}${x.system ? ' <span class="mut" style="font-size:11px">系统</span>' : ''}</td><td>${x.tables != null ? x.tables : '-'}</td><td class="mut">${x.bytes != null ? fmtBytes(x.bytes) : '-'}</td><td class="act">${x.system ? '' : `<button class="btn sm danger" data-db="${esc(x.name)}">删除</button>`}</td></tr>`).join('') + '</table>';
    document.querySelectorAll('#myDbs [data-db]').forEach((btn) => btn.onclick = async () => { if (await confirmDanger(`删除数据库 ${btn.dataset.db}？此操作会清空其中所有数据。`)) op('mysql', { op: 'drop_database', inst: id, database: btn.dataset.db }).then(() => { toast('已删除', 'ok'); loadMyDbs(id); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('myDbs').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
function myUsers(id) {
  const b = $('myMBody'); b.innerHTML = '<div class="sechead"><h3>账号</h3><span class="sp"></span><button class="btn sm" id="myAddU">新建账号</button></div><div id="myUList">' + loading() + '</div>';
  $('myAddU').onclick = () => modal('新建账号', `<div class="formgrid"><div><label class="lbl">用户名</label><input id="auU" class="field" /></div><div><label class="lbl">来源主机</label><input id="auH" class="field" value="%" /></div><div class="full"><label class="lbl">密码</label><input id="auP" class="field" /></div></div><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="auGo">创建</button></div>`, (close) => { $('auGo').onclick = () => op('mysql', { op: 'create_user', inst: id, username: $('auU').value.trim(), host: $('auH').value.trim() || '%', password: $('auP').value }).then(() => { close(); toast('已创建', 'ok'); myUsers(id); }).catch((e) => toast(e.message, 'err')); });
  op('mysql', { op: 'list_users', inst: id }).then((d) => {
    const users = d.users || [];
    if (!users.length) { $('myUList').innerHTML = '<div class="empty">无</div>'; return; }
    $('myUList').innerHTML = '<table><tr><th>用户</th><th>主机</th><th style="width:1%">操作</th></tr>' + users.map((u) => `<tr><td>${esc(u.user)}</td><td class="mut">${esc(u.host)}</td><td>${u.system ? '<span class="mut" style="font-size:12px">系统</span>' : `<button class="btn sm danger" data-u="${esc(u.user)}" data-h="${esc(u.host)}">删除</button>`}</td></tr>`).join('') + '</table>';
    document.querySelectorAll('#myUList [data-u]').forEach((btn) => btn.onclick = async () => { if (await confirmDanger(`删除账号 ${btn.dataset.u}@${btn.dataset.h}？`)) op('mysql', { op: 'drop_user', inst: id, username: btn.dataset.u, host: btn.dataset.h }).then(() => { toast('已删除', 'ok'); myUsers(id); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('myUList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
function myQuery() { /* SQL runner removed per product decision. */ }
function myMore(id, close, reload) {
  const b = $('myMBody');
  b.innerHTML = `
    <div class="sechead"><h3>重置 root 密码</h3></div><div class="row"><button class="btn sec sm" id="myReset">重置并显示新密码</button></div>
    <div class="sechead" style="margin-top:18px"><h3>端口映射</h3></div><div class="row"><input id="myPort" class="field" type="number" placeholder="3306" style="max-width:160px" /><label style="display:flex;gap:7px;align-items:center"><input type="checkbox" id="myExpose" checked /> 对外映射</label><button class="btn sec sm" id="myPortGo">应用（重建容器）</button></div>
    <div class="sechead" style="margin-top:18px"><h3>备份</h3></div><div class="row"><button class="btn sec sm" id="myBackup">导出 mysqldump</button></div>
    <div id="myMoreLine" class="ok" style="margin-top:10px"></div>
    <div class="hidden" id="myBackupJob" style="margin-top:12px"></div>`;
  $('myReset').onclick = () => op('mysql', { op: 'reset_password', inst: id }).then((r) => { $('myMoreLine').textContent = '新 root 密码：' + (r.password || ''); }).catch((e) => toast(e.message, 'err'));
  $('myPortGo').onclick = () => { const body = { op: 'change_port', inst: id, expose: $('myExpose').checked }; if (body.expose && $('myPort').value) body.port = Number($('myPort').value); op('mysql', body).then(() => { toast('已应用', 'ok'); reload(); }).catch((e) => toast(e.message, 'err')); };
  $('myBackup').onclick = () => { $('myBackup').disabled = true; $('myBackupJob').classList.remove('hidden'); op('mysql', { op: 'backup', inst: id }).then((r) => renderJob($('myBackupJob'), 'mysql', r.op_id, '', { onDone: () => { toast('备份完成', 'ok'); $('myBackup').disabled = false; }, onError: () => { $('myBackup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('myBackup').disabled = false; }); };
}
