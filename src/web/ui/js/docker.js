// =========================================================================
// Docker management
// =========================================================================
function renderDocker(v) {
  v.innerHTML = `<div style="padding:8px">${loading('正在检测 Docker')}</div>`;
  // If an install job is still running (user left + came back), re-attach.
  if (getJob('docker:install')) {
    v.innerHTML = `<div class="card"><h3>正在安装 Docker</h3><div id="dkInstallJob"></div></div>`;
    reattachJob($('dkInstallJob'), 'docker:install', { onDone: () => setTimeout(() => renderDocker(v), 800) });
    return;
  }
  op('docker', { op: 'info' }).then((info) => {
    if (!info.installed) {
      v.innerHTML = `<div class="card" style="max-width:520px"><h3>Docker</h3><p class="mut">本机未检测到 Docker 守护进程。</p>
        <label class="lbl">安装方式</label>
        <select id="dkChannel" class="field" style="margin-bottom:10px">
          <option value="distro">系统自带 docker.io（推荐，最稳，走系统镜像）</option>
          <option value="ce">官方最新 docker-ce</option>
        </select>
        <label class="lbl">网络 / 地区</label>
        <select id="dkRegion" class="field" style="margin-bottom:14px">
          <option value="auto">自动检测</option>
          <option value="cn">国内（镜像加速）</option>
          <option value="global">海外（官方源）</option>
        </select>
        <button class="btn" id="dkInstall">一键安装 Docker</button>
        <div id="dkInstallJob" class="hidden" style="margin-top:14px"></div></div>`;
      $('dkInstall').onclick = () => {
        $('dkInstall').disabled = true; $('dkInstallJob').classList.remove('hidden');
        const body = { op: 'install', channel: $('dkChannel').value, region: $('dkRegion').value };
        op('docker', body).then((r) => renderJob($('dkInstallJob'), 'docker', r.op_id, 'docker:install', { onDone: () => setTimeout(() => renderDocker(v), 800), onError: () => { $('dkInstall').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('dkInstall').disabled = false; });
      };
      return;
    }
    v.innerHTML = `
      <div class="subtabs" id="dkTabs">
        <button data-t="containers" class="on">容器</button>
        <button data-t="images">镜像</button>
        <button data-t="networks">网络</button>
      </div>
      <div class="row" style="margin-bottom:14px"><span class="chip">Docker ${esc(info.server_version || '')}</span><span class="chip">API ${esc(info.client_version || '')}</span><span class="sp" style="flex:1"></span></div>
      <div id="dkBody"></div>`;
    const tabs = $('dkTabs');
    const sel = (t) => { tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); if (t === 'containers') dkContainers(); else if (t === 'images') dkImages(info); else dkNetworks(); };
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
    sel('containers');
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}

function dkContainers() {
  const body = $('dkBody');
  body.innerHTML = '<div class="sechead"><h3>容器</h3><span class="sp"></span><button class="btn sm" id="dkNew">创建容器</button><button class="btn sec sm" id="dkRefC">刷新</button></div><div id="dkCList">' + loading() + '</div>';
  $('dkRefC').onclick = dkContainers;
  $('dkNew').onclick = dkCreateForm;
  op('docker', { op: 'list_containers' }).then((d) => {
    const list = d.containers || [];
    if (!list.length) { $('dkCList').innerHTML = '<div class="empty">暂无容器</div>'; return; }
    let h = '<table class="optable"><tr><th>名称</th><th>镜像</th><th>状态</th><th>端口</th><th class="act">操作</th></tr>';
    list.forEach((c) => {
      const running = c.state === 'running';
      h += `<tr>
        <td><b>${esc(c.name)}</b><div class="mut mono" style="font-size:11px">${esc(c.id)}</div></td>
        <td class="mono" style="font-size:12px">${esc(c.image)}</td>
        <td><span class="chip ${running ? 'on' : 'off'}"><span class="dot-s ${running ? 'on' : ''}"></span>${esc(c.status || c.state)}</span></td>
        <td class="mono" style="font-size:11.5px">${esc(c.ports || '-')}</td>
        <td class="act"><div class="actions" data-id="${esc(c.id)}" data-name="${esc(c.name)}" data-shell="${c.has_shell ? 1 : 0}" data-running="${running ? 1 : 0}" data-managed="${c.managed ? 1 : 0}"></div></td>
      </tr>`;
    });
    $('dkCList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkCList .actions').forEach((a) => buildContainerActions(a, dkContainers));
  }).catch((e) => { $('dkCList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function buildContainerActions(holder, reload) {
  const id = holder.dataset.id, name = holder.dataset.name, hasShell = holder.dataset.shell === '1', running = holder.dataset.running === '1';
  const managed = holder.dataset.managed === '1';
  // DN7 Panel-managed service containers (nginx / mysql) are operated only from
  // their own pages — show a plain "内置" tag, no action buttons.
  if (managed) { holder.innerHTML = '<span class="chip">内置</span>'; return; }
  const mk = (label, cls, fn) => { const b = el('button', { class: 'btn sm ' + (cls || 'sec') }, label); b.onclick = fn; holder.appendChild(b); };
  if (running) {
    mk('停止', 'sec', () => doCAction('stop_container', id, reload));
    mk('重启', 'sec', () => doCAction('restart_container', id, reload));
    if (hasShell) mk('终端', '', () => ticket().then((t) => openTerminalModal('容器终端 · ' + name, `/api/container/terminal?ticket=${encodeURIComponent(t)}&container=${encodeURIComponent(id)}`)).catch((e) => toast(e.message, 'err')));
    mk('文件', 'sec', () => openFileBrowser('容器文件 · ' + name, id));
  } else {
    mk('启动', '', () => doCAction('start_container', id, reload));
  }
  mk('日志', 'sec', () => dkLogs(id, name));
  mk('网络', 'sec', () => dkContainerNetworks(id, name));
  mk('删除', 'danger', async () => { if (await confirmDanger(`删除容器 ${name}？`)) doCAction('remove_container', id, reload); });
}
function doCAction(o, id, reload) { op('docker', { op: o, ref: id }).then(() => { toast('操作成功', 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); }

function dkLogs(id, name) {
  modal('日志 · ' + name, '<div id="dkLogWrap">' + loading() + '</div>', () => {
    op('docker', { op: 'logs', ref: id, tail: 400 }).then((d) => { $('dkLogWrap').innerHTML = '<pre class="out" id="dkLogOut" style="max-height:64vh"></pre>'; $('dkLogOut').textContent = d.logs || '(空)'; $('dkLogOut').scrollTop = $('dkLogOut').scrollHeight; }).catch((e) => { $('dkLogWrap').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

function dkContainerNetworks(id, name) {
  modal('网络 · ' + name, '<div id="cnBody">' + loading() + '</div>', () => {
    const load = () => op('docker', { op: 'inspect_container_networks', ref: id }).then((d) => {
      let h = '<h3 style="font-size:13px;margin:0 0 8px">已连接</h3>';
      h += (d.attached || []).map((n) => `<div class="row" style="margin-bottom:6px"><span class="chip on">${esc(n)}</span><button class="btn sm sec" data-dis="${esc(n)}">断开</button></div>`).join('') || '<div class="mut" style="margin-bottom:10px">无</div>';
      h += '<h3 style="font-size:13px;margin:14px 0 8px">可连接</h3>';
      h += (d.available || []).map((n) => `<div class="row" style="margin-bottom:6px"><span class="chip">${esc(n.name)}</span><button class="btn sm" data-con="${esc(n.name)}">连接</button></div>`).join('') || '<div class="mut">无</div>';
      $('cnBody').innerHTML = h;
      document.querySelectorAll('#cnBody [data-con]').forEach((b) => b.onclick = () => op('docker', { op: 'connect_network', ref: id, network: b.dataset.con }).then(load).catch((e) => toast(e.message, 'err')));
      document.querySelectorAll('#cnBody [data-dis]').forEach((b) => b.onclick = () => op('docker', { op: 'disconnect_network', ref: id, network: b.dataset.dis }).then(load).catch((e) => toast(e.message, 'err')));
    }).catch((e) => { $('cnBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    load();
  });
}

function dkImages(info) {
  const body = $('dkBody');
  body.innerHTML = '<div class="sechead"><h3>镜像</h3><span class="sp"></span><button class="btn sm" id="dkPull">拉取镜像</button><button class="btn sec sm" id="dkRefI">刷新</button></div><div id="dkIList">' + loading() + '</div>';
  $('dkRefI').onclick = () => dkImages(info);
  $('dkPull').onclick = dkPullForm;
  op('docker', { op: 'list_images' }).then((d) => {
    const list = d.images || [];
    if (!list.length) { $('dkIList').innerHTML = '<div class="empty">暂无镜像</div>'; return; }
    let h = '<table class="optable"><tr><th>镜像</th><th>大小</th><th>创建</th><th class="act">操作</th></tr>';
    list.forEach((im) => {
      const acts = im.managed
        ? '<span class="chip">内置</span>'
        : `<div class="actions"><button class="btn sm danger" data-rm="${esc(im.name)}">删除</button></div>`;
      h += `<tr><td class="mono" style="font-size:12px">${esc(im.name)}</td><td>${esc(im.size)}</td><td class="mut">${esc(im.created)}</td>
        <td class="act">${acts}</td></tr>`;
    });
    $('dkIList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkIList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(`删除镜像 ${b.dataset.rm}？`)) op('docker', { op: 'remove_image', ref: b.dataset.rm }).then(() => { toast('已删除', 'ok'); dkImages(info); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkIList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function dkPullForm() {
  modal('拉取镜像', `
    <label class="lbl">镜像名（如 nginx:latest）</label>
    <input id="plImg" class="field" placeholder="nginx:latest" style="margin-bottom:12px" />
    <label class="lbl">加速镜像源（可选）</label>
    <select id="plMirror" class="field" style="margin-bottom:16px">
      <option value="">不使用</option>
      <option value="m.daocloud.io">m.daocloud.io</option>
      <option value="docker.m.daocloud.io">docker.m.daocloud.io</option>
      <option value="docker.1panel.live">docker.1panel.live</option>
      <option value="hub.rat.dev">hub.rat.dev</option>
    </select>
    <div class="row" style="justify-content:flex-end"><button class="btn" id="plGo">开始拉取</button></div>
    <div class="hidden" id="plJob" style="margin-top:14px"></div>`, (close) => {
    $('plGo').onclick = () => {
      const image = $('plImg').value.trim(); if (!image) return toast('请输入镜像名', 'err');
      $('plGo').disabled = true; $('plJob').classList.remove('hidden');
      op('docker', { op: 'pull_image', image, mirror: $('plMirror').value || undefined }).then((r) => renderJob($('plJob'), 'docker', r.op_id, '', { onDone: () => { toast('拉取完成', 'ok'); close(); if (S.tab === 'docker') renderDocker($('view')); }, onError: () => { $('plGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('plGo').disabled = false; });
    };
  });
}

function dkCreateForm(image, info) {
  modal('创建容器', `
    <div class="formgrid">
      <div class="full"><label class="lbl">镜像</label>
        <div class="imgpick" id="ccImgPick">
          <input id="ccImg" class="field" value="${esc(image || '')}" placeholder="选择或输入镜像，如 nginx:latest" autocomplete="off" />
          <div class="imgpop hidden" id="ccImgPop"></div>
        </div>
      </div>
      <div><label class="lbl">容器名（可选）</label><input id="ccName" class="field" placeholder="my-app" /></div>
      <div><label class="lbl">重启策略</label><select id="ccRestart" class="field"><option value="unless-stopped">unless-stopped</option><option value="always">always</option><option value="no">no</option></select></div>
      <div class="full"><label class="lbl">端口映射</label><div class="kvlist" id="ccPorts"></div><button type="button" class="kvadd" id="ccPortsAdd">+ 添加端口</button></div>
      <div class="full"><label class="lbl">环境变量</label><div class="kvlist" id="ccEnv"></div><button type="button" class="kvadd" id="ccEnvAdd">+ 添加变量</button></div>
      <div class="full"><label class="lbl">挂载卷</label><div class="kvlist" id="ccVol"></div><button type="button" class="kvadd" id="ccVolAdd">+ 添加挂载</button></div>
      <div><label class="lbl">启动命令（可选）</label><input id="ccCmd" class="field" placeholder="留空用镜像默认" /></div>
      <div style="display:flex;align-items:flex-end;gap:16px"><label style="display:flex;gap:7px;align-items:center"><input type="checkbox" id="ccTty" checked /> 分配终端</label><label style="display:flex;gap:7px;align-items:center"><input type="checkbox" id="ccStart" checked /> 创建后启动</label></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="ccGo">创建</button></div>
    <div class="hidden" id="ccJob" style="margin-top:14px"></div>`, (close) => {
    // Searchable image picker: all local images (incl. 内置), filtered live.
    setupImagePicker();
    // Dynamic row helpers.
    const portRow = (v) => kvRow('ccPorts', [
      { ph: '宿主端口', val: v && v.h }, { sep: ':' }, { ph: '容器端口', val: v && v.c },
    ], { proto: true, protoVal: v && v.proto });
    const envRow = (v) => kvRow('ccEnv', [
      { ph: 'KEY', val: v && v.k }, { sep: '=' }, { ph: 'VALUE', val: v && v.v, grow: true },
    ]);
    const volRow = (v) => kvRow('ccVol', [
      { ph: '宿主路径 /data/app', val: v && v.h, grow: true }, { sep: ':' }, { ph: '容器路径 /app', val: v && v.c, grow: true },
    ], { ro: true });
    $('ccPortsAdd').onclick = () => portRow();
    $('ccEnvAdd').onclick = () => envRow();
    $('ccVolAdd').onclick = () => volRow();
    portRow(); // start with one empty row each
    $('ccGo').onclick = () => {
      const image = $('ccImg').value.trim(); if (!image) return toast('请输入镜像', 'err');
      const ports = readKv('ccPorts').map((r) => ({ host: Number(r[0]), container: Number(r[1]), proto: r.proto || 'tcp' })).filter((p) => p.host && p.container);
      const env = readKv('ccEnv').map((r) => (r[0] ? r[0] + '=' + (r[1] || '') : '')).filter(Boolean);
      const volumes = readKv('ccVol').map((r) => ({ host: r[0], container: r[1], readonly: !!r.ro })).filter((vv) => vv.host && vv.container);
      const body = { op: 'create_container', image, name: $('ccName').value.trim() || undefined, restart: $('ccRestart').value, ports, env, volumes, command: $('ccCmd').value.trim() || undefined, tty: $('ccTty').checked, start: $('ccStart').checked };
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden');
      op('docker', body).then((r) => renderJob($('ccJob'), 'docker', r.op_id, '', { onDone: () => { toast('容器已创建', 'ok'); close(); switchTab('docker'); }, onError: () => { $('ccGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ccGo').disabled = false; });
    };
  });
}

// Wire the searchable image dropdown in the create form: loads all local images
// (built-in ones included), shows a filtered list as the user types/focuses.
function setupImagePicker() {
  const inp = $('ccImg'), pop = $('ccImgPop');
  let names = [];
  op('docker', { op: 'list_images' }).then((d) => {
    names = (d.images || []).map((im) => ({ name: im.name, managed: im.managed })).filter((x) => x.name && x.name !== '<none>:<none>');
    if (document.activeElement === inp) renderPop();
  }).catch(() => {});
  const renderPop = () => {
    const q = inp.value.trim().toLowerCase();
    const list = names.filter((x) => !q || x.name.toLowerCase().includes(q)).slice(0, 30);
    if (!list.length) { pop.classList.add('hidden'); return; }
    pop.innerHTML = list.map((x) => `<div class="imgopt" data-n="${esc(x.name)}">${esc(x.name)}${x.managed ? '<span class="imgtag">内置</span>' : ''}</div>`).join('');
    pop.classList.remove('hidden');
    pop.querySelectorAll('.imgopt').forEach((o) => o.onmousedown = (e) => { e.preventDefault(); inp.value = o.dataset.n; pop.classList.add('hidden'); });
  };
  inp.addEventListener('focus', renderPop);
  inp.addEventListener('input', renderPop);
  inp.addEventListener('blur', () => setTimeout(() => pop.classList.add('hidden'), 150));
}

// Append a dynamic key/value row to list `id`. `cells` is an array of either
// { ph, val, grow } (an input) or { sep } (a literal separator). `opts` adds a
// proto select (ports) or a readonly checkbox (volumes).
function kvRow(id, cells, opts) {
  opts = opts || {};
  const wrap = $(id);
  const row = el('div', { class: 'kvrow' });
  cells.forEach((c) => {
    if (c.sep != null) { row.appendChild(el('span', { class: 'sep' }, c.sep)); return; }
    const i = el('input', { class: 'field' + (c.grow ? ' grow' : ''), placeholder: c.ph || '' });
    if (c.grow) i.style.flex = '1';
    if (c.val != null) i.value = c.val;
    row.appendChild(i);
  });
  if (opts.proto) {
    const sel = el('select', { class: 'field', style: 'flex:0 0 70px' });
    sel.innerHTML = '<option value="tcp">tcp</option><option value="udp">udp</option>';
    if (opts.protoVal === 'udp') sel.value = 'udp';
    sel._proto = true;
    row.appendChild(sel);
  }
  if (opts.ro) {
    const lab = el('label', { class: 'ro' });
    lab.innerHTML = '<input type="checkbox" /> 只读';
    lab.querySelector('input')._ro = true;
    row.appendChild(lab);
  }
  const rm = el('button', { class: 'rm', type: 'button' }, '×');
  rm.onclick = () => row.remove();
  row.appendChild(rm);
  wrap.appendChild(row);
}
// Read a dynamic kv list back: array of [v0, v1, ...] with .proto / .ro extras.
function readKv(id) {
  return Array.from($(id).querySelectorAll('.kvrow')).map((row) => {
    const vals = Array.from(row.querySelectorAll('input[type="text"], input:not([type])')).map((i) => i.value.trim());
    const out = vals;
    const proto = row.querySelector('select');
    if (proto && proto._proto) out.proto = proto.value;
    const ro = row.querySelector('input[type="checkbox"]');
    if (ro && ro._ro) out.ro = ro.checked;
    return out;
  });
}

function dkNetworks() {
  const body = $('dkBody');
  body.innerHTML = '<div class="sechead"><h3>网络</h3><span class="sp"></span><button class="btn sm" id="dkNetNew">创建网络</button><button class="btn sec sm" id="dkRefN">刷新</button></div><div id="dkNList">' + loading() + '</div>';
  $('dkRefN').onclick = dkNetworks;
  $('dkNetNew').onclick = () => modal('创建网络', '<label class="lbl">网络名</label><input id="nnName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="nnGo">创建</button></div>', (close) => { $('nnGo').onclick = () => op('docker', { op: 'create_network', name: $('nnName').value.trim() }).then(() => { close(); toast('已创建', 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
  op('docker', { op: 'list_networks' }).then((d) => {
    let h = '<table class="optable"><tr><th>名称</th><th>驱动</th><th>范围</th><th class="act">操作</th></tr>';
    (d.networks || []).forEach((n) => { h += `<tr><td>${esc(n.name)}</td><td class="mut">${esc(n.driver)}</td><td class="mut">${esc(n.scope)}</td><td class="act">${['bridge', 'host', 'none'].includes(n.name) ? '<span class="mut" style="font-size:12px">内置</span>' : `<button class="btn sm danger" data-rm="${esc(n.name)}">删除</button>`}</td></tr>`; });
    $('dkNList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkNList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(`删除网络 ${b.dataset.rm}？`)) op('docker', { op: 'remove_network', ref: b.dataset.rm }).then(() => { toast('已删除', 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkNList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
