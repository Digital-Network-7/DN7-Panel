// =========================================================================
// Docker management
// =========================================================================
function renderDocker(v) {
  v.innerHTML = `<div style="padding:8px">${loading(tr('dk.detecting'))}</div>`;
  // If an install job is still running (user left + came back), re-attach.
  if (getJob('docker:install')) {
    v.innerHTML = `<div class="card"><h3>${tr('dk.installing')}</h3><div id="dkInstallJob"></div></div>`;
    reattachJob($('dkInstallJob'), 'docker:install', { onDone: () => setTimeout(() => renderDocker(v), 800) });
    return;
  }
  op('docker', { op: 'info' }).then((info) => {
    if (!info.installed) {
      v.innerHTML = `<div class="card" style="max-width:520px"><h3>Docker</h3><p class="mut">${tr('dk.not_found')}</p>
        <label class="lbl">${tr('dk.install_method')}</label>
        <select id="dkChannel" class="field" style="margin-bottom:10px">
          <option value="distro">${tr('dk.ch_distro')}</option>
          <option value="ce">${tr('dk.ch_ce')}</option>
        </select>
        <label class="lbl">${tr('dk.network_region')}</label>
        <select id="dkRegion" class="field" style="margin-bottom:14px">
          <option value="auto">${tr('dk.rg_auto')}</option>
          <option value="cn">${tr('dk.rg_cn')}</option>
          <option value="global">${tr('dk.rg_global')}</option>
        </select>
        <button class="btn" id="dkInstall">${tr('dk.install_btn')}</button>
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
        <button data-t="containers" class="on">${tr('dk.tab_containers')}</button>
        <button data-t="images">${tr('dk.tab_images')}</button>
        <button data-t="networks">${tr('dk.tab_networks')}</button>
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
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_containers')}</h3><span class="sp"></span><button class="btn sm" id="dkNew">${tr('dk.create_container')}</button><button class="btn sec sm" id="dkRefC">${tr('dk.refresh')}</button></div><div id="dkCList">` + loading() + '</div>';
  $('dkRefC').onclick = dkContainers;
  $('dkNew').onclick = () => dkCreateForm();
  op('docker', { op: 'list_containers' }).then((d) => {
    const list = d.containers || [];
    if (!list.length) { $('dkCList').innerHTML = `<div class="empty">${tr('dk.no_containers')}</div>`; return; }
    let h = `<table class="optable"><tr><th>${tr('dk.col_name')}</th><th>${tr('dk.col_image')}</th><th>${tr('dk.col_status')}</th><th>${tr('dk.col_ports')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
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
  if (managed) { holder.innerHTML = `<span class="chip">${tr('dk.builtin')}</span>`; return; }
  const mk = (label, cls, fn) => { const b = el('button', { class: 'btn sm ' + (cls || 'sec') }, label); b.onclick = fn; holder.appendChild(b); };
  if (running) {
    mk(tr('dk.stop'), 'sec', () => doCAction('stop_container', id, reload));
    mk(tr('dk.restart'), 'sec', () => doCAction('restart_container', id, reload));
    if (hasShell) mk(tr('dk.terminal'), '', () => ticket().then((t) => openTerminalModal(tr('dk.ctn_term') + name, `/api/container/terminal?ticket=${encodeURIComponent(t)}&container=${encodeURIComponent(id)}`)).catch((e) => toast(e.message, 'err')));
    mk(tr('dk.files'), 'sec', () => openFileBrowser(tr('dk.ctn_files') + name, id));
  } else {
    mk(tr('dk.start'), '', () => doCAction('start_container', id, reload));
  }
  mk(tr('dk.logs'), 'sec', () => dkLogs(id, name));
  mk(tr('dk.networks'), 'sec', () => dkContainerNetworks(id, name));
  mk(tr('dk.delete'), 'danger', async () => { if (await confirmDanger(tr('dk.confirm_rm_ctn', { name }))) doCAction('remove_container', id, reload); });
}
function doCAction(o, id, reload) { op('docker', { op: o, ref: id }).then(() => { toast(tr('dk.op_ok'), 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); }

function dkLogs(id, name) {
  modal(tr('dk.logs_title') + name, '<div id="dkLogWrap">' + loading() + '</div>', () => {
    op('docker', { op: 'logs', ref: id, tail: 400 }).then((d) => { $('dkLogWrap').innerHTML = '<pre class="out" id="dkLogOut" style="max-height:64vh"></pre>'; $('dkLogOut').textContent = d.logs || tr('dk.empty_log'); $('dkLogOut').scrollTop = $('dkLogOut').scrollHeight; }).catch((e) => { $('dkLogWrap').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

function dkContainerNetworks(id, name) {
  modal(tr('dk.net_title') + name, '<div id="cnBody">' + loading() + '</div>', () => {
    const load = () => op('docker', { op: 'inspect_container_networks', ref: id }).then((d) => {
      let h = `<h3 style="font-size:13px;margin:0 0 8px">${tr('dk.connected')}</h3>`;
      h += (d.attached || []).map((n) => `<div class="row" style="margin-bottom:6px"><span class="chip on">${esc(n)}</span><button class="btn sm sec" data-dis="${esc(n)}">${tr('dk.disconnect')}</button></div>`).join('') || `<div class="mut" style="margin-bottom:10px">${tr('dk.none')}</div>`;
      h += `<h3 style="font-size:13px;margin:14px 0 8px">${tr('dk.connectable')}</h3>`;
      h += (d.available || []).map((n) => `<div class="row" style="margin-bottom:6px"><span class="chip">${esc(n.name)}</span><button class="btn sm" data-con="${esc(n.name)}">${tr('dk.connect')}</button></div>`).join('') || `<div class="mut">${tr('dk.none')}</div>`;
      $('cnBody').innerHTML = h;
      document.querySelectorAll('#cnBody [data-con]').forEach((b) => b.onclick = () => op('docker', { op: 'connect_network', ref: id, network: b.dataset.con }).then(load).catch((e) => toast(e.message, 'err')));
      document.querySelectorAll('#cnBody [data-dis]').forEach((b) => b.onclick = () => op('docker', { op: 'disconnect_network', ref: id, network: b.dataset.dis }).then(load).catch((e) => toast(e.message, 'err')));
    }).catch((e) => { $('cnBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    load();
  });
}

function dkImages(info) {
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_images')}</h3><span class="sp"></span><button class="btn sm" id="dkPull">${tr('dk.pull_image')}</button><button class="btn sec sm" id="dkRefI">${tr('dk.refresh')}</button></div><div id="dkIList">` + loading() + '</div>';
  $('dkRefI').onclick = () => dkImages(info);
  $('dkPull').onclick = dkPullForm;
  op('docker', { op: 'list_images' }).then((d) => {
    const list = d.images || [];
    if (!list.length) { $('dkIList').innerHTML = `<div class="empty">${tr('dk.no_images')}</div>`; return; }
    let h = `<table class="optable"><tr><th>${tr('dk.col_image')}</th><th>${tr('dk.col_size')}</th><th>${tr('dk.col_created')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    list.forEach((im) => {
      const acts = im.managed
        ? `<span class="chip">${tr('dk.builtin')}</span>`
        : `<div class="actions"><button class="btn sm danger" data-rm="${esc(im.name)}">${tr('dk.delete')}</button></div>`;
      h += `<tr><td class="mono" style="font-size:12px">${esc(im.name)}</td><td>${esc(im.size)}</td><td class="mut">${esc(im.created)}</td>
        <td class="act">${acts}</td></tr>`;
    });
    $('dkIList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkIList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_img', { name: b.dataset.rm }))) op('docker', { op: 'remove_image', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkImages(info); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkIList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function dkPullForm() {
  modal(tr('dk.pull_image'), `
    <label class="lbl">${tr('dk.img_name_label')}</label>
    <input id="plImg" class="field" placeholder="nginx:latest" style="margin-bottom:12px" />
    <label class="lbl">${tr('dk.mirror_label')}</label>
    <select id="plMirror" class="field" style="margin-bottom:16px">
      <option value="">${tr('dk.mirror_none')}</option>
      <option value="m.daocloud.io">m.daocloud.io</option>
      <option value="docker.m.daocloud.io">docker.m.daocloud.io</option>
      <option value="docker.1panel.live">docker.1panel.live</option>
      <option value="hub.rat.dev">hub.rat.dev</option>
    </select>
    <div class="row" style="justify-content:flex-end"><button class="btn" id="plGo">${tr('dk.pull_start')}</button></div>
    <div class="hidden" id="plJob" style="margin-top:14px"></div>`, (close) => {
    $('plGo').onclick = () => {
      const image = $('plImg').value.trim(); if (!image) return toast(tr('dk.need_image_name'), 'err');
      $('plGo').disabled = true; $('plJob').classList.remove('hidden');
      op('docker', { op: 'pull_image', image, mirror: $('plMirror').value || undefined }).then((r) => renderJob($('plJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.pull_done'), 'ok'); close(); if (S.tab === 'docker') renderDocker($('view')); }, onError: () => { $('plGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('plGo').disabled = false; });
    };
  });
}

function dkCreateForm(image, info) {
  modal(tr('dk.create_container'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('dk.image')}</label><select id="ccImg" class="field"><option value="">${tr('dk.image_ph')}</option></select></div>
      <div><label class="lbl">${tr('dk.ctn_name')}</label><input id="ccName" class="field" placeholder="my-app" /></div>
      <div><label class="lbl">${tr('dk.restart_policy')}</label><select id="ccRestart" class="field"><option value="unless-stopped">unless-stopped</option><option value="always">always</option><option value="no">no</option></select></div>
      <div class="full"><label class="lbl">${tr('dk.start_cmd')}</label><input id="ccCmd" class="field" placeholder="${tr('dk.cmd_ph')}" /></div>
      <div class="full" style="margin-top:2px">
        <label class="switch"><input type="checkbox" id="ccTty" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.alloc_tty')}</b><span>${tr('dk.alloc_tty_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccStart" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.start_after')}</b><span>${tr('dk.start_after_d')}</span></span></label>
      </div>
      <div class="full"><label class="lbl">${tr('dk.port_map')}</label><div class="kvlist" id="ccPorts"></div><button type="button" class="kvadd" id="ccPortsAdd">${tr('dk.add_port')}</button></div>
      <div class="full"><label class="lbl">${tr('dk.env')}</label><div class="kvlist" id="ccEnv"></div><button type="button" class="kvadd" id="ccEnvAdd">${tr('dk.add_env')}</button></div>
      <div class="full"><label class="lbl">${tr('dk.volumes')}</label><div class="kvlist" id="ccVol"></div><button type="button" class="kvadd" id="ccVolAdd">${tr('dk.add_vol')}</button></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="ccGo">${tr('dk.create')}</button></div>
    <div class="hidden" id="ccJob" style="margin-top:14px"></div>`, (close) => {
    // Image picker: a select of all local images (built-in ones included).
    loadImageOptions(image);
    // Dynamic row helpers.
    const portRow = (v) => kvRow('ccPorts', [
      { ph: tr('dk.host_port'), val: v && v.h }, { sep: ':' }, { ph: tr('dk.container_port'), val: v && v.c },
    ], { proto: true, protoVal: v && v.proto });
    const envRow = (v) => kvRow('ccEnv', [
      { ph: 'KEY', val: v && v.k }, { sep: '=' }, { ph: 'VALUE', val: v && v.v, grow: true },
    ]);
    const volRow = (v) => kvRow('ccVol', [
      { ph: tr('dk.host_path'), val: v && v.h, grow: true }, { sep: ':' }, { ph: tr('dk.container_path'), val: v && v.c, grow: true },
    ], { ro: true });
    $('ccPortsAdd').onclick = () => portRow();
    $('ccEnvAdd').onclick = () => envRow();
    $('ccVolAdd').onclick = () => volRow();
    // No default rows — ports/env/volumes start empty.
    $('ccGo').onclick = () => {
      const image = $('ccImg').value.trim(); if (!image) return toast(tr('dk.need_image'), 'err');
      const ports = readKv('ccPorts').map((r) => ({ host: Number(r[0]), container: Number(r[1]), proto: r.proto || 'tcp' })).filter((p) => p.host && p.container);
      const env = readKv('ccEnv').map((r) => (r[0] ? r[0] + '=' + (r[1] || '') : '')).filter(Boolean);
      const volumes = readKv('ccVol').map((r) => ({ host: r[0], container: r[1], readonly: !!r.ro })).filter((vv) => vv.host && vv.container);
      const body = { op: 'create_container', image, name: $('ccName').value.trim() || undefined, restart: $('ccRestart').value, ports, env, volumes, command: $('ccCmd').value.trim() || undefined, tty: $('ccTty').checked, start: $('ccStart').checked };
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden');
      op('docker', body).then((r) => renderJob($('ccJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.ctn_created'), 'ok'); close(); switchTab('docker'); }, onError: () => { $('ccGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ccGo').disabled = false; });
    };
  });
}

// Populate the create-form image dropdown with all local images (built-in ones
// included). Pre-selects `preselect` when given.
function loadImageOptions(preselect) {
  const sel = $('ccImg'); if (!sel) return;
  op('docker', { op: 'list_images' }).then((d) => {
    const names = (d.images || []).map((im) => im.name).filter((n) => n && n !== '<none>:<none>');
    if (!names.length) { sel.innerHTML = `<option value="">${tr('dk.no_images_pull')}</option>`; return; }
    sel.innerHTML = names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    if (preselect && names.includes(preselect)) sel.value = preselect;
  }).catch(() => {});
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
    lab.innerHTML = `<input type="checkbox" /> ${tr('dk.readonly')}`;
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
  body.innerHTML = `<div class="sechead"><h3>${tr('dk.tab_networks')}</h3><span class="sp"></span><button class="btn sm" id="dkNetNew">${tr('dk.create_network')}</button><button class="btn sec sm" id="dkRefN">${tr('dk.refresh')}</button></div><div id="dkNList">` + loading() + '</div>';
  $('dkRefN').onclick = dkNetworks;
  $('dkNetNew').onclick = () => modal(tr('dk.create_network'), `<label class="lbl">${tr('dk.net_name')}</label><input id="nnName" class="field" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="nnGo">${tr('dk.create')}</button></div>`, (close) => { $('nnGo').onclick = () => op('docker', { op: 'create_network', name: $('nnName').value.trim() }).then(() => { close(); toast(tr('common.created'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
  op('docker', { op: 'list_networks' }).then((d) => {
    let h = `<table class="optable"><tr><th>${tr('dk.col_name')}</th><th>${tr('dk.col_driver')}</th><th>${tr('dk.col_scope')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    (d.networks || []).forEach((n) => { h += `<tr><td>${esc(n.name)}</td><td class="mut">${esc(n.driver)}</td><td class="mut">${esc(n.scope)}</td><td class="act">${['bridge', 'host', 'none'].includes(n.name) ? `<span class="mut" style="font-size:12px">${tr('dk.builtin')}</span>` : `<button class="btn sm danger" data-rm="${esc(n.name)}">${tr('dk.delete')}</button>`}</td></tr>`; });
    $('dkNList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkNList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_net', { name: b.dataset.rm }))) op('docker', { op: 'remove_network', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('dkNList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
