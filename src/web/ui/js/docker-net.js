// Docker: networks + daemon settings tabs (split from docker.js).
function dkNetworks() {
  const body = $('dkBody');
  body.innerHTML = `<div class="sechead">${dkVerChips()}<span class="sp"></span><button class="btn sm" id="dkNetNew">${tr('dk.create_network')}</button><button class="btn sec sm" id="dkRefN">${tr('dk.refresh')}</button></div><div id="dkNList">` + loading() + '</div>';
  $('dkRefN').onclick = dkNetworks;
  $('dkNetNew').onclick = () => modal(tr('dk.create_network'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('dk.net_name')}</label><input id="nnName" class="field" placeholder="my-net" /></div>
      <div><label class="lbl">${tr('dk.net_mode')}</label><select id="nnDriver" class="field"><option value="bridge">bridge</option><option value="macvlan">macvlan</option><option value="ipvlan">ipvlan</option><option value="overlay">overlay</option></select></div>
      <div><label class="lbl">${tr('dk.net_subnet')}${tr('dk.optional')}</label><input id="nnSubnet" class="field mono" placeholder="172.20.0.0/16" /></div>
      <div><label class="lbl">${tr('dk.net_gateway')}${tr('dk.optional')}</label><input id="nnGateway" class="field mono" placeholder="172.20.0.1" /></div>
      <div class="full"><label class="lbl">${tr('dk.net_iprange')}${tr('dk.optional')}</label><input id="nnRange" class="field mono" placeholder="172.20.5.0/24" /></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="nnGo">${tr('dk.create')}</button></div>`, (close) => {
    $('nnGo').onclick = () => op('docker', {
      op: 'create_network', name: $('nnName').value.trim(), driver: $('nnDriver').value,
      subnet: $('nnSubnet').value.trim() || undefined, gateway: $('nnGateway').value.trim() || undefined, ip_range: $('nnRange').value.trim() || undefined,
    }).then(() => { close(); toast(tr('common.created'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err'));
    bindDirty('nnGo');
  });
  op('docker', { op: 'list_networks' }).then((d) => {
    let h = `<table class="optable nettbl"><tr><th>${tr('dk.col_name')}</th><th>${tr('dk.col_driver')}</th><th>${tr('dk.col_scope')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    (d.networks || []).forEach((n) => {
      const predefined = ['bridge', 'host', 'none'].includes(n.name);
      const builtin = predefined ? ` <span class="chip">${tr('dk.builtin')}</span>` : '';
      const rnBtn = predefined
        ? `<button class="btn sm sec" data-rnbuiltin="1">${tr('dk.rename')}</button>`
        : `<button class="btn sm sec" data-rn="${esc(n.name)}">${tr('dk.rename')}</button>`;
      const ipBtn = `<button class="btn sm sec" data-ip="${esc(n.name)}">${tr('dk.net_ippool')}</button>`;
      const rmBtn = predefined
        ? `<button class="btn sm danger" data-rmbuiltin="1">${tr('dk.delete')}</button>`
        : `<button class="btn sm danger" data-rm="${esc(n.name)}">${tr('dk.delete')}</button>`;
      h += `<tr><td data-tip="${esc(n.name)}"><div class="clamp1"><b>${esc(n.name)}</b>${builtin}</div></td><td class="mut">${esc(n.driver)}</td><td class="mut">${esc(n.scope)}</td><td class="act"><div class="actions">${rnBtn}${ipBtn}${rmBtn}</div></td></tr>`;
    });
    $('dkNList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkNList [data-rnbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.net_builtin_block'), 'err'));
    document.querySelectorAll('#dkNList [data-rmbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.net_builtin_block'), 'err'));
    document.querySelectorAll('#dkNList [data-rn]').forEach((b) => b.onclick = () => dkNetRename(b.dataset.rn));
    document.querySelectorAll('#dkNList [data-ip]').forEach((b) => b.onclick = () => dkNetIpPool(b.dataset.ip));
    document.querySelectorAll('#dkNList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_net', { name: b.dataset.rm }))) op('docker', { op: 'remove_network', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkNetworks(); }).catch((e) => toast(e.message, 'err')); });
    wireCellTips($('dkNList'));
  }).catch((e) => { $('dkNList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Rename a network (recreate under the new name; containers are reconnected).
function dkNetRename(name) {
  modal(tr('dk.net_rename_title') + name, `
    <label class="lbl">${tr('dk.net_new_name')}</label>
    <input id="rnName" class="field" value="${esc(name)}" />
    <p class="formnote" style="color:var(--warn)">${tr('dk.net_rename_warn')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="rnGo" disabled>${tr('dk.rename')}</button></div>`, (close) => {
    bindDirty('rnGo', 'rnName');
    $('rnGo').onclick = async () => {
      const nn = $('rnName').value.trim();
      if (!nn || nn === name) return;
      if (!await confirmDanger(tr('dk.net_rename_confirm'))) return;
      op('docker', { op: 'rename_network', ref: name, new_name: nn }).then(() => { toast(tr('dk.net_renamed'), 'ok'); close(); dkNetworks(); }).catch((e) => toast(e.message, 'err'));
    };
  });
}

// IP pool: view (and on user-defined networks, edit) the IPv4 of each attached
// container, or disconnect a container from the network.
function dkNetIpPool(name) {
  modal(tr('dk.net_ippool_title') + name, `<div id="ipBody">${loading()}</div>`, (close) => {
    const load = () => {
      op('docker', { op: 'network_ips', ref: name }).then((d) => {
        const cons = d.containers || [];
        const head = `<div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:wrap">`
          + `<span class="chip">${tr('dk.net_subnet')}: ${esc(d.subnet || '-')}</span>`
          + `<span class="chip">${tr('dk.net_gateway')}: ${esc(d.gateway || '-')}</span></div>`;
        if (!cons.length) { $('ipBody').innerHTML = head + `<div class="empty">${tr('dk.net_ip_none')}</div>`; return; }
        let h = head + `<table class="optable"><tr><th>${tr('dk.col_name')}</th><th>IPv4</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
        cons.forEach((c) => {
          const ipCell = d.editable
            ? `<input class="field mono" style="max-width:170px;padding:6px 9px" data-ipin="${esc(c.full_id)}" value="${esc(c.ipv4)}" />`
            : `<span class="mono">${esc(c.ipv4 || '-')}</span>`;
          const acts = d.editable
            ? `<div class="actions"><button class="btn sm sec" data-save="${esc(c.full_id)}">${tr('ng.save')}</button><button class="btn sm danger" data-dc="${esc(c.full_id)}">${tr('dk.disconnect')}</button></div>`
            : `<div class="actions"><button class="btn sm danger" data-dc="${esc(c.full_id)}">${tr('dk.disconnect')}</button></div>`;
          h += `<tr><td><b>${esc(c.name)}</b></td><td>${ipCell}</td><td class="act">${acts}</td></tr>`;
        });
        $('ipBody').innerHTML = h + '</table>';
        document.querySelectorAll('#ipBody [data-save]').forEach((b) => b.onclick = () => {
          const ip = (document.querySelector(`#ipBody [data-ipin="${b.dataset.save}"]`) || {}).value;
          op('docker', { op: 'set_network_ip', ref: b.dataset.save, network: name, ipv4: (ip || '').trim() }).then(() => { toast(tr('common.saved'), 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
        });
        document.querySelectorAll('#ipBody [data-dc]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.net_confirm_dc'))) op('docker', { op: 'disconnect_network', ref: b.dataset.dc, network: name }).then(() => { toast(tr('dk.op_ok'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
      }).catch((e) => { $('ipBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    };
    load();
  });
}

// ---- Settings tab (daemon.json knobs; mirror/registry lists live under Images → Advanced) ----
function dkSettings() {
  const body = $('dkBody');
  body.innerHTML = loading();
  op('docker', { op: 'get_settings' }).then((s) => {
    const cg = s.cgroup_driver || 'systemd';
    body.innerHTML = `
      <div style="max-width:560px">
        <div class="sechead" style="margin-top:0"><h3>${tr('dk.set_daemon')}</h3></div>
        <p class="formnote" style="margin:0 0 14px">${tr('dk.set_daemon_d')}</p>
        <div class="formgrid">
          <div><label class="lbl">${tr('dk.set_cgroup')}</label><select id="dkCgroup" class="field"><option value="systemd"${cg === 'systemd' ? ' selected' : ''}>systemd</option><option value="cgroupfs"${cg === 'cgroupfs' ? ' selected' : ''}>cgroupfs</option></select></div>
          <div><label class="lbl">${tr('dk.set_socket')}</label><input id="dkSocket" class="field mono" value="${esc(s.socket_path || '/var/run/docker.sock')}" /></div>
          <div><label class="lbl">${tr('dk.set_logsize')}</label><input id="dkLogSize" class="field" value="${esc(s.log_max_size || '10m')}" placeholder="10m" /></div>
          <div><label class="lbl">${tr('dk.set_logfile')}</label><input id="dkLogFile" class="field" type="number" min="1" value="${esc(String(s.log_max_file != null ? s.log_max_file : 3))}" /></div>
        </div>
        <div class="switchrow" style="margin-top:16px;gap:2px 24px">
          <label class="switch" style="padding:7px 0"><input type="checkbox" id="dkLogRotate" ${s.log_rotate ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_logrotate')}</b><span>${tr('dk.set_logrotate_d')}</span></span></label>
          <label class="switch" style="padding:7px 0"><input type="checkbox" id="dkGzip6" ${s.ipv6 ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_ipv6')}</b><span>${tr('dk.set_ipv6_d')}</span></span></label>
          <label class="switch" style="padding:7px 0"><input type="checkbox" id="dkIptables" ${s.iptables ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_iptables')}</b><span>${tr('dk.set_iptables_d')}</span></span></label>
          <label class="switch" style="padding:7px 0"><input type="checkbox" id="dkLiveRestore" ${s.live_restore ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.set_live')}</b><span>${tr('dk.set_live_d')}</span></span></label>
        </div>
        <div class="row" style="align-items:center;gap:12px;margin-top:18px"><button class="btn danger" id="dkSaveDaemon" disabled>${tr('dk.set_apply')}</button><span class="err ok" id="dkDaemonMsg"></span></div>
        <p class="formnote" style="margin-top:10px">${tr('dk.set_daemon_warn')}</p>
      </div>`;

    const collect = () => ({
      ipv6: $('dkGzip6').checked,
      iptables: $('dkIptables').checked,
      live_restore: $('dkLiveRestore').checked,
      cgroup_driver: $('dkCgroup').value,
      log_rotate: $('dkLogRotate').checked,
      log_max_size: $('dkLogSize').value.trim(),
      log_max_file: Number($('dkLogFile').value) || 3,
      socket_path: $('dkSocket').value.trim(),
    });
    $('dkSaveDaemon').onclick = async () => {
      if (!await confirmDanger(tr('dk.set_restart_confirm'))) return;
      const m = $('dkDaemonMsg'); m.className = 'err ok'; m.textContent = tr('dk.set_applying'); $('dkSaveDaemon').disabled = true;
      op('docker', { op: 'set_settings', settings: collect() }).then(() => { m.className = 'err ok'; m.textContent = tr('common.saved'); if ($('dkSaveDaemon')._dirtyReset) $('dkSaveDaemon')._dirtyReset(); }).catch((e) => { m.className = 'err'; m.textContent = e.message; $('dkSaveDaemon').disabled = false; });
    };
    bindDirty('dkSaveDaemon', 'dkBody');
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
