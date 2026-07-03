// Docker: networks + daemon settings tabs (split from docker.js).
// Both runtimes support user-defined networks (create / rename / delete / IP
// pool); the built-in networks (dn7 / bridge / host / none) are flagged and
// their mutating actions are blocked. The create button renders for both.
function dkNetworks(info) {
  const body = $('dkBody');
  if (!body) return; // tab left before an async refresh landed — nothing to render into
  body.innerHTML = loading();
  const have = info && typeof info === 'object' && ('runtime' in info || 'docker_present' in info);
  (have ? Promise.resolve(info) : op('docker', { op: 'info' }).catch(() => ({}))).then((inf) => {
    if (!$('dkBody')) return; // tab left while info was in flight
    inf = inf || {};
    const dn7 = inf.runtime === 'dn7';
    // The docker daemon reporting itself down is NOT the dn7 runtime — don't
    // mislabel it with the built-in-network explainer. Show a plain error state
    // (and no create/rename/delete toolbox, all of which would just fail).
    if (inf.docker_present === false && !dn7) {
      body.innerHTML = `<div class="sechead"><span class="sp"></span><button class="btn sec sm" id="dkRefN">${tr('dk.refresh')}</button></div>`
        + `<div class="empty">${tr('dk.daemon_down')}</div>`;
      $('dkRefN').onclick = () => dkNetworks();
      return;
    }
    // Both runtimes support user-defined networks now; the create button shows
    // for both. Per-network mutating actions are gated on the built-in flag.
    const head = `<div class="sechead"><span class="sp"></span><button class="btn sm" id="dkNetNew">${tr('dk.create_network')}</button><button class="btn sec sm" id="dkRefN">${tr('dk.refresh')}</button></div>`;
    body.innerHTML = head + `<div id="dkNList">${loading()}</div>`;
    $('dkRefN').onclick = () => dkNetworks(inf);
    $('dkNetNew').onclick = () => dkNetCreate(inf);
    op('docker', { op: 'list_networks' }).then((d) => {
      let h = `<table class="optable nettbl"><tr><th>${tr('dk.col_name')}</th><th>${tr('dk.col_driver')}</th><th>${tr('dk.col_scope')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
      (d.networks || []).forEach((n) => {
        // Prefer the backend `builtin` flag; fall back to the well-known names.
        const predefined = ('builtin' in n) ? n.builtin : ['bridge', 'host', 'none', 'dn7'].includes(n.name);
        const builtin = predefined ? ` <span class="chip">${tr('dk.builtin')}</span>` : '';
        const rnBtn = predefined
          ? `<button class="btn sm sec" data-rnbuiltin="1">${tr('dk.rename')}</button>`
          : `<button class="btn sm sec" data-rn="${esc(n.name)}">${tr('dk.rename')}</button>`;
        const ipBtn = `<button class="btn sm sec" data-ip="${esc(n.name)}">${tr('dk.net_ippool')}</button>`;
        const rmBtn = predefined
          ? `<button class="btn sm danger" data-rmbuiltin="1">${tr('dk.delete')}</button>`
          : `<button class="btn sm danger" data-rm="${esc(n.name)}">${tr('dk.delete')}</button>`;
        const acts = `<div class="actions">${rnBtn}${ipBtn}${rmBtn}</div>`;
        h += `<tr><td data-tip="${esc(n.name)}"><div class="clamp1"><b>${esc(n.name)}</b>${builtin}</div></td><td class="mut">${esc(n.driver)}</td><td class="mut">${esc(n.scope)}</td><td class="act">${acts}</td></tr>`;
      });
      $('dkNList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#dkNList [data-rnbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.net_builtin_block'), 'err'));
      document.querySelectorAll('#dkNList [data-rmbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.net_builtin_block'), 'err'));
      document.querySelectorAll('#dkNList [data-rn]').forEach((b) => b.onclick = () => dkNetRename(b.dataset.rn, inf));
      document.querySelectorAll('#dkNList [data-ip]').forEach((b) => b.onclick = () => dkNetIpPool(b.dataset.ip));
      document.querySelectorAll('#dkNList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_net', { name: b.dataset.rm }))) op('docker', { op: 'remove_network', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkNetworks(inf); }).catch((e) => toast(e.message, 'err')); });
      wireCellTips($('dkNList'));
    }).catch((e) => { $('dkNList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

// Create-network modal. Subnet/gateway/range are all optional and checked
// client-side (CIDR / IPv4 / gateway-in-subnet) only when supplied, so a typo
// fails right here with a highlighted field; an omitted subnet is auto-assigned
// a free private range by the backend (Docker parity).
function dkNetCreate(inf) {
  modal(tr('dk.create_network'), `
    <div class="formgrid">
      <div><label class="lbl">${tr('dk.net_name')}</label><input id="nnName" class="field" placeholder="my-net" /></div>
      <div><label class="lbl">${tr('dk.net_mode')}</label><select id="nnDriver" class="field"><option value="bridge">bridge</option><option value="macvlan">macvlan</option><option value="ipvlan">ipvlan</option><option value="overlay">overlay</option></select></div>
      <div><label class="lbl">${tr('dk.net_subnet')}${tr('dk.optional')}</label><input id="nnSubnet" class="field mono" placeholder="172.20.0.0/16" /></div>
      <div><label class="lbl">${tr('dk.net_gateway')}${tr('dk.optional')}</label><input id="nnGateway" class="field mono" placeholder="172.20.0.1" /></div>
      <div class="full"><label class="lbl">${tr('dk.net_iprange')}${tr('dk.optional')}</label><input id="nnRange" class="field mono" placeholder="172.20.5.0/24" /></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="nnGo">${tr('dk.create')}</button></div>`, (close) => {
    ['nnName', 'nnSubnet', 'nnGateway', 'nnRange'].forEach((id) => $(id).addEventListener('input', () => $(id).classList.remove('bad')));
    const bad = (id, msg) => { $(id).classList.add('bad'); toast(msg, 'err'); };
    $('nnGo').onclick = () => {
      const name = $('nnName').value.trim();
      const sub = $('nnSubnet').value.trim(), gw = $('nnGateway').value.trim(), rng = $('nnRange').value.trim();
      if (!name) return bad('nnName', tr('dk.net_need_name'));
      if (sub && !isCidr(sub)) return bad('nnSubnet', tr('dk.bad_cidr', { v: sub }));
      if (gw && !isIPv4(gw)) return bad('nnGateway', tr('dk.bad_ipv4', { v: gw }));
      if (gw && sub && !ipInSubnet(gw, sub)) return bad('nnGateway', tr('dk.net_gw_outside', { ip: gw, subnet: sub }));
      if (rng && !isCidr(rng)) return bad('nnRange', tr('dk.bad_cidr', { v: rng }));
      if (rng && sub && !ipInSubnet(rng.split('/')[0], sub)) return bad('nnRange', tr('dk.net_range_outside', { range: rng, subnet: sub }));
      op('docker', {
        op: 'create_network', name, driver: $('nnDriver').value,
        subnet: sub || undefined, gateway: gw || undefined, ip_range: rng || undefined,
      }).then(() => { close(); toast(tr('common.created'), 'ok'); dkNetworks(inf); }).catch((e) => toast(e.message, 'err'));
    };
    bindDirty('nnGo');
  });
}

// Rename a network (recreate under the new name; containers are reconnected).
function dkNetRename(name, inf) {
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
      op('docker', { op: 'rename_network', ref: name, new_name: nn }).then(() => { toast(tr('dk.net_renamed'), 'ok'); close(); dkNetworks(inf); }).catch((e) => toast(e.message, 'err'));
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
          // Both set-IP and disconnect are gated on `editable`: the in-house dn7
          // runtime auto-allocates addresses and has no per-endpoint hot-attach,
          // so its IP pool is view-only (no buttons that would just error out).
          const acts = d.editable
            ? `<div class="actions"><button class="btn sm sec" data-save="${esc(c.full_id)}">${tr('ng.save')}</button><button class="btn sm danger" data-dc="${esc(c.full_id)}">${tr('dk.disconnect')}</button></div>`
            : '';
          h += `<tr><td><b>${esc(c.name)}</b></td><td>${ipCell}</td><td class="act">${acts}</td></tr>`;
        });
        $('ipBody').innerHTML = h + '</table>';
        document.querySelectorAll('#ipBody [data-ipin]').forEach((i) => i.addEventListener('input', () => i.classList.remove('bad')));
        document.querySelectorAll('#ipBody [data-save]').forEach((b) => b.onclick = () => {
          const inp = document.querySelector(`#ipBody [data-ipin="${b.dataset.save}"]`);
          const ip = ((inp && inp.value) || '').trim();
          // Validate the address client-side (format + inside the subnet).
          const mark = (msg) => { if (inp) inp.classList.add('bad'); toast(msg, 'err'); };
          if (!isIPv4(ip)) return mark(tr('dk.bad_ipv4', { v: ip }));
          if (d.subnet && !ipInSubnet(ip, d.subnet)) return mark(tr('dk.net_ip_outside', { ip, net: name, subnet: d.subnet }));
          op('docker', { op: 'set_network_ip', ref: b.dataset.save, network: name, ipv4: ip }).then(() => { toast(tr('common.saved'), 'ok'); load(); }).catch((e) => toast(e.message, 'err'));
        });
        document.querySelectorAll('#ipBody [data-dc]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.net_confirm_dc'))) op('docker', { op: 'disconnect_network', ref: b.dataset.dc, network: name }).then(() => { toast(tr('dk.op_ok'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
      }).catch((e) => { $('ipBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    };
    load();
  });
}
