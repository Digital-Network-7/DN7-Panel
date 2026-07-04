// Docker: create-container form/modal + helpers (split from docker.js).

// "Generate random" dice icon for the per-network MAC / IPv4 randomize buttons.
const DICE_ICON = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1.2" fill="currentColor" stroke="none"/><circle cx="15" cy="9" r="1.2" fill="currentColor" stroke="none"/><circle cx="9" cy="15" r="1.2" fill="currentColor" stroke="none"/><circle cx="15" cy="15" r="1.2" fill="currentColor" stroke="none"/></svg>';

function dkCreateForm() {
  // Fetch host capacity (CPU/mem caps), networks and volumes up front so the
  // Resources / Network / Volumes tabs can be populated.
  Promise.all([
    op('docker', { op: 'info' }).catch(() => ({})),
    op('docker', { op: 'list_networks' }).catch(() => ({ networks: [] })),
    op('docker', { op: 'list_volumes' }).catch(() => ({ volumes: [] })),
  ]).then(([info, nd, vd]) => dkCreateModal(info || {}, (nd && nd.networks) || [], { volumes: (vd && vd.volumes) || [] }));
}

function dkCreateModal(info, networks, opts) {
  opts = opts || {};
  const prefill = opts.prefill || null;
  // The in-house dn7 runtime has exactly one built-in network and rejects any
  // networking_config (custom MAC / static IPv4) — so on dn7 we never prefill a
  // random MAC and hide the per-row MAC / static-IP inputs entirely.
  const isDn7 = !!(info && info.runtime === 'dn7');
  const hostCpus = Number(info.host_cpus) || 0;
  const hostMem = Number(info.host_mem_bytes) || 0;
  const cpuMax = hostCpus > 0 ? hostCpus : 2;
  const memMaxMb = hostMem > 0 ? (hostMem / 1048576) : 0;
  const memMaxTxt = memMaxMb > 0 ? memMaxMb.toFixed(2) + 'MB' : '';
  const vols = opts.volumes || [];
  // Eligible networks (bridge included once; host/none excluded). A container
  // can join several, but never the same network twice — selects only offer
  // networks not already chosen by another row.
  const netList = networks.filter((n) => n.name !== 'host' && n.name !== 'none')
    .map((n) => ({ name: n.name, subnet: n.subnet || '' }));
  const volOpts = `<option value="">${tr('dk.vol_pick')}</option>` + vols.map((v) => `<option value="${esc(v.name)}">${esc(v.name)}</option>`).join('');
  modal(opts.title || tr('dk.create_container'), `
    <div class="subtabs" id="ccTabs">
      <button data-s="basic" class="on">${tr('dk.tab_basic')}</button>
      <button data-s="net">${tr('dk.tab_networks')}</button>
      <button data-s="ports">${tr('dk.tab_ports')}</button>
      <button data-s="vol">${tr('dk.tab_volumes')}</button>
      <button data-s="res">${tr('dk.tab_resources')}</button>
      <button data-s="env">${tr('dk.tab_env')}</button>
    </div>
    <div id="ccBasic">
      <div class="formgrid">
        <div class="full"><label class="lbl">${tr('dk.image')}</label><select id="ccImg" class="field" data-selx-search><option value="">${tr('dk.image_ph')}</option></select></div>
        <div><label class="lbl">${tr('dk.ctn_name')}</label><input id="ccName" class="field" placeholder="my-app" /></div>
        <div><label class="lbl">${tr('dk.restart_policy')}</label><div style="display:flex;gap:6px"><select id="ccRestart" class="field" style="flex:1 1 auto"><option value="unless-stopped">unless-stopped</option><option value="always">always</option><option value="on-failure">on-failure</option><option value="no">no</option></select><input id="ccRestartN" class="field hidden" type="number" min="0" max="1000" value="0" style="flex:0 0 92px" title="${esc(tr('dk.restart_max_retries'))}" placeholder="N" /></div></div>
        <div class="full"><label class="lbl">${tr('dk.start_cmd')}</label><input id="ccCmd" class="field" placeholder="${tr('dk.cmd_ph')}" /></div>
      </div>
      <div class="switchrow" style="margin-top:10px">
        <label class="switch"><input type="checkbox" id="ccStdin" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.alloc_stdin')}</b><span>${tr('dk.alloc_stdin_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccTty" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.alloc_tty')}</b><span>${tr('dk.alloc_tty_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccStart" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.start_after')}</b><span>${tr('dk.start_after_d')}</span></span></label>
      </div>
    </div>
    <div id="ccNet" class="hidden">
      <div style="margin-bottom:12px"><label class="lbl">${tr('dk.net_mode')}</label><select id="ccNetMode" class="field" style="max-width:260px"><option value="">${tr('dk.net_mode_bridge')}</option><option value="host">host</option><option value="none">none</option></select><p class="formnote hidden" id="ccNetModeHint" style="margin-top:5px"></p></div>
      <div id="ccNetRows">
      <label class="lbl">${tr('dk.net_join')}</label>
      <div class="kvlist" id="ccNets"></div>
      <button type="button" class="kvadd" id="ccNetAdd">${tr('dk.net_add')}</button>
      <p class="formnote" style="margin-top:8px">${tr('dk.net_static_hint')}</p>
      </div>
      <div class="formgrid" style="margin-top:16px">
        <div><label class="lbl">${tr('dk.hostname')}</label><input id="ccHost" class="field" placeholder="web-01" /></div>
        <div><label class="lbl">${tr('dk.domainname')}</label><input id="ccDomain" class="field" placeholder="example.com" /></div>
        <div class="full"><label class="lbl">${tr('dk.dns')}</label><input id="ccDns" class="field mono" placeholder="1.1.1.1 8.8.8.8" /><p class="formnote" style="margin-top:5px">${tr('dk.dns_hint')}</p></div>
      </div>
    </div>
    <div id="ccPortsT" class="hidden">
      <label class="lbl">${tr('dk.port_map')}</label><div class="kvlist" id="ccPorts"></div><button type="button" class="kvadd" id="ccPortsAdd">${tr('dk.add_port')}</button>
    </div>
    <div id="ccVolT" class="hidden">
      <label class="lbl">${tr('dk.volumes')}</label><div class="kvlist" id="ccVol"></div><button type="button" class="kvadd" id="ccVolAdd">${tr('dk.add_vol')}</button>
    </div>
    <div id="ccRes" class="hidden">
      <div class="formgrid res3">
        <div><label class="lbl">${tr('dk.cpu_weight')}</label><input id="ccCpuShares" class="field" type="number" min="0" value="1024" /><p class="formnote" style="margin-top:5px">${tr('dk.cpu_weight_hint')}</p></div>
        <div><label class="lbl">${tr('dk.cpu_limit')}</label><div class="field-suffix"><input id="ccCpus" class="field" type="number" min="0" max="${cpuMax}" step="0.1" value="0" /><span class="suffix-tag">${tr('dk.unit_core')}</span></div><p class="formnote" style="margin-top:5px">${tr('dk.cpu_limit_hint', { n: cpuMax })}</p></div>
        <div><label class="lbl">${tr('dk.mem_limit')}</label><div class="field-suffix"><input id="ccMem" class="field" type="number" min="0" value="0" /><button type="button" class="suffix-btn" id="ccMemUnit">MB</button></div><p class="formnote" style="margin-top:5px" id="ccMemHint"></p></div>
      </div>
      <div class="formgrid res3" style="margin-top:12px">
        <div><label class="lbl">${tr('dk.pids_limit')}</label><input id="ccPids" class="field" type="number" min="0" value="0" /><p class="formnote" style="margin-top:5px">${tr('dk.pids_limit_hint')}</p></div>
        <div><label class="lbl">${tr('dk.stop_timeout')}</label><div class="field-suffix"><input id="ccStopT" class="field" type="number" min="0" value="10" /><span class="suffix-tag">${tr('dk.unit_sec')}</span></div></div>
        <div><label class="lbl">${tr('dk.stop_signal')}</label><input id="ccStopSig" class="field mono" placeholder="SIGTERM" /></div>
      </div>
      <div class="switchrow" style="margin-top:12px">
        <label class="switch"><input type="checkbox" id="ccPriv" /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.privileged')}</b><span>${tr('dk.privileged_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="ccRm" /><span class="swbox"></span><span class="swtxt"><b>${tr('dk.auto_remove')}</b><span>${tr('dk.auto_remove_d')}</span></span></label>
      </div>
    </div>
    <div id="ccEnvT" class="hidden">
      <label class="lbl">${tr('dk.env')}</label><div class="kvlist" id="ccEnv"></div><button type="button" class="kvadd" id="ccEnvAdd">${tr('dk.add_env')}</button>
    </div>`, (close, root) => {
    // Image options: fetch, then apply any prefill inside the same promise so a
    // slow list_images can never wipe the injected current image and silently
    // fall back to another one (edit-modal prefill race).
    const loadImages = (preselect) => op('docker', { op: 'list_images' }).then((d) => {
      const sel = root.querySelector('#ccImg'); if (!sel) return;
      const names = (d.images || []).map((im) => im.name).filter((n) => n && n !== '<none>:<none>');
      if (preselect && !names.includes(preselect)) names.unshift(preselect);
      if (!names.length) { sel.innerHTML = `<option value="">${tr('dk.no_images_pull')}</option>`; return; }
      // Value keeps the full ref (used on create); display drops the
      // registry-1.docker.io/library/ prefix for readability.
      sel.innerHTML = names.map((n) => `<option value="${esc(n)}">${esc(dockerShortRef(n))}</option>`).join('');
      if (preselect) sel.value = preselect;
      // Options arriving is not a user edit — re-baseline the dirty snapshot.
      const mb = root.querySelector('.modal-b');
      if (mb && mb.dataset.dirty !== '1' && $('ccGo') && $('ccGo')._dirtyReset) $('ccGo')._dirtyReset();
    }).catch(() => {});
    loadImages(prefill ? prefill.image : undefined);
    // Tab switching.
    const panes = { basic: 'ccBasic', net: 'ccNet', ports: 'ccPortsT', vol: 'ccVolT', res: 'ccRes', env: 'ccEnvT' };
    const tabs = root.querySelector('#ccTabs');
    const selTab = (s) => {
      tabs.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.s === s));
      Object.keys(panes).forEach((k) => root.querySelector('#' + panes[k]).classList.toggle('hidden', k !== s));
    };
    tabs.querySelectorAll('button').forEach((btn) => btn.onclick = () => selTab(btn.dataset.s));
    // Dynamic row helpers.
    const portRow = (v) => kvRow('ccPorts', [
      { ph: tr('dk.host_ip'), val: v && v.ip }, { sep: ':' }, { ph: tr('dk.host_port'), val: v && v.h }, { sep: '→' }, { ph: tr('dk.container_port'), val: v && v.c },
      // dn7's DNAT is IPv4-only (create rejects ipv6 publishes) — don't offer
      // the toggle there at all.
    ], { proto: true, protoVal: v && v.proto, ipv6: !isDn7, ipv6Val: v && v.ipv6 });
    const envRow = (v) => kvRow('ccEnv', [
      { ph: 'KEY', val: v && v.k, flex: '0 0 34%' }, { sep: '=' }, { ph: 'VALUE', val: v && v.v, flex: '1 1 auto' },
    ]);
    // Volume row: source is a host path or a docker named volume (toggle), then
    // the container path.
    const volRow = (v) => {
      const row = el('div', { class: 'kvrow volrow' });
      row.innerHTML = `<select class="vr-type field"><option value="host">${tr('dk.vol_src_host')}</option><option value="vol">${tr('dk.vol_src_vol')}</option></select>`
        + `<input class="vr-host field" placeholder="/data/app" />`
        + `<select class="vr-vol field hidden">${volOpts}</select>`
        + `<span class="sep">→</span>`
        + `<input class="vr-ctn field" placeholder="/app" />`
        + `<label class="tgl"><input type="checkbox" class="vr-ro" /><span class="tglbox"></span><span class="tgltxt">${tr('dk.readonly')}</span></label>`
        + `<button type="button" class="rm">×</button>`;
      const type = row.querySelector('.vr-type'), host = row.querySelector('.vr-host'), vsel = row.querySelector('.vr-vol');
      const syncType = () => { const isVol = type.value === 'vol'; host.classList.toggle('hidden', isVol); vsel.classList.toggle('hidden', !isVol); };
      type.onchange = syncType;
      if (v) {
        const isVol = v.host && !v.host.startsWith('/');
        type.value = isVol ? 'vol' : 'host';
        if (isVol) vsel.value = v.host; else host.value = v.host || '';
        row.querySelector('.vr-ctn').value = v.container || '';
        if (v.readonly) row.querySelector('.vr-ro').checked = true;
      }
      syncType();
      attachPathSuggest(host);
      row.querySelector('.rm').onclick = () => row.remove();
      $('ccVol').appendChild(row);
    };
    const readVolumes = () => Array.from($('ccVol').querySelectorAll('.volrow')).map((r) => {
      const isVol = r.querySelector('.vr-type').value === 'vol';
      const src = isVol ? r.querySelector('.vr-vol').value : r.querySelector('.vr-host').value.trim();
      return { host: src, container: r.querySelector('.vr-ctn').value.trim(), readonly: r.querySelector('.vr-ro').checked };
    }).filter((vv) => vv.host && vv.container);
    $('ccPortsAdd').onclick = () => portRow();
    $('ccEnvAdd').onclick = () => envRow();
    $('ccVolAdd').onclick = () => volRow();
    // Network tab: a container can join several networks (never the same one
    // twice). Each row is a network pick + optional MAC (auto-random) + optional
    // static IPv4 (auto from the chosen network's subnet). The random generators
    // sit inside the inputs.
    const usedNets = () => Array.from($('ccNets').querySelectorAll('.nr-net')).map((s) => s.value);
    // Re-prune every select so it only offers networks not chosen elsewhere, and
    // hide the add button once every eligible network is taken.
    const refreshNetUI = () => {
      const used = usedNets();
      Array.from($('ccNets').querySelectorAll('.netrow')).forEach((row) => {
        const sel = row.querySelector('.nr-net');
        const cur = sel.value;
        sel.innerHTML = netList.filter((n) => n.name === cur || !used.includes(n.name))
          .map((n) => `<option value="${esc(n.name)}" data-subnet="${esc(n.subnet)}">${esc(n.name)}</option>`).join('');
        sel.value = cur;
      });
      const remaining = netList.filter((n) => !used.includes(n.name));
      $('ccNetAdd').style.display = remaining.length ? '' : 'none';
    };
    const netRow = (v) => {
      const used = usedNets();
      const def = (v && v.network) || ((netList.find((n) => !used.includes(n.name)) || netList[0] || {}).name) || '';
      const row = el('div', { class: 'netrow' });
      const allOpts = netList.map((n) => `<option value="${esc(n.name)}" data-subnet="${esc(n.subnet)}">${esc(n.name)}</option>`).join('');
      row.innerHTML = `<select class="nr-net field">${allOpts}</select>`
        + `<div class="ifield"><input class="nr-mac field mono" placeholder="${tr('dk.mac_addr')}" /><button type="button" class="ifield-btn nr-macgen" title="${tr('dk.gen_random')}">${DICE_ICON}</button></div>`
        + `<div class="ifield"><input class="nr-ip field mono" placeholder="${tr('dk.ipv4_addr')}" /><button type="button" class="ifield-btn nr-ipgen" title="${tr('dk.gen_random')}">${DICE_ICON}</button></div>`
        + `<button type="button" class="rm">×</button>`;
      const sel = row.querySelector('.nr-net'), mac = row.querySelector('.nr-mac'), ip = row.querySelector('.nr-ip');
      const ipgenBtn = row.querySelector('.nr-ipgen');
      const macgenBtn = row.querySelector('.nr-macgen');
      if (def) sel.value = def;
      // dn7 attaches with no MAC/IP — never prefill a random MAC there (dn7
      // rejects any networking_config), and hide the MAC field + dice button.
      if (isDn7) {
        const macField = mac.closest('.ifield') || mac;
        macField.style.display = 'none';
        mac.disabled = true;
      } else {
        mac.value = (v && v.mac) || randMac();
      }
      const subnet = () => { const o = sel.options[sel.selectedIndex]; return o ? (o.dataset.subnet || '') : ''; };
      // The default `bridge` (and any subnet-less network) can't take a static
      // IPv4 — disable the field there so the form matches what Docker allows.
      // dn7's built-in network never takes a static IPv4 either.
      const supportsIp = () => !isDn7 && sel.value !== 'bridge' && !!subnet();
      const syncIp = () => {
        const ok = supportsIp();
        ip.disabled = !ok;
        ipgenBtn.style.display = ok ? '' : 'none';
        if (!ok) { ip.value = ''; ip.placeholder = tr('dk.net_no_static'); }
        else ip.placeholder = tr('dk.ipv4_addr');
      };
      if (v && v.ipv4) ip.value = v.ipv4;
      else if (v && v.genip && supportsIp()) { const g = randIpFromSubnet(subnet()); if (g) ip.value = g; }
      syncIp();
      sel.onchange = () => { syncIp(); if (supportsIp() && !ip.value) { const g = randIpFromSubnet(subnet()); if (g) ip.value = g; } refreshNetUI(); };
      macgenBtn.onclick = () => { mac.value = randMac(); mac.dispatchEvent(new Event('input', { bubbles: true })); };
      ipgenBtn.onclick = () => { if (!supportsIp()) return; const g = randIpFromSubnet(subnet()); if (g) { ip.value = g; ip.dispatchEvent(new Event('input', { bubbles: true })); } else toast(tr('dk.ipv4_need_subnet'), 'err'); };
      row.querySelector('.rm').onclick = () => { row.remove(); refreshNetUI(); };
      $('ccNets').appendChild(row);
      refreshNetUI();
    };
    $('ccNetAdd').onclick = () => netRow({ genip: true });
    // Network MODE: default (bridge / custom rows) vs the exclusive host/none
    // modes. host/none hide the attachment rows and take no port mappings.
    const netMode = () => $('ccNetMode').value;
    const syncNetMode = () => {
      const m = netMode();
      $('ccNetRows').classList.toggle('hidden', !!m);
      const hint = $('ccNetModeHint');
      hint.classList.toggle('hidden', !m);
      if (m) hint.textContent = m === 'host' ? tr('dk.net_mode_host_hint') : tr('dk.net_mode_none_hint');
    };
    $('ccNetMode').onchange = syncNetMode;
    const readNetworks = () => {
      const m = netMode();
      if (m) return [{ network: m }];
      return Array.from($('ccNets').querySelectorAll('.netrow')).map((r) => ({
        network: r.querySelector('.nr-net').value,
        mac: r.querySelector('.nr-mac').value.trim() || undefined,
        ipv4: r.querySelector('.nr-ip').value.trim() || undefined,
      })).filter((n) => n.network);
    };
    // on-failure exposes the optional max-retries count (0 = unlimited).
    const syncRestartN = () => $('ccRestartN').classList.toggle('hidden', $('ccRestart').value !== 'on-failure');
    $('ccRestart').onchange = syncRestartN;
    const readRestart = () => {
      const v = $('ccRestart').value;
      const n = Number($('ccRestartN').value) || 0;
      return (v === 'on-failure' && n > 0) ? `on-failure:${n}` : v;
    };
    // Memory unit (MB/GB) toggle.
    let memUnit = 'MB';
    const updMemHint = () => {
      const max = memMaxMb > 0 ? (memUnit === 'GB' ? (memMaxMb / 1024).toFixed(2) + 'GB' : memMaxMb.toFixed(0) + 'MB') : '';
      $('ccMemHint').textContent = max ? tr('dk.mem_limit_hint', { n: max }) : tr('dk.mem_limit_off');
    };
    $('ccMemUnit').onclick = () => { memUnit = memUnit === 'MB' ? 'GB' : 'MB'; $('ccMemUnit').textContent = memUnit; updMemHint(); $('ccMem').dispatchEvent(new Event('input', { bubbles: true })); };
    updMemHint();
    // Pre-fill from an existing container (edit / upgrade).
    if (prefill) {
      const cfg = prefill;
      const applyImg = () => {
        const sel = $('ccImg');
        if (cfg.image && !Array.from(sel.options).some((o) => o.value === cfg.image)) {
          const o = document.createElement('option'); o.value = cfg.image; o.textContent = dockerShortRef(cfg.image); sel.appendChild(o);
        }
        if (cfg.image) sel.value = cfg.image;
      };
      applyImg(); // immediate; loadImages re-asserts it once the list arrives
      // Editing can't change the image (recreating with a different image is
      // what "Upgrade" is for) — lock the select so it's clearly read-only.
      const img = $('ccImg');
      img.disabled = true;
      img.removeAttribute('data-selx-search');
      $('ccName').value = cfg.name || '';
      // "on-failure:3" round-trips into the select + the retries count.
      const rp = cfg.restart || 'unless-stopped';
      const rpm = rp.match(/^on-failure(?::(\d+))?$/);
      $('ccRestart').value = rpm ? 'on-failure' : rp;
      if (rpm && rpm[1]) $('ccRestartN').value = rpm[1];
      syncRestartN();
      $('ccCmd').value = cfg.command || '';
      $('ccTty').checked = !!cfg.tty;
      $('ccStdin').checked = !!cfg.interactive;
      $('ccStart').checked = true;
      (cfg.ports || []).forEach((p) => portRow({ ip: p.host_ip, h: p.host, c: p.container, proto: p.proto, ipv6: p.ipv6 }));
      (cfg.env || []).forEach((e) => { const i = e.indexOf('='); envRow({ k: i >= 0 ? e.slice(0, i) : e, v: i >= 0 ? e.slice(i + 1) : '' }); });
      (cfg.volumes || []).forEach((v) => volRow({ host: v.host, container: v.container, readonly: v.readonly }));
      // A host/none first network is the exclusive MODE, not an attachment row.
      const nets = cfg.networks || [];
      const exclusive = nets.length === 1 && (nets[0].network === 'host' || nets[0].network === 'none');
      if (exclusive) { $('ccNetMode').value = nets[0].network; syncNetMode(); }
      else nets.forEach((n) => netRow(n));
      $('ccHost').value = cfg.hostname || '';
      $('ccDomain').value = cfg.domainname || '';
      $('ccDns').value = (cfg.dns || []).join(' ');
      $('ccCpuShares').value = cfg.cpu_shares ? cfg.cpu_shares : 1024;
      $('ccCpus').value = cfg.cpus ? Number(cfg.cpus) : 0;
      $('ccMem').value = cfg.memory ? Math.round(Number(cfg.memory) / 1048576) : 0;
      $('ccPriv').checked = !!cfg.privileged;
      $('ccPids').value = cfg.pids_limit || 0;
      $('ccStopT').value = cfg.stop_timeout || 10;
      $('ccStopSig').value = cfg.stop_signal || '';
      $('ccRm').checked = !!cfg.auto_remove;
    } else {
      // New container: pre-add the default bridge network (random MAC). The
      // default bridge can't take a static IPv4, so none is generated for it.
      // (On the dn7 runtime there is no `bridge` — fall back to the built-in.)
      netRow({ network: netList.some((n) => n.name === 'bridge') ? 'bridge' : (netList[0] || {}).name });
    }
    // Row validation: truly empty rows are dropped silently at submit, but a
    // half-filled or malformed row blocks submit — the row is highlighted and a
    // toast names the offending tab (instead of silently discarding the data).
    const rowSt = {
      ports: (row) => {
        const [h, c] = Array.from(row.querySelectorAll('input:not([type="checkbox"])')).map((i) => i.value.trim());
        if (!h && !c) return 'empty';
        return (isPortNum(h) && isPortNum(c)) ? 'ok' : 'bad';
      },
      env: (row) => {
        const [k, vv] = Array.from(row.querySelectorAll('input')).map((i) => i.value.trim());
        if (!k && !vv) return 'empty';
        return /^[^=\s]+$/.test(k) ? 'ok' : 'bad';
      },
      vol: (row) => {
        const isVol = row.querySelector('.vr-type').value === 'vol';
        const src = isVol ? row.querySelector('.vr-vol').value : row.querySelector('.vr-host').value.trim();
        const ctn = row.querySelector('.vr-ctn').value.trim();
        if (!src && !ctn) return 'empty';
        if (!src || !ctn.startsWith('/')) return 'bad';
        return (isVol || src.startsWith('/')) ? 'ok' : 'bad';
      },
      net: (row) => {
        const net = row.querySelector('.nr-net').value;
        const mac = row.querySelector('.nr-mac').value.trim();
        const ip = row.querySelector('.nr-ip').value.trim();
        if (!net) return 'empty';
        if (mac && !isMac(mac)) return 'bad';
        if (ip) {
          if (!isIPv4(ip)) return 'bad';
          const sub = (netList.find((x) => x.name === net) || {}).subnet;
          if (sub && !ipInSubnet(ip, sub)) { ccBadMsg = ccBadMsg || tr('dk.net_ip_outside', { ip, net, subnet: sub }); return 'bad'; }
        }
        return 'ok';
      },
    };
    let ccBadMsg = null;
    const ccValidate = () => {
      ccBadMsg = null;
      const groups = [
        { tab: 'net', id: 'ccNets', row: '.netrow', st: rowSt.net, label: tr('dk.tab_networks') },
        { tab: 'ports', id: 'ccPorts', row: '.kvrow', st: rowSt.ports, label: tr('dk.tab_ports') },
        { tab: 'vol', id: 'ccVol', row: '.volrow', st: rowSt.vol, label: tr('dk.tab_volumes') },
        { tab: 'env', id: 'ccEnv', row: '.kvrow', st: rowSt.env, label: tr('dk.tab_env') },
      ];
      let first = null;
      groups.forEach((g) => Array.from($(g.id).querySelectorAll(g.row)).forEach((row) => {
        const s = g.st(row);
        row.classList.toggle('bad', s === 'bad');
        if (s === 'bad' && !first) first = g;
      }));
      if (!first) return true;
      selTab(first.tab);
      toast((first.tab === 'net' && ccBadMsg) || tr('dk.rows_invalid', { tab: first.label }), 'err');
      return false;
    };
    // Editing a highlighted row clears its error mark right away.
    ['ccNets', 'ccPorts', 'ccVol', 'ccEnv'].forEach((id) => ['input', 'change'].forEach((evn) =>
      $(id).addEventListener(evn, (e) => { const r = e.target.closest('.kvrow,.netrow'); if (r) r.classList.remove('bad'); })));
    const doSubmit = () => {
      const image = $('ccImg').value.trim(); if (!image) return toast(tr('dk.need_image'), 'err');
      if (!ccValidate()) return;
      const ports = readKv('ccPorts').map((r) => ({ host_ip: (r[0] || '').trim() || undefined, host: Number(r[1]), container: Number(r[2]), proto: r.proto || 'tcp', ipv6: r.ipv6 || undefined })).filter((p) => p.host && p.container);
      // Mirror the server rule up front: host/none network modes take no port
      // mappings (host already exposes everything; none has no connectivity).
      if (ports.length && netMode()) { selTab('ports'); return toast(tr('err.docker.ports_with_host_net'), 'err'); }
      const env = readKv('ccEnv').map((r) => (r[0] ? r[0] + '=' + (r[1] || '') : '')).filter(Boolean);
      const volumes = readVolumes();
      const networks = readNetworks();
      const dns = $('ccDns').value.trim().split(/[\s,]+/).filter(Boolean);
      const cpuShares = Number($('ccCpuShares').value) || 0;
      const cpusV = Number($('ccCpus').value) || 0;
      const memV = Number($('ccMem').value) || 0;
      const body = {
        op: 'create_container', image, name: $('ccName').value.trim() || undefined, restart: readRestart(),
        ports, env, volumes, command: $('ccCmd').value.trim() || undefined, tty: $('ccTty').checked, interactive: $('ccStdin').checked, start: $('ccStart').checked,
        networks,
        hostname: $('ccHost').value.trim() || undefined, domainname: $('ccDomain').value.trim() || undefined,
        dns: dns.length ? dns : undefined, cpu_shares: cpuShares || undefined,
        cpus: cpusV > 0 ? String(cpusV) : undefined, memory: memV > 0 ? memV + (memUnit === 'GB' ? 'g' : 'm') : undefined,
        privileged: $('ccPriv').checked || undefined,
        pids_limit: Number($('ccPids').value) > 0 ? Number($('ccPids').value) : undefined,
        stop_timeout: (Number($('ccStopT').value) > 0 && Number($('ccStopT').value) !== 10) ? Number($('ccStopT').value) : undefined,
        stop_signal: $('ccStopSig').value.trim() || undefined,
        auto_remove: $('ccRm').checked || undefined,
      };
      if (opts.replaceName) body.replace = opts.replaceName;
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden');
      op('docker', body).then((r) => renderJob($('ccJob'), 'docker', r.op_id, 'docker:create', { onDone: () => { toast(opts.doneMsg || tr('dk.ctn_created'), 'ok'); close(); switchTab('docker'); }, onError: () => { $('ccGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ccGo').disabled = false; });
    };
    $('ccGo').onclick = () => {
      if (opts.confirmMsg) { confirmDanger(opts.confirmMsg).then((ok) => { if (ok) doSubmit(); }); } else doSubmit();
    };
    // Bind on the modal body so the whole 6-tab form is dirty-tracked — modal()
    // then guards backdrop/X/Escape dismissal behind a discard confirm.
    bindDirty('ccGo', root.querySelector('.modal-b'));
  }, {
    big: true,
    // Rendered as a flex sibling of .modal-b so the primary button reads as a
    // true footer flush to the modal bottom (not a sticky row inside the body).
    foot: `<div id="ccJob" class="mf-job hidden"></div><button class="btn" id="ccGo">${opts.submitLabel || tr('dk.create')}</button>`,
  });
}

// Generate a locally-administered random unicast MAC (02:xx:xx:xx:xx:xx).
function randMac() {
  const h = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  return ['02', h(), h(), h(), h(), h()].join(':');
}

// Suggest a random host address inside an IPv4 subnet (last octet 2–251).
// Editable by the user; only a convenience for user-defined networks.
function randIpFromSubnet(subnet) {
  if (!subnet || subnet.indexOf('/') < 0) return '';
  const base = subnet.split('/')[0].split('.');
  if (base.length !== 4) return '';
  base[3] = String(2 + Math.floor(Math.random() * 250));
  return base.join('.');
}

// ---- Shared format validators (used here and by docker-net.js) ----
function isPortNum(v) { const n = Number(v); return Number.isInteger(n) && n >= 1 && n <= 65535; }
function isIPv4(s) { const p = String(s || '').split('.'); return p.length === 4 && p.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255); }
function isCidr(s) { const p = String(s || '').split('/'); return p.length === 2 && isIPv4(p[0]) && /^\d{1,2}$/.test(p[1]) && Number(p[1]) <= 32; }
function isMac(s) { return /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(String(s || '')); }

// True if an IPv4 address falls within a CIDR subnet (e.g. 172.20.0.5 in
// 172.20.0.0/16). Returns true when the subnet is unparseable (skip check).
function ipInSubnet(ip, cidr) {
  const toInt = (s) => {
    const p = s.split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (const o of p) { const v = Number(o); if (!Number.isInteger(v) || v < 0 || v > 255) return null; n = (n * 256) + v; }
    return n >>> 0;
  };
  const parts = (cidr || '').split('/');
  if (parts.length !== 2) return true;
  const net = toInt(parts[0]), bits = Number(parts[1]), addr = toInt(ip);
  if (net == null || addr == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return true;
  if (bits === 0) return true;
  const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
  return (net & mask) === (addr & mask);
}

// Human-readable byte size + epoch-second timestamp helpers (monitor/backups).
function dkHuman(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + u[i];
}
function dkFmtTime(secs) { return secs ? fmtTsFull(secs) : '-'; }
// Absolute YYYY-MM-DD HH:MM:SS (configured display timezone) from epoch seconds
// (number) or an ISO string.
function fmtDateTime(v) {
  if (v == null || v === '' || v === 0) return '-';
  const d = (typeof v === 'number') ? new Date(v * 1000) : new Date(v);
  if (isNaN(d.getTime())) return (typeof v === 'string' ? v : '-');
  return fmtTsFull(d.getTime() / 1000);
}
