// =========================================================================
// Website management
// =========================================================================
// Active Website sub-tab: 'hosts' | 'access' | 'certs' | 'settings'.
let ngTab = 'hosts';
function renderWebsite(v) {
  v.innerHTML = `<div style="padding:8px">${loading(tr('ng.detecting'))}</div>`;
  if (getJob('website:setup')) {
    v.innerHTML = `<div class="card"><h3>${tr('ng.initializing')}</h3><div id="ngSetupJob"></div></div>`;
    reattachJob($('ngSetupJob'), 'website:setup', { onDone: () => setTimeout(() => renderWebsite(v), 800) });
    return;
  }
  op('website', { op: 'info' }).then((info) => {
    if (!info.managed) {
      v.innerHTML = `<div class="card"><h3>${tr('ng.init_title')}</h3>
        <p class="mut">${tr('ng.init_hint')}</p>
        <div class="row" style="margin:14px 0">
          <button class="btn" id="ngSetup">${tr('ng.init_btn')}</button>
        </div>
        <div class="hidden" id="ngSetupJob"></div></div>`;
      $('ngSetup').onclick = () => { $('ngSetup').disabled = true; $('ngSetupJob').classList.remove('hidden'); op('website', { op: 'setup' }).then((r) => renderJob($('ngSetupJob'), 'website', r.op_id, 'website:setup', { onDone: () => { toast(tr('ng.init_done'), 'ok'); setTimeout(() => renderWebsite(v), 600); }, onError: () => { $('ngSetup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ngSetup').disabled = false; }); };
      return;
    }
    const banner = info.port_conflict ? portConflictCard(info) : '';
    v.innerHTML = banner + `
      <div class="subtabs" id="ngTabs" style="margin-bottom:16px">
        <button data-t="hosts">${tr('ng.tab_hosts')}</button>
        <button data-t="access">${tr('ng.tab_access')}</button>
        <button data-t="certs">${tr('ng.tab_certs')}</button>
        <button data-t="default">${tr('ng.tab_default')}</button>
        <button data-t="settings">${tr('ng.tab_settings')}</button>
      </div>
      <div id="ngBody"></div>`;
    if (info.port_conflict) wireForceStart(v);
    const tabs = $('ngTabs');
    const sel = (t) => {
      ngTab = t;
      tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.t === t));
      if (t === 'access') ngAccessTab(v);
      else if (t === 'certs') ngCertsTab(v);
      else if (t === 'default') ngDefaultTab(v);
      else if (t === 'settings') ngSettingsTab(v);
      else ngHostsTab(v, info);
    };
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => sel(b.dataset.t));
    sel(ngTab);
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}

// A warning banner shown when the built-in web server couldn't bind :80/:443
// because another process holds them. Offers a force-start (kills the occupant).
function portConflictCard(info) {
  const ports = (info.conflict_ports || []).join('、');
  const procs = info.conflict_procs || {};
  const who = Object.keys(procs)
    .map((p) => `:${p} → ${esc(procs[p] || '?')}`)
    .join('；');
  return `<div class="card" id="ngConflict" style="border-color:var(--err,#c0392b);margin-bottom:14px">
    <h3 class="err">${tr('ng.conflict_title')}</h3>
    <p class="mut">${tr('ng.conflict_msg', { ports: esc(ports) })}</p>
    ${who ? `<p class="mut" style="font-size:.9em">${who}</p>` : ''}
    <div class="row" style="margin-top:10px">
      <button class="btn danger" id="ngForceStart">${tr('ng.force_start_btn')}</button>
    </div>
  </div>`;
}

// Wire the force-start button: confirm (destructive — it kills processes), then
// call the op and re-render on success.
function wireForceStart(v) {
  const btn = $('ngForceStart');
  if (!btn) return;
  btn.onclick = async () => {
    if (!(await confirmDanger(tr('ng.force_confirm')))) return;
    btn.disabled = true;
    op('website', { op: 'force_start' })
      .then(() => { toast(tr('ng.force_done'), 'ok'); setTimeout(() => renderWebsite(v), 600); })
      .catch((e) => { toast(e.message, 'err'); btn.disabled = false; });
  };
}

// ---- Tab 1: Proxy Hosts (the managed site list) ----
function ngHostsTab(v, info) {
  const body = $('ngBody');
  // Status chip reflects the server state instead of a hard-coded green:
  // a port conflict means the sites below are in fact not being served.
  const bad = !!(info && (info.port_conflict || info.host_owns_ports === false));
  const ports = (info && info.conflict_ports && info.conflict_ports.length) ? info.conflict_ports.join('、') : '80/443';
  const st = bad
    ? `<span class="chip warn" title="${esc(tr('ng.conflict_msg', { ports }))}">${esc(tr('ng.conflict_title'))}</span>`
    : `<span class="chip on">${tr('ng.running')}</span>`;
  body.innerHTML = `<div class="row" style="margin-bottom:14px">${st}<span class="sp" style="flex:1"></span><button class="btn sm" id="ngAdd">${tr('ng.add_site')}</button><button class="btn sec sm" id="ngRef">${tr('ng.refresh')}</button></div><div class="hidden" id="ngIssueWrap" style="margin-bottom:14px"><div class="card"><h3>${tr('site.issuing')}</h3><div id="ngIssueJob"></div></div></div><div id="ngSites">${loading()}</div>`;
  $('ngRef').onclick = () => ngHostsTab(v, info);
  $('ngAdd').onclick = () => ngAddSite(() => ngHostsTab(v, info));
  // A site create/update (possibly with an ACME issuance) persisted in the job
  // store keeps reporting here even after its modal was closed.
  if (getJob('website:issue')) {
    $('ngIssueWrap').classList.remove('hidden');
    reattachJob($('ngIssueJob'), 'website:issue', { onDone: () => setTimeout(() => ngHostsTab(v, info), 800) });
  }
  Promise.all([op('website', { op: 'list_sites' }), op('website', { op: 'list_named_certs' }), op('website', { op: 'list_access' })]).then(([d, cd, ad]) => {
    const sites = d.sites || [];
    const modes = {};
    (cd.certs || []).forEach((c) => { modes[c.name] = c; });
    const accById = {};
    (ad.access || []).forEach((a) => { accById[a.id] = a.name; });
    if (!sites.length) { $('ngSites').innerHTML = `<div class="empty">${tr('ng.no_sites')}</div>`; return; }
    let h = `<table class="optable"><tr><th>${tr('ng.col_domain')}</th><th>${tr('ng.col_type')}</th><th>${tr('ng.col_target')}</th><th>${tr('ng.col_access')}</th><th>${tr('ng.col_ssl')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
    sites.forEach((s) => {
      const sch = s.scheme === 'https' ? 'https://' : (s.kind === 'static' ? '' : 'http://');
      let target = s.kind === 'proxy_host' ? esc(sch + s.target_url) : s.kind === 'proxy_container' ? esc(`${sch}${s.container}:${s.container_port}`) : esc(s.local_root ? s.local_root : '/' + s.root);
      if (s.locations && s.locations.length) target += ` <span class="mut">${tr('ng.rules_count', { n: s.locations.length })}</span>`;
      const acc = s.access_id && accById[s.access_id] ? `<span class="chip">${esc(accById[s.access_id])}</span>` : `<span class="mut">${tr('ng.access_public')}</span>`;
      h += `<tr><td><b>${esc(s.server_name)}</b></td><td class="mut">${esc(kindLabel(s.kind))}</td><td class="mono" style="font-size:12px">${target}</td><td>${acc}</td><td>${sslLabel(s, modes)}</td><td class="act"><button class="btn sm sec" data-edit="${esc(s.id)}">${tr('ng.edit_site')}</button><button class="btn sm danger" data-rm="${esc(s.id)}">${tr('ng.delete')}</button></td></tr>`;
    });
    $('ngSites').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#ngSites [data-edit]').forEach((b) => b.onclick = () => { const s = sites.find((x) => String(x.id) === b.dataset.edit); if (s) ngAddSite(() => ngHostsTab(v, info), s); });
    document.querySelectorAll('#ngSites [data-rm]').forEach((b) => b.onclick = async () => { const s = sites.find((x) => String(x.id) === b.dataset.rm); if (await confirmDanger(tr('site.confirm_del', { name: (s && s.server_name) || b.dataset.rm }))) op('website', { op: 'remove_site', site_id: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); ngHostsTab(v, info); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { $('ngSites').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
function kindLabel(k) { return { proxy_host: tr('ng.kind_proxy_host'), proxy_container: tr('ng.kind_proxy_container'), static: tr('ng.kind_static') }[k] || k; }

// Health of a library cert entry: 'missing' | 'expired' | 'expiring' (within
// 14 days) | null (healthy or unknown). `not_after` is "YYYY-MM-DD".
function ngCertHealth(c) {
  if (!c) return null;
  if (!c.has_cert) return 'missing';
  const t = Date.parse(c.not_after || '');
  if (isNaN(t)) return null;
  if (t < Date.now()) return 'expired';
  if (t - Date.now() < 14 * 864e5) return 'expiring';
  return null;
}

// SSL column label: show the certificate kind (Let's Encrypt / self-signed /
// custom) instead of a plain yes/no, plus a health chip when the referenced
// library cert is missing/expired/expiring. `certs` maps cert name → cert.
function sslLabel(s, certs) {
  if (!s.ssl) return `<span class="chip">${tr('ng.ssl_off')}</span>`;
  const c = (s.cert_name && certs[s.cert_name]) || null;
  const m = (c && c.cert_mode) || s.cert_mode || 'named';
  let base;
  if (m === 'le') base = `<span class="chip on">Let's Encrypt</span>`;
  else if (m === 'self') base = `<span class="chip">${tr('ng.cm_self')}</span>`;
  else if (m === 'manual') base = `<span class="chip on">${tr('ng.cm_manual')}</span>`;
  else base = `<span class="chip on">${tr('ng.yes')}</span>`;
  const hl = (s.cert_name && !c) ? 'missing' : ngCertHealth(c); // named cert gone from the library counts as missing
  if (hl === 'missing') base += ` <span class="chip err">${tr('ng.missing')}</span>`;
  else if (hl === 'expired') base += ` <span class="chip err" title="${esc(c.not_after || '')}">${tr('site.cert_expired')}</span>`;
  else if (hl === 'expiring') base += ` <span class="chip warn" title="${esc(c.not_after || '')}">${tr('site.cert_expiring')}</span>`;
  return base;
}

// Feather-style line icons for the advanced-feature cards (the app draws icons
// as inline SVG, not an icon font). stroke=currentColor inherits the accent.
const AF_ICONS = {
  rl: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  bw: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>',
  conn: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/>',
  acl: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  hot: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="M21 15l-5-5L5 21"/>',
  waf: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  code: '<path d="M16 18l6-6-6-6"/><path d="M8 6l-6 6 6 6"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
  warn: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
};
function afsvg(k, sz) { return `<svg viewBox="0 0 24 24" width="${sz || 18}" height="${sz || 18}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${AF_ICONS[k]}</svg>`; }

// One advanced-feature card: accent icon + title + master switch; the body
// (config) shows only while the switch is on. `swId` is the persisted control.
function afCard(feat, color, icon, title, desc, swId, body, checked) {
  return `<div class="afcard" data-feat="${feat}">
    <div class="afhead">
      <span class="afic ${color}">${afsvg(icon)}</span>
      <span class="afm"><b>${title}</b><span>${desc}</span></span>
      <label class="afsw"><input type="checkbox" id="${swId}"${checked ? ' checked' : ''} /><span class="afsb"></span></label>
    </div>
    <div class="afbody">${body}</div>
  </div>`;
}

function ngAddSite(reload, site) {
  const editing = !!site;
  modal(editing ? tr('ng.edit_site_title') : tr('ng.add_site_title'), `
    <div class="ftabs" id="nsTabs">
      <button class="on" data-t="detail">${tr('ng.tab_detail')}</button>
      <button data-t="rules">${tr('ng.tab_rules')}</button>
      <button data-t="ssl">${tr('ng.tab_ssl')}</button>
      <button data-t="conf">${tr('ng.tab_adv')}</button>
    </div>
    <div class="ftab-pane on" data-p="detail">
      <div class="formgrid">
        <div class="full"><label class="lbl">${tr('ng.domain_label')}</label><input id="nsName" class="field" placeholder="example.com" /></div>
        <div class="full"><label class="lbl">${tr('ng.type')}</label><select id="nsKind" class="field">
          <option value="proxy_host">${tr('ng.type_proxy_host')}</option>
          <option value="proxy_container">${tr('ng.type_proxy_container')}</option>
          <option value="static">${tr('ng.type_static')}</option>
        </select></div>
        <div class="full" id="nsKindFields"></div>
      </div>
      <div style="margin-top:14px"><label class="lbl">${tr('ng.access_label')}</label><select id="nsAccess" class="field"><option value="">${tr('ng.access_public')}</option></select><p class="formnote" style="margin-top:6px">${tr('ng.access_hint')}</p></div>
      <div class="switchrow" style="margin-top:8px;gap:2px 18px">
        <label class="switch"><input type="checkbox" id="nsCache" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.sw_cache')}</b><span>${tr('ng.sw_cache_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="nsWs" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.sw_ws')}</b><span>${tr('ng.sw_ws_d')}</span></span></label>
      </div>
    </div>
    <div class="ftab-pane" data-p="rules">
      <p class="mut" style="font-size:12.5px;margin:0 0 12px">${tr('ng.rules_intro')}</p>
      <div id="nsLocs"></div>
      <button type="button" class="locadd" id="nsLocAdd">${tr('ng.add_rule')}</button>
    </div>
    <div class="ftab-pane" data-p="ssl">
      <label class="switch"><input type="checkbox" id="nsSsl" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.enable_https')}</b><span>${tr('ng.enable_https_d')}</span></span></label>
      <div class="hidden" id="nsSslBody" style="margin-top:16px">
        <label class="lbl">${tr('ng.cert_method')}</label>
        <div class="segbtns" id="nsCertMethod">
          <button type="button" class="on" data-m="auto">${tr('ng.cm_auto')}</button>
          <button type="button" data-m="self">${tr('ng.cm_self')}</button>
        </div>
        <div id="nsKeyTypeWrap" style="margin-top:14px">
          <label class="lbl">${tr('ng.key_type')}</label>
          <select id="nsKeyType" class="field"><option value="ecdsa-p256">${tr('ng.key_type_p256')}</option><option value="ecdsa-p384">${tr('ng.key_type_p384')}</option></select>
          <p class="formnote" style="margin-top:4px">${tr('ng.key_type_hint')}</p>
        </div>
        <div id="nsAutoWrap" style="margin-top:14px">
          <label class="lbl">${tr('ng.same_domain_certs')}</label>
          <div id="nsCertList" class="certlist"></div>
          <p class="formnote hidden" id="nsLeHint">${tr('ng.hint_le')}</p>
        </div>
        <div class="ssltoggles" style="margin-top:16px">
          <label class="switch"><input type="checkbox" id="nsForceSsl" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.force_ssl')}</b><span>${tr('ng.force_ssl_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsHsts" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.hsts')}</b><span>${tr('ng.hsts_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsHstsSub" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.hsts_sub')}</b><span>${tr('ng.hsts_sub_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsTrustProxy" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.trust_proxy')}</b><span>${tr('ng.trust_proxy_d')}</span></span></label>
          <div id="nsTrustProxyCidrsRow" style="display:none;margin-top:8px">
            <label class="lbl" style="font-size:12.5px">${tr('ng.trust_proxy_cidrs')}</label>
            <input type="text" id="nsTrustProxyCidrs" placeholder="${tr('ng.trust_proxy_cidrs_ph')}" />
            <p class="formnote" style="margin-top:4px">${tr('ng.trust_proxy_cidrs_d')}</p>
          </div>
        </div>
        <p class="formnote">${tr('ng.autorenew_note')}</p>
      </div>
    </div>
    <div class="ftab-pane" data-p="conf">
      <div class="afbar">${afsvg('waf', 16)}<span><b id="nsAfCount">0</b> ${tr('ng.af_active')}</span>
        <span class="afpips"><span class="afpip" data-feat="rl" style="background:var(--cy)"></span><span class="afpip" data-feat="bw" style="background:var(--br)"></span><span class="afpip" data-feat="ban" style="background:var(--warn)"></span><span class="afpip" data-feat="acl" style="background:var(--vio)"></span><span class="afpip" data-feat="waf" style="background:var(--err)"></span></span></div>
      <div class="afstack" id="nsAdv">
        ${afCard('rl', 'cy', 'rl', tr('ng.af_rl'), tr('ng.af_rl_d'), 'nsRlOn',
          `<div class="afgrid">
            <div class="affld"><label>${tr('ng.af_rl_rps')}</label><div class="field-suffix"><input id="nsRlRps" class="field" type="number" min="0" value="10" /><span class="suffix-tag">req/s</span></div></div>
            <div class="affld"><label>${tr('ng.af_rl_burst')}</label><div class="field-suffix"><input id="nsRlBurst" class="field" type="number" min="0" value="20" /><span class="suffix-tag">${tr('ng.af_u_times')}</span></div></div>
          </div><p class="afnote">${afsvg('info', 14)}${tr('ng.af_rl_note')}</p>`)}
        ${afCard('bw', 'br', 'bw', tr('ng.af_bw'), tr('ng.af_bw_d'), 'nsBwOn',
          `<div class="afgrid"><div class="affld"><label>${tr('ng.af_bw_rate')}</label><div class="field-suffix"><input id="nsBwKbps" class="field" type="number" min="0" value="1024" /><span class="suffix-tag">KB/s</span></div></div><div class="affld spacer"></div></div>`)}
        ${afCard('conn', 'br', 'conn', tr('ng.af_conn'), tr('ng.af_conn_d'), 'nsConnOn',
          `<div class="afgrid"><div class="affld"><label>${tr('ng.af_conn_max')}</label><div class="field-suffix"><input id="nsConnIp" class="field" type="number" min="0" value="50" /><span class="suffix-tag">${tr('ng.af_u_conn')}</span></div></div><div class="affld spacer"></div></div>`)}
        ${afCard('ban', 'wn', 'ban', tr('ng.af_ban'), tr('ng.af_ban_d'), 'nsBanOn',
          `<div class="afgrid">
            <div class="affld"><label>${tr('ng.af_ban_thresh')}</label><div class="field-suffix"><input id="nsBanThresh" class="field" type="number" min="0" value="10" /><span class="suffix-tag">${tr('ng.af_u_times')}</span></div></div>
            <div class="affld"><label>${tr('ng.af_ban_window')}</label><div class="field-suffix"><input id="nsBanWindow" class="field" type="number" min="0" value="60" /><span class="suffix-tag">${tr('ng.af_u_sec')}</span></div></div>
            <div class="affld"><label>${tr('ng.af_ban_dur')}</label><div class="field-suffix"><input id="nsBanMin" class="field" type="number" min="0" value="10" /><span class="suffix-tag">${tr('ng.af_u_min')}</span></div></div>
          </div>`)}
        ${afCard('acl', 'vio', 'acl', tr('ng.af_acl'), tr('ng.af_acl_d'), 'nsAclOn',
          `<div class="aflabel">${tr('ng.af_acl_mode')}</div><div class="segbtns" id="nsAclSeg"><button type="button" class="on" data-m="allow">${tr('ng.af_acl_allow')}</button><button type="button" data-m="deny">${tr('ng.af_acl_deny')}</button></div>
           <div class="aflabel">${tr('ng.af_acl_list')}</div><textarea id="nsAclList" class="field mono" rows="2" spellcheck="false" placeholder="203.0.113.0/24"></textarea>`)}
        ${afCard('hot', 'vio', 'hot', tr('ng.af_hot'), tr('ng.af_hot_d'), 'nsHotOn',
          `<div class="aflabel">${tr('ng.af_hot_ref')}</div><input id="nsHotlink" class="field" placeholder="example.com  *.example.com" />`)}
        ${afCard('waf', 'er', 'waf', tr('ng.af_waf'), tr('ng.af_waf_d'), 'nsBlock',
          `<div class="afchips"><span class="afchip">${tr('ng.af_waf_sqli')}</span><span class="afchip">${tr('ng.af_waf_xss')}</span><span class="afchip">${tr('ng.af_waf_trav')}</span><span class="afchip">${tr('ng.af_waf_scan')}</span></div>`)}
        ${afCard('code', 'mu', 'code', tr('ng.af_expert'), tr('ng.af_expert_d'), 'nsConfOn',
          `<textarea id="nsConf" class="field mono confbox" rows="6" spellcheck="false" placeholder="${tr('ng.conf_ph')}"></textarea><p class="afnote">${afsvg('warn', 14)}${tr('ng.conf_note')}</p>`)}
      </div>
    </div>`, (close, root) => {
    document.querySelectorAll('#nsTabs button').forEach((b) => b.onclick = () => {
      document.querySelectorAll('#nsTabs button').forEach((x) => x.className = x === b ? 'on' : '');
      document.querySelectorAll('.ftab-pane').forEach((p) => p.className = 'ftab-pane' + (p.dataset.p === b.dataset.t ? ' on' : ''));
      if (b.dataset.t === 'ssl' && $('nsSsl').checked && certMethod === 'auto') loadCertList();
    });

    // Advanced-feature cards: the head toggles its master switch + reveals the
    // body; the summary bar counts active features. (No inline handlers — the
    // CSP forbids them.) afSync() is called once after the edit-prefill below.
    const afSync = () => {
      let n = 0;
      document.querySelectorAll('#nsAdv .afcard').forEach((c) => {
        const on = c.querySelector('.afsw input').checked;
        c.classList.toggle('on', on);
        const pip = document.querySelector(`.afpip[data-feat="${c.dataset.feat}"]`);
        if (pip) pip.style.opacity = on ? '1' : '.3';
        if (on) n++;
      });
      $('nsAfCount').textContent = n;
    };
    document.querySelectorAll('#nsAdv .afhead').forEach((h) => h.onclick = (e) => {
      if (e.target.closest('.afsw')) return;
      const cb = h.querySelector('.afsw input'); cb.checked = !cb.checked; afSync();
    });
    document.querySelectorAll('#nsAdv .afsw input').forEach((cb) => cb.onchange = afSync);
    document.querySelectorAll('#nsAclSeg button').forEach((b) => b.onclick = () => document.querySelectorAll('#nsAclSeg button').forEach((x) => x.classList.toggle('on', x === b)));

    // SSL state: 'auto' (Let's Encrypt — reuse a matching cert or issue one) or
    // 'self' (self-signed). `selectedCert` is the chosen library cert name, ''
    // means "issue a new Let's Encrypt cert", null means "not yet decided".
    // `userPicked` pins an explicit select choice; `sitePrefill` seeds the edit
    // form's saved cert once — both yield to a re-match when the domain changes.
    let certMethod = 'auto';
    let selectedCert = null;
    let userPicked = false;
    let sitePrefill = editing && !!site.cert_name;
    let domainCerts = [];
    const certCovers = (cd, host) => {
      if (!cd || !host) return false;
      if (cd === host) return true;
      if (cd.startsWith('*.')) return host.endsWith(cd.slice(1)) && host.split('.').length === cd.split('.').length;
      return false;
    };
    // The Let's Encrypt preconditions hint (port 80 reachable, DNS pointing
    // here) shows whenever "issue a new LE cert" is the effective choice.
    const syncLeHint = () => { const e = $('nsLeHint'); if (e) e.classList.toggle('hidden', !(certMethod === 'auto' && selectedCert === '')); };
    const renderCertList = () => {
      const list = $('nsCertList'); if (!list) return;
      const host = $('nsName').value.trim();
      if (selectedCert === null) {
        if (sitePrefill) selectedCert = site.cert_name;
        else { const m = domainCerts.find((c) => certCovers(c.domain, host)); selectedCert = m ? m.name : ''; }
      }
      const names = domainCerts.map((c) => c.name);
      let opts = `<option value=""${selectedCert === '' ? ' selected' : ''} data-sub="${esc(tr('ng.use_new_le_d'))}">${esc(tr('ng.use_new_le'))}</option>`;
      domainCerts.forEach((c) => {
        const right = c.not_after ? esc(tr('ng.col_expire') + ' ' + c.not_after) : '';
        opts += `<option value="${esc(c.name)}"${selectedCert === c.name ? ' selected' : ''} data-sub="${esc(c.name)}" data-right="${right}">${esc(c.domain || c.name)}</option>`;
      });
      // Keep a previously-chosen cert selectable even if it's outside the current
      // base-domain filter (e.g. when editing before the domain field changes).
      if (selectedCert && !names.includes(selectedCert)) {
        opts += `<option value="${esc(selectedCert)}" selected data-sub="${esc(selectedCert)}">${esc(selectedCert)}</option>`;
      }
      list.innerHTML = `<select id="nsCertSel" class="field" data-selx-search>${opts}</select>`;
      $('nsCertSel').onchange = () => { selectedCert = $('nsCertSel').value; userPicked = true; syncLeHint(); };
      syncLeHint();
    };
    const loadCertList = () => {
      $('nsCertList').innerHTML = loading();
      op('website', { op: 'list_named_certs' }).then((d) => {
        domainCerts = (d.certs || []).filter((c) => c.has_cert);
        renderCertList();
      }).catch(() => { domainCerts = []; renderCertList(); });
    };

    let containers = [];
    // Build <option>s for a location-rule container picker, preserving a
    // selected value even if the container list hasn't loaded (or no longer
    // lists it).
    const ctnOptsHtml = (sel) => {
      let opts = containers.map((c) => `<option value="${esc(c.name)}"${c.name === sel ? ' selected' : ''}>${esc(c.name)}${c.ports ? ' · ' + esc(c.ports) : ''}</option>`).join('');
      if (sel && !containers.some((c) => c.name === sel)) opts = `<option value="${esc(sel)}" selected>${esc(sel)}</option>` + opts;
      if (!opts) opts = `<option value="">${tr('ng.no_running_ctn')}</option>`;
      return opts;
    };
    op('website', { op: 'list_containers' }).then((d) => {
      containers = d.containers || [];
      if ($('nsKind').value === 'proxy_container') { kindFields(); prefillKind(); }
      // Refresh any location-rule container pickers built before the list arrived.
      $('nsLocs').querySelectorAll('.lr-ctn').forEach((s) => { s.innerHTML = ctnOptsHtml(s.value); });
    }).catch(() => {});

    // Populate the Access list dropdown (assign an access list to this host).
    op('website', { op: 'list_access' }).then((d) => {
      const sel = $('nsAccess'); if (!sel) return;
      (d.access || []).forEach((a) => { const o = document.createElement('option'); o.value = a.id; o.textContent = a.name; sel.appendChild(o); });
      if (editing && site.access_id) sel.value = site.access_id;
    }).catch(() => {});

    const staticUpload = { mode: null, zip: null };
    // Static-site source: 'upload' (managed www subdir) or 'local' (existing
    // host directory). `setStaticSource` is wired when the static fields render.
    let staticSource = 'upload';
    let setStaticSource = () => {};

    const kindFields = () => {
      const k = $('nsKind').value;
      const proto = `<div><label class="lbl">${tr('ng.scheme')}</label><select id="nsScheme" class="field"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div>`;
      if (k === 'proxy_host') {
        $('nsKindFields').innerHTML = `<div class="formgrid">${proto}<div><label class="lbl">${tr('ng.host_port')}</label><input id="nsTarget" class="field" placeholder="${tr('ng.host_port_ph')}" /></div></div>`;
      } else if (k === 'proxy_container') {
        const opts = containers.length
          ? containers.map((c) => `<option value="${esc(c.name)}">${esc(c.name)}${c.ports ? ' · ' + esc(c.ports) : ''}</option>`).join('')
          : `<option value="">${tr('ng.no_running_ctn')}</option>`;
        $('nsKindFields').innerHTML = `<div class="formgrid">${proto}<div><label class="lbl">${tr('ng.container')}</label><select id="nsCtn" class="field">${opts}</select></div><div><label class="lbl">${tr('ng.container_port')}</label><input id="nsCtnPort" class="field" type="number" placeholder="80" /></div></div>`;
      } else {
        $('nsKindFields').innerHTML = `
          <label class="lbl">${tr('ng.static_source')}</label>
          <div class="segbtns" id="nsSrc">
            <button type="button" class="on" data-s="upload">${tr('ng.src_upload')}</button>
            <button type="button" data-s="local">${tr('ng.src_local')}</button>
          </div>
          <div id="nsSrcUpload" style="margin-top:12px">
            <label class="lbl">${tr('ng.upload_content')}</label>
            <div class="dropz" id="nsDrop"><b>${tr('ng.drop_a')}</b>${tr('ng.drop_b')}<br/><span style="font-size:11.5px">${editing ? tr('ng.drop_keep') : tr('ng.drop_sub')}</span></div>
            <input type="file" id="nsZip" accept=".zip" class="hidden" />
            <div class="uplist" id="nsUpList"></div>
          </div>
          <div id="nsSrcLocal" class="hidden" style="margin-top:12px">
            <label class="lbl">${tr('ng.local_dir')}</label>
            <div class="field-suffix"><input id="nsLocalRoot" class="field" placeholder="/var/www/example" readonly /><button type="button" class="suffix-btn" id="nsBrowse">${tr('ng.browse')}</button></div>
            <p class="formnote" style="margin-top:6px">${tr('ng.local_dir_hint')}</p>
          </div>`;
        setStaticSource = (s) => {
          staticSource = s;
          $('nsSrc').querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.s === s));
          $('nsSrcUpload').classList.toggle('hidden', s !== 'upload');
          $('nsSrcLocal').classList.toggle('hidden', s !== 'local');
        };
        $('nsSrc').querySelectorAll('button').forEach((b) => b.onclick = () => setStaticSource(b.dataset.s));
        $('nsBrowse').onclick = () => ngDirPicker((p) => { $('nsLocalRoot').value = p; });
        wireStaticPickers();
        setStaticSource(staticSource);
      }
    };
    const wireStaticPickers = () => {
      const drop = $('nsDrop');
      drop.onclick = () => $('nsZip').click();
      $('nsZip').onchange = (e) => { const f = e.target.files[0]; if (!f) return; if (!/\.zip$/i.test(f.name)) return toast(tr('site.zip_only'), 'warn'); staticUpload.mode = 'zip'; staticUpload.zip = f; $('nsUpList').innerHTML = tr('ng.sel_zip', { name: esc(f.name), size: fmtBytes(f.size) }); };
      ['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
      ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
      drop.addEventListener('drop', (e) => { const f = (e.dataTransfer.files || [])[0]; if (f && /\.zip$/i.test(f.name)) { staticUpload.mode = 'zip'; staticUpload.zip = f; $('nsUpList').innerHTML = tr('ng.sel_zip', { name: esc(f.name), size: fmtBytes(f.size) }); } else if (f) toast(tr('site.zip_only'), 'warn'); });
    };

    // Prefill the kind-specific fields when editing (re-run after kindFields()
    // rebuilds them, e.g. once the container list loads).
    const prefillKind = () => {
      if (!editing) return;
      if (site.kind === 'proxy_host') {
        if ($('nsScheme')) $('nsScheme').value = site.scheme || 'http';
        if ($('nsTarget')) $('nsTarget').value = site.target_url || '';
      } else if (site.kind === 'proxy_container') {
        if ($('nsScheme')) $('nsScheme').value = site.scheme || 'http';
        if ($('nsCtn') && site.container) {
          if (![...$('nsCtn').options].some((o) => o.value === site.container)) $('nsCtn').insertAdjacentHTML('afterbegin', `<option value="${esc(site.container)}">${esc(site.container)}</option>`);
          $('nsCtn').value = site.container;
        }
        if ($('nsCtnPort')) $('nsCtnPort').value = site.container_port || '';
      } else if (site.kind === 'static') {
        if (site.local_root) {
          setStaticSource('local');
          if ($('nsLocalRoot')) $('nsLocalRoot').value = site.local_root;
        } else {
          setStaticSource('upload');
        }
      }
    };

    if (editing) {
      $('nsName').value = site.server_name || '';
      $('nsKind').value = site.kind || 'proxy_host';
      $('nsCache').checked = !!site.cache;
      $('nsBlock').checked = !!site.block_attacks;
      $('nsWs').checked = site.websockets !== false;
      $('nsConf').value = site.extra_conf || '';
      const sv = (id, v) => { const e = $(id); if (e) e.value = v; };
      const so = (id, v) => { const e = $(id); if (e) e.checked = v; };
      sv('nsRlRps', site.rate_limit_rps || 10); sv('nsRlBurst', site.rate_limit_burst || 20); so('nsRlOn', !!site.rate_limit_rps);
      sv('nsBwKbps', site.bandwidth_kbps || 1024); so('nsBwOn', !!site.bandwidth_kbps);
      sv('nsConnIp', site.conn_per_ip || 50); so('nsConnOn', !!site.conn_per_ip);
      sv('nsBanThresh', site.autoban_threshold || 10); sv('nsBanWindow', site.autoban_window || 60); sv('nsBanMin', site.autoban_minutes || 10); so('nsBanOn', !!site.autoban_threshold);
      sv('nsAclList', site.ip_acl_list || ''); so('nsAclOn', !!site.ip_acl_mode);
      document.querySelectorAll('#nsAclSeg button').forEach((x) => x.classList.toggle('on', x.dataset.m === (site.ip_acl_mode || 'allow')));
      sv('nsHotlink', site.hotlink_referers || ''); so('nsHotOn', !!site.hotlink_referers);
      so('nsConfOn', !!site.extra_conf);
    }
    afSync();
    $('nsKind').onchange = kindFields; kindFields(); prefillKind();

    const locRow = (v) => {
      v = v || {};
      const isCtn = v.kind === 'container';
      const wrap = el('div', { class: 'locrule' });
      wrap.innerHTML = `
        <div class="lr-head"><input class="field lr-path" placeholder="/api" value="${esc(v.path || '')}" /><button type="button" class="lr-del" title="${tr('ng.delete')}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
        <div class="lr-row">
          <select class="field proto lr-kind"><option value="host">${tr('ng.loc_host')}</option><option value="container">${tr('ng.loc_container')}</option></select>
          <select class="field proto lr-scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select>
          <input class="field lr-target" placeholder="127.0.0.1:3001" value="${esc(v.target || '')}" />
          <select class="field lr-ctn">${ctnOptsHtml(v.container || '')}</select>
          <input class="field lr-ctnport" type="number" placeholder="80" value="${v.container_port || ''}" />
        </div>
        <label class="switch" style="padding:8px 0 2px"><input type="checkbox" class="lr-ws"${v.websockets ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.sw_ws')}</b></span></label>`;
      const kindSel = wrap.querySelector('.lr-kind');
      kindSel.value = isCtn ? 'container' : 'host';
      if (v.scheme === 'https') wrap.querySelector('.lr-scheme').value = 'https';
      const syncKind = () => {
        const ctn = kindSel.value === 'container';
        wrap.querySelector('.lr-target').classList.toggle('hidden', ctn);
        wrap.querySelector('.lr-ctn').classList.toggle('hidden', !ctn);
        wrap.querySelector('.lr-ctnport').classList.toggle('hidden', !ctn);
      };
      kindSel.onchange = syncKind; syncKind();
      wrap.querySelector('.lr-del').onclick = () => wrap.remove();
      $('nsLocs').appendChild(wrap);
    };
    $('nsLocAdd').onclick = () => locRow();
    if (editing && site.locations) site.locations.forEach((l) => locRow(l));

    $('nsSsl').onchange = () => {
      $('nsSslBody').classList.toggle('hidden', !$('nsSsl').checked);
      if ($('nsSsl').checked && certMethod === 'auto') loadCertList();
    };
    $('nsCertMethod').querySelectorAll('button').forEach((b) => b.onclick = () => {
      certMethod = b.dataset.m;
      $('nsCertMethod').querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
      $('nsAutoWrap').classList.toggle('hidden', certMethod !== 'auto');
      if (certMethod === 'auto') loadCertList();
      syncLeHint();
    });
    // Re-run the domain→cert auto-match when the domain changes after the SSL
    // tab picked one (stale otherwise) — unless the user explicitly chose.
    $('nsName').addEventListener('input', () => {
      if ($('nsSsl').checked && certMethod === 'auto' && !userPicked) { sitePrefill = false; selectedCert = null; renderCertList(); }
    });
    if (editing && site.ssl) {
      $('nsSsl').checked = true;
      $('nsSslBody').classList.remove('hidden');
      certMethod = site.cert_mode === 'self' ? 'self' : 'auto';
      $('nsCertMethod').querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.m === certMethod));
      $('nsAutoWrap').classList.toggle('hidden', certMethod !== 'auto');
      selectedCert = site.cert_name ? site.cert_name : (site.cert_mode === 'le' ? '' : null);
      if (site.key_type) $('nsKeyType').value = site.key_type;
      $('nsForceSsl').checked = site.force_ssl !== false;
      $('nsHsts').checked = !!site.hsts;
      $('nsHstsSub').checked = !!site.hsts_sub;
      $('nsTrustProxy').checked = !!site.trust_proxy;
      $('nsTrustProxyCidrs').value = site.trust_proxy_cidrs || '';
      $('nsTrustProxyCidrsRow').style.display = site.trust_proxy ? '' : 'none';
      if (certMethod === 'auto') loadCertList();
    }
    $('nsTrustProxy').onchange = () => { $('nsTrustProxyCidrsRow').style.display = $('nsTrustProxy').checked ? '' : 'none'; };

    const collectLocs = () => Array.from($('nsLocs').querySelectorAll('.locrule')).map((w) => {
      const kind = w.querySelector('.lr-kind').value;
      const l = { path: w.querySelector('.lr-path').value.trim(), scheme: w.querySelector('.lr-scheme').value, websockets: w.querySelector('.lr-ws').checked, kind };
      if (kind === 'container') { l.container = w.querySelector('.lr-ctn').value.trim(); l.container_port = Number(w.querySelector('.lr-ctnport').value) || 0; }
      else { l.target = w.querySelector('.lr-target').value.trim(); }
      return l;
    }).filter((l) => l.path || l.target || l.container);

    $('nsGo').onclick = async () => {
      const k = $('nsKind').value;
      const body = { op: editing ? 'update_site' : 'add_site', server_name: $('nsName').value.trim(), kind: k, ssl: $('nsSsl').checked, cache: $('nsCache').checked, block_attacks: $('nsBlock').checked, websockets: $('nsWs').checked, locations: collectLocs(), extra_conf: ($('nsConfOn').checked ? $('nsConf').value : ''), access_id: ($('nsAccess') ? $('nsAccess').value : '') };
      // Advanced features — each value is sent only when its card is enabled.
      const afN = (onId, valId) => ($(onId).checked ? Number($(valId).value) || 0 : 0);
      body.rate_limit_rps = afN('nsRlOn', 'nsRlRps');
      body.rate_limit_burst = afN('nsRlOn', 'nsRlBurst');
      body.bandwidth_kbps = afN('nsBwOn', 'nsBwKbps');
      body.conn_per_ip = afN('nsConnOn', 'nsConnIp');
      body.autoban_threshold = afN('nsBanOn', 'nsBanThresh');
      body.autoban_window = afN('nsBanOn', 'nsBanWindow');
      body.autoban_minutes = afN('nsBanOn', 'nsBanMin');
      body.ip_acl_mode = $('nsAclOn').checked ? ((document.querySelector('#nsAclSeg button.on') || {}).dataset || {}).m || 'allow' : '';
      body.ip_acl_list = $('nsAclOn').checked ? $('nsAclList').value.trim() : '';
      body.hotlink_referers = $('nsHotOn').checked ? $('nsHotlink').value.trim() : '';
      if (editing) body.site_id = site.id;
      if (!body.server_name) return toast(tr('ng.need_domain'), 'err');
      if (k === 'proxy_host') { body.scheme = $('nsScheme').value; const p = $('nsTarget').value.trim(); if (!p) return toast(tr('ng.need_host_port'), 'err'); body.target_url = /^\d+$/.test(p) ? '127.0.0.1:' + p : p; }
      else if (k === 'proxy_container') { body.scheme = $('nsScheme').value; body.container = $('nsCtn').value.trim(); body.container_port = Number($('nsCtnPort').value); if (!body.container) return toast(tr('ng.need_container'), 'err'); }
      else { if (staticSource === 'local') { const lr = ($('nsLocalRoot') ? $('nsLocalRoot').value.trim() : ''); if (!lr) return toast(tr('ng.need_local_dir'), 'err'); body.local_root = lr; } else { body.root = (editing && site.root) ? site.root : ('site-' + Math.random().toString(36).slice(2, 10)); if (!editing && !staticUpload.mode) return toast(tr('ng.need_upload'), 'err'); } }
      if (body.ssl) {
        if (certMethod === 'self') {
          body.cert_mode = 'self';
        } else if (selectedCert) {
          body.cert_mode = 'named'; body.cert_name = selectedCert;
        } else {
          body.cert_mode = 'le'; // auto, no existing cert → issue Let's Encrypt
        }
        // Key type applies only to freshly-generated certs (self/le), not an
        // existing library cert (named) which already has its own key.
        if (body.cert_mode === 'self' || body.cert_mode === 'le') body.key_type = $('nsKeyType').value;
        body.force_ssl = $('nsForceSsl').checked;
        body.hsts = $('nsHsts').checked;
        body.hsts_sub = $('nsHstsSub').checked;
        body.trust_proxy = $('nsTrustProxy').checked;
        if (body.trust_proxy) body.trust_proxy_cidrs = $('nsTrustProxyCidrs').value.trim();
      }
      const okMsg = editing ? tr('ng.site_updated') : tr('ng.site_created');
      $('nsGo').disabled = true; $('nsJob').classList.remove('hidden'); $('nsJob').innerHTML = `<div class="mut">${tr('ng.submitting')}</div>`;
      try {
        if (k === 'static' && staticSource === 'upload' && staticUpload.mode) { $('nsJob').innerHTML = `<div class="mut">${tr('ng.uploading')}</div>`; await uploadStatic(body.root, staticUpload); }
      } catch (e) { toast(tr('ng.upload_failed') + '：' + e.message, 'err'); $('nsJob').innerHTML = ''; $('nsGo').disabled = false; return; }
      op('website', body).then((r) => {
        // Persisted slot: closing the modal mid-issuance doesn't orphan the op —
        // ngHostsTab re-attaches 'website:issue' and keeps reporting.
        if (r.op_id) renderJob($('nsJob'), 'website', r.op_id, 'website:issue', { onDone: () => { toast(okMsg, 'ok'); close(); reload(); }, onError: () => { $('nsGo').disabled = false; } });
        else { toast(okMsg, 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('nsJob').innerHTML = ''; $('nsGo').disabled = false; });
    };
    // Explicit .modal-b root: #nsGo now lives in the sibling .modal-foot, so the
    // closest('.modal-b') fallback would miss the form fields.
    bindDirty('nsGo', root.querySelector('.modal-b'));
  }, {
    foot: `<div class="hidden" id="nsJob" style="width:100%"></div><button class="btn" id="nsGo">${editing ? tr('ng.save') : tr('ng.create')}</button>`,
    onDismiss: () => { if (getJob('website:issue')) reload(); },
  });
}

// Upload staged static content to a site's webroot. ZIP → one extract request;
// folder → per-file requests (first file clears the webroot).
async function uploadStatic(root, su) {
  if (su.mode === 'zip' && su.zip) {
    const qs = `root=${encodeURIComponent(root)}&mode=zip&clear=1`;
    const r = await fetch('/api/website/static-upload?' + qs, { method: 'POST', headers: authHeaders(), body: su.zip });
    const b = await r.json().catch(() => ({}));
    if (!r.ok || b.ok === false) throw new Error(b.error || tr('ng.upload_failed'));
  }
}

