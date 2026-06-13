// =========================================================================
// Nginx management (presented as the "Website" section)
// =========================================================================
function renderNginx(v) {
  v.innerHTML = `<div style="padding:8px">${loading(tr('ng.detecting'))}</div>`;
  if (getJob('nginx:setup')) {
    v.innerHTML = `<div class="card"><h3>${tr('ng.initializing')}</h3><div id="ngSetupJob"></div></div>`;
    reattachJob($('ngSetupJob'), 'nginx:setup', { onDone: () => setTimeout(() => renderNginx(v), 800) });
    return;
  }
  op('nginx', { op: 'info' }).then((info) => {
    if (!info.managed) {
      const ver = info.host_nginx_version ? ' (' + esc(info.host_nginx_version) + ')' : '';
      const hint = info.host_nginx_present ? tr('ng.hint_present', { ver }) : tr('ng.hint_absent');
      v.innerHTML = `<div class="card"><h3>${tr('ng.init_title')}</h3>
        <p class="mut">${hint}</p>
        <div class="row" style="margin:14px 0">
          <button class="btn" id="ngSetup">${tr('ng.init_btn')}</button>
        </div>
        <div class="hidden" id="ngSetupJob"></div></div>`;
      $('ngSetup').onclick = () => { $('ngSetup').disabled = true; $('ngSetupJob').classList.remove('hidden'); op('nginx', { op: 'setup' }).then((r) => renderJob($('ngSetupJob'), 'nginx', r.op_id, 'nginx:setup', { onDone: () => { toast(tr('ng.init_done'), 'ok'); setTimeout(() => renderNginx(v), 600); }, onError: () => { $('ngSetup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ngSetup').disabled = false; }); };
      return;
    }
    v.innerHTML = `<div class="row" style="margin-bottom:14px"><span class="chip on">${tr('ng.running')}</span><span class="sp" style="flex:1"></span><button class="btn sm" id="ngAdd">${tr('ng.add_site')}</button><button class="btn sec sm" id="ngCert">${tr('ng.ssl_cert')}</button><button class="btn sec sm" id="ngRef">${tr('ng.refresh')}</button></div><div id="ngSites">${loading()}</div>`;
    $('ngRef').onclick = () => renderNginx(v);
    $('ngAdd').onclick = () => ngAddSite(() => renderNginx(v));
    $('ngCert').onclick = () => ngCerts();
    Promise.all([op('nginx', { op: 'list_sites' }), op('nginx', { op: 'list_named_certs' })]).then(([d, cd]) => {
      const sites = d.sites || [];
      const modes = {};
      (cd.certs || []).forEach((c) => { modes[c.name] = c.cert_mode; });
      if (!sites.length) { $('ngSites').innerHTML = `<div class="empty">${tr('ng.no_sites')}</div>`; return; }
      let h = `<table class="optable"><tr><th>${tr('ng.col_domain')}</th><th>${tr('ng.col_type')}</th><th>${tr('ng.col_target')}</th><th>${tr('ng.col_ssl')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
      sites.forEach((s) => {
        const sch = s.scheme === 'https' ? 'https://' : (s.kind === 'static' ? '' : 'http://');
        let target = s.kind === 'proxy_host' ? esc(sch + s.target_url) : s.kind === 'proxy_container' ? esc(`${sch}${s.container}:${s.container_port}`) : esc('/' + s.root);
        if (s.locations && s.locations.length) target += ` <span class="mut">${tr('ng.rules_count', { n: s.locations.length })}</span>`;
        h += `<tr><td><b>${esc(s.server_name)}</b></td><td class="mut">${esc(kindLabel(s.kind))}</td><td class="mono" style="font-size:12px">${target}</td><td>${sslLabel(s, modes)}</td><td class="act"><button class="btn sm sec" data-edit="${esc(s.id)}">${tr('ng.edit_site')}</button><button class="btn sm danger" data-rm="${esc(s.id)}">${tr('ng.delete')}</button></td></tr>`;
      });
      $('ngSites').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#ngSites [data-edit]').forEach((b) => b.onclick = () => { const s = sites.find((x) => String(x.id) === b.dataset.edit); if (s) ngAddSite(() => renderNginx(v), s); });
      document.querySelectorAll('#ngSites [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('ng.confirm_rm_site'))) op('nginx', { op: 'remove_site', site_id: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); renderNginx(v); }).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('ngSites').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}
function kindLabel(k) { return { proxy_host: tr('ng.kind_proxy_host'), proxy_container: tr('ng.kind_proxy_container'), static: tr('ng.kind_static') }[k] || k; }

// SSL column label: show the certificate kind (Let's Encrypt / self-signed /
// custom) instead of a plain yes/no. `modes` maps a library cert name → mode.
function sslLabel(s, modes) {
  if (!s.ssl) return `<span class="chip">${tr('ng.ssl_off')}</span>`;
  const m = (s.cert_name && modes[s.cert_name]) || s.cert_mode || 'named';
  if (m === 'le') return `<span class="chip on">Let's Encrypt</span>`;
  if (m === 'self') return `<span class="chip">${tr('ng.cm_self')}</span>`;
  if (m === 'manual') return `<span class="chip on">${tr('ng.cm_manual')}</span>`;
  return `<span class="chip on">${tr('ng.yes')}</span>`;
}

function ngAddSite(reload, site) {
  const editing = !!site;
  modal(editing ? tr('ng.edit_site_title') : tr('ng.add_site_title'), `
    <div class="ftabs" id="nsTabs">
      <button class="on" data-t="detail">${tr('ng.tab_detail')}</button>
      <button data-t="rules">${tr('ng.tab_rules')}</button>
      <button data-t="ssl">${tr('ng.tab_ssl')}</button>
      <button data-t="conf">${tr('ng.tab_conf')}</button>
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
      <div style="margin-top:8px">
        <label class="switch"><input type="checkbox" id="nsCache" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.sw_cache')}</b><span>${tr('ng.sw_cache_d')}</span></span></label>
        <label class="switch"><input type="checkbox" id="nsBlock" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.sw_block')}</b><span>${tr('ng.sw_block_d')}</span></span></label>
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
        <div id="nsAutoWrap" style="margin-top:14px">
          <label class="lbl">${tr('ng.same_domain_certs')}</label>
          <div id="nsCertList" class="certlist"></div>
        </div>
        <div class="ssltoggles" style="margin-top:16px">
          <label class="switch"><input type="checkbox" id="nsForceSsl" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.force_ssl')}</b><span>${tr('ng.force_ssl_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsHttp2" checked /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.http2')}</b><span>${tr('ng.http2_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsHsts" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.hsts')}</b><span>${tr('ng.hsts_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsHstsSub" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.hsts_sub')}</b><span>${tr('ng.hsts_sub_d')}</span></span></label>
          <label class="switch"><input type="checkbox" id="nsTrustProxy" /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.trust_proxy')}</b><span>${tr('ng.trust_proxy_d')}</span></span></label>
        </div>
        <p class="formnote">${tr('ng.autorenew_note')}</p>
      </div>
    </div>
    <div class="ftab-pane" data-p="conf">
      <p class="mut" style="font-size:12.5px;margin:0 0 10px">${tr('ng.conf_intro')}</p>
      <textarea id="nsConf" class="field mono confbox" rows="13" spellcheck="false" placeholder="${tr('ng.conf_ph')}"></textarea>
      <p class="formnote">${tr('ng.conf_note')}</p>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="nsGo">${editing ? tr('ng.save') : tr('ng.create')}</button></div>
    <div class="hidden" id="nsJob" style="margin-top:14px"></div>`, (close) => {
    document.querySelectorAll('#nsTabs button').forEach((b) => b.onclick = () => {
      document.querySelectorAll('#nsTabs button').forEach((x) => x.className = x === b ? 'on' : '');
      document.querySelectorAll('.ftab-pane').forEach((p) => p.className = 'ftab-pane' + (p.dataset.p === b.dataset.t ? ' on' : ''));
      if (b.dataset.t === 'ssl' && $('nsSsl').checked && certMethod === 'auto') loadCertList();
    });

    // SSL state: 'auto' (Let's Encrypt — reuse a matching cert or issue one) or
    // 'self' (self-signed). `selectedCert` is the chosen library cert name, ''
    // means "issue a new Let's Encrypt cert", null means "not yet decided".
    let certMethod = 'auto';
    let selectedCert = null;
    let domainCerts = [];
    const baseDomain = (d) => { const p = (d || '').split('.').filter(Boolean); return p.length <= 2 ? p.join('.') : p.slice(-2).join('.'); };
    const certCovers = (cd, host) => {
      if (!cd || !host) return false;
      if (cd === host) return true;
      if (cd.startsWith('*.')) return host.endsWith(cd.slice(1)) && host.split('.').length === cd.split('.').length;
      return false;
    };
    const renderCertList = () => {
      const list = $('nsCertList'); if (!list) return;
      const host = $('nsName').value.trim();
      if (selectedCert === null) {
        if (editing && site.cert_name) selectedCert = site.cert_name;
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
      list.innerHTML = `<select id="nsCertSel" class="field">${opts}</select>`;
      $('nsCertSel').onchange = () => { selectedCert = $('nsCertSel').value; };
    };
    const loadCertList = () => {
      const base = baseDomain($('nsName').value.trim());
      $('nsCertList').innerHTML = loading();
      op('nginx', { op: 'list_named_certs' }).then((d) => {
        domainCerts = (d.certs || []).filter((c) => c.has_cert && base && baseDomain(c.domain) === base);
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
    op('nginx', { op: 'list_containers' }).then((d) => {
      containers = d.containers || [];
      if ($('nsKind').value === 'proxy_container') { kindFields(); prefillKind(); }
      // Refresh any location-rule container pickers built before the list arrived.
      $('nsLocs').querySelectorAll('.lr-ctn').forEach((s) => { s.innerHTML = ctnOptsHtml(s.value); });
    }).catch(() => {});

    const staticUpload = { mode: null, zip: null, files: [] };

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
          <label class="lbl">${tr('ng.static_dirname')}</label><input id="nsRoot" class="field" placeholder="mysite" style="margin-bottom:10px" />
          <label class="lbl">${tr('ng.upload_content')}</label>
          <div class="dropz" id="nsDrop"><b>${tr('ng.drop_a')}</b>${tr('ng.drop_b')}<br/><span style="font-size:11.5px">${editing ? tr('ng.drop_keep') : tr('ng.drop_sub')}</span></div>
          <input type="file" id="nsZip" accept=".zip" class="hidden" />
          <input type="file" id="nsDir" webkitdirectory multiple class="hidden" />
          <div class="row" style="gap:8px;margin-top:8px"><button type="button" class="btn sm sec" id="nsPickZip">${tr('ng.pick_zip')}</button><button type="button" class="btn sm sec" id="nsPickDir">${tr('ng.pick_dir')}</button></div>
          <div class="uplist" id="nsUpList"></div>`;
        wireStaticPickers();
      }
    };
    const wireStaticPickers = () => {
      const drop = $('nsDrop');
      $('nsPickZip').onclick = () => $('nsZip').click();
      $('nsPickDir').onclick = () => $('nsDir').click();
      drop.onclick = () => $('nsZip').click();
      $('nsZip').onchange = (e) => { const f = e.target.files[0]; if (!f) return; staticUpload.mode = 'zip'; staticUpload.zip = f; staticUpload.files = []; $('nsUpList').innerHTML = tr('ng.sel_zip', { name: esc(f.name), size: fmtBytes(f.size) }); };
      $('nsDir').onchange = (e) => { const fs = Array.from(e.target.files || []); if (!fs.length) return; staticUpload.mode = 'dir'; staticUpload.zip = null; staticUpload.files = fs; $('nsUpList').innerHTML = tr('ng.sel_files', { n: fs.length }) + '<br/>' + fs.slice(0, 20).map((f) => esc(f.webkitRelativePath || f.name)).join('<br/>') + (fs.length > 20 ? '<br/>…' : ''); };
      ['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
      ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
      drop.addEventListener('drop', (e) => { const f = (e.dataTransfer.files || [])[0]; if (f && /\.zip$/i.test(f.name)) { staticUpload.mode = 'zip'; staticUpload.zip = f; staticUpload.files = []; $('nsUpList').innerHTML = tr('ng.sel_zip', { name: esc(f.name), size: fmtBytes(f.size) }); } });
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
      } else if (site.kind === 'static' && $('nsRoot')) {
        $('nsRoot').value = site.root || '';
      }
    };

    if (editing) {
      $('nsName').value = site.server_name || '';
      $('nsKind').value = site.kind || 'proxy_host';
      $('nsCache').checked = !!site.cache;
      $('nsBlock').checked = !!site.block_attacks;
      $('nsWs').checked = site.websockets !== false;
      $('nsConf').value = site.extra_conf || '';
    }
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
    });
    if (editing && site.ssl) {
      $('nsSsl').checked = true;
      $('nsSslBody').classList.remove('hidden');
      certMethod = site.cert_mode === 'self' ? 'self' : 'auto';
      $('nsCertMethod').querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.m === certMethod));
      $('nsAutoWrap').classList.toggle('hidden', certMethod !== 'auto');
      selectedCert = site.cert_name ? site.cert_name : (site.cert_mode === 'le' ? '' : null);
      $('nsForceSsl').checked = site.force_ssl !== false;
      $('nsHttp2').checked = site.http2 !== false;
      $('nsHsts').checked = !!site.hsts;
      $('nsHstsSub').checked = !!site.hsts_sub;
      $('nsTrustProxy').checked = !!site.trust_proxy;
      if (certMethod === 'auto') loadCertList();
    }

    const collectLocs = () => Array.from($('nsLocs').querySelectorAll('.locrule')).map((w) => {
      const kind = w.querySelector('.lr-kind').value;
      const l = { path: w.querySelector('.lr-path').value.trim(), scheme: w.querySelector('.lr-scheme').value, websockets: w.querySelector('.lr-ws').checked, kind };
      if (kind === 'container') { l.container = w.querySelector('.lr-ctn').value.trim(); l.container_port = Number(w.querySelector('.lr-ctnport').value) || 0; }
      else { l.target = w.querySelector('.lr-target').value.trim(); }
      return l;
    }).filter((l) => l.path || l.target || l.container);

    $('nsGo').onclick = async () => {
      const k = $('nsKind').value;
      const body = { op: editing ? 'update_site' : 'add_site', server_name: $('nsName').value.trim(), kind: k, ssl: $('nsSsl').checked, cache: $('nsCache').checked, block_attacks: $('nsBlock').checked, websockets: $('nsWs').checked, locations: collectLocs(), extra_conf: $('nsConf').value };
      if (editing) body.site_id = site.id;
      if (!body.server_name) return toast(tr('ng.need_domain'), 'err');
      if (k === 'proxy_host') { body.scheme = $('nsScheme').value; const p = $('nsTarget').value.trim(); if (!p) return toast(tr('ng.need_host_port'), 'err'); body.target_url = /^\d+$/.test(p) ? '127.0.0.1:' + p : p; }
      else if (k === 'proxy_container') { body.scheme = $('nsScheme').value; body.container = $('nsCtn').value.trim(); body.container_port = Number($('nsCtnPort').value); if (!body.container) return toast(tr('ng.need_container'), 'err'); }
      else { body.root = $('nsRoot').value.trim(); if (!body.root) return toast(tr('ng.need_static_dir'), 'err'); if (!editing && !staticUpload.mode) return toast(tr('ng.need_upload'), 'err'); }
      if (body.ssl) {
        if (certMethod === 'self') {
          body.cert_mode = 'self';
        } else if (selectedCert) {
          body.cert_mode = 'named'; body.cert_name = selectedCert;
        } else {
          body.cert_mode = 'le'; // auto, no existing cert → issue Let's Encrypt
        }
        body.force_ssl = $('nsForceSsl').checked;
        body.http2 = $('nsHttp2').checked;
        body.hsts = $('nsHsts').checked;
        body.hsts_sub = $('nsHstsSub').checked;
        body.trust_proxy = $('nsTrustProxy').checked;
      }
      const okMsg = editing ? tr('ng.site_updated') : tr('ng.site_created');
      $('nsGo').disabled = true; $('nsJob').classList.remove('hidden'); $('nsJob').innerHTML = `<div class="mut">${tr('ng.submitting')}</div>`;
      try {
        if (k === 'static' && staticUpload.mode) { $('nsJob').innerHTML = `<div class="mut">${tr('ng.uploading')}</div>`; await uploadStatic(body.root, staticUpload); }
      } catch (e) { toast(tr('ng.upload_failed') + '：' + e.message, 'err'); $('nsJob').innerHTML = ''; $('nsGo').disabled = false; return; }
      op('nginx', body).then((r) => {
        if (r.op_id) renderJob($('nsJob'), 'nginx', r.op_id, '', { onDone: () => { toast(okMsg, 'ok'); close(); reload(); }, onError: () => { $('nsGo').disabled = false; } });
        else { toast(okMsg, 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('nsJob').innerHTML = ''; $('nsGo').disabled = false; });
    };
  });
}

// Upload staged static content to a site's webroot. ZIP → one extract request;
// folder → per-file requests (first file clears the webroot).
async function uploadStatic(root, su) {
  if (su.mode === 'zip' && su.zip) {
    const qs = `root=${encodeURIComponent(root)}&mode=zip&clear=1`;
    const r = await fetch('/api/nginx/static-upload?' + qs, { method: 'POST', headers: { 'Authorization': 'Bearer ' + S.token }, body: su.zip });
    const b = await r.json().catch(() => ({}));
    if (!r.ok || b.ok === false) throw new Error(b.error || tr('ng.upload_failed'));
    return;
  }
  if (su.mode === 'dir' && su.files.length) {
    for (let i = 0; i < su.files.length; i++) {
      const f = su.files[i];
      let rel = f.webkitRelativePath || f.name;
      const slash = rel.indexOf('/');
      if (slash > 0) rel = rel.slice(slash + 1);
      const qs = `root=${encodeURIComponent(root)}&mode=file&rel=${encodeURIComponent(rel)}` + (i === 0 ? '&clear=1' : '');
      const r = await fetch('/api/nginx/static-upload?' + qs, { method: 'POST', headers: { 'Authorization': 'Bearer ' + S.token }, body: f });
      const b = await r.json().catch(() => ({}));
      if (!r.ok || b.ok === false) throw new Error(b.error || (tr('ng.upload_failed') + '：' + rel));
    }
  }
}

// SSL certificate library (standalone named certs). Per-site certificates are
// managed from each site's Edit dialog (SSL tab).
function ngCerts() {
  modal(tr('ng.cert_mgr'), `<div id="ngCertBody">${loading()}</div>`, () => {
    const load = () => op('nginx', { op: 'list_named_certs' }).then((d) => {
      const certs = d.certs || [];
      let h = `<div class="row" style="margin-bottom:12px"><span class="mut" style="font-size:12.5px;flex:1">${tr('ng.cert_lib_intro')}</span><button class="btn sm" id="ngCertNew">${tr('ng.create_cert')}</button></div><p class="formnote" style="margin-top:0;margin-bottom:12px">${tr('ng.autorenew_note')}</p>`;
      if (!certs.length) { h += `<div class="empty">${tr('ng.cert_lib_empty')}</div>`; }
      else {
        h += `<table class="optable"><tr><th>${tr('ng.col_name')}</th><th>${tr('ng.col_domain')}</th><th>${tr('ng.col_mode')}</th><th>${tr('ng.col_expire')}</th><th>${tr('ng.col_used')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
        certs.forEach((c) => {
          const modeLabel = { le: tr('ng.mode_le'), self: tr('ng.mode_self'), manual: tr('ng.mode_manual') }[c.cert_mode] || c.cert_mode;
          const used = (c.used_by && c.used_by.length) ? esc(c.used_by.join('、')) : `<span class="mut">${tr('ng.unused')}</span>`;
          h += `<tr><td><b>${esc(c.name)}</b>${c.has_cert ? '' : ` <span class="chip warn">${tr('ng.missing')}</span>`}</td><td class="mut">${esc(c.domain || '-')}</td><td class="mut">${esc(modeLabel)}</td><td class="mono" style="font-size:12px">${esc(c.not_after || '-')}</td><td style="font-size:12px">${used}</td><td class="act"><button class="btn sm danger" data-del="${esc(c.name)}">${tr('ng.delete')}</button></td></tr>`;
        });
        h += '</table>';
      }
      $('ngCertBody').innerHTML = '<div class="tablewrap">' + h + '</div>';
      $('ngCertNew').onclick = () => ngCreateCert(load);
      document.querySelectorAll('#ngCertBody [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('ng.confirm_del_cert', { name: b.dataset.del }))) op('nginx', { op: 'delete_cert', cert_name: b.dataset.del }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('ngCertBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    load();
  });
}

// Create a standalone named certificate (self-signed / LE / manual).
function ngCreateCert(reload) {
  modal(tr('ng.create_cert'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('ng.cert_name')}</label><input id="ccName" class="field" placeholder="${tr('ng.cert_name_ph')}" /></div>
      <div class="full"><label class="lbl">${tr('ng.cert_mode')}</label><select id="ccMode" class="field"><option value="le">${tr('ng.cm_le')}</option><option value="manual">${tr('ng.cm_manual')}</option><option value="self">${tr('ng.cm_self')}</option></select></div>
      <div class="full" id="ccDomainWrap"><label class="lbl">${tr('ng.domain')}</label><input id="ccDomain" class="field" placeholder="example.com" /></div>
      <div class="full hidden" id="ccManual">
        <label class="lbl">${tr('ng.cert_key_file')}</label>
        <div class="filepick"><button type="button" class="btn sm sec" id="ccKeyBtn">${tr('ng.choose_file')}</button><span class="fp-name" id="ccKeyName">${tr('ng.no_file')}</span></div>
        <input type="file" id="ccKeyFile" class="hidden" />
        <label class="lbl" style="margin-top:10px">${tr('ng.cert_file')}</label>
        <div class="filepick"><button type="button" class="btn sm sec" id="ccCertBtn">${tr('ng.choose_file')}</button><span class="fp-name" id="ccCertName">${tr('ng.no_file')}</span></div>
        <input type="file" id="ccCertFile" class="hidden" />
        <label class="lbl" style="margin-top:10px">${tr('ng.chain_file')} <span class="mut">${tr('ng.optional_suffix')}</span></label>
        <div class="filepick"><button type="button" class="btn sm sec" id="ccChainBtn">${tr('ng.choose_file')}</button><span class="fp-name" id="ccChainName">${tr('ng.no_file')}</span></div>
        <input type="file" id="ccChainFile" class="hidden" />
      </div>
    </div>
    <p class="mut" style="font-size:12px;margin-top:6px" id="ccHint"></p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="ccGo">${tr('ng.create')}</button></div>
    <div class="hidden" id="ccJob" style="margin-top:14px"></div>`, (close) => {
    const sync = () => {
      const m = $('ccMode').value;
      $('ccManual').classList.toggle('hidden', m !== 'manual');
      $('ccDomainWrap').classList.toggle('hidden', m === 'manual');
      $('ccHint').textContent = m === 'le' ? tr('ng.hint_le') : m === 'self' ? tr('ng.hint_self') : tr('ng.hint_manual');
    };
    $('ccMode').onchange = sync; sync();

    // Custom-certificate file imports: read PEM text from local files. Key and
    // certificate are required; the chain/intermediate is optional.
    const pem = { key: '', cert: '', chain: '' };
    const wirePick = (btn, input, name, slot) => {
      $(btn).onclick = () => $(input).click();
      $(input).onchange = (e) => {
        const f = e.target.files[0]; if (!f) return;
        f.text().then((t) => { pem[slot] = t; $(name).textContent = f.name; });
      };
    };
    wirePick('ccKeyBtn', 'ccKeyFile', 'ccKeyName', 'key');
    wirePick('ccCertBtn', 'ccCertFile', 'ccCertName', 'cert');
    wirePick('ccChainBtn', 'ccChainFile', 'ccChainName', 'chain');

    $('ccGo').onclick = () => {
      const mode = $('ccMode').value;
      const body = { op: 'create_cert', cert_name: $('ccName').value.trim(), cert_mode: mode };
      if (!body.cert_name) return toast(tr('ng.need_cert_name'), 'err');
      if (mode === 'manual') {
        if (!pem.key || !pem.cert) return toast(tr('ng.need_cert_files'), 'err');
        body.cert_pem = pem.cert + (pem.chain ? '\n' + pem.chain : '');
        body.key_pem = pem.key;
      }
      else { body.server_name = $('ccDomain').value.trim(); if (!body.server_name) return toast(tr('ng.need_domain'), 'err'); }
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden'); $('ccJob').innerHTML = `<div class="mut">${tr('ng.submitting')}</div>`;
      op('nginx', body).then((r) => {
        if (r.op_id) renderJob($('ccJob'), 'nginx', r.op_id, '', { onDone: () => { toast(tr('ng.cert_created'), 'ok'); close(); reload(); }, onError: () => { $('ccGo').disabled = false; } });
        else { toast(tr('ng.cert_created'), 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('ccJob').innerHTML = ''; $('ccGo').disabled = false; });
    };
  });
}
