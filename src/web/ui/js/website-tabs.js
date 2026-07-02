// Website: cert / access-list / default-site / settings tabs + dir picker (split from website.js).
// ---- Tab 3: Certificates (standalone named cert library) ----
// Per-site certificates are managed from each site's Edit dialog (SSL tab).
function ngCertsTab(v) {
  const body = $('ngBody');
  const load = () => op('website', { op: 'list_named_certs' }).then((d) => {
    const certs = d.certs || [];
    let h = `<div class="row" style="margin-bottom:12px"><span class="mut" style="font-size:12.5px;flex:1">${tr('ng.cert_lib_intro')}</span><button class="btn sm" id="ngCertNew">${tr('ng.create_cert')}</button></div><p class="formnote" style="margin-top:0;margin-bottom:12px">${tr('ng.autorenew_note')}</p>`;
    if (!certs.length) { h += `<div class="empty">${tr('ng.cert_lib_empty')}</div>`; }
    else {
      h += `<table class="optable"><tr><th>${tr('ng.col_domain')}</th><th>${tr('ng.col_mode')}</th><th>${tr('ng.col_expire')}</th><th>${tr('ng.col_used')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
      certs.forEach((c) => {
        const modeLabel = { le: tr('ng.mode_le'), self: tr('ng.mode_self'), manual: tr('ng.mode_manual') }[c.cert_mode] || c.cert_mode;
        const used = (c.used_by && c.used_by.length) ? esc(c.used_by.join('、')) : `<span class="mut">${tr('ng.unused')}</span>`;
        const renewBtn = c.cert_mode === 'manual' ? '' : `<button class="btn sm sec" data-renew="${esc(c.name)}">${tr('ng.renew_now')}</button>`;
        const hl = ngCertHealth(c);
        const dateStyle = hl === 'expired' ? ';color:var(--err)' : hl === 'expiring' ? ';color:var(--warn)' : '';
        h += `<tr><td><b>${esc(c.domain || c.name)}</b>${c.has_cert ? '' : ` <span class="chip amber">${tr('ng.missing')}</span>`}</td><td class="mut">${esc(modeLabel)}</td><td class="mono" style="font-size:12px${dateStyle}">${esc(c.not_after || '-')}</td><td style="font-size:12px">${used}</td><td class="act">${renewBtn}<button class="btn sm danger" data-del="${esc(c.name)}">${tr('ng.delete')}</button></td></tr>`;
      });
      h += '</table>';
    }
    body.innerHTML = `<div class="hidden" id="ngRenewWrap" style="margin-bottom:12px"><div class="card"><h3>${tr('ng.renewing')}</h3><div id="ngRenewJob"></div></div></div><div class="tablewrap">` + h + '</div>';
    $('ngCertNew').onclick = () => ngCreateCert(load);
    // ACME renewals run through the persisted job slot so a slow/failed renewal
    // is actually reported (progress + error line) instead of a blind reload.
    const renewBtns = (dis) => document.querySelectorAll('#ngBody [data-renew]').forEach((x) => { x.disabled = dis; if (!dis) x.textContent = tr('ng.renew_now'); });
    const renewCbs = {
      onDone: () => { toast(tr('ng.renewed'), 'ok'); load(); },
      onError: (e) => { toast(codeMsg(e || '') || tr('job.failed'), 'err'); renewBtns(false); },
    };
    document.querySelectorAll('#ngBody [data-renew]').forEach((b) => b.onclick = () => {
      b.disabled = true; b.textContent = tr('ng.renewing');
      op('website', { op: 'renew_cert', cert_name: b.dataset.renew }).then((r) => {
        if (r.op_id) { renewBtns(true); $('ngRenewWrap').classList.remove('hidden'); renderJob($('ngRenewJob'), 'website', r.op_id, 'website:renew', renewCbs); }
        else { toast(tr('ng.renewed'), 'ok'); setTimeout(load, 300); }
      }).catch((e) => { toast(e.message, 'err'); b.disabled = false; b.textContent = tr('ng.renew_now'); });
    });
    // A renewal started earlier (or on a previous visit) keeps reporting here.
    if (getJob('website:renew')) { renewBtns(true); $('ngRenewWrap').classList.remove('hidden'); reattachJob($('ngRenewJob'), 'website:renew', renewCbs); }
    document.querySelectorAll('#ngBody [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('ng.confirm_del_cert', { name: b.dataset.del }))) op('website', { op: 'delete_cert', cert_name: b.dataset.del }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  body.innerHTML = loading();
  load();
}

// Create a standalone named certificate (self-signed / LE / manual).
function ngCreateCert(reload) {
  modal(tr('ng.create_cert'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('ng.cert_mode')}</label><select id="ccMode" class="field"><option value="le">${tr('ng.cm_le')}</option><option value="manual">${tr('ng.cm_manual')}</option><option value="self">${tr('ng.cm_self')}</option></select></div>
      <div class="full" id="ccDomainWrap"><label class="lbl">${tr('ng.domain')}</label><input id="ccDomain" class="field" placeholder="example.com" /></div>
      <div class="full" id="ccKeyTypeWrap"><label class="lbl">${tr('ng.key_type')}</label><select id="ccKeyType" class="field"><option value="ecdsa-p256">${tr('ng.key_type_p256')}</option><option value="ecdsa-p384">${tr('ng.key_type_p384')}</option></select></div>
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
      // Key type only applies to auto-generated (le/self) certs; a manual cert
      // already carries its own key.
      $('ccKeyTypeWrap').classList.toggle('hidden', m === 'manual');
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
      const domain = $('ccDomain').value.trim();
      if (!domain) return toast(tr('ng.need_domain'), 'err');
      const body = { op: 'create_cert', cert_mode: mode, server_name: domain };
      if (mode === 'manual') {
        if (!pem.key || !pem.cert) return toast(tr('ng.need_cert_files'), 'err');
        body.cert_pem = pem.cert + (pem.chain ? '\n' + pem.chain : '');
        body.key_pem = pem.key;
      } else {
        body.key_type = $('ccKeyType').value;
      }
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden'); $('ccJob').innerHTML = `<div class="mut">${tr('ng.submitting')}</div>`;
      op('website', body).then((r) => {
        if (r.op_id) renderJob($('ccJob'), 'website', r.op_id, '', { onDone: () => { toast(tr('ng.cert_created'), 'ok'); close(); reload(); }, onError: () => { $('ccGo').disabled = false; } });
        else { toast(tr('ng.cert_created'), 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('ccJob').innerHTML = ''; $('ccGo').disabled = false; });
    };
    bindDirty('ccGo');
  });
}

// ---- Tab 2: Access Lists (HTTP Basic Auth + IP allow/deny) ----
function ngAccessTab(v) {
  const body = $('ngBody');
  const load = () => op('website', { op: 'list_access' }).then((d) => {
    const lists = d.access || [];
    let h = `<div class="row" style="margin-bottom:12px"><span class="mut" style="font-size:12.5px;flex:1">${tr('ng.access_intro')}</span><button class="btn sm" id="ngAccNew">${tr('ng.access_new')}</button></div>`;
    if (!lists.length) { h += `<div class="empty">${tr('ng.access_empty')}</div>`; }
    else {
      h += `<table class="optable"><tr><th>${tr('ng.col_name')}</th><th>${tr('ng.access_users')}</th><th>${tr('ng.access_rules')}</th><th>${tr('ng.col_used')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
      lists.forEach((a) => {
        const used = (a.used_by && a.used_by.length) ? esc(a.used_by.join('、')) : `<span class="mut">${tr('ng.unused')}</span>`;
        h += `<tr><td><b>${esc(a.name)}</b></td><td class="mut">${(a.users || []).length}</td><td class="mut">${(a.clients || []).length}</td><td style="font-size:12px">${used}</td><td class="act"><button class="btn sm sec" data-edit="${esc(a.id)}">${tr('ng.edit_site')}</button><button class="btn sm danger" data-del="${esc(a.id)}">${tr('ng.delete')}</button></td></tr>`;
      });
      h += '</table>';
    }
    body.innerHTML = '<div class="tablewrap">' + h + '</div>';
    $('ngAccNew').onclick = () => ngAccessForm(load, null);
    document.querySelectorAll('#ngBody [data-edit]').forEach((b) => b.onclick = () => { const a = lists.find((x) => x.id === b.dataset.edit); if (a) ngAccessForm(load, a); });
    document.querySelectorAll('#ngBody [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('ng.confirm_del_access'))) op('website', { op: 'delete_access', access_id: b.dataset.del }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  body.innerHTML = loading();
  load();
}

// Create / edit an access list (auth users + allow-deny rules).
function ngAccessForm(reload, al) {
  const editing = !!al;
  modal(editing ? tr('ng.access_edit_title') : tr('ng.access_new'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('ng.access_name')}</label><input id="alName" class="field" placeholder="${tr('ng.access_name_ph')}" value="${editing ? esc(al.name) : ''}" /></div>
    </div>
    <div class="sechead" style="margin-top:14px"><h3>${tr('ng.access_users')}</h3><span class="sp"></span><button type="button" class="btn sm sec" id="alAddUser">${tr('ng.access_add_user')}</button></div>
    <div id="alUsers"></div>
    <div class="sechead" style="margin-top:14px"><h3>${tr('ng.access_rules')}</h3><span class="sp"></span><button type="button" class="btn sm sec" id="alAddRule">${tr('ng.access_add_rule')}</button></div>
    <p class="formnote" style="margin-top:0">${tr('ng.access_rules_hint')}</p>
    <div id="alRules"></div>
    <div class="ssltoggles" style="margin-top:16px">
      <label class="switch"><input type="checkbox" id="alSatisfy"${editing && al.satisfy === 'all' ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.access_satisfy_all')}</b><span>${tr('ng.access_satisfy_all_d')}</span></span></label>
      <label class="switch"><input type="checkbox" id="alPassAuth"${editing && al.pass_auth ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.access_pass_auth')}</b><span>${tr('ng.access_pass_auth_d')}</span></span></label>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="alGo">${editing ? tr('ng.save') : tr('ng.create')}</button></div>`, (close) => {
    const userRow = (u) => {
      u = u || {};
      const w = el('div', { class: 'locrule' });
      w.innerHTML = `<div class="lr-row"><input class="field au-user" placeholder="${tr('ng.access_username')}" value="${esc(u.username || '')}" /><input class="field au-pw" type="text" placeholder="${u.username ? tr('ng.access_pw_keep') : tr('ng.access_password')}" autocomplete="new-password" /><button type="button" class="lr-del" title="${tr('ng.delete')}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>`;
      w.querySelector('.lr-del').onclick = () => w.remove();
      $('alUsers').appendChild(w);
    };
    const ruleRow = (c) => {
      c = c || {};
      const w = el('div', { class: 'locrule' });
      w.innerHTML = `<div class="lr-row"><select class="field proto ar-dir"><option value="allow">${tr('ng.access_allow')}</option><option value="deny">${tr('ng.access_deny')}</option></select><input class="field ar-addr" placeholder="${tr('ng.access_addr_ph')}" value="${esc(c.address || '')}" /><button type="button" class="lr-del" title="${tr('ng.delete')}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>`;
      if (c.directive === 'deny') w.querySelector('.ar-dir').value = 'deny';
      w.querySelector('.lr-del').onclick = () => w.remove();
      $('alRules').appendChild(w);
    };
    $('alAddUser').onclick = () => userRow();
    $('alAddRule').onclick = () => ruleRow();
    if (editing) {
      (al.users || []).forEach((u) => userRow(u));
      (al.clients || []).forEach((c) => ruleRow(c));
    }
    $('alGo').onclick = () => {
      const name = $('alName').value.trim();
      if (!name) return toast(tr('ng.need_access_name'), 'err');
      const users = Array.from($('alUsers').querySelectorAll('.locrule')).map((w) => ({ username: w.querySelector('.au-user').value.trim(), password: w.querySelector('.au-pw').value })).filter((u) => u.username);
      const clients = Array.from($('alRules').querySelectorAll('.locrule')).map((w) => ({ directive: w.querySelector('.ar-dir').value, address: w.querySelector('.ar-addr').value.trim() })).filter((c) => c.address);
      const body = { op: 'save_access', name, satisfy: $('alSatisfy').checked ? 'all' : 'any', pass_auth: $('alPassAuth').checked, users, clients };
      if (editing) body.access_id = al.id;
      $('alGo').disabled = true;
      op('website', body).then(() => { toast(editing ? tr('common.saved') : tr('common.created'), 'ok'); close(); reload(); }).catch((e) => { toast(e.message, 'err'); $('alGo').disabled = false; });
    };
    bindDirty('alGo');
  });
}

// ---- Tab: Default site (catch-all for unmatched requests) ----
function ngDefaultTab(v) {
  const body = $('ngBody');
  body.innerHTML = loading();
  op('website', { op: 'get_settings' }).then((d) => {
    const ds = (d.default_site) || { mode: '404', redirect_url: '' };
    body.innerHTML = `
      <div style="max-width:560px">
        <div class="sechead" style="margin-top:0"><h3>${tr('ng.default_site')}</h3></div>
        <p class="mut" style="font-size:12.5px;margin:0 0 14px">${tr('ng.default_site_desc')}</p>
        <div id="ngDsBox">
        <label class="lbl">${tr('ng.default_behavior')}</label>
        <select id="ngDsMode" class="field" style="max-width:300px;margin-bottom:12px">
          <option value="404">${tr('ng.ds_404')}</option>
          <option value="welcome">${tr('ng.ds_welcome')}</option>
          <option value="444">${tr('ng.ds_444')}</option>
          <option value="redirect">${tr('ng.ds_redirect')}</option>
        </select>
        <div id="ngDsRedirectWrap" class="hidden"><label class="lbl">${tr('ng.ds_redirect_url')}</label><input id="ngDsUrl" class="field" placeholder="https://example.com" value="${esc(ds.redirect_url || '')}" style="margin-bottom:12px" /></div>
        <div class="row" style="align-items:center;gap:12px"><button class="btn sm" id="ngDsSave" disabled>${tr('ng.save')}</button><span class="err ok" id="ngDsMsg"></span></div>
        </div>
      </div>`;
    $('ngDsMode').value = ds.mode || '404';
    const sync = () => $('ngDsRedirectWrap').classList.toggle('hidden', $('ngDsMode').value !== 'redirect');
    $('ngDsMode').onchange = sync; sync();
    $('ngDsSave').onclick = () => {
      const m = $('ngDsMsg');
      const bodyReq = { op: 'set_default_site', default_mode: $('ngDsMode').value, redirect_url: $('ngDsUrl') ? $('ngDsUrl').value.trim() : '' };
      $('ngDsSave').disabled = true;
      op('website', bodyReq).then(() => { m.className = 'err ok'; m.textContent = tr('common.saved'); if ($('ngDsSave')._dirtyReset) $('ngDsSave')._dirtyReset(); }).catch((e) => { m.className = 'err'; m.textContent = e.message; $('ngDsSave').disabled = false; });
    };
    bindDirty('ngDsSave', 'ngDsBox');
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ---- Tab: Settings (performance / tuning) ----
function ngSettingsTab(v) {
  const body = $('ngBody');
  body.innerHTML = loading();
  op('website', { op: 'get_settings' }).then((d) => {
    const t = d.tuning || {};
    const bktOpts = [32, 64, 128, 256, 512].map((n) => `<option value="${n}"${Number(t.server_names_hash_bucket_size) === n ? ' selected' : ''}>${n}</option>`).join('');
    const lvlOpts = Array.from({ length: 9 }, (_, i) => i + 1).map((n) => `<option value="${n}"${Number(t.gzip_comp_level) === n ? ' selected' : ''}>${n}</option>`).join('');
    body.innerHTML = `
      <div style="max-width:560px">
        <div class="sechead" style="margin-top:0"><h3>${tr('ng.perf_sec')}</h3></div>
        <p class="mut" style="font-size:12.5px;margin:0 0 14px">${tr('ng.perf_desc')}</p>
        <div id="ngTuneBox">
        <div class="formgrid">
          <div><label class="lbl">${tr('ng.t_cmbs')}</label><div class="field-suffix"><input id="ngCmbs" class="field" type="number" min="0" value="${esc(String(parseInt(t.client_max_body_size, 10) || 1024))}" /><span class="suffix-tag">MB</span></div></div>
          <div><label class="lbl">${tr('ng.t_chdr')}</label><div class="field-suffix"><input id="ngChdr" class="field" type="number" min="0" value="${esc(String(parseInt(t.client_header_buffer_size, 10) || 32))}" /><span class="suffix-tag">KB</span></div></div>
          <div><label class="lbl">${tr('ng.t_kat')}</label><input id="ngKat" class="field" type="number" min="0" value="${esc(String(t.keepalive_timeout != null ? t.keepalive_timeout : 60))}" /></div>
          <div><label class="lbl">${tr('ng.t_snhbs')}</label><select id="ngSnhbs" class="field">${bktOpts}</select></div>
        </div>
        <label class="switch" style="padding:0;margin-top:14px"><input type="checkbox" id="ngGzip" ${t.gzip !== false ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('ng.t_gzip')}</b><span>${tr('ng.t_gzip_d')}</span></span></label>
        <div id="ngGzipWrap" class="formgrid" style="margin-top:12px">
          <div><label class="lbl">${tr('ng.t_gmin')}</label><input id="ngGmin" class="field" type="number" min="0" value="${esc(String(t.gzip_min_length != null ? t.gzip_min_length : 20))}" /></div>
          <div><label class="lbl">${tr('ng.t_gcl')}</label><select id="ngGcl" class="field">${lvlOpts}</select></div>
        </div>
        <div class="row" style="align-items:center;gap:12px;margin-top:16px"><button class="btn sm" id="ngTuneSave" disabled>${tr('ng.save')}</button><button class="btn sm sec" id="ngTuneDefault">${tr('ng.restore_defaults')}</button><span class="err ok" id="ngTuneMsg"></span></div>
        <p class="formnote" style="margin-top:10px">${tr('ng.perf_note')}</p>
        </div>
      </div>`;
    const syncGz = () => $('ngGzipWrap').classList.toggle('hidden', !$('ngGzip').checked);
    $('ngGzip').onchange = syncGz; syncGz();
    const collect = () => ({
      op: 'set_tuning',
      client_max_body_size: (Number($('ngCmbs').value) || 0) + 'm',
      client_header_buffer_size: (Number($('ngChdr').value) || 0) + 'k',
      keepalive_timeout: Number($('ngKat').value) || 0,
      server_names_hash_bucket_size: Number($('ngSnhbs').value),
      gzip: $('ngGzip').checked,
      gzip_min_length: Number($('ngGmin').value) || 0,
      gzip_comp_level: Number($('ngGcl').value),
    });
    const save = (bodyReq) => {
      const m = $('ngTuneMsg');
      $('ngTuneSave').disabled = true;
      op('website', bodyReq).then(() => { m.className = 'err ok'; m.textContent = tr('common.saved'); if ($('ngTuneSave')._dirtyReset) $('ngTuneSave')._dirtyReset(); }).catch((e) => { m.className = 'err'; m.textContent = e.message; $('ngTuneSave').disabled = false; });
    };
    $('ngTuneSave').onclick = () => save(collect());
    $('ngTuneDefault').onclick = () => {
      $('ngCmbs').value = '50'; $('ngChdr').value = '32'; $('ngKat').value = '60';
      $('ngSnhbs').value = '64'; $('ngGzip').checked = true; syncGz();
      $('ngGmin').value = '20'; $('ngGcl').value = '1';
      save(collect());
    };
    bindDirty('ngTuneSave', 'ngTuneBox');
  }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Host directory picker (for static sites served from an existing directory).
// Navigates the host filesystem via the website `list_dirs` op (admin-gated).
function ngDirPicker(onPick) {
  modal(tr('ng.pick_dir_title'), `
    <div class="mono mut" id="dpPath" style="font-size:12px;margin-bottom:8px;word-break:break-all">/</div>
    <div class="tablescroll" style="max-height:300px"><div id="dpList">${loading()}</div></div>
    <div class="row" style="justify-content:space-between;margin-top:14px"><button class="btn sec" id="dpUp">${tr('ng.dir_up')}</button><button class="btn" id="dpSelect">${tr('ng.select_dir')}</button></div>`, (close) => {
    let cur = '/';
    let parent = null;
    const load = (p) => {
      $('dpList').innerHTML = loading();
      op('website', { op: 'list_dirs', path: p }).then((d) => {
        cur = d.path || '/';
        parent = d.parent || null;
        $('dpPath').textContent = cur;
        const dirs = d.dirs || [];
        $('dpList').innerHTML = dirs.length
          ? dirs.map((n) => `<button type="button" class="dpitem" data-d="${esc(n)}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>${esc(n)}</button>`).join('')
          : `<div class="empty">${tr('ng.dir_empty')}</div>`;
        $('dpList').querySelectorAll('[data-d]').forEach((b) => b.onclick = () => load((cur.endsWith('/') ? cur : cur + '/') + b.dataset.d));
        $('dpUp').disabled = !parent;
      }).catch((e) => { $('dpList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    };
    $('dpUp').onclick = () => { if (parent) load(parent); };
    $('dpSelect').onclick = () => { onPick(cur); close(); };
    load('/');
  });
}
