// =========================================================================
// Nginx management
// =========================================================================
function renderNginx(v) {
  v.innerHTML = `<div style="padding:8px">${loading('正在检测 Nginx')}</div>`;
  if (getJob('nginx:setup')) {
    v.innerHTML = `<div class="card"><h3>正在初始化 Nginx</h3><div id="ngSetupJob"></div></div>`;
    reattachJob($('ngSetupJob'), 'nginx:setup', { onDone: () => setTimeout(() => renderNginx(v), 800) });
    return;
  }
  op('nginx', { op: 'info' }).then((info) => {
    if (!info.managed) {
      const present = info.host_nginx_present;
      const hint = present
        ? `检测到宿主机已安装 Nginx${info.host_nginx_version ? '（' + esc(info.host_nginx_version) + '）' : ''}，初始化后即可统一托管站点与 HTTPS 证书。`
        : '宿主机未安装 Nginx，初始化将使用系统包管理器自动安装并启用，然后即可托管站点与 HTTPS 证书。';
      v.innerHTML = `<div class="card"><h3>Nginx 初始化</h3>
        <p class="mut">${hint}</p>
        <div class="row" style="margin:14px 0">
          <button class="btn" id="ngSetup">初始化</button>
        </div>
        <div class="hidden" id="ngSetupJob"></div></div>`;
      $('ngSetup').onclick = () => { $('ngSetup').disabled = true; $('ngSetupJob').classList.remove('hidden'); op('nginx', { op: 'setup' }).then((r) => renderJob($('ngSetupJob'), 'nginx', r.op_id, 'nginx:setup', { onDone: () => { toast('初始化完成', 'ok'); setTimeout(() => renderNginx(v), 600); }, onError: () => { $('ngSetup').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ngSetup').disabled = false; }); };
      return;
    }
    v.innerHTML = `<div class="row" style="margin-bottom:14px"><span class="chip on">运行中</span><span class="sp" style="flex:1"></span><button class="btn sm" id="ngAdd">添加站点</button><button class="btn sec sm" id="ngCert">SSL 证书</button><button class="btn sec sm" id="ngReload">重载配置</button><button class="btn sec sm" id="ngRef">刷新</button></div><div id="ngSites">${loading()}</div>`;
    $('ngRef').onclick = () => renderNginx(v);
    $('ngReload').onclick = () => op('nginx', { op: 'reload' }).then(() => toast('已重载', 'ok')).catch((e) => toast(e.message, 'err'));
    $('ngAdd').onclick = () => ngAddSite(() => renderNginx(v));
    $('ngCert').onclick = () => ngCerts();
    op('nginx', { op: 'list_sites' }).then((d) => {
      const sites = d.sites || [];
      if (!sites.length) { $('ngSites').innerHTML = '<div class="empty">暂无站点</div>'; return; }
      let h = '<table class="optable"><tr><th>域名</th><th>类型</th><th>目标</th><th>SSL</th><th class="act">操作</th></tr>';
      sites.forEach((s) => {
        const sch = s.scheme === 'https' ? 'https://' : (s.kind === 'static' ? '' : 'http://');
        let target = s.kind === 'proxy_host' ? esc(sch + s.target_url) : s.kind === 'proxy_container' ? esc(`${sch}${s.container}:${s.container_port}`) : esc('/' + s.root);
        if (s.locations && s.locations.length) target += ` <span class="mut">+${s.locations.length} 规则</span>`;
        h += `<tr><td><b>${esc(s.server_name)}</b></td><td class="mut">${esc(kindLabel(s.kind))}</td><td class="mono" style="font-size:12px">${target}</td><td>${s.ssl ? '<span class="chip on">是</span>' : '<span class="chip">否</span>'}</td><td class="act"><button class="btn sm danger" data-rm="${esc(s.id)}">删除</button></td></tr>`;
      });
      $('ngSites').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#ngSites [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger('删除该站点？')) op('nginx', { op: 'remove_site', site_id: b.dataset.rm }).then(() => { toast('已删除', 'ok'); renderNginx(v); }).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('ngSites').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  }).catch((e) => { v.innerHTML = `<div class="card"><p class="err">${esc(e.message)}</p></div>`; });
}
function kindLabel(k) { return { proxy_host: '反代主机', proxy_container: '反代容器', static: '静态站点' }[k] || k; }

function ngAddSite(reload) {
  modal('添加站点', `
    <div class="ftabs" id="nsTabs">
      <button class="on" data-t="detail">详情</button>
      <button data-t="rules">自定义路径规则</button>
      <button data-t="ssl">SSL</button>
    </div>
    <!-- Tab: 详情 -->
    <div class="ftab-pane on" data-p="detail">
      <div class="formgrid">
        <div class="full"><label class="lbl">域名（server_name）</label><input id="nsName" class="field" placeholder="example.com" /></div>
        <div class="full"><label class="lbl">类型</label><select id="nsKind" class="field">
          <option value="proxy_host">反向代理到宿主机</option>
          <option value="proxy_container">反向代理到容器</option>
          <option value="static">静态文件</option>
        </select></div>
        <div class="full" id="nsKindFields"></div>
      </div>
      <div style="margin-top:8px">
        <label class="switch"><input type="checkbox" id="nsCache" /><span class="swbox"></span><span class="swtxt"><b>缓存资源</b><span>对静态资源设置长期缓存</span></span></label>
        <label class="switch"><input type="checkbox" id="nsBlock" /><span class="swbox"></span><span class="swtxt"><b>阻止常见攻击</b><span>拦截常见的恶意请求特征</span></span></label>
        <label class="switch"><input type="checkbox" id="nsWs" checked /><span class="swbox"></span><span class="swtxt"><b>Websockets 支持</b><span>转发 Upgrade/Connection 头</span></span></label>
      </div>
    </div>
    <!-- Tab: 自定义路径规则 -->
    <div class="ftab-pane" data-p="rules">
      <p class="mut" style="font-size:12.5px;margin:0 0 12px">为特定路径前缀设置独立的转发目标（类似 Nginx Proxy Manager 的自定义 location）。</p>
      <div id="nsLocs"></div>
      <button type="button" class="locadd" id="nsLocAdd">+ 添加路径规则</button>
    </div>
    <!-- Tab: SSL -->
    <div class="ftab-pane" data-p="ssl">
      <label class="switch"><input type="checkbox" id="nsSsl" /><span class="swbox"></span><span class="swtxt"><b>启用 HTTPS</b><span>为该站点配置 SSL 证书</span></span></label>
      <div class="hidden" id="nsCertWrap" style="margin-top:12px"><label class="lbl">证书方式</label><select id="nsCert" class="field"><option value="named">引用证书库</option><option value="le">Let's Encrypt 自动签发</option><option value="self">自签名</option><option value="manual">手动粘贴</option></select></div>
      <div class="full hidden" id="nsNamedWrap" style="margin-top:10px"><label class="lbl">选择证书</label><select id="nsNamed" class="field"></select></div>
      <div class="full hidden" id="nsManual" style="margin-top:10px"><label class="lbl">证书 PEM</label><textarea id="nsCertPem" class="field" rows="3"></textarea><label class="lbl" style="margin-top:8px">私钥 PEM</label><textarea id="nsKeyPem" class="field" rows="3"></textarea></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="nsGo">创建</button></div>
    <div class="hidden" id="nsJob" style="margin-top:14px"></div>`, (close) => {
    // Tab switching.
    document.querySelectorAll('#nsTabs button').forEach((b) => b.onclick = () => {
      document.querySelectorAll('#nsTabs button').forEach((x) => x.className = x === b ? 'on' : '');
      document.querySelectorAll('.ftab-pane').forEach((p) => p.className = 'ftab-pane' + (p.dataset.p === b.dataset.t ? ' on' : ''));
    });

    // SSL cert library options.
    let named = [];
    op('nginx', { op: 'list_named_certs' }).then((d) => {
      named = (d.certs || []).filter((c) => c.has_cert);
      $('nsNamed').innerHTML = named.length
        ? named.map((c) => `<option value="${esc(c.name)}">${esc(c.name)}${c.domain ? '（' + esc(c.domain) + '）' : ''}</option>`).join('')
        : '<option value="">证书库为空，请先在「SSL 证书」创建</option>';
    }).catch(() => {});

    // Available containers (for the proxy_container picker).
    let containers = [];
    op('nginx', { op: 'list_containers' }).then((d) => { containers = d.containers || []; if ($('nsKind').value === 'proxy_container') kindFields(); }).catch(() => {});

    // Static-upload state: collected files (zip or folder) staged client-side,
    // uploaded after the site is created (so the webroot name is known).
    const staticUpload = { mode: null, zip: null, files: [] };

    const kindFields = () => {
      const k = $('nsKind').value;
      if (k === 'proxy_host') {
        $('nsKindFields').innerHTML = '<div class="formgrid"><div><label class="lbl">协议</label><select id="nsScheme" class="field"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div><div><label class="lbl">宿主机端口</label><input id="nsTarget" class="field" placeholder="3000 或 127.0.0.1:3000" /></div></div>';
      } else if (k === 'proxy_container') {
        const opts = containers.length
          ? containers.map((c) => `<option value="${esc(c.name)}">${esc(c.name)}${c.ports ? ' · ' + esc(c.ports) : ''}</option>`).join('')
          : '<option value="">未发现运行中的容器</option>';
        $('nsKindFields').innerHTML = `<div class="formgrid"><div><label class="lbl">协议</label><select id="nsScheme" class="field"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div><div><label class="lbl">容器</label><select id="nsCtn" class="field">${opts}</select></div><div><label class="lbl">容器端口</label><input id="nsCtnPort" class="field" type="number" placeholder="80" /></div></div>`;
      } else {
        $('nsKindFields').innerHTML = `
          <label class="lbl">静态站点目录名</label><input id="nsRoot" class="field" placeholder="mysite" style="margin-bottom:10px" />
          <label class="lbl">上传内容</label>
          <div class="dropz" id="nsDrop"><b>点击选择</b> ZIP 压缩包，或拖拽文件夹到此处<br/><span style="font-size:11.5px">支持上传 .zip，或选择整个文件夹逐文件上传</span></div>
          <input type="file" id="nsZip" accept=".zip" class="hidden" />
          <input type="file" id="nsDir" webkitdirectory multiple class="hidden" />
          <div class="row" style="gap:8px;margin-top:8px"><button type="button" class="btn sm sec" id="nsPickZip">选择 ZIP</button><button type="button" class="btn sm sec" id="nsPickDir">选择文件夹</button></div>
          <div class="uplist" id="nsUpList"></div>`;
        wireStaticPickers();
      }
    };
    const wireStaticPickers = () => {
      const drop = $('nsDrop');
      $('nsPickZip').onclick = () => $('nsZip').click();
      $('nsPickDir').onclick = () => $('nsDir').click();
      drop.onclick = () => $('nsZip').click();
      $('nsZip').onchange = (e) => { const f = e.target.files[0]; if (!f) return; staticUpload.mode = 'zip'; staticUpload.zip = f; staticUpload.files = []; $('nsUpList').innerHTML = `已选择 ZIP：${esc(f.name)}（${fmtBytes(f.size)}）`; };
      $('nsDir').onchange = (e) => { const fs = Array.from(e.target.files || []); if (!fs.length) return; staticUpload.mode = 'dir'; staticUpload.zip = null; staticUpload.files = fs; $('nsUpList').innerHTML = `已选择 ${fs.length} 个文件：<br/>` + fs.slice(0, 20).map((f) => esc(f.webkitRelativePath || f.name)).join('<br/>') + (fs.length > 20 ? '<br/>…' : ''); };
      ['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
      ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
      drop.addEventListener('drop', (e) => { const f = (e.dataTransfer.files || [])[0]; if (f && /\.zip$/i.test(f.name)) { staticUpload.mode = 'zip'; staticUpload.zip = f; staticUpload.files = []; $('nsUpList').innerHTML = `已选择 ZIP：${esc(f.name)}（${fmtBytes(f.size)}）`; } });
    };
    $('nsKind').onchange = kindFields; kindFields();

    // Path-rule rows.
    const locRow = (v) => {
      v = v || {};
      const wrap = el('div', { class: 'locrule' });
      wrap.innerHTML = `
        <div class="lr-head"><input class="field lr-path" placeholder="/api" value="${esc(v.path || '')}" /><button type="button" class="rm">×</button></div>
        <div class="lr-row"><select class="field proto lr-scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select><input class="field lr-target" placeholder="127.0.0.1:3001" value="${esc(v.target || '')}" /></div>
        <label class="switch" style="padding:8px 0 2px"><input type="checkbox" class="lr-ws"${v.websockets ? ' checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>Websockets 支持</b></span></label>`;
      if (v.scheme === 'https') wrap.querySelector('.lr-scheme').value = 'https';
      wrap.querySelector('.rm').onclick = () => wrap.remove();
      $('nsLocs').appendChild(wrap);
    };
    $('nsLocAdd').onclick = () => locRow();

    // SSL toggles.
    $('nsSsl').onchange = () => { $('nsCertWrap').classList.toggle('hidden', !$('nsSsl').checked); certFields(); };
    const certFields = () => {
      const on = $('nsSsl').checked;
      const m = $('nsCert').value;
      $('nsManual').classList.toggle('hidden', !(on && m === 'manual'));
      $('nsNamedWrap').classList.toggle('hidden', !(on && m === 'named'));
    };
    $('nsCert') && ($('nsCert').onchange = certFields);

    const collectLocs = () => Array.from($('nsLocs').querySelectorAll('.locrule')).map((w) => ({
      path: w.querySelector('.lr-path').value.trim(),
      scheme: w.querySelector('.lr-scheme').value,
      target: w.querySelector('.lr-target').value.trim(),
      websockets: w.querySelector('.lr-ws').checked,
    })).filter((l) => l.path || l.target);

    $('nsGo').onclick = async () => {
      const k = $('nsKind').value;
      const body = { op: 'add_site', server_name: $('nsName').value.trim(), kind: k, ssl: $('nsSsl').checked, cache: $('nsCache').checked, block_attacks: $('nsBlock').checked, websockets: $('nsWs').checked, locations: collectLocs() };
      if (!body.server_name) return toast('请输入域名', 'err');
      if (k === 'proxy_host') { body.scheme = $('nsScheme').value; const p = $('nsTarget').value.trim(); if (!p) return toast('请输入宿主机端口', 'err'); body.target_url = /^\d+$/.test(p) ? '127.0.0.1:' + p : p; }
      else if (k === 'proxy_container') { body.scheme = $('nsScheme').value; body.container = $('nsCtn').value.trim(); body.container_port = Number($('nsCtnPort').value); if (!body.container) return toast('请选择容器', 'err'); }
      else { body.root = $('nsRoot').value.trim(); if (!body.root) return toast('请输入静态站点目录名', 'err'); if (!staticUpload.mode) return toast('请选择要上传的 ZIP 或文件夹', 'err'); }
      if (body.ssl) {
        body.cert_mode = $('nsCert').value;
        if (body.cert_mode === 'manual') { body.cert_pem = $('nsCertPem').value; body.key_pem = $('nsKeyPem').value; }
        else if (body.cert_mode === 'named') { body.cert_name = $('nsNamed').value; if (!body.cert_name) return toast('请先在 SSL 证书库创建证书', 'err'); }
      }
      $('nsGo').disabled = true; $('nsJob').classList.remove('hidden'); $('nsJob').innerHTML = '<div class="mut">提交中…</div>';
      // For static sites, upload content first so the webroot exists before the
      // site is generated (nginx -t needs the root to exist for some checks).
      try {
        if (k === 'static') { $('nsJob').innerHTML = '<div class="mut">上传站点内容…</div>'; await uploadStatic(body.root, staticUpload); }
      } catch (e) { toast('上传失败：' + e.message, 'err'); $('nsJob').innerHTML = ''; $('nsGo').disabled = false; return; }
      op('nginx', body).then((r) => {
        if (r.op_id) renderJob($('nsJob'), 'nginx', r.op_id, '', { onDone: () => { toast('站点已创建', 'ok'); close(); reload(); }, onError: () => { $('nsGo').disabled = false; } });
        else { toast('站点已创建', 'ok'); close(); reload(); }
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
    if (!r.ok || b.ok === false) throw new Error(b.error || '上传失败');
    return;
  }
  if (su.mode === 'dir' && su.files.length) {
    for (let i = 0; i < su.files.length; i++) {
      const f = su.files[i];
      // Strip the leading top-level folder so files land at the webroot root.
      let rel = f.webkitRelativePath || f.name;
      const slash = rel.indexOf('/');
      if (slash > 0) rel = rel.slice(slash + 1);
      const qs = `root=${encodeURIComponent(root)}&mode=file&rel=${encodeURIComponent(rel)}` + (i === 0 ? '&clear=1' : '');
      const r = await fetch('/api/nginx/static-upload?' + qs, { method: 'POST', headers: { 'Authorization': 'Bearer ' + S.token }, body: f });
      const b = await r.json().catch(() => ({}));
      if (!r.ok || b.ok === false) throw new Error(b.error || ('上传失败：' + rel));
    }
  }
}

// SSL certificate management. Two sections:
//   1. Standalone certs — create/list/delete certs independent of any site.
//   2. Per-site certs — each site's current cert status + (re)issue.
function ngCerts() {
  modal('SSL 证书管理', `
    <div class="seg" id="ngCertTabs" style="margin-bottom:14px">
      <button class="on" data-t="standalone">证书库</button>
      <button data-t="sites">站点证书</button>
    </div>
    <div id="ngCertBody">${loading()}</div>`, () => {
    let tab = 'standalone';
    const loadStandalone = () => op('nginx', { op: 'list_named_certs' }).then((d) => {
      const certs = d.certs || [];
      let h = '<div class="row" style="margin-bottom:12px"><span class="mut" style="font-size:12.5px;flex:1">独立创建的证书可在「添加站点」或「站点证书」中被复用。</span><button class="btn sm" id="ngCertNew">创建证书</button></div>';
      if (!certs.length) { h += '<div class="empty">暂无证书。点击「创建证书」新建。</div>'; }
      else {
        h += '<table class="optable"><tr><th>名称</th><th>域名</th><th>方式</th><th>到期</th><th>使用</th><th class="act">操作</th></tr>';
        certs.forEach((c) => {
          const modeLabel = { le: "Let's Encrypt", self: '自签名', manual: '手动' }[c.cert_mode] || c.cert_mode;
          const used = (c.used_by && c.used_by.length) ? esc(c.used_by.join('、')) : '<span class="mut">未使用</span>';
          h += `<tr><td><b>${esc(c.name)}</b>${c.has_cert ? '' : ' <span class="chip warn">缺失</span>'}</td><td class="mut">${esc(c.domain || '-')}</td><td class="mut">${esc(modeLabel)}</td><td class="mono" style="font-size:12px">${esc(c.not_after || '-')}</td><td style="font-size:12px">${used}</td><td class="act"><button class="btn sm danger" data-del="${esc(c.name)}">删除</button></td></tr>`;
        });
        h += '</table>';
      }
      $('ngCertBody').innerHTML = '<div class="tablewrap">' + h + '</div>';
      $('ngCertNew').onclick = () => ngCreateCert(loadStandalone);
      document.querySelectorAll('#ngCertBody [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger('删除证书「' + b.dataset.del + '」？')) op('nginx', { op: 'delete_cert', cert_name: b.dataset.del }).then(() => { toast('已删除', 'ok'); loadStandalone(); }).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('ngCertBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    const loadSites = () => op('nginx', { op: 'list_certs' }).then((d) => {
      const certs = d.certs || [];
      if (!certs.length) { $('ngCertBody').innerHTML = '<div class="empty">暂无站点。先在「添加站点」创建站点，再来管理其证书。</div>'; return; }
      let h = '<table class="optable"><tr><th>域名</th><th>方式</th><th>到期</th><th>状态</th><th class="act">操作</th></tr>';
      certs.forEach((c) => {
        const modeLabel = c.cert_mode === 'named' ? '引用证书库' : ({ le: "Let's Encrypt", self: '自签名', manual: '手动' }[c.cert_mode] || (c.ssl ? c.cert_mode : '—'));
        const status = !c.ssl ? '<span class="chip">未启用</span>' : (c.has_cert ? '<span class="chip on">已签发</span>' : '<span class="chip warn">缺失</span>');
        h += `<tr><td><b>${esc(c.server_name)}</b></td><td class="mut">${esc(modeLabel)}</td><td class="mono" style="font-size:12px">${esc(c.not_after || '-')}</td><td>${status}</td><td class="act"><button class="btn sm" data-id="${esc(c.id)}" data-name="${esc(c.server_name)}">配置证书</button></td></tr>`;
      });
      $('ngCertBody').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#ngCertBody [data-id]').forEach((b) => b.onclick = () => ngSetCert(b.dataset.id, b.dataset.name, loadSites));
    }).catch((e) => { $('ngCertBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    const refresh = () => { tab === 'standalone' ? loadStandalone() : loadSites(); };
    document.querySelectorAll('#ngCertTabs button').forEach((b) => b.onclick = () => {
      tab = b.dataset.t;
      document.querySelectorAll('#ngCertTabs button').forEach((x) => x.className = x.dataset.t === tab ? 'on' : '');
      $('ngCertBody').innerHTML = loading();
      refresh();
    });
    refresh();
  });
}

// Create a standalone named certificate (self-signed / LE / manual).
function ngCreateCert(reload) {
  modal('创建证书', `
    <div class="formgrid">
      <div class="full"><label class="lbl">证书名称</label><input id="ccName" class="field" placeholder="例如 mysite-2026" /></div>
      <div class="full"><label class="lbl">证书方式</label><select id="ccMode" class="field"><option value="self">自签名</option><option value="le">Let's Encrypt 自动签发</option><option value="manual">手动粘贴</option></select></div>
      <div class="full" id="ccDomainWrap"><label class="lbl">域名</label><input id="ccDomain" class="field" placeholder="example.com" /></div>
      <div class="full hidden" id="ccManual"><label class="lbl">证书 PEM</label><textarea id="ccCert" class="field" rows="3"></textarea><label class="lbl" style="margin-top:8px">私钥 PEM</label><textarea id="ccKey" class="field" rows="3"></textarea></div>
    </div>
    <p class="mut" style="font-size:12px;margin-top:6px" id="ccHint"></p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="ccGo">创建</button></div>
    <div class="hidden" id="ccJob" style="margin-top:14px"></div>`, (close) => {
    const sync = () => {
      const m = $('ccMode').value;
      $('ccManual').classList.toggle('hidden', m !== 'manual');
      $('ccDomainWrap').classList.toggle('hidden', m === 'manual');
      $('ccHint').textContent = m === 'le'
        ? "Let's Encrypt 需要该域名已解析到本机且 80 端口可被公网访问。"
        : m === 'self' ? '自签名证书浏览器会提示不受信任，适合内网/测试。' : '粘贴你已有的证书链和私钥（PEM）。';
    };
    $('ccMode').onchange = sync; sync();
    $('ccGo').onclick = () => {
      const mode = $('ccMode').value;
      const body = { op: 'create_cert', cert_name: $('ccName').value.trim(), cert_mode: mode };
      if (!body.cert_name) return toast('请输入证书名称', 'err');
      if (mode === 'manual') { body.cert_pem = $('ccCert').value; body.key_pem = $('ccKey').value; }
      else { body.server_name = $('ccDomain').value.trim(); if (!body.server_name) return toast('请输入域名', 'err'); }
      $('ccGo').disabled = true; $('ccJob').classList.remove('hidden'); $('ccJob').innerHTML = '<div class="mut">提交中…</div>';
      op('nginx', body).then((r) => {
        if (r.op_id) renderJob($('ccJob'), 'nginx', r.op_id, '', { onDone: () => { toast('证书已创建', 'ok'); close(); reload(); }, onError: () => { $('ccGo').disabled = false; } });
        else { toast('证书已创建', 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('ccJob').innerHTML = ''; $('ccGo').disabled = false; });
    };
  });
}

// Per-site cert (re)issue dialog.
function ngSetCert(siteId, name, reload) {
  modal('配置证书 · ' + name, `
    <label class="lbl">证书方式</label>
    <select id="scMode" class="field" style="margin-bottom:14px">
      <option value="named">引用证书库</option>
      <option value="le">Let's Encrypt 自动签发</option>
      <option value="self">自签名</option>
      <option value="manual">手动粘贴</option>
    </select>
    <div class="hidden" id="scNamedWrap"><label class="lbl">选择证书</label><select id="scNamed" class="field" style="margin-bottom:14px"></select></div>
    <div class="hidden" id="scManual"><label class="lbl">证书 PEM</label><textarea id="scCert" class="field" rows="4"></textarea><label class="lbl" style="margin-top:8px">私钥 PEM</label><textarea id="scKey" class="field" rows="4"></textarea></div>
    <p class="mut" style="font-size:12px;margin-top:6px" id="scHint"></p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="scGo">应用</button></div>
    <div class="hidden" id="scJob" style="margin-top:14px"></div>`, (close) => {
    let named = [];
    op('nginx', { op: 'list_named_certs' }).then((d) => {
      named = (d.certs || []).filter((c) => c.has_cert);
      $('scNamed').innerHTML = named.length
        ? named.map((c) => `<option value="${esc(c.name)}">${esc(c.name)}${c.domain ? '（' + esc(c.domain) + '）' : ''}</option>`).join('')
        : '<option value="">证书库为空，请先在「证书库」创建</option>';
      sync();
    }).catch(() => {});
    const sync = () => {
      const m = $('scMode').value;
      $('scManual').classList.toggle('hidden', m !== 'manual');
      $('scNamedWrap').classList.toggle('hidden', m !== 'named');
      $('scHint').textContent = m === 'le'
        ? "Let's Encrypt 需要该域名已解析到本机且 80 端口可被公网访问。"
        : m === 'self' ? '自签名证书浏览器会提示不受信任，适合内网/测试。'
        : m === 'named' ? '复用证书库中已创建的证书，多个站点可共用同一张证书。'
        : '粘贴你已有的证书链和私钥（PEM）。';
    };
    $('scMode').onchange = sync; sync();
    $('scGo').onclick = () => {
      const mode = $('scMode').value;
      const body = { op: 'set_cert', site_id: siteId, cert_mode: mode };
      if (mode === 'manual') { body.cert_pem = $('scCert').value; body.key_pem = $('scKey').value; }
      else if (mode === 'named') { body.cert_name = $('scNamed').value; if (!body.cert_name) return toast('请先在证书库创建证书', 'err'); }
      $('scGo').disabled = true; $('scJob').classList.remove('hidden'); $('scJob').innerHTML = '<div class="mut">提交中…</div>';
      op('nginx', body).then((r) => {
        if (r.op_id) renderJob($('scJob'), 'nginx', r.op_id, '', { onDone: () => { toast('证书已配置', 'ok'); close(); reload(); }, onError: () => { $('scGo').disabled = false; } });
        else { toast('证书已配置', 'ok'); close(); reload(); }
      }).catch((e) => { toast(e.message, 'err'); $('scJob').innerHTML = ''; $('scGo').disabled = false; });
    };
  });
}
