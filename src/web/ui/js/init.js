// =========================================================================
// First-run init wizard
// =========================================================================
// Shown instead of the login screen while the panel is UNINITIALIZED. The
// operator reaches it via the banner's http://<ip>/?init_token=<token> URL
// (past the init-token gate, which has set the dn7_init cookie this code rides).
// Two steps: (1) external access address + HTTPS mode, (2) admin account.

let iwState = { addr: '', mode: 'none' };

// Decide login vs wizard at boot. Resolves true when the wizard took over.
function bootInit() {
  const login = $('login');
  login.classList.add('hidden'); // avoid flashing login before we know
  return fetch('/api/init/status')
    .then((r) => (r.ok ? r.json() : Promise.reject()))
    .then((s) => {
      if (s && s.initialized === false) {
        startInitWizard();
        return true;
      }
      login.classList.remove('hidden');
      return false;
    })
    .catch(() => {
      login.classList.remove('hidden');
      return false;
    });
}

function startInitWizard() {
  const root = $('modalRoot');
  if (document.getElementById('iwCard')) return;
  const mask = el('div', { class: 'mask' });
  mask.innerHTML = `<div class="modal" id="iwCard" style="width:480px">
    <div class="modal-h"><h3 id="iwTitle">初始化面板</h3></div>
    <div class="modal-b" id="iwBody"></div>
  </div>`;
  root.appendChild(mask);
  iwStep1();
}

function iwStep1() {
  $('iwTitle').textContent = '初始化 · 第 1 步：访问地址与 HTTPS';
  $('iwBody').innerHTML = `
    <p class="mut" style="margin:0 0 16px;font-size:13px;line-height:1.6">设置控制台的对外访问地址。默认使用当前地址，也可改为已解析到本机的域名。</p>
    <label class="lbl">对外访问地址</label>
    <input id="iwAddr" class="field" style="margin-bottom:4px" placeholder="example.com 或 1.2.3.4" />
    <div class="mut" style="font-size:12px;margin-bottom:14px">使用域名才能申请 Let's Encrypt 证书。</div>
    <label class="lbl">HTTPS</label>
    <div style="margin:6px 0 16px;display:flex;flex-direction:column;gap:8px">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="none" checked> 不启用（仅 HTTP）</label>
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="selfsigned"> 自签名证书（浏览器会提示不受信任）</label>
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="le"> Let's Encrypt（需域名且公网可访问 80 端口）</label>
    </div>
    <button class="btn" id="iwNext" style="width:100%">下一步</button>
    <div class="err" id="iwErr" style="margin-top:10px"></div>`;
  $('iwAddr').value = location.hostname;
  $('iwNext').addEventListener('click', iwSubmit1);
}

function iwMode() {
  const r = document.querySelector('input[name="iwHttps"]:checked');
  return r ? r.value : 'none';
}

// A host that looks like an IP literal (so we can reject LE on an IP up front).
function iwIsIp(s) {
  return /^[0-9.]+$/.test(s) || s.indexOf(':') >= 0;
}

function iwSubmit1() {
  const err = $('iwErr');
  err.textContent = '';
  const addr = $('iwAddr').value.trim();
  const mode = iwMode();
  if (!addr) {
    err.textContent = '请填写访问地址';
    return;
  }
  if (mode === 'le' && iwIsIp(addr)) {
    err.textContent = "Let's Encrypt 需要域名，不能使用 IP";
    return;
  }
  const btn = $('iwNext');
  btn.disabled = true;
  btn.textContent = mode === 'le' ? '正在申请证书…（可能需要一会儿）' : '处理中…';
  fetch('/api/init/step1', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ external_address: addr, https_mode: mode }),
  })
    .then(async (r) => {
      const b = await r.json().catch(() => ({}));
      if (!r.ok || !b.ok) throw new Error(b.msg || '处理失败');
    })
    .then(() => {
      iwState = { addr, mode };
      iwStep2();
    })
    .catch((e) => {
      btn.disabled = false;
      btn.textContent = '下一步';
      err.textContent = e.message;
    });
}

function iwStep2() {
  $('iwTitle').textContent = '初始化 · 第 2 步：管理员账号';
  $('iwBody').innerHTML = `
    <p class="mut" style="margin:0 0 16px;font-size:13px;line-height:1.6">创建管理员账号，用于登录控制台。</p>
    <label class="lbl">账号</label>
    <input id="iwUser" class="field" style="margin-bottom:12px" autocomplete="username" placeholder="小写字母开头，可含数字 _ -" />
    <label class="lbl">密码</label>
    <input id="iwPw" class="field" type="password" autocomplete="new-password" style="margin-bottom:12px" />
    <label class="lbl">确认密码</label>
    <input id="iwPw2" class="field" type="password" autocomplete="new-password" />
    <button class="btn" id="iwDone" style="margin-top:18px;width:100%">完成初始化</button>
    <div class="err" id="iwErr" style="margin-top:10px"></div>`;
  $('iwDone').addEventListener('click', iwSubmit2);
}

function iwSubmit2() {
  const err = $('iwErr');
  err.textContent = '';
  const un = $('iwUser').value.trim();
  const pw = $('iwPw').value;
  const pw2 = $('iwPw2').value;
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(un) || un === 'root') {
    err.textContent = '用户名格式不正确（小写字母开头，1-32 位，且不能为 root）';
    return;
  }
  if (pw.length < 6 || pw.length > 128) {
    err.textContent = '密码长度需为 6-128 位';
    return;
  }
  if (pw !== pw2) {
    err.textContent = '两次输入的密码不一致';
    return;
  }
  const btn = $('iwDone');
  btn.disabled = true;
  btn.textContent = '提交中…';
  const salt = randHex(16);
  const body = {
    username: un,
    pw_salt: salt,
    pw_hash: deriveVerifier(salt, pw, newKdf()),
    pw_kdf: newKdf(),
  };
  fetch('/api/init/step2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(async (r) => {
      const b = await r.json().catch(() => ({}));
      if (!r.ok || !b.ok) throw new Error(b.msg || '处理失败');
    })
    .then(() => iwFinish())
    .catch((e) => {
      btn.disabled = false;
      btn.textContent = '完成初始化';
      err.textContent = e.message;
    });
}

function iwFinish() {
  const addr = iwState.addr;
  const scheme = iwState.mode === 'none' ? 'http' : 'https';
  // If the access address is the host we're already on, the console is reachable
  // right here — reload into the login page (an https mode redirects there).
  if (addr === location.hostname) {
    location.replace('/');
    return;
  }
  // Otherwise the console moved to a new name; point the operator at it.
  const url = scheme + '://' + addr + '/';
  $('iwTitle').textContent = '初始化完成';
  $('iwBody').innerHTML = `
    <p style="margin:0 0 16px;line-height:1.7">控制台已就绪，请通过新的访问地址登录：</p>
    <a class="btn" style="width:100%;display:block;text-align:center;box-sizing:border-box;text-decoration:none" href="${url}">${url}</a>`;
}
