// =========================================================================
// First-run UI init wizard (the "UI custom" deploy mode)
// =========================================================================
// Shown instead of the login screen while the panel is UNINITIALIZED. The
// operator reaches it via the printed http://<addr>/init?init_token=<token> URL
// (past the init-token gate, which set the dn7_init cookie this code rides).
// Mirrors the CLI custom wizard's config set — access address + HTTPS mode +
// website HTTP/HTTPS ports + console port — then the admin account.

let iwState = { addr: '', mode: 'none', httpPort: 80, httpsPort: 443, consolePort: 0 };

// Decide login vs wizard at boot. Resolves true when the wizard took over.
function bootInit() {
  const login = $('login');
  if (login) login.classList.add('hidden'); // avoid flashing login before we know
  return fetch('/api/init/status')
    .then((r) => (r.ok ? r.json() : Promise.reject()))
    .then((s) => {
      if (s && s.initialized === false) {
        startInitWizard();
        return true;
      }
      if (login) login.classList.remove('hidden');
      return false;
    })
    .catch(() => {
      if (login) login.classList.remove('hidden');
      return false;
    });
}

function startInitWizard() {
  const root = $('modalRoot');
  if (document.getElementById('iwCard')) return;
  const mask = el('div', { class: 'mask' });
  mask.innerHTML = `<div class="modal" id="iwCard" style="width:480px">
    <div class="modal-h"><h3 id="iwTitle">${esc(tr('init.title'))}</h3></div>
    <div class="modal-b" id="iwBody"></div>
  </div>`;
  root.appendChild(mask);
  iwStep1();
}

function iwStep1() {
  $('iwTitle').textContent = tr('init.step1_title');
  $('iwBody').innerHTML = `
    <p class="mut" style="margin:0 0 16px;font-size:13px;line-height:1.6">${esc(tr('init.step1_intro'))}</p>
    <label class="lbl">${esc(tr('init.addr'))}</label>
    <input id="iwAddr" class="field" style="margin-bottom:4px" placeholder="${esc(tr('init.addr_ph'))}" />
    <div class="mut" style="font-size:12px;margin-bottom:14px">${esc(tr('init.addr_hint'))}</div>
    <label class="lbl">${esc(tr('init.https'))}</label>
    <div style="margin:6px 0 16px;display:flex;flex-direction:column;gap:8px">
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="none" checked> ${esc(tr('init.https_none'))}</label>
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="selfsigned"> ${esc(tr('init.https_self'))}</label>
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="iwHttps" value="le"> ${esc(tr('init.https_le'))}</label>
    </div>
    <details style="margin-bottom:16px">
      <summary style="cursor:pointer;font-size:13px" class="mut">${esc(tr('init.adv'))}</summary>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
        <div><label class="lbl">${esc(tr('init.http_port'))}</label><input id="iwHttp" class="field" type="number" min="1" max="65535" value="80" /></div>
        <div><label class="lbl">${esc(tr('init.https_port'))}</label><input id="iwHttps" class="field" type="number" min="1" max="65535" value="443" /></div>
      </div>
      <label class="lbl" style="margin-top:10px;display:block">${esc(tr('init.console_port'))}</label>
      <input id="iwConsole" class="field" type="number" min="0" max="65535" placeholder="0" />
      <div class="mut" style="font-size:12px;margin-top:4px">${esc(tr('init.console_port_hint'))}</div>
    </details>
    <button class="btn" id="iwNext" style="width:100%">${esc(tr('init.next'))}</button>
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
  const httpPort = parseInt($('iwHttp').value, 10) || 80;
  const httpsPort = parseInt($('iwHttps').value, 10) || 443;
  const consolePort = parseInt($('iwConsole').value, 10) || 0;
  if (!addr) {
    err.textContent = tr('init.err_addr');
    return;
  }
  if (mode === 'le' && iwIsIp(addr)) {
    err.textContent = tr('init.err_le_ip');
    return;
  }
  if (httpPort < 1 || httpPort > 65535 || httpsPort < 1 || httpsPort > 65535 || consolePort < 0 || consolePort > 65535) {
    err.textContent = tr('init.err_port_range');
    return;
  }
  if (httpPort === httpsPort) {
    err.textContent = tr('init.err_ports_same');
    return;
  }
  const btn = $('iwNext');
  btn.disabled = true;
  btn.textContent = mode === 'le' ? tr('init.issuing') : tr('init.processing');
  // Language follows the wizard's current UI language; timezone is the browser's
  // IANA zone — both mirror what the CLI wizard asks, without extra prompts.
  let tz = '';
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { tz = ''; }
  fetch('/api/init/step1', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      external_address: addr,
      https_mode: mode,
      language: curLang(),
      timezone: tz,
      website_http_port: httpPort,
      website_https_port: httpsPort,
      console_port: consolePort,
    }),
  })
    .then(async (r) => {
      const b = await r.json().catch(() => ({}));
      if (!r.ok || !b.ok) throw new Error(b.msg || tr('init.err_generic'));
    })
    .then(() => {
      iwState = { addr, mode, httpPort, httpsPort, consolePort };
      iwStep2();
    })
    .catch((e) => {
      btn.disabled = false;
      btn.textContent = tr('init.next');
      err.textContent = e.message;
    });
}

function iwStep2() {
  $('iwTitle').textContent = tr('init.step2_title');
  $('iwBody').innerHTML = `
    <p class="mut" style="margin:0 0 16px;font-size:13px;line-height:1.6">${esc(tr('init.step2_intro'))}</p>
    <label class="lbl">${esc(tr('init.username'))}</label>
    <input id="iwUser" class="field" style="margin-bottom:12px" autocomplete="username" placeholder="${esc(tr('init.username_ph'))}" />
    <label class="lbl">${esc(tr('init.password'))}</label>
    <input id="iwPw" class="field" type="password" autocomplete="new-password" style="margin-bottom:12px" />
    <label class="lbl">${esc(tr('init.password2'))}</label>
    <input id="iwPw2" class="field" type="password" autocomplete="new-password" />
    <button class="btn" id="iwDone" style="margin-top:18px;width:100%">${esc(tr('init.finish'))}</button>
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
    err.textContent = tr('init.err_user');
    return;
  }
  if (pw.length < 6 || pw.length > 128) {
    err.textContent = tr('init.err_pw_len');
    return;
  }
  if (pw !== pw2) {
    err.textContent = tr('init.err_pw_match');
    return;
  }
  const btn = $('iwDone');
  btn.disabled = true;
  btn.textContent = tr('init.submitting');
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
      if (!r.ok || !b.ok) throw new Error(b.msg || tr('init.err_generic'));
    })
    .then(() => iwFinish())
    .catch((e) => {
      btn.disabled = false;
      btn.textContent = tr('init.finish');
      err.textContent = e.message;
    });
}

// Build the console's post-init login URL from the chosen address + SSL + ports.
function iwLoginUrl() {
  const scheme = iwState.mode === 'none' ? 'http' : 'https';
  const port =
    iwState.consolePort && iwState.consolePort !== iwState.httpPort && iwState.consolePort !== iwState.httpsPort
      ? iwState.consolePort
      : iwState.mode === 'none'
        ? iwState.httpPort
        : iwState.httpsPort;
  const dflt = scheme === 'https' ? 443 : 80;
  const host = iwState.addr.indexOf(':') >= 0 && iwState.addr[0] !== '[' ? '[' + iwState.addr + ']' : iwState.addr;
  return scheme + '://' + host + (port === dflt ? '' : ':' + port) + '/';
}

function iwFinish() {
  const url = iwLoginUrl();
  $('iwTitle').textContent = tr('init.done_title');
  $('iwBody').innerHTML = `
    <p style="margin:0 0 16px;line-height:1.7">${esc(tr('init.done_intro'))}</p>
    <a class="btn" style="width:100%;display:block;text-align:center;box-sizing:border-box;text-decoration:none" href="${esc(url)}">${esc(url)}</a>`;
}
