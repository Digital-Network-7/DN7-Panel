// =========================================================================
// Account menu (top-right): edit profile / change password / 2FA / logout,
// plus the admin-only User management page.
// =========================================================================

// Dropdown anchored to the top-right user box.
function toggleAccountMenu(ev) {
  if (ev) ev.stopPropagation();
  let pop = document.querySelector('.acct-pop');
  if (pop) { pop.remove(); return; }
  const box = $('userBox');
  pop = el('div', { class: 'acct-pop' });
  const item = (label, fn, cls) => {
    const b = el('button', { class: 'acct-item' + (cls ? ' ' + cls : '') }, esc(label));
    b.onclick = () => { pop.remove(); fn(); };
    return b;
  };
  pop.appendChild(item(tr('acct.profile'), editProfile));
  pop.appendChild(item(tr('acct.password'), changePassword));
  pop.appendChild(item(tr('acct.twofa'), twoFactor));
  pop.appendChild(el('div', { class: 'acct-sep' }));
  pop.appendChild(item(tr('shell.logout'), logout, 'danger'));
  document.body.appendChild(pop);
  const r = box.getBoundingClientRect();
  pop.style.top = (r.bottom + 6) + 'px';
  pop.style.right = Math.max(8, window.innerWidth - r.right) + 'px';
  const close = (e) => { if (!e.target.closest('.acct-pop') && !e.target.closest('#userBox')) { pop.remove(); document.removeEventListener('mousedown', close, true); } };
  setTimeout(() => document.addEventListener('mousedown', close, true), 0);
}

// ---- Edit profile (avatar + full name + nickname) ----
function editProfile() {
  const me = S.me || {};
  const state = { avatar: me.avatar || '' };
  modal(tr('acct.profile'), `
    <div class="formgrid">
      <div class="full">
        <label class="lbl">${tr('acct.avatar')}</label>
        <div class="row" style="align-items:center;gap:12px">
          <span class="av av-lg" id="pfAv"></span>
          <input id="pfFile" type="file" accept="image/*" class="hidden" />
          <button type="button" class="btn sm sec" id="pfPick">${tr('set.choose_img')}</button>
          <button type="button" class="btn sm sec" id="pfClear">${tr('set.restore_default')}</button>
        </div>
      </div>
      <div class="full"><label class="lbl">${tr('acct.full_name')}</label><input id="pfFull" class="field" maxlength="64" value="${esc(me.full_name || '')}" /></div>
      <div class="full"><label class="lbl">${tr('acct.nickname')}</label><input id="pfNick" class="field" maxlength="40" value="${esc(me.nickname || '')}" /></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="pfSave">${tr('ng.save')}</button></div>
    <div class="err" id="pfErr" style="margin-top:10px"></div>`, () => {
    const renderAv = () => {
      const a = $('pfAv');
      if (state.avatar) a.innerHTML = `<img src="${esc(state.avatar)}" alt="" />`;
      else a.textContent = ((me.nickname || me.username || 'A')[0] || 'A').toUpperCase();
    };
    renderAv();
    $('pfPick').onclick = () => $('pfFile').click();
    $('pfClear').onclick = () => { state.avatar = ''; renderAv(); };
    $('pfFile').onchange = () => {
      const f = $('pfFile').files[0]; if (!f) return;
      if (f.size > 512 * 1024) { $('pfErr').textContent = tr('set.img_too_big'); return; }
      const rd = new FileReader();
      rd.onload = () => { state.avatar = rd.result; renderAv(); };
      rd.readAsDataURL(f);
    };
    $('pfSave').onclick = () => {
      const body = { full_name: $('pfFull').value, nickname: $('pfNick').value, avatar: state.avatar };
      api('/api/profile', { method: 'POST', body: JSON.stringify(body) })
        .then(() => {
          S.me.full_name = body.full_name.trim();
          S.me.nickname = body.nickname.trim();
          S.me.avatar = state.avatar;
          setUser(S.me.nickname || S.me.username, S.me.avatar);
          toast(tr('common.saved'), 'ok');
          $('modalRoot').innerHTML = '';
        })
        .catch((e) => { $('pfErr').textContent = e.message; });
    };
  });
}

// ---- Change own password ----
function changePassword() {
  modal(tr('acct.password'), `
    <label class="lbl">${tr('setup.new_pw')}</label>
    <input id="cpPw" class="field" type="password" autocomplete="new-password" style="margin-bottom:12px" />
    <label class="lbl">${tr('setup.confirm_pw')}</label>
    <input id="cpPw2" class="field" type="password" autocomplete="new-password" />
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="cpSave">${tr('ng.save')}</button></div>
    <div class="err" id="cpErr" style="margin-top:10px"></div>`, () => {
    const submit = () => {
      const err = $('cpErr'); err.textContent = '';
      const pw = $('cpPw').value, pw2 = $('cpPw2').value;
      if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
      if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
      // Fetch the current salt so the server can verify the new password isn't
      // the default (only enforced for the super-admin while still default).
      fetch('/api/login/challenge')
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(tr('login.err_conn')))))
        .then((c) => {
          const salt = randHex(16);
          const body = { pw_salt: salt, pw_hash: sha256Hex(salt + ':' + pw), pw_check: sha256Hex((c.salt || '') + ':' + pw) };
          return api('/api/password', { method: 'POST', body: JSON.stringify(body) });
        })
        .then(() => { toast(tr('common.saved'), 'ok'); $('modalRoot').innerHTML = ''; })
        .catch((e) => { err.textContent = e.message; });
    };
    $('cpSave').onclick = submit;
    $('cpPw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  });
}

// ---- Two-factor (TOTP) ----
function twoFactor() {
  const enabled = !!(S.me && S.me.totp_enabled);
  modal(tr('acct.twofa'), `<div id="tfBody">${loading()}</div>`, () => {
    const body = $('tfBody');
    if (enabled) {
      body.innerHTML = `
        <p class="mut" style="font-size:13px;margin:0 0 14px">${tr('tfa.on_intro')}</p>
        <label class="lbl">${tr('tfa.code')}</label>
        <input id="tfCode" class="field" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" style="margin-bottom:6px;max-width:180px" />
        <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn danger" id="tfDisable">${tr('tfa.disable')}</button></div>
        <div class="err" id="tfErr" style="margin-top:10px"></div>`;
      $('tfDisable').onclick = () => {
        $('tfErr').textContent = '';
        api('/api/2fa/disable', { method: 'POST', body: JSON.stringify({ code: $('tfCode').value }) })
          .then(() => { S.me.totp_enabled = false; toast(tr('tfa.disabled'), 'ok'); $('modalRoot').innerHTML = ''; })
          .catch((e) => { $('tfErr').textContent = e.message; });
      };
      return;
    }
    // Not enabled → fetch a fresh secret + QR, require a live code to bind.
    api('/api/2fa/setup', { method: 'POST' }).then((b) => {
      const d = b.data || {};
      body.innerHTML = `
        <p class="mut" style="font-size:13px;margin:0 0 12px">${tr('tfa.setup_intro')}</p>
        <div class="tfa-qr">${d.qr_svg || ''}</div>
        <label class="lbl">${tr('tfa.secret')}</label>
        <div class="tfa-secret mono" id="tfSecret">${esc(d.secret || '')}</div>
        <label class="lbl" style="margin-top:12px">${tr('tfa.verify_intro')}</label>
        <input id="tfCode" class="field" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" style="max-width:180px" />
        <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="tfEnable">${tr('tfa.enable')}</button></div>
        <div class="err" id="tfErr" style="margin-top:10px"></div>`;
      const submit = () => {
        $('tfErr').textContent = '';
        api('/api/2fa/enable', { method: 'POST', body: JSON.stringify({ code: $('tfCode').value }) })
          .then(() => { S.me.totp_enabled = true; toast(tr('tfa.enabled'), 'ok'); $('modalRoot').innerHTML = ''; })
          .catch((e) => { $('tfErr').textContent = e.message; });
      };
      $('tfEnable').onclick = submit;
      $('tfCode').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

// ---- User management (admin only) ----
function renderUsers(v) {
  v.innerHTML = `<div class="row" style="margin-bottom:14px"><h3 style="margin:0;font-size:15px">${tr('um.title')}</h3><span class="sp" style="flex:1"></span><button class="btn sm" id="umAdd">${tr('um.add')}</button></div><div id="umBody">${loading()}</div>`;
  $('umAdd').onclick = () => umCreate(() => renderUsers(v));
  api('/api/users').then((b) => {
    const users = (b.data && b.data.users) || [];
    let h = `<table class="optable"><tr><th>${tr('um.account')}</th><th>${tr('acct.full_name')}</th><th>${tr('um.role')}</th><th>UID</th><th>${tr('acct.twofa')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
    users.forEach((u) => {
      const role = u.is_super ? tr('um.super') : (u.role === 'admin' ? tr('um.admin') : tr('um.user'));
      const chip = u.is_super ? 'chip on' : (u.role === 'admin' ? 'chip warn' : 'chip');
      const tfa = u.totp_enabled ? `<span class="chip on">${tr('ng.yes')}</span>` : `<span class="chip">${tr('ng.no')}</span>`;
      const del = u.is_super ? '' : `<button class="btn sm danger" data-del="${esc(u.username)}">${tr('ng.delete')}</button>`;
      h += `<tr><td><b>${esc(u.username)}</b></td><td class="mut">${esc(u.full_name || '-')}</td><td><span class="${chip}">${esc(role)}</span></td><td class="mono" style="font-size:12px">${u.uid || '-'}</td><td>${tfa}</td><td class="act">${del}</td></tr>`;
    });
    h += '</table>';
    $('umBody').innerHTML = '<div class="tablewrap">' + h + '</div><p class="formnote">' + tr('um.note') + '</p>';
    document.querySelectorAll('#umBody [data-del]').forEach((b) => b.onclick = async () => {
      if (await confirmDanger(tr('um.confirm_del', { name: b.dataset.del }))) {
        api('/api/users/delete', { method: 'POST', body: JSON.stringify({ username: b.dataset.del }) })
          .then(() => { toast(tr('common.deleted'), 'ok'); renderUsers(v); })
          .catch((e) => toast(e.message, 'err'));
      }
    });
  }).catch((e) => { $('umBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

function umCreate(reload) {
  modal(tr('um.add'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('um.account')}</label><input id="umUser" class="field" placeholder="${tr('um.account_ph')}" autocomplete="off" /></div>
      <div class="full"><label class="lbl">${tr('acct.full_name')}</label><input id="umFull" class="field" maxlength="64" /></div>
      <div class="full"><label class="lbl">${tr('um.role')}</label><select id="umRole" class="field"><option value="user">${tr('um.user')}</option><option value="admin">${tr('um.admin_sudo')}</option></select></div>
      <div class="full"><label class="lbl">${tr('setup.new_pw')}</label><input id="umPw" class="field" type="password" autocomplete="new-password" /></div>
      <div class="full"><label class="lbl">${tr('setup.confirm_pw')}</label><input id="umPw2" class="field" type="password" autocomplete="new-password" /></div>
    </div>
    <p class="formnote">${tr('um.create_note')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="umGo">${tr('ng.create')}</button></div>
    <div class="hidden" id="umJob" style="margin-top:12px"></div>
    <div class="err" id="umErr" style="margin-top:10px"></div>`, (close) => {
    $('umGo').onclick = () => {
      const err = $('umErr'); err.textContent = '';
      const un = $('umUser').value.trim();
      const pw = $('umPw').value, pw2 = $('umPw2').value;
      if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(un)) { err.textContent = tr('err.users.bad_username'); return; }
      if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
      if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
      const salt = randHex(16);
      const body = { username: un, full_name: $('umFull').value, role: $('umRole').value, pw_salt: salt, pw_hash: sha256Hex(salt + ':' + pw) };
      $('umGo').disabled = true; $('umJob').classList.remove('hidden'); $('umJob').innerHTML = `<div class="mut">${tr('um.creating')}</div>`;
      api('/api/users', { method: 'POST', body: JSON.stringify(body) })
        .then(() => { toast(tr('um.created'), 'ok'); close(); reload(); })
        .catch((e) => { err.textContent = e.message; $('umGo').disabled = false; $('umJob').classList.add('hidden'); });
    };
  });
}
