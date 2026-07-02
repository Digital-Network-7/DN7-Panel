// =========================================================================
// Account menu (top-right): edit profile / change password / 2FA / logout,
// plus the admin-only User management page.
// =========================================================================

// Dropdown anchored to the top-right user box. Keyboard operable: opens
// focused on the first item, ArrowUp/Down cycle, Escape closes and returns
// focus to the trigger (which carries aria-haspopup/expanded, see bottom).
function toggleAccountMenu(ev) {
  if (ev) ev.stopPropagation();
  const box = $('userBox');
  const open = document.querySelector('.acct-pop');
  if (open) { open._close(false); return; }
  const pop = el('div', { class: 'acct-pop', role: 'menu' });
  pop._close = closePop;
  function closePop(refocus) {
    pop.remove();
    document.removeEventListener('mousedown', onOut, true);
    box.setAttribute('aria-expanded', 'false');
    if (refocus) box.focus();
  }
  function onOut(e) { if (!e.target.closest('.acct-pop') && !e.target.closest('#userBox')) closePop(false); }
  const items = () => Array.from(pop.querySelectorAll('.acct-item'));
  const item = (label, fn, cls) => {
    const b = el('button', { class: 'acct-item' + (cls ? ' ' + cls : ''), role: 'menuitem' }, esc(label));
    b.onclick = () => { closePop(false); fn(); };
    return b;
  };
  pop.appendChild(item(tr('acct.profile'), editProfile));
  pop.appendChild(item(tr('acct.password'), changePassword));
  pop.appendChild(item(tr('acct.twofa'), twoFactor));
  pop.appendChild(el('div', { class: 'acct-sep' }));
  // Density toggle: relabels in place (menu stays open so the change is seen).
  const denLabel = () => tr('acct.density', { mode: tr(getDensity() === 'compact' ? 'acct.den_compact' : 'acct.den_comfort') });
  const den = el('button', { class: 'acct-item', role: 'menuitem' }, esc(denLabel()));
  den.onclick = () => { setDensity(getDensity() === 'compact' ? '' : 'compact'); den.textContent = denLabel(); };
  pop.appendChild(den);
  pop.appendChild(el('div', { class: 'acct-sep' }));
  pop.appendChild(item(tr('shell.logout'), logout, 'danger'));
  pop.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePop(true); return; }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const f = items(); if (!f.length) return;
    const i = f.indexOf(document.activeElement);
    f[(i + (e.key === 'ArrowDown' ? 1 : -1) + f.length) % f.length].focus();
  });
  document.body.appendChild(pop);
  const r = box.getBoundingClientRect();
  pop.style.top = (r.bottom + 6) + 'px';
  pop.style.right = Math.max(8, window.innerWidth - r.right) + 'px';
  box.setAttribute('aria-expanded', 'true');
  setTimeout(() => document.addEventListener('mousedown', onOut, true), 0);
  const first = items()[0]; if (first) first.focus();
}

// ---- Edit profile (avatar + full name + nickname) ----
function editProfile() {
  const me = Auth.me || {};
  const state = { avatar: me.avatar || '' };
  modal(tr('acct.profile'), `
    <div class="formgrid">
      <div class="full">
        <label class="lbl">${tr('acct.avatar')}</label>
        <div class="row" style="align-items:center;gap:12px">
          <span class="av av-lg" id="pfAv"></span>
          <input id="pfFile" type="file" accept="image/*" class="hidden" />
          <input id="pfAvState" type="hidden" value="0" />
          <button type="button" class="btn sm sec" id="pfPick">${tr('set.choose_img')}</button>
          <button type="button" class="btn sm sec" id="pfClear">${tr('set.restore_default')}</button>
        </div>
      </div>
      <div class="full"><label class="lbl">${tr('acct.full_name')}</label><input id="pfFull" class="field" maxlength="64" value="${esc(me.full_name || '')}" /></div>
      <div class="full"><label class="lbl">${tr('acct.nickname')}</label><input id="pfNick" class="field" maxlength="40" value="${esc(me.nickname || '')}" /></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="pfSave">${tr('ng.save')}</button></div>
    <div class="err" id="pfErr" style="margin-top:10px"></div>`, (close) => {
    const renderAv = () => {
      const a = $('pfAv');
      if (state.avatar) a.innerHTML = `<img src="${esc(state.avatar)}" alt="" />`;
      else a.textContent = ((me.nickname || me.username || 'A')[0] || 'A').toUpperCase();
    };
    renderAv();
    // Mirror every avatar mutation into a hidden input so bindDirty's value
    // snapshot sees a real change (clearing alone alters no control's value).
    const touchAv = () => {
      const st = $('pfAvState');
      st.value = String(Number(st.value || 0) + 1);
      st.dispatchEvent(new Event('input', { bubbles: true }));
    };
    $('pfPick').onclick = () => $('pfFile').click();
    $('pfClear').onclick = () => { if (!state.avatar) return; state.avatar = ''; renderAv(); touchAv(); };
    $('pfFile').onchange = () => {
      const f = $('pfFile').files[0]; if (!f) return;
      $('pfErr').textContent = '';
      const rd = new FileReader();
      rd.onload = () => {
        // Downscale to ≤256px (the avatar renders at ≤56px) so big photos just
        // work instead of dead-ending on the 512KB limit.
        const img = new Image();
        img.onload = () => {
          let out = rd.result;
          const sc = Math.min(1, 256 / Math.max(img.width, img.height, 1));
          if (sc < 1 || f.size > 512 * 1024) {
            const cv = document.createElement('canvas');
            cv.width = Math.max(1, Math.round(img.width * sc));
            cv.height = Math.max(1, Math.round(img.height * sc));
            const cx = cv.getContext('2d');
            cx.fillStyle = '#fff'; cx.fillRect(0, 0, cv.width, cv.height); // JPEG has no alpha
            cx.drawImage(img, 0, 0, cv.width, cv.height);
            out = cv.toDataURL('image/jpeg', 0.85);
          }
          if (out.length > 700000) { $('pfErr').textContent = tr('set.img_too_big'); return; } // server data-URI cap
          state.avatar = out; renderAv(); touchAv();
        };
        img.onerror = () => { $('pfErr').textContent = tr('acct.img_bad'); };
        img.src = rd.result;
      };
      rd.readAsDataURL(f);
    };
    $('pfSave').onclick = () => {
      const body = { full_name: $('pfFull').value, nickname: $('pfNick').value, avatar: state.avatar };
      AccountApi.updateProfile(body)
        .then(() => {
          Auth.me.full_name = body.full_name.trim();
          Auth.me.nickname = body.nickname.trim();
          Auth.me.avatar = state.avatar;
          setUser(Auth.me.nickname || Auth.me.username, Auth.me.avatar);
          toast(tr('common.saved'), 'ok');
          close();
        })
        .catch((e) => { $('pfErr').textContent = e.message; });
    };
    bindDirty('pfSave');
  });
}

// ---- Change own password (requires the current password) ----
function changePassword() {
  modal(tr('acct.password'), `
    <label class="lbl">${tr('acct.old_pw')}</label>
    <input id="cpOld" class="field" type="password" autocomplete="current-password" style="margin-bottom:12px" />
    <label class="lbl">${tr('setup.new_pw')}</label>
    <input id="cpPw" class="field" type="password" autocomplete="new-password" style="margin-bottom:12px" />
    <label class="lbl">${tr('setup.confirm_pw')}</label>
    <input id="cpPw2" class="field" type="password" autocomplete="new-password" />
    ${(Auth.me && Auth.me.is_super) ? '' : `<p class="formnote">${tr('acct.os_sync_note')}</p>`}
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="cpSave">${tr('ng.save')}</button></div>
    <div class="err" id="cpErr" style="margin-top:10px"></div>`, (close) => {
    let busy = false;
    const submit = () => {
      if (busy) return; // a second submit would fail old_verifier: the first already rotated the salt
      const err = $('cpErr'); err.textContent = '';
      const oldPw = $('cpOld').value, pw = $('cpPw').value, pw2 = $('cpPw2').value;
      if (!oldPw) { err.textContent = tr('acct.need_old_pw'); return; }
      if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
      if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
      const btn = $('cpSave'); const orig = btn.textContent;
      busy = true; btn.disabled = true; btn.textContent = tr('acct.working');
      // Fetch a one-time nonce + the account's own salt (pass our username so a
      // non-super user gets THEIR salt, not the super-admin's): prove the old
      // password, bound to the nonce so the proof can't be replayed, and salt the
      // new one. For the owner no plaintext crosses the wire; non-owner accounts
      // additionally send the plaintext once for the OS (SSH) password sync —
      // stated in the dialog note above.
      fetch('/api/login/challenge?username=' + encodeURIComponent((Auth.me && Auth.me.username) || ''))
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(tr('login.err_conn')))))
        .then((c) => {
          const salt = randHex(16);
          // Old-password proof: the verifier under the CURRENT account's salt+KDF
          // (a hash, not the plaintext), checked server-side against the stored
          // Argon2id credential. New password: stretch with newKdf(). Chunked
          // async KDF so the disabled button paints instead of freezing the tab.
          return deriveVerifierAsync(salt, pw, newKdf())
            .then((hash) => deriveVerifierAsync(c.salt || '', oldPw, c.kdf).then((oldv) => ({ c, salt, hash, oldv })));
        })
        .then(({ c, salt, hash, oldv }) => {
          const body = { pw_salt: salt, pw_hash: hash, pw_kdf: newKdf(), nonce: c.nonce, old_verifier: oldv };
          // Non-owner accounts sync their OS password to the panel password.
          if (!(Auth.me && Auth.me.is_super)) body.password = pw;
          return AccountApi.changePassword(body);
        })
        .then(() => { toast(tr('common.saved'), 'ok'); close(); })
        .catch((e) => { err.textContent = e.message; busy = false; btn.disabled = false; btn.textContent = orig; });
    };
    $('cpSave').onclick = submit;
    bindDirty('cpSave');
    $('cpPw2').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  });
}

// ---- Two-factor (TOTP) ----
function twoFactor() {
  const enabled = !!(Auth.me && Auth.me.totp_enabled);
  modal(tr('acct.twofa'), `<div id="tfBody">${loading()}</div>`, (close) => {
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
        AccountApi.twofaDisable($('tfCode').value)
          .then(() => { Auth.me.totp_enabled = false; toast(tr('tfa.disabled'), 'ok'); close(); })
          .catch((e) => { $('tfErr').textContent = e.message; });
      };
      bindDirty('tfDisable');
      return;
    }
    // Not enabled → fetch a fresh secret + QR, require a live code to bind.
    AccountApi.twofaSetup().then((b) => {
      const d = b.data || {};
      body.innerHTML = `
        <p class="mut" style="font-size:13px;margin:0 0 12px">${tr('tfa.setup_intro')}</p>
        <div class="tfa-qr">${d.qr_svg || ''}</div>
        <label class="lbl">${tr('tfa.secret')}</label>
        <div class="row" style="align-items:center;gap:8px">
          <div class="tfa-secret mono" id="tfSecret" style="flex:1">${esc(d.secret || '')}</div>
          <button type="button" class="btn sm sec" id="tfCopy">${tr('common.copy')}</button>
        </div>
        <p class="formnote warnnote">${tr('tfa.lock_warn')}</p>
        <label class="lbl" style="margin-top:12px">${tr('tfa.verify_intro')}</label>
        <input id="tfCode" class="field" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" style="max-width:180px" />
        <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="tfEnable">${tr('tfa.enable')}</button></div>
        <div class="err" id="tfErr" style="margin-top:10px"></div>`;
      $('tfCopy').onclick = () => acctCopy(d.secret || '').then((ok) => toast(ok ? tr('common.copied') : tr('common.copy_fail'), ok ? 'ok' : 'err'));
      const submit = () => {
        $('tfErr').textContent = '';
        AccountApi.twofaEnable($('tfCode').value)
          .then(() => { Auth.me.totp_enabled = true; toast(tr('tfa.enabled'), 'ok'); close(); })
          .catch((e) => { $('tfErr').textContent = e.message; });
      };
      $('tfEnable').onclick = submit;
      bindDirty('tfEnable');
      $('tfCode').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
      // Content arrived after modal()'s global autofocus ran — focus manually.
      setTimeout(() => { const c = $('tfCode'); if (c) c.focus(); }, 30);
    }).catch((e) => { body.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
  });
}

// Clipboard write with a legacy fallback (the clipboard API is unavailable on
// the plain-HTTP origins the panel explicitly supports). Resolves to a bool.
function acctCopy(s) {
  const legacy = () => {
    const ta = document.createElement('textarea');
    ta.value = s; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { /* no path left */ }
    ta.remove();
    return ok;
  };
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(s).then(() => true).catch(() => legacy());
  }
  return Promise.resolve(legacy());
}

// ---- User management (admin only) ----
// Privilege level: owner(super)=2, admin=1, user=0.
function userLevel(u) { return u.is_super ? 2 : (u.role === 'admin' ? 1 : 0); }
function myLevel() { return Auth.level(); }
// Role <option>s the current account may assign (strictly below itself).
function roleOptions(current) {
  let h = `<option value="user">${tr('um.user')}</option>`;
  if (myLevel() >= 2) h += `<option value="admin">${tr('um.admin_sudo')}</option>`;
  return h.replace(`value="${current}"`, `value="${current}" selected`);
}

function renderUsers(v) {
  v.innerHTML = `<div class="row" style="margin-bottom:14px"><h3 style="margin:0;font-size:15px">${tr('um.title')}</h3><span class="sp" style="flex:1"></span><button class="btn sm" id="umAdd">${tr('um.add')}</button></div><div id="umBody">${loading()}</div>`;
  $('umAdd').onclick = () => umCreate(() => renderUsers(v));
  AccountApi.listUsers().then((b) => {
    const users = (b.data && b.data.users) || [];
    const mine = myLevel();
    let h = `<table class="optable"><tr><th>${tr('um.account')}</th><th>${tr('acct.full_name')}</th><th>${tr('um.role')}</th><th>UID</th><th>${tr('acct.twofa')}</th><th class="act">${tr('ng.col_actions')}</th></tr>`;
    users.forEach((u) => {
      const role = u.is_super ? tr('um.super') : (u.role === 'admin' ? tr('um.admin') : tr('um.user'));
      const roleCls = u.is_super ? 'owner' : (u.role === 'admin' ? 'admin' : 'user');
      const tfa = u.totp_enabled ? `<span class="chip on">${tr('ng.yes')}</span>` : `<span class="chip">${tr('ng.no')}</span>`;
      // Manage only accounts strictly below your own privilege.
      const canManage = !u.is_super && mine > userLevel(u);
      const acts = canManage
        ? `<div class="actions"><button class="btn sm sec" data-edit="${esc(u.username)}">${tr('ng.edit_site')}</button><button class="btn sm danger" data-del="${esc(u.username)}">${tr('ng.delete')}</button></div>`
        : `<div class="actions"><span class="mut" title="${esc(tr('um.no_manage'))}">—</span></div>`;
      const isMe = Auth.me && u.username === Auth.me.username;
      const you = isMe ? ` <span class="chip on">${tr('um.you')}</span>` : '';
      h += `<tr><td><b>${esc(u.username)}</b>${you}</td><td class="mut">${esc(u.full_name || '-')}</td><td><span class="role-chip ${roleCls}">${esc(role)}</span></td><td class="mono" style="font-size:12px">${u.uid || '-'}</td><td>${tfa}</td><td class="act">${acts}</td></tr>`;
    });
    h += '</table>';
    $('umBody').innerHTML = '<div class="tablewrap">' + h + '</div><p class="formnote">' + tr('um.note') + '</p>';
    const usersByName = {}; users.forEach((u) => usersByName[u.username] = u);
    document.querySelectorAll('#umBody [data-edit]').forEach((b) => b.onclick = () => umEdit(usersByName[b.dataset.edit], () => renderUsers(v)));
    document.querySelectorAll('#umBody [data-del]').forEach((b) => b.onclick = () => umDelete(b.dataset.del, () => renderUsers(v)));
  }).catch((e) => { $('umBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Typed-confirmation delete: the username must be re-typed exactly to enable
// the destructive button (an irreversible OS-account + home-directory wipe
// deserves more ceremony than a generic OK/Cancel).
function umDelete(name, reload) {
  modal(tr('common.confirm'), `
    <p style="margin:0 0 12px">${esc(tr('um.confirm_del', { name }))}</p>
    <label class="lbl">${esc(tr('um.del_type', { name }))}</label>
    <input id="udName" class="field" autocomplete="off" spellcheck="false" />
    <div class="row" style="justify-content:flex-end;gap:10px;margin-top:16px">
      <button class="btn sec" id="udNo">${tr('common.cancel')}</button>
      <button class="btn danger" id="udGo" disabled>${tr('ng.delete')}</button>
    </div>
    <div class="err" id="udErr" style="margin-top:10px"></div>`, (close) => {
    let busy = false;
    const match = () => $('udName').value === name;
    $('udName').addEventListener('input', () => { $('udGo').disabled = !match(); });
    $('udNo').onclick = close;
    const go = () => {
      if (busy || !match()) return;
      busy = true;
      $('udGo').disabled = true;
      AccountApi.deleteUser(name)
        .then(() => { toast(tr('common.deleted'), 'ok'); close(); reload(); })
        .catch((e) => { busy = false; $('udErr').textContent = e.message; $('udGo').disabled = !match(); });
    };
    $('udGo').onclick = go;
    $('udName').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  });
}

function umCreate(reload) {
  modal(tr('um.add'), `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('um.account')}</label><input id="umUser" class="field" placeholder="${tr('um.account_ph')}" autocomplete="off" /></div>
      <div class="full"><label class="lbl">${tr('acct.full_name')}</label><input id="umFull" class="field" maxlength="64" /></div>
      <div class="full"><label class="lbl">${tr('um.role')}</label><select id="umRole" class="field">${roleOptions('user')}</select></div>
      <div class="full"><label class="lbl">${tr('setup.new_pw')}</label><input id="umPw" class="field" type="password" autocomplete="new-password" /></div>
      <div class="full"><label class="lbl">${tr('setup.confirm_pw')}</label><input id="umPw2" class="field" type="password" autocomplete="new-password" /></div>
    </div>
    <p class="formnote">${tr('um.create_note')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="umGo">${tr('ng.create')}</button></div>
    <div class="hidden" id="umJob" style="margin-top:12px"></div>
    <div class="err" id="umErr" style="margin-top:10px"></div>`, (close) => {
    let busy = false;
    $('umGo').onclick = () => {
      if (busy) return;
      const err = $('umErr'); err.textContent = '';
      const un = $('umUser').value.trim();
      const pw = $('umPw').value, pw2 = $('umPw2').value;
      if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(un)) { err.textContent = tr('err.users.bad_username'); return; }
      if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
      if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
      const go = $('umGo'); const orig = go.textContent;
      busy = true; go.disabled = true; go.textContent = tr('acct.working');
      $('umJob').classList.remove('hidden'); $('umJob').innerHTML = `<div class="mut">${tr('um.creating')}</div>`;
      const salt = randHex(16);
      // Chunked async KDF so the just-disabled button paints before the stretch.
      deriveVerifierAsync(salt, pw, newKdf())
        .then((hash) => AccountApi.createUser({ username: un, full_name: $('umFull').value, role: $('umRole').value, pw_salt: salt, pw_hash: hash, pw_kdf: newKdf(), password: pw }))
        .then(() => { toast(tr('um.created'), 'ok'); close(); reload(); })
        .catch((e) => { err.textContent = e.message; busy = false; go.disabled = false; go.textContent = orig; $('umJob').classList.add('hidden'); });
    };
    bindDirty('umGo');
  });
}

// Edit a lower-privilege user's profile / role / password (owner & admins).
function umEdit(u, reload) {
  if (!u) return;
  modal(tr('um.edit') + '：' + u.username, `
    <div class="formgrid">
      <div class="full"><label class="lbl">${tr('acct.full_name')}</label><input id="ueFull" class="field" maxlength="64" value="${esc(u.full_name || '')}" /></div>
      <div class="full"><label class="lbl">${tr('acct.nickname')}</label><input id="ueNick" class="field" maxlength="40" value="${esc(u.nickname || '')}" /></div>
      <div class="full"><label class="lbl">${tr('um.role')}</label><select id="ueRole" class="field">${roleOptions(u.role || 'user')}</select></div>
      <div class="full"><label class="lbl">${tr('um.new_pw_opt')}</label><input id="uePw" class="field" type="password" autocomplete="new-password" placeholder="${tr('set.pw_ph')}" /></div>
      <div class="full"><label class="lbl">${tr('setup.confirm_pw')}</label><input id="uePw2" class="field" type="password" autocomplete="new-password" placeholder="${tr('set.pw_ph')}" /></div>
    </div>
    <p class="formnote">${tr('um.os_sync_note')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="ueGo">${tr('ng.save')}</button></div>
    <div class="err" id="ueErr" style="margin-top:10px"></div>`, (close) => {
    let busy = false;
    $('ueGo').onclick = () => {
      if (busy) return;
      const err = $('ueErr'); err.textContent = '';
      const body = { username: u.username, full_name: $('ueFull').value, nickname: $('ueNick').value, role: $('ueRole').value };
      const pw = $('uePw').value, pw2 = $('uePw2').value;
      if (pw || pw2) {
        if (pw.length < 6 || pw.length > 128) { err.textContent = tr('set.pw_len'); return; }
        if (pw !== pw2) { err.textContent = tr('setup.err_mismatch'); return; }
      }
      const go = $('ueGo'); const orig = go.textContent;
      busy = true; go.disabled = true; go.textContent = tr('acct.working');
      const derive = () => {
        if (!pw) return Promise.resolve(body);
        const salt = randHex(16);
        // Chunked async KDF so the just-disabled button paints before the stretch.
        return deriveVerifierAsync(salt, pw, newKdf()).then((hash) => {
          body.pw_salt = salt;
          body.pw_hash = hash;
          body.pw_kdf = newKdf();
          body.password = pw; // sync the OS password to the new panel password (see note)
          return body;
        });
      };
      derive()
        .then((b) => AccountApi.updateUser(b))
        .then(() => { toast(tr('common.saved'), 'ok'); close(); reload(); })
        .catch((e) => { err.textContent = e.message; busy = false; go.disabled = false; go.textContent = orig; });
    };
    bindDirty('ueGo');
  });
}

// The menu trigger is a plain <div> in the markup — make it keyboard operable
// (focusable, Enter/Space/ArrowDown open) and announce the popup to AT.
(() => {
  const box = $('userBox');
  if (!box) return;
  box.setAttribute('tabindex', '0');
  box.setAttribute('role', 'button');
  box.setAttribute('aria-haspopup', 'menu');
  box.setAttribute('aria-expanded', 'false');
  box.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') { e.preventDefault(); toggleAccountMenu(e); }
  });
})();
