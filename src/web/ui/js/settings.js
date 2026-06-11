// =========================================================================
// Settings
// =========================================================================
function renderSettings(v) {
  v.innerHTML = '<div class="card">' + loading() + '</div>';
  api('/api/settings').then((sb) => {
    const s = sb.data;
    v.innerHTML = `
    <div class="card" style="max-width:520px">
      <h3>${tr('set.account_sec')}</h3>
      <label class="lbl">${tr('set.account')}</label>
      <input id="setUser" class="field" style="margin-bottom:12px" value="${esc(s.username)}" />
      <label class="lbl">${tr('set.password')}</label>
      <div class="row" style="margin-bottom:4px"><input id="setPw" class="field" type="password" value="" placeholder="${tr('set.pw_ph')}" autocomplete="new-password" style="flex:1" /><button class="btn sec sm" id="setPwShow" type="button">${tr('set.show')}</button></div>
      <div class="sub" style="margin:2px 0 0">${tr('set.pw_forgot_a')} <code>dn7 panel reset</code> ${tr('set.pw_forgot_b')}</div>
      <h3 style="margin-top:18px">${tr('set.port_sec')}</h3>
      <input id="setPort" class="field" type="number" value="${s.port}" />
      <label style="display:flex;gap:8px;align-items:center;margin:14px 0"><input type="checkbox" id="setEnabled" ${s.enabled ? 'checked' : ''}/> ${tr('set.enable')}</label>
      <button class="btn" id="setSave">${tr('set.save')}</button>
      <div class="err ok" id="setMsg" style="margin-top:10px"></div>
    </div>
    <div class="card" style="max-width:520px;margin-top:16px">
      <h3>${tr('set.appearance')}</h3>
      <label class="lbl">${tr('set.language')}</label>
      <select id="brLang" class="field" style="margin-bottom:12px">
        <option value="en">English</option>
        <option value="zh-CN">简体中文</option>
        <option value="zh-TW">繁體中文</option>
        <option value="ja">日本語</option>
      </select>
      <label class="lbl">${tr('set.panel_name')}</label>
      <input id="brName" class="field" style="margin-bottom:12px" maxlength="40" />
      <label class="lbl">${tr('set.logo_label')}</label>
      <div class="row" style="align-items:center;margin-bottom:12px">
        <span id="brLogoPrev" style="width:40px;height:40px;border-radius:10px;flex-shrink:0;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1px solid var(--line)"></span>
        <input id="brLogoFile" type="file" accept="image/*" style="display:none" />
        <button class="btn sec sm" type="button" id="brLogoPick">${tr('set.choose_img')}</button>
        <button class="btn sec sm" type="button" id="brLogoClear">${tr('set.restore_default')}</button>
      </div>
      <label class="lbl">${tr('set.accent')}</label>
      <div class="row" style="align-items:center;margin-bottom:12px">
        <input id="brAccent" type="color" style="width:46px;height:34px;padding:2px;border-radius:8px;border:1px solid var(--line);background:var(--panel2)" />
        <button class="btn sec sm" type="button" id="brAccentClear">${tr('set.restore_default')}</button>
        <span class="sub" id="brAccentVal" style="margin:0"></span>
      </div>
      <label class="lbl">${tr('set.default_theme')}</label>
      <select id="brTheme" class="field" style="margin-bottom:14px">
        <option value="auto">${tr('theme.auto')}</option>
        <option value="light">${tr('theme.light')}</option>
        <option value="dark">${tr('theme.dark')}</option>
      </select>
      <button class="btn" id="brSave">${tr('set.save_appearance')}</button>
      <div class="err ok" id="brMsg" style="margin-top:10px"></div>
    </div>`;
    $('brLang').value = curLang();
    $('brLang').onchange = () => setLang($('brLang').value);
    $('setPwShow').onclick = () => { const i = $('setPw'); const show = i.type === 'password'; i.type = show ? 'text' : 'password'; $('setPwShow').textContent = show ? tr('set.hide') : tr('set.show'); };
    $('setSave').onclick = () => {
      const body = { username: $('setUser').value, port: Number($('setPort').value), enabled: $('setEnabled').checked };
      const pw = $('setPw').value;
      if (pw) {
        if (pw.length < 6 || pw.length > 128) { const m = $('setMsg'); m.className = 'err'; m.textContent = tr('set.pw_len'); return; }
        // Hash client-side with a fresh salt so the new password never crosses
        // the (plaintext-HTTP) wire; the server stores salt + hash verbatim.
        const salt = randHex(16);
        body.pw_salt = salt;
        body.pw_hash = sha256Hex(salt + ':' + pw);
      }
      api('/api/settings', { method: 'POST', body: JSON.stringify(body) })
        .then((b) => { const m = $('setMsg'); m.className = 'err ok'; m.textContent = tr('common.saved') + (b.needs_restart ? tr('common.restart_hint') : ''); $('setPw').value = ''; setUser(body.username); })
        .catch((e) => { const m = $('setMsg'); m.className = 'err'; m.textContent = e.message; });
    };
    // ---- Appearance / branding ----
    const B = window.__BRAND__ || {};
    const brState = { logo: B.logo || '', accent: B.accent || '' };
    const DEF_ACCENT = '#3b82f6';
    function brRenderPrev() {
      const p = $('brLogoPrev');
      if (brState.logo) { p.innerHTML = `<img src="${esc(brState.logo)}" alt="" style="width:100%;height:100%;object-fit:contain" />`; }
      else { p.innerHTML = `<span style="font-size:11px;color:var(--mut)">${tr('set.restore_default')}</span>`; }
      $('brAccent').value = brState.accent || DEF_ACCENT;
      $('brAccentVal').textContent = brState.accent || tr('set.default_paren');
    }
    $('brName').value = B.name || 'DN7 Panel';
    $('brTheme').value = B.theme || 'auto';
    brRenderPrev();
    $('brLogoPick').onclick = () => $('brLogoFile').click();
    $('brLogoFile').onchange = () => {
      const f = $('brLogoFile').files[0]; if (!f) return;
      if (f.size > 512 * 1024) { const m = $('brMsg'); m.className = 'err'; m.textContent = tr('set.img_too_big'); return; }
      const rd = new FileReader();
      rd.onload = () => { brState.logo = rd.result; brRenderPrev(); };
      rd.readAsDataURL(f);
    };
    $('brLogoClear').onclick = () => { brState.logo = ''; $('brLogoFile').value = ''; brRenderPrev(); };
    $('brAccent').oninput = () => { brState.accent = $('brAccent').value; $('brAccentVal').textContent = brState.accent; };
    $('brAccentClear').onclick = () => { brState.accent = ''; brRenderPrev(); };
    $('brSave').onclick = () => {
      const body = { panel_name: $('brName').value, theme_default: $('brTheme').value, accent: brState.accent, logo: brState.logo };
      api('/api/branding', { method: 'POST', body: JSON.stringify(body) })
        .then(() => { const m = $('brMsg'); m.className = 'err ok'; m.textContent = tr('set.saving_refresh'); setTimeout(() => location.reload(), 600); })
        .catch((e) => { const m = $('brMsg'); m.className = 'err'; m.textContent = e.message; });
    };
  }).catch((e) => { v.innerHTML = '<div class="card">' + tr('common.loadfail') + esc(e.message) + '</div>'; });
}
