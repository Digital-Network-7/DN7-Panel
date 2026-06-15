// =========================================================================
// Settings (tabbed: Console / Appearance & branding)
// =========================================================================
function renderSettings(v) {
  v.innerHTML = '<div style="padding:8px">' + loading() + '</div>';
  SettingsApi.get().then((sb) => {
    const s = sb.data;
    let allowIps = (s.allow_ips || []).slice();
    const ipDisplay = () => {
      const n = allowIps.length;
      if (!n) return tr('set.allow_ip_empty');
      const head = allowIps.slice(0, 3).join(', ');
      return n > 3 ? head + ' ' + tr('set.allow_ip_more', { n: n - 3 }) : head;
    };
    v.innerHTML = `
    <div class="subtabs" id="setTabs" style="margin-bottom:18px">
      <button data-s="general" class="on">${tr('set.tab_general')}</button>
      <button data-s="appear">${tr('set.tab_appearance')}</button>
    </div>
    <div id="setGeneral">
      <div style="max-width:480px">
        <label class="lbl">${tr('set.port_label')}</label>
        <input id="setPort" class="field" type="number" value="${esc(String(s.port || ''))}" style="max-width:160px" />
        <p class="formnote" style="margin-top:6px">${tr('set.port_restart_d')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.entry')}</label>
        <div class="field-suffix"><input id="setEntry" class="field" placeholder="/ab12cd" value="${esc(s.entry_path === '/' ? '' : (s.entry_path || ''))}" /><button type="button" class="suffix-btn" id="setEntryGen">${tr('set.generate')}</button></div>
        <p class="formnote" style="margin-top:6px">${tr('set.entry_hint')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.timeout')}</label>
        <input id="setTimeout" class="field" type="number" min="1" value="${esc(String(s.session_timeout || 1440))}" style="max-width:160px" />
        <p class="formnote" style="margin-top:6px">${tr('set.timeout_hint')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.allow_ip')}</label>
        <div class="field-suffix"><input id="setAllowIp" class="field" readonly /><button type="button" class="suffix-btn" id="setAllowIpBtn">${tr('set.allow_ip_set')}</button></div>
        <p class="formnote" style="margin-top:6px">${tr('set.allow_ip_hint')}</p>
        <label class="switch" style="padding:0;margin-top:16px"><input type="checkbox" id="setHttps" ${s.https ? 'checked' : ''} /><span class="swbox"></span><span class="swtxt"><b>${tr('set.https')}</b><span>${tr('set.https_hint')}</span></span></label>
      </div>
      <div class="row" style="align-items:center;gap:12px;margin-top:18px"><button class="btn" id="setSave">${tr('set.save')}</button><span class="err ok" id="setMsg"></span></div>
    </div>
    <div id="setAppear" class="hidden">
      <div style="max-width:480px">
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
      </div>
      <div class="row" style="align-items:center;gap:12px"><button class="btn" id="brSave">${tr('set.save_appearance')}</button><span class="err ok" id="brMsg"></span></div>
    </div>`;

    // ---- Tabs ----
    const tabs = $('setTabs');
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => {
      tabs.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
      $('setGeneral').classList.toggle('hidden', b.dataset.s !== 'general');
      $('setAppear').classList.toggle('hidden', b.dataset.s !== 'appear');
    });

    // ---- Console: port / entry path / session timeout / authorized IPs / https ----
    $('setEntryGen').onclick = () => {
      const cs = 'abcdefghijkmnpqrstuvwxyz23456789';
      const a = new Uint8Array(6);
      if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a); else for (let i = 0; i < 6; i++) a[i] = Math.floor(Math.random() * 256);
      $('setEntry').value = '/' + Array.from(a).map((b) => cs[b % cs.length]).join('');
    };
    $('setAllowIp').value = ipDisplay();
    $('setAllowIpBtn').onclick = () => {
      modal(tr('set.allow_ip_modal'), `
        <label class="lbl">${tr('set.allow_ip')}</label>
        <textarea id="aiText" class="field mono" rows="7" spellcheck="false" placeholder="${tr('set.allow_ip_ph')}">${esc(allowIps.join('\n'))}</textarea>
        <p class="formnote" style="margin-top:6px">${tr('set.allow_ip_hint')}</p>
        <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="aiOk">${tr('common.ok')}</button></div>`, (close) => {
        $('aiOk').onclick = () => {
          allowIps = $('aiText').value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
          $('setAllowIp').value = ipDisplay();
          $('setAllowIp').dispatchEvent(new Event('input', { bubbles: true }));
          close();
        };
      });
    };
    $('setSave').onclick = () => {
      const m = $('setMsg');
      const body = {
        port: Number($('setPort').value),
        entry_path: $('setEntry').value.trim() || '/',
        session_timeout: Number($('setTimeout').value) || 1440,
        allow_ips: allowIps,
        https: $('setHttps').checked,
      };
      SettingsApi.save(body)
        .then((b) => { m.className = 'err ok'; m.textContent = tr('common.saved') + (b.needs_restart ? tr('common.restart_hint') : ''); if ($('setSave')._dirtyReset) $('setSave')._dirtyReset(); })
        .catch((e) => { m.className = 'err'; m.textContent = e.message; });
    };
    bindDirty('setSave', 'setGeneral');

    // ---- Appearance / branding ----
    $('brLang').value = curLang();
    $('brLang').onchange = () => setLang($('brLang').value);
    const B = window.__BRAND__ || {};
    const brState = { logo: B.logo || '', accent: B.accent || '' };
    const DEF_ACCENT = '#3b82f6';
    function brRenderPrev() {
      const p = $('brLogoPrev');
      if (brState.logo) {
        p.innerHTML = `<img src="${esc(brState.logo)}" alt="" style="width:100%;height:100%;object-fit:contain" />`;
      } else {
        // No custom logo → show the current (built-in) mark from the sidebar.
        const cup = document.querySelector('aside .logo .cup');
        p.innerHTML = cup ? cup.innerHTML : '';
      }
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
    $('brLogoClear').onclick = () => { brState.logo = ''; $('brLogoFile').value = ''; brRenderPrev(); $('brName').dispatchEvent(new Event('input', { bubbles: true })); };
    $('brAccent').oninput = () => { brState.accent = $('brAccent').value; $('brAccentVal').textContent = brState.accent; };
    $('brAccentClear').onclick = () => { brState.accent = ''; brRenderPrev(); $('brName').dispatchEvent(new Event('input', { bubbles: true })); };
    $('brSave').onclick = () => {
      const body = { panel_name: $('brName').value, theme_default: $('brTheme').value, accent: brState.accent, logo: brState.logo };
      SettingsApi.saveBranding(body)
        .then(() => { const m = $('brMsg'); m.className = 'err ok'; m.textContent = tr('set.saving_refresh'); setTimeout(() => location.reload(), 600); })
        .catch((e) => { const m = $('brMsg'); m.className = 'err'; m.textContent = e.message; });
    };
    bindDirty('brSave', 'setAppear');
  }).catch((e) => { v.innerHTML = '<div class="card">' + tr('common.loadfail') + esc(e.message) + '</div>'; });
}
