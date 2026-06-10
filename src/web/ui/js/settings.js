// =========================================================================
// Settings
// =========================================================================
function renderSettings(v) {
  v.innerHTML = '<div class="card">' + loading() + '</div>';
  api('/api/settings').then((sb) => {
    const s = sb.data;
    v.innerHTML = `
    <div class="card" style="max-width:520px">
      <h3>登录账号</h3>
      <label class="lbl">账号</label>
      <input id="setUser" class="field" style="margin-bottom:12px" value="${esc(s.username)}" />
      <label class="lbl">密码</label>
      <div class="row" style="margin-bottom:4px"><input id="setPw" class="field" type="password" value="${esc(s.password)}" style="flex:1" /><button class="btn sec sm" id="setPwShow" type="button">显示</button></div>
      <h3 style="margin-top:18px">端口（改后重启 Agent 生效）</h3>
      <input id="setPort" class="field" type="number" value="${s.port}" />
      <label style="display:flex;gap:8px;align-items:center;margin:14px 0"><input type="checkbox" id="setEnabled" ${s.enabled ? 'checked' : ''}/> 启用本机管理（关闭后需重启生效）</label>
      <button class="btn" id="setSave">保存</button>
      <div class="err ok" id="setMsg" style="margin-top:10px"></div>
    </div>
    <div class="card" style="max-width:520px;margin-top:16px">
      <h3>外观与品牌</h3>
      <label class="lbl">面板名称</label>
      <input id="brName" class="field" style="margin-bottom:12px" maxlength="40" />
      <label class="lbl">Logo（登录页与侧边栏，建议方形透明 PNG/SVG，≤512KB）</label>
      <div class="row" style="align-items:center;margin-bottom:12px">
        <span id="brLogoPrev" style="width:40px;height:40px;border-radius:10px;flex-shrink:0;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1px solid var(--line)"></span>
        <input id="brLogoFile" type="file" accept="image/*" style="display:none" />
        <button class="btn sec sm" type="button" id="brLogoPick">选择图片</button>
        <button class="btn sec sm" type="button" id="brLogoClear">恢复默认</button>
      </div>
      <label class="lbl">主色调</label>
      <div class="row" style="align-items:center;margin-bottom:12px">
        <input id="brAccent" type="color" style="width:46px;height:34px;padding:2px;border-radius:8px;border:1px solid var(--line);background:var(--panel2)" />
        <button class="btn sec sm" type="button" id="brAccentClear">恢复默认</button>
        <span class="sub" id="brAccentVal" style="margin:0"></span>
      </div>
      <label class="lbl">默认主题（新访客；用户切换后以其选择为准）</label>
      <select id="brTheme" class="field" style="margin-bottom:14px">
        <option value="auto">跟随系统</option>
        <option value="light">浅色</option>
        <option value="dark">深色</option>
      </select>
      <button class="btn" id="brSave">保存外观</button>
      <div class="err ok" id="brMsg" style="margin-top:10px"></div>
    </div>`;
    $('setPwShow').onclick = () => { const i = $('setPw'); const show = i.type === 'password'; i.type = show ? 'text' : 'password'; $('setPwShow').textContent = show ? '隐藏' : '显示'; };
    $('setSave').onclick = () => {
      const body = { username: $('setUser').value, password: $('setPw').value, port: Number($('setPort').value), enabled: $('setEnabled').checked };
      api('/api/settings', { method: 'POST', body: JSON.stringify(body) })
        .then((b) => { const m = $('setMsg'); m.className = 'err ok'; m.textContent = '已保存' + (b.needs_restart ? '（端口/开关改动需重启 Agent 生效）' : ''); setUser(body.username); })
        .catch((e) => { const m = $('setMsg'); m.className = 'err'; m.textContent = e.message; });
    };
    // ---- Appearance / branding ----
    const B = window.__BRAND__ || {};
    const brState = { logo: B.logo || '', accent: B.accent || '' };
    const DEF_ACCENT = '#3b82f6';
    function brRenderPrev() {
      const p = $('brLogoPrev');
      if (brState.logo) { p.innerHTML = `<img src="${esc(brState.logo)}" alt="" style="width:100%;height:100%;object-fit:contain" />`; }
      else { p.innerHTML = '<span style="font-size:11px;color:var(--mut)">默认</span>'; }
      $('brAccent').value = brState.accent || DEF_ACCENT;
      $('brAccentVal').textContent = brState.accent || '（默认）';
    }
    $('brName').value = B.name || 'DN7 Panel';
    $('brTheme').value = B.theme || 'auto';
    brRenderPrev();
    $('brLogoPick').onclick = () => $('brLogoFile').click();
    $('brLogoFile').onchange = () => {
      const f = $('brLogoFile').files[0]; if (!f) return;
      if (f.size > 512 * 1024) { const m = $('brMsg'); m.className = 'err'; m.textContent = '图片过大（上限 512KB）'; return; }
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
        .then(() => { const m = $('brMsg'); m.className = 'err ok'; m.textContent = '已保存，正在刷新…'; setTimeout(() => location.reload(), 600); })
        .catch((e) => { const m = $('brMsg'); m.className = 'err'; m.textContent = e.message; });
    };
  }).catch((e) => { v.innerHTML = '<div class="card">加载失败：' + esc(e.message) + '</div>'; });
}
