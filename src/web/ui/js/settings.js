// =========================================================================
// Settings (tabbed: Console / Appearance & branding)
// =========================================================================

// ---- IP/CIDR helpers ----
// Client-side mirror of the server's normalize_allow_ips (web/settings.rs):
// each entry is an IPv4/IPv6 address or CIDR. Parsed form is { bits: BigInt,
// len: 32|128 } so CIDR containment (the lockout guard) is a single shift.
const SetIp = {
  v4(s) {
    // Each octet is a single '0' or a leading-zero-free 1..255 — mirror the
    // server's std::net::IpAddr parser, which rejects '010.0.0.1' etc.
    if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(s)) return null;
    const p = s.split('.').map(Number);
    if (p.some((o) => o > 255)) return null;
    return { bits: BigInt(((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]), len: 32 };
  },
  v6(s) {
    const dd = s.split('::');
    if (dd.length > 2) return null;
    const groups = (str) => {
      if (str === '') return [];
      const gs = str.split(':'), out = [];
      for (let i = 0; i < gs.length; i++) {
        if (gs[i].indexOf('.') >= 0) { // embedded IPv4 tail (::ffff:1.2.3.4)
          const t = i === gs.length - 1 ? SetIp.v4(gs[i]) : null;
          if (!t) return null;
          out.push(Number(t.bits >> 16n), Number(t.bits & 0xffffn));
        } else {
          if (!/^[0-9a-fA-F]{1,4}$/.test(gs[i])) return null;
          out.push(parseInt(gs[i], 16));
        }
      }
      return out;
    };
    const head = groups(dd[0]);
    if (head === null) return null;
    let all;
    if (dd.length === 2) {
      const tail = groups(dd[1]);
      if (tail === null || head.length + tail.length > 7) return null;
      all = head.concat(new Array(8 - head.length - tail.length).fill(0), tail);
    } else {
      if (head.length !== 8) return null;
      all = head;
    }
    let b = 0n;
    for (const g of all) b = (b << 16n) | BigInt(g);
    return { bits: b, len: 128 };
  },
  parse(s) { return SetIp.v4(s) || SetIp.v6(s); },
  valid(s) {
    const i = s.indexOf('/');
    if (i < 0) return !!SetIp.parse(s);
    const ip = SetIp.parse(s.slice(0, i)), pfx = s.slice(i + 1);
    return !!ip && /^\d{1,3}$/.test(pfx) && Number(pfx) <= ip.len;
  },
  // Whether address `ip` is covered by list entry `entry` (plain IP or CIDR).
  covered(ip, entry) {
    const i = entry.indexOf('/');
    const c = SetIp.parse(ip), e = SetIp.parse(i < 0 ? entry : entry.slice(0, i));
    if (!c || !e || c.len !== e.len) return false;
    const shift = BigInt(e.len - (i < 0 ? e.len : Math.min(Number(entry.slice(i + 1)), e.len)));
    return (c.bits >> shift) === (e.bits >> shift);
  },
};

function renderSettings(v) {
  v.innerHTML = '<div style="padding:8px">' + loading() + '</div>';
  SettingsApi.get().then((sb) => {
    const s = sb.data;
    let allowIps = (s.allow_ips || []).slice();
    let trustedProxies = (s.trusted_proxies || []).slice();
    // The caller's observed address (backend may not send it yet) powers the
    // lockout guard; a v4-mapped v6 form is normalized to plain v4.
    let clientIp = typeof s.client_ip === 'string' ? s.client_ip.trim() : '';
    if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(clientIp)) clientIp = clientIp.slice(7);
    if (clientIp && !SetIp.parse(clientIp)) clientIp = ''; // unusable value → guard off
    const listLabel = (list, emptyKey) => {
      const n = list.length;
      if (!n) return tr(emptyKey);
      const head = list.slice(0, 3).join(', ');
      return n > 3 ? head + ' ' + tr('set.allow_ip_more', { n: n - 3 }) : head;
    };
    v.innerHTML = `
    <div class="subtabs" id="setTabs" style="margin-bottom:18px">
      <button data-s="general" class="on">${tr('set.tab_general')}</button>
      <button data-s="appear">${tr('set.tab_appearance')}</button>
    </div>
    <div id="setGeneral">
      <div style="max-width:480px;margin-bottom:8px">
        <label class="lbl" style="font-size:15px;font-weight:600">${tr('set.access_title')}</label>
        <p class="formnote" style="margin:2px 0 12px">${tr('set.access_hint')}</p>
        <label class="lbl">${tr('init.addr')}</label>
        <input id="setAddr" class="field" value="${esc(s.external_address || '')}" placeholder="${tr('init.addr_ph')}" autocapitalize="none" spellcheck="false" />
        <label class="lbl" style="margin-top:14px">${tr('init.https')}</label>
        <div style="margin:6px 0 12px;display:flex;flex-direction:column;gap:8px">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="setHttps" value="none"> ${tr('init.https_none')}</label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="setHttps" value="selfsigned"> ${tr('init.https_self')}</label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="radio" name="setHttps" value="le"> ${tr('init.https_le')}</label>
        </div>
        <details style="margin-bottom:8px">
          <summary style="cursor:pointer;font-size:13px" class="mut">${tr('init.adv')}</summary>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px">
            <div><label class="lbl">${tr('init.http_port')}</label><input id="setHttpPort" class="field" type="number" min="1" max="65535" value="${esc(String(s.website_http_port || 80))}" /></div>
            <div><label class="lbl">${tr('init.https_port')}</label><input id="setHttpsPort" class="field" type="number" min="1" max="65535" value="${esc(String(s.website_https_port || 443))}" /></div>
          </div>
          <label class="lbl" style="margin-top:10px;display:block">${tr('init.console_port')}</label>
          <input id="setConsolePort" class="field" type="number" min="0" max="65535" value="${esc(String(s.console_port || 0))}" />
          <p class="formnote" style="margin-top:4px">${tr('init.console_port_hint')}</p>
        </details>
        <div class="row" style="align-items:center;gap:12px;margin-top:6px"><button class="btn" id="setAccessSave">${tr('set.save_restart')}</button><span class="err ok" id="setAccessMsg"></span></div>
      </div>
      <hr style="border:none;border-top:1px solid rgba(128,128,128,.2);margin:22px 0" />
      <div style="max-width:480px">
        <label class="lbl">${tr('set.timeout')}</label>
        <input id="setTimeout" class="field" type="number" min="1" max="43200" step="1" value="${esc(String(s.session_timeout || 1440))}" style="max-width:160px" />
        <p class="formnote" style="margin-top:6px">${tr('set.timeout_hint')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.allow_ip')}</label>
        <div class="field-suffix"><input id="setAllowIp" class="field" readonly /><button type="button" class="suffix-btn" id="setAllowIpBtn">${tr('set.allow_ip_set')}</button></div>
        <input id="setAllowIpFull" type="hidden" />
        <p class="formnote" style="margin-top:6px">${tr('set.allow_ip_hint')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.trusted_proxies')}</label>
        <div class="field-suffix"><input id="setTrustProx" class="field" readonly /><button type="button" class="suffix-btn" id="setTrustProxBtn">${tr('set.allow_ip_set')}</button></div>
        <input id="setTrustProxFull" type="hidden" />
        <p class="formnote" style="margin-top:6px">${tr('set.tp_hint')}</p>
        <label class="lbl" style="margin-top:16px">${tr('set.entry')}</label>
        <div class="field-suffix"><input id="setEntry" class="field" value="${esc(s.entry_path || '')}" placeholder="${tr('set.entry_ph')}" autocapitalize="none" spellcheck="false" /><button type="button" class="suffix-btn" id="setEntryGen">${tr('set.generate')}</button></div>
        <p class="formnote" style="margin-top:6px">${tr('set.entry_hint')}</p>
      </div>
      <div class="row" style="align-items:center;gap:12px;margin-top:18px"><button class="btn" id="setSave">${tr('set.save')}</button><span class="err ok" id="setMsg"></span></div>
    </div>
    <div id="setAppear" class="hidden">
      <div style="max-width:480px">
        <label class="lbl">${tr('set.language')}</label>
        <select id="brLang" class="field">
          <option value="en">English</option>
          <option value="zh-CN">简体中文</option>
          <option value="zh-TW">繁體中文</option>
          <option value="ja">日本語</option>
        </select>
        <p class="formnote" style="margin:6px 0 12px">${tr('set.language_hint')}</p>
        <div id="brForm">
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
          <div class="row" style="align-items:center;gap:12px"><button class="btn" id="brSave">${tr('set.save_appearance')}</button><span class="err ok" id="brMsg"></span></div>
        </div>
      </div>
    </div>`;

    // ---- Tabs ----
    const tabs = $('setTabs');
    tabs.querySelectorAll('button').forEach((b) => b.onclick = () => {
      tabs.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
      $('setGeneral').classList.toggle('hidden', b.dataset.s !== 'general');
      $('setAppear').classList.toggle('hidden', b.dataset.s !== 'appear');
    });

    // ---- Console: session timeout / authorized IPs / trusted proxies ----
    // Shared line-by-line IP/CIDR list editor: every line is validated before
    // the modal closes (never after the step-up password). `guardIp` (the
    // caller's own address) arms the lockout check — a non-empty list that
    // doesn't cover it needs an explicit extra confirm or one click on
    // "add my IP".
    const editIpList = (titleKey, hintKey, cur, guardIp, onSave) => {
      modal(tr(titleKey), `
        <label class="lbl">${tr(titleKey)}</label>
        <textarea id="ilText" class="field mono" rows="7" spellcheck="false" placeholder="${tr('set.allow_ip_ph')}">${esc(cur.join('\n'))}</textarea>
        <p class="formnote" style="margin-top:6px">${tr(hintKey)}</p>
        ${guardIp ? `<p class="formnote" style="margin-top:4px">${tr('set.your_ip', { ip: esc(guardIp) })}</p>` : ''}
        <div id="ilWarn" class="warn hidden" style="margin:10px 0 0"></div>
        <p class="err" id="ilErr" style="margin-top:8px"></p>
        <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="ilOk">${tr('common.ok')}</button></div>`, (close) => {
        const lines = () => $('ilText').value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
        $('ilText').addEventListener('input', () => { $('ilErr').textContent = ''; $('ilWarn').classList.add('hidden'); });
        $('ilOk').onclick = async () => {
          const err = $('ilErr'), raw = lines();
          const bad = raw.findIndex((l) => !SetIp.valid(l));
          if (bad >= 0) { err.textContent = tr('set.ip_line_bad', { n: bad + 1, line: raw[bad] }); return; }
          const ls = [];
          for (const l of raw) if (!ls.includes(l)) ls.push(l); // dedupe like the server
          if (ls.length > 200) { err.textContent = tr('set.ip_too_many'); return; }
          if (guardIp && ls.length && !ls.some((l) => SetIp.covered(guardIp, l))) {
            // Lockout hazard: inline warn with a one-click fix, plus an
            // explicit confirm before accepting the list as-is.
            const w = $('ilWarn');
            w.classList.remove('hidden');
            w.innerHTML = `<div style="margin-bottom:8px">${tr('set.lockout_warn', { ip: esc(guardIp) })}</div><button type="button" class="btn sm sec" id="ilAddMe">${tr('set.add_my_ip')}</button>`;
            $('ilAddMe').onclick = () => { $('ilText').value = lines().concat([guardIp]).join('\n'); w.classList.add('hidden'); };
            const yes = await confirmDanger(tr('set.lockout_warn', { ip: guardIp }));
            if (!yes) return;
          }
          onSave(ls);
          close();
        };
      });
    };
    // The readonly summary input shows a truncated label (first 3 + "+n more"),
    // which can't distinguish edits past position 3 or same-count swaps. The
    // dirty-gate snapshots the FULL list from a hidden sibling input so any
    // change flips Save on; a title tooltip surfaces the whole list on hover.
    const setListField = (id, list, emptyKey, fire) => {
      const inp = $(id), full = $(id + 'Full');
      inp.value = listLabel(list, emptyKey);
      inp.title = list.length ? list.join('\n') : tr(emptyKey);
      full.value = list.join('\n');
      if (fire) full.dispatchEvent(new Event('input', { bubbles: true }));
    };
    setListField('setAllowIp', allowIps, 'set.allow_ip_empty', false);
    setListField('setTrustProx', trustedProxies, 'set.tp_empty', false);
    $('setAllowIpBtn').onclick = () => editIpList('set.allow_ip_modal', 'set.allow_ip_hint', allowIps, clientIp, (ls) => {
      allowIps = ls;
      setListField('setAllowIp', allowIps, 'set.allow_ip_empty', true);
    });
    $('setTrustProxBtn').onclick = () => editIpList('set.trusted_proxies', 'set.tp_hint', trustedProxies, '', (ls) => {
      trustedProxies = ls;
      setListField('setTrustProx', trustedProxies, 'set.tp_empty', true);
    });
    $('setSave').onclick = async () => {
      const m = $('setMsg');
      // Validate before collecting the step-up password — never re-auth for a
      // request already known to fail (server range: 1..=43200 minutes).
      const tv = String($('setTimeout').value).trim();
      if (!/^\d+$/.test(tv) || +tv < 1 || +tv > 43200) { m.className = 'err'; m.textContent = tr('err.settings.timeout_range'); return; }
      const ep = $('setEntry').value.trim().replace(/^\/+/, '');
      if (ep && !/^[A-Za-z0-9_-]{1,64}$/.test(ep)) { m.className = 'err'; m.textContent = tr('err.settings.bad_entry_path'); return; }
      m.textContent = '';
      // Step-up re-auth doubles as the confirmation here: changing the panel's
      // access/security settings requires re-entering the password.
      const tok = await stepUp(tr('stepup.msg_settings'));
      if (!tok) return;
      const body = { session_timeout: +tv, allow_ips: allowIps, trusted_proxies: trustedProxies, entry_path: ep };
      try {
        await SettingsApi.save(body, { 'X-DN7-Stepup': tok });
        if ($('setSave')._dirtyReset) $('setSave')._dirtyReset();
        // The entry path applies live; if it changed, the current session's
        // `dn7_entry` cookie is now stale — reload to the new front door so a fresh
        // cookie is set (else the next request 404s). Disabled → back to `/`.
        if (ep !== (s.entry_path || '')) { location.href = ep ? '/' + ep : '/'; return; }
        m.className = 'err ok'; m.textContent = '';
        toast(tr('common.saved'), 'ok');
      } catch (e) { m.className = 'err'; m.textContent = e.message; }
    };
    bindDirty('setSave', 'setGeneral');

    // Security entry path: Generate a fresh random 6-letter path into the field.
    $('setEntryGen').onclick = () => {
      const a = 'abcdefghijklmnopqrstuvwxyz'; let x = '';
      for (let k = 0; k < 6; k++) x += a[Math.floor(Math.random() * a.length)];
      const i = $('setEntry'); i.value = x; i.dispatchEvent(new Event('input', { bubbles: true }));
    };

    // ---- Console access (address / HTTPS / ports) — applied by a restart ----
    const httpsPick = document.querySelector(`input[name="setHttps"][value="${s.https_mode || 'none'}"]`);
    if (httpsPick) httpsPick.checked = true; else document.querySelector('input[name="setHttps"][value="none"]').checked = true;
    $('setAccessSave').onclick = async () => {
      const m = $('setAccessMsg');
      const addr = $('setAddr').value.trim();
      const mode = (document.querySelector('input[name="setHttps"]:checked') || {}).value || 'none';
      const httpPort = parseInt($('setHttpPort').value, 10) || 80;
      const httpsPort = parseInt($('setHttpsPort').value, 10) || 443;
      const consolePort = parseInt($('setConsolePort').value, 10) || 0;
      if (!addr || !/^[A-Za-z0-9._\-:[\]]{1,253}$/.test(addr)) { m.className = 'err'; m.textContent = tr('err.settings.bad_address'); return; }
      if (mode === 'le' && /^[0-9.]+$/.test(addr)) { m.className = 'err'; m.textContent = tr('err.settings.le_needs_domain'); return; }
      if (httpPort === httpsPort) { m.className = 'err'; m.textContent = tr('err.settings.ports_same'); return; }
      m.textContent = '';
      const tok = await stepUp(tr('stepup.msg_settings'));
      if (!tok) return;
      m.className = 'err ok'; m.textContent = mode === 'le' ? tr('init.issuing') : tr('set.applying');
      try {
        const rb = await SettingsApi.consoleAccess({ external_address: addr, https_mode: mode, website_http_port: httpPort, website_https_port: httpsPort, console_port: consolePort }, { 'X-DN7-Stepup': tok });
        const url = (rb && rb.data && rb.data.url) || '';
        // The panel is restarting to bind the new ports/TLS and may move to a new
        // address; show the new login URL in a non-dismissible dialog.
        modal(tr('set.access_saved_title'),
          `<p style="margin:0 0 16px;line-height:1.7">${esc(tr('set.access_saved_intro'))}</p>` +
          (url ? `<a class="btn" style="width:100%;display:block;text-align:center;box-sizing:border-box;text-decoration:none" href="${esc(url)}">${esc(url)}</a>` : ''),
          () => {}, { noClose: true });
      } catch (e) { m.className = 'err'; m.textContent = e.message; }
    };

    // ---- Appearance / branding ----
    // The language select is a per-browser personal preference and applies
    // immediately (setLang reloads the page) — it lives outside the branding
    // form (#brForm) so it neither marks it dirty nor silently discards
    // unsaved edits: a dirty form gets a confirm first.
    $('brLang').value = curLang();
    $('brLang').onchange = () => {
      const nv = $('brLang').value;
      if (nv === curLang()) return;
      if ($('brForm').dataset.dirty === '1') {
        confirmDanger(tr('common.discard_confirm')).then((yes) => { if (yes) setLang(nv); else $('brLang').value = curLang(); });
      } else setLang(nv);
    };
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
    bindDirty('brSave', 'brForm');
  }).catch((e) => { v.innerHTML = '<div class="card">' + tr('common.loadfail') + esc(e.message) + '</div>'; });
}
