// =========================================================================
// i18n — 4 languages (en / zh-CN / zh-TW / ja).
//
// The active language is resolved synchronously in <head> (window.__LANG__):
// a manual choice (localStorage 'dn7_lang') wins; otherwise the browser
// language, falling back to English. This module supplies the dictionary +
// `tr(key)`, translates static [data-i18n*] nodes, wires the language switcher,
// and then reveals the page (data-i18n-ready) — so the UI only ever paints in
// the correct language (no flash). Switching language persists the choice and
// reloads, so every view re-renders in the new language with no half state.
// =========================================================================
const I18N = {
  en: {
    'common.cancel': 'Cancel', 'common.ok': 'OK', 'common.confirm': 'Please confirm',
    'common.saved': 'Saved', 'common.loadfail': 'Failed to load: ',
    'common.restart_hint': ' (port/toggle changes take effect after restarting Panel)',
    'login.title': 'SIGN IN', 'login.sub': 'Sign in securely to the local console',
    'login.account': 'Account', 'login.password': 'Password',
    'login.ph_account': 'Please enter your account', 'login.ph_password': 'Please enter your password',
    'login.submit': 'Sign in', 'login.err_conn': 'Cannot reach the server', 'login.err_fail': 'Login failed',
    'tab.dash': 'Monitor', 'tab.term': 'Terminal', 'tab.files': 'Files', 'tab.settings': 'Settings',
    'shell.logout': 'Sign out', 'shell.update_hint': 'Click to check for updates',
    'theme.tip': 'Theme: ', 'theme.auto': 'Auto', 'theme.light': 'Light', 'theme.dark': 'Dark',
    'lang.name': 'Language',
    'dash.mem': 'Memory', 'dash.disk': 'Disk', 'dash.cores': ' cores', 'dash.vcpu': ' vCPU',
    'dash.proc': 'Process', 'dash.user': 'User', 'dash.up': 'Up', 'dash.dn': 'Down', 'dash.net': 'Network',
    'set.account_sec': 'Login account', 'set.account': 'Account', 'set.password': 'Password',
    'set.pw_ph': 'Leave blank to keep unchanged',
    'set.pw_forgot_a': 'Forgot it? Run', 'set.pw_forgot_b': 'on the host to reset.',
    'set.show': 'Show', 'set.hide': 'Hide', 'set.pw_len': 'Password length must be 6-128',
    'set.port_sec': 'Port (restart Panel to apply)',
    'set.enable': 'Enable local management (restart required after disabling)',
    'set.save': 'Save', 'set.appearance': 'Appearance & branding', 'set.panel_name': 'Panel name',
    'set.logo_label': 'Logo (login + sidebar; square transparent PNG/SVG, ≤512KB)',
    'set.choose_img': 'Choose image', 'set.restore_default': 'Restore default',
    'set.accent': 'Accent color', 'set.default_paren': '(default)',
    'set.default_theme': 'Default theme (new visitors; a user’s own choice wins)',
    'set.save_appearance': 'Save appearance', 'set.img_too_big': 'Image too large (max 512KB)',
    'set.saving_refresh': 'Saved, refreshing…', 'set.language': 'Language',
  },
  'zh-CN': {
    'common.cancel': '取消', 'common.ok': '确定', 'common.confirm': '请确认',
    'common.saved': '已保存', 'common.loadfail': '加载失败：',
    'common.restart_hint': '（端口/开关改动需重启 Panel 生效）',
    'login.title': '登录', 'login.sub': '安全登录到本机控制台',
    'login.account': '账号', 'login.password': '密码',
    'login.ph_account': '请输入账号', 'login.ph_password': '请输入密码',
    'login.submit': '登 录', 'login.err_conn': '无法连接服务', 'login.err_fail': '登录失败',
    'tab.dash': '监控', 'tab.term': '终端', 'tab.files': '文件', 'tab.settings': '设置',
    'shell.logout': '退出登录', 'shell.update_hint': '点击查看更新',
    'theme.tip': '主题：', 'theme.auto': '跟随系统', 'theme.light': '浅色', 'theme.dark': '深色',
    'lang.name': '语言',
    'dash.mem': '内存', 'dash.disk': '磁盘', 'dash.cores': ' 核心', 'dash.vcpu': ' vCPU',
    'dash.proc': '进程', 'dash.user': '用户', 'dash.up': '上行', 'dash.dn': '下行', 'dash.net': '网络吞吐',
    'set.account_sec': '登录账号', 'set.account': '账号', 'set.password': '密码',
    'set.pw_ph': '留空表示不修改',
    'set.pw_forgot_a': '忘记密码？在主机上运行', 'set.pw_forgot_b': '重置账号密码。',
    'set.show': '显示', 'set.hide': '隐藏', 'set.pw_len': '密码长度需为 6-128',
    'set.port_sec': '端口（改后重启 Panel 生效）',
    'set.enable': '启用本机管理（关闭后需重启生效）',
    'set.save': '保存', 'set.appearance': '外观与品牌', 'set.panel_name': '面板名称',
    'set.logo_label': 'Logo（登录页与侧边栏，建议方形透明 PNG/SVG，≤512KB）',
    'set.choose_img': '选择图片', 'set.restore_default': '恢复默认',
    'set.accent': '主色调', 'set.default_paren': '（默认）',
    'set.default_theme': '默认主题（新访客；用户切换后以其选择为准）',
    'set.save_appearance': '保存外观', 'set.img_too_big': '图片过大（上限 512KB）',
    'set.saving_refresh': '已保存，正在刷新…', 'set.language': '语言',
  },
  'zh-TW': {
    'common.cancel': '取消', 'common.ok': '確定', 'common.confirm': '請確認',
    'common.saved': '已儲存', 'common.loadfail': '載入失敗：',
    'common.restart_hint': '（連接埠/開關變更需重啟 Panel 生效）',
    'login.title': '登入', 'login.sub': '安全登入本機主控台',
    'login.account': '帳號', 'login.password': '密碼',
    'login.ph_account': '請輸入帳號', 'login.ph_password': '請輸入密碼',
    'login.submit': '登 入', 'login.err_conn': '無法連線到服務', 'login.err_fail': '登入失敗',
    'tab.dash': '監控', 'tab.term': '終端機', 'tab.files': '檔案', 'tab.settings': '設定',
    'shell.logout': '登出', 'shell.update_hint': '點擊查看更新',
    'theme.tip': '主題：', 'theme.auto': '跟隨系統', 'theme.light': '淺色', 'theme.dark': '深色',
    'lang.name': '語言',
    'dash.mem': '記憶體', 'dash.disk': '磁碟', 'dash.cores': ' 核心', 'dash.vcpu': ' vCPU',
    'dash.proc': '程序', 'dash.user': '使用者', 'dash.up': '上行', 'dash.dn': '下行', 'dash.net': '網路吞吐',
    'set.account_sec': '登入帳號', 'set.account': '帳號', 'set.password': '密碼',
    'set.pw_ph': '留空表示不修改',
    'set.pw_forgot_a': '忘記密碼？在主機上執行', 'set.pw_forgot_b': '重設帳號密碼。',
    'set.show': '顯示', 'set.hide': '隱藏', 'set.pw_len': '密碼長度需為 6-128',
    'set.port_sec': '連接埠（變更後重啟 Panel 生效）',
    'set.enable': '啟用本機管理（停用後需重啟生效）',
    'set.save': '儲存', 'set.appearance': '外觀與品牌', 'set.panel_name': '面板名稱',
    'set.logo_label': 'Logo（登入頁與側邊欄，建議方形透明 PNG/SVG，≤512KB）',
    'set.choose_img': '選擇圖片', 'set.restore_default': '恢復預設',
    'set.accent': '主色調', 'set.default_paren': '（預設）',
    'set.default_theme': '預設主題（新訪客；使用者切換後以其選擇為準）',
    'set.save_appearance': '儲存外觀', 'set.img_too_big': '圖片過大（上限 512KB）',
    'set.saving_refresh': '已儲存，正在重新整理…', 'set.language': '語言',
  },
  ja: {
    'common.cancel': 'キャンセル', 'common.ok': 'OK', 'common.confirm': '確認してください',
    'common.saved': '保存しました', 'common.loadfail': '読み込み失敗：',
    'common.restart_hint': '（ポート/スイッチの変更は Panel 再起動後に有効）',
    'login.title': 'サインイン', 'login.sub': 'ローカルコンソールに安全にサインイン',
    'login.account': 'アカウント', 'login.password': 'パスワード',
    'login.ph_account': 'アカウントを入力', 'login.ph_password': 'パスワードを入力',
    'login.submit': 'サインイン', 'login.err_conn': 'サーバーに接続できません', 'login.err_fail': 'ログインに失敗しました',
    'tab.dash': 'モニター', 'tab.term': 'ターミナル', 'tab.files': 'ファイル', 'tab.settings': '設定',
    'shell.logout': 'ログアウト', 'shell.update_hint': 'クリックして更新を確認',
    'theme.tip': 'テーマ：', 'theme.auto': 'システムに従う', 'theme.light': 'ライト', 'theme.dark': 'ダーク',
    'lang.name': '言語',
    'dash.mem': 'メモリ', 'dash.disk': 'ディスク', 'dash.cores': ' コア', 'dash.vcpu': ' vCPU',
    'dash.proc': 'プロセス', 'dash.user': 'ユーザー', 'dash.up': '上り', 'dash.dn': '下り', 'dash.net': 'ネットワーク',
    'set.account_sec': 'ログインアカウント', 'set.account': 'アカウント', 'set.password': 'パスワード',
    'set.pw_ph': '空欄なら変更しません',
    'set.pw_forgot_a': 'パスワードを忘れた場合、ホストで', 'set.pw_forgot_b': 'を実行して再設定します。',
    'set.show': '表示', 'set.hide': '非表示', 'set.pw_len': 'パスワードは6〜128文字',
    'set.port_sec': 'ポート（変更後 Panel 再起動で有効）',
    'set.enable': 'ローカル管理を有効化（無効化後は再起動が必要）',
    'set.save': '保存', 'set.appearance': '外観とブランド', 'set.panel_name': 'パネル名',
    'set.logo_label': 'ロゴ（ログイン＋サイドバー、正方形・透過 PNG/SVG、512KB以下）',
    'set.choose_img': '画像を選択', 'set.restore_default': '既定に戻す',
    'set.accent': 'アクセントカラー', 'set.default_paren': '（既定）',
    'set.default_theme': '既定テーマ（新規訪問者；ユーザーの選択が優先）',
    'set.save_appearance': '外観を保存', 'set.img_too_big': '画像が大きすぎます（上限512KB）',
    'set.saving_refresh': '保存しました。更新中…', 'set.language': '言語',
  },
};

// Short label shown on the switcher button per language.
const LANG_SHORT = { en: 'EN', 'zh-CN': '简', 'zh-TW': '繁', ja: '日' };
const LANG_FULL = { en: 'English', 'zh-CN': '简体中文', 'zh-TW': '繁體中文', ja: '日本語' };

function curLang() { return window.__LANG__ || 'en'; }

// Translate a key (with optional {var} substitution); falls back to English,
// then to the key itself.
function tr(key, vars) {
  const d = I18N[curLang()] || I18N.en;
  let s = (d && d[key] != null) ? d[key] : (I18N.en[key] != null ? I18N.en[key] : key);
  if (vars) for (const k in vars) s = s.split('{' + k + '}').join(vars[k]);
  return s;
}

// Translate static nodes: text via data-i18n, placeholder via data-i18n-ph,
// title via data-i18n-title.
function applyI18n(root) {
  const r = root || document;
  r.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = tr(el.getAttribute('data-i18n')); });
  r.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', tr(el.getAttribute('data-i18n-ph'))); });
  r.querySelectorAll('[data-i18n-title]').forEach((el) => { el.setAttribute('title', tr(el.getAttribute('data-i18n-title'))); });
}

// Persist a manual language choice and reload so the whole UI re-renders in it.
function setLang(code) {
  if (!I18N[code] || code === curLang()) return;
  try { localStorage.setItem('dn7_lang', code); } catch (e) {}
  location.reload();
}

// Language switcher popup anchored to the topbar button.
function toggleLangMenu() {
  let pop = document.querySelector('.lang-pop');
  if (pop) { pop.remove(); return; }
  const btn = document.getElementById('langBtn');
  if (!btn) return;
  pop = document.createElement('div');
  pop.className = 'selx-pop lang-pop';
  ['en', 'zh-CN', 'zh-TW', 'ja'].forEach((code) => {
    const o = document.createElement('div');
    o.className = 'selx-opt' + (code === curLang() ? ' sel' : '');
    o.textContent = LANG_FULL[code];
    o.addEventListener('mousedown', (e) => { e.preventDefault(); pop.remove(); setLang(code); });
    pop.appendChild(o);
  });
  document.body.appendChild(pop);
  const r = btn.getBoundingClientRect();
  pop.style.minWidth = '120px';
  pop.style.left = Math.max(8, r.right - 120) + 'px';
  pop.style.top = (r.bottom + 4) + 'px';
  const close = (e) => { if (!e.target.closest('.lang-pop') && e.target.id !== 'langBtn') { pop.remove(); document.removeEventListener('mousedown', close, true); } };
  setTimeout(() => document.addEventListener('mousedown', close, true), 0);
}

// Initialize: translate the static DOM, label the switcher, then reveal.
(function initI18n() {
  applyI18n(document);
  const btn = document.getElementById('langBtn');
  if (btn) {
    btn.textContent = LANG_SHORT[curLang()] || 'EN';
    btn.title = tr('lang.name');
    btn.onclick = toggleLangMenu;
  }
  document.documentElement.setAttribute('data-i18n-ready', '1');
})();
