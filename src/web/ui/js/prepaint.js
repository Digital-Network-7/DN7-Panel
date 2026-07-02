// Pre-paint theme + language + auth view resolution.
//
// Loaded as an external <script> in <head> (parser-blocking) so it runs before
// first paint — there's no flash of the wrong theme/language/login-page before
// the app JS runs. Kept external (not inline) so the Content-Security-Policy
// can use a strict `script-src 'self'` with no `'unsafe-inline'`.
(function () {
  try {
    // Brand config arrives as a same-origin JSON data block (CSP-safe; a strict
    // `script-src 'self'` blocks an inline brand script). Parse it into
    // window.__BRAND__ for this and the later app scripts (theme/settings).
    try {
      var bn = document.getElementById('__dn7_brand__');
      if (bn) window.__BRAND__ = JSON.parse(bn.textContent || '{}');
    } catch (e) { /* fall back to default branding */ }
    var m = localStorage.getItem('dn7_theme') || (window.__BRAND__ && window.__BRAND__.theme) || 'auto';
    var eff = m;
    if (m === 'auto') eff = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', eff);
    document.documentElement.setAttribute('data-mode', m);
    // Density preference (see theme.js setDensity) — applied here so compact
    // tables don't flash comfortable on refresh.
    if (localStorage.getItem('dn7_dens') === 'compact') document.documentElement.setAttribute('data-density', 'compact');
    // Decide auth view before first paint so a logged-in refresh never flashes
    // the login page (CSS hides the opposite view based on this attr).
    document.documentElement.setAttribute('data-auth', localStorage.getItem('dn7_web_token') ? 'in' : 'out');
    // Language: a manual choice wins; otherwise follow the browser, falling
    // back to English. Resolved here so the page renders once, in the right
    // language, with no flicker.
    var SUP = ['en', 'zh-CN', 'zh-TW', 'ja'];
    var saved = localStorage.getItem('dn7_lang');
    // The operator's init-wizard choice, injected server-side into __BRAND__.
    var serverDefault = (window.__BRAND__ && window.__BRAND__.default_lang) || '';
    var lang;
    if (SUP.indexOf(saved) >= 0) {
      lang = saved; // an explicit in-console choice always wins
    } else if (SUP.indexOf(serverDefault) >= 0) {
      lang = serverDefault; // else the operator-configured console default
    } else {
      var ls = (navigator.languages && navigator.languages.length) ? navigator.languages : [navigator.language || ''];
      lang = 'en';
      for (var i = 0; i < ls.length; i++) {
        var l = (ls[i] || '').toLowerCase();
        if (l.indexOf('zh') === 0) { lang = (l.indexOf('tw') >= 0 || l.indexOf('hk') >= 0 || l.indexOf('mo') >= 0 || l.indexOf('hant') >= 0) ? 'zh-TW' : 'zh-CN'; break; }
        if (l.indexOf('ja') === 0) { lang = 'ja'; break; }
        if (l.indexOf('en') === 0) { lang = 'en'; break; }
      }
    }
    window.__LANG__ = lang;
    document.documentElement.lang = lang;
  } catch (e) { window.__LANG__ = 'en'; }
})();
