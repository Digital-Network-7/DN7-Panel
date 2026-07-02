// Regression guard for the website "高级功能" advanced-feature cards.
//
// An earlier audit batch (P2b) HID three cards — 每 IP 并发 (conn_per_ip),
// per-site IP ACL (ip_acl_mode/ip_acl_list) and 防盗链 (hotlink_referers) —
// by marking them "coming soon": disabled switch + disabled inputs + values
// dropped from the add_site/update_site body. Those features are now enforced
// at the edge, so the cards must render interactive again and re-send their
// values. This asserts the un-hiding stayed reverted (no false "coming soon").
const fs = require('fs');
const dir = './src/web/ui/js/';
const site = fs.readFileSync(dir + 'website.js', 'utf8');
const i18n = fs.readFileSync(dir + 'i18n.js', 'utf8');
let ok = true;
const fail = (m) => { ok = false; console.log('FAIL:', m); };

// 1. The three cards must NOT pass the `soon` flag (the 9th afCard arg) or a
//    disabled attribute — that is exactly what P2b added to hide them.
for (const feat of ['conn', 'acl', 'hot']) {
  const re = new RegExp(`afCard\\('${feat}',[\\s\\S]*?\\)\\)\\}`);
  const m = re.exec(site);
  if (!m) { fail(`afCard('${feat}', …) not found`); continue; }
  const card = m[0];
  if (/,\s*false,\s*true\)\)/.test(card)) fail(`${feat} card still marked "coming soon" (soon=true)`);
  if (/\bdisabled\b/.test(card)) fail(`${feat} card still has a disabled control`);
}

// 2. The add/update body must send all four values again.
for (const key of ['conn_per_ip', 'ip_acl_mode', 'ip_acl_list', 'hotlink_referers']) {
  if (!new RegExp(`body\\.${key}\\s*=`).test(site)) fail(`body.${key} is not sent`);
}

// 3. Edit-prefill must restore the saved values for those cards.
for (const id of ['nsConnIp', 'nsAclList', 'nsHotlink']) {
  if (!new RegExp(`sv\\('${id}'`).test(site)) fail(`${id} is not prefilled on edit`);
}

// 4. The "coming soon" i18n key P2b added must be gone from every language.
if (/'ng\.af_soon'/.test(i18n)) fail("stale 'ng.af_soon' key still present in i18n.js");

console.log(ok ? 'ADVANCED_FEATURES_OK' : 'ADVANCED_FEATURES_FAIL');
process.exit(ok ? 0 : 1);
