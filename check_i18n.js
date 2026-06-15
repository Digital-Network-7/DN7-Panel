const fs = require('fs');
const dir = './src/web/ui/js/';
const src = fs.readFileSync(dir + 'i18n.js', 'utf8');
const start = src.indexOf('const I18N = {');
const bodyStart = src.indexOf('{', start);
function parseLangs(text, from) {
  let i = from + 1; const langs = {};
  while (i < text.length) {
    while (i < text.length && /[\s,]/.test(text[i])) i++;
    if (text[i] === '}') break;
    let m = /^['"]?([\w-]+)['"]?\s*:\s*\{/.exec(text.slice(i));
    if (!m) break;
    const name = m[1]; let j = i + m[0].length - 1; let depth = 1; j++;
    const objStart = j;
    while (j < text.length && depth > 0) { if (text[j] === '{') depth++; else if (text[j] === '}') depth--; j++; }
    const objBody = text.slice(objStart, j - 1);
    const keys = new Set(); const re = /['"]([\w.{}\- ]+?)['"]\s*:/g; let km;
    while ((km = re.exec(objBody))) keys.add(km[1]);
    langs[name] = keys; i = j;
  }
  return langs;
}
const langs = parseLangs(src, bodyStart);
const names = Object.keys(langs);
console.log('Languages:', names.map(n => n + '(' + langs[n].size + ')').join(', '));
const en = langs.en; let ok = true;
for (const n of names) {
  if (n === 'en') continue;
  const missing = [...en].filter(k => !langs[n].has(k));
  const extra = [...langs[n]].filter(k => !en.has(k));
  if (missing.length) { ok = false; console.log(n, 'MISSING', missing); }
  if (extra.length) { ok = false; console.log(n, 'EXTRA', extra); }
}
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
const used = new Set();
for (const f of files) { const c = fs.readFileSync(dir + f, 'utf8'); const re = /\btr\(\s*['"]([\w.\-]+?)['"]/g; let m; while ((m = re.exec(c))) used.add(m[1]); }
const missingKeys = [...used].filter(k => !en.has(k) && k !== 'theme.');
console.log('Used tr() keys:', used.size);
if (missingKeys.length) { ok = false; console.log('MISSING in dict:', missingKeys.sort()); }
else console.log('All used tr() keys exist (ignoring dynamic theme.).');
console.log(ok ? 'CONSISTENCY_OK' : 'CONSISTENCY_FAIL');
