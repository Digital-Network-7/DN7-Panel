import re, os
d = 'src/web/ui/js/'
src = open(d + 'i18n.js', encoding='utf-8').read()
start = src.index('const I18N = {')
i = src.index('{', start) + 1
langs = {}
while i < len(src):
    while i < len(src) and src[i] in ' \t\r\n,':
        i += 1
    if src[i] == '}':
        break
    m = re.match(r"['\"]?([\w-]+)['\"]?\s*:\s*\{", src[i:])
    if not m:
        break
    name = m.group(1); j = i + m.end() - 1; depth = 1; j += 1; s0 = j
    while j < len(src) and depth > 0:
        if src[j] == '{': depth += 1
        elif src[j] == '}': depth -= 1
        j += 1
    langs[name] = re.findall(r"['\"]([\w.{}\- ]+?)['\"]\s*:", src[s0:j-1])
    i = j
names = list(langs)
print('Languages:', ', '.join(f'{n}({len(set(langs[n]))})' for n in names))
en = set(langs['en']); ok = True
for n in names:
    if n == 'en': continue
    if set(en) - set(langs[n]): ok = False; print(n, 'MISSING', sorted(set(en) - set(langs[n])))
    if set(langs[n]) - en: ok = False; print(n, 'EXTRA', sorted(set(langs[n]) - en))
for n in names:
    seen = {}
    for k in langs[n]: seen[k] = seen.get(k, 0) + 1
    dd = [k for k, c in seen.items() if c > 1]
    if dd: ok = False; print(n, 'DUP', dd)
used = set()
for f in os.listdir(d):
    if f.endswith('.js'):
        used |= set(re.findall(r"\btr\(\s*['\"]([\w.\-]+?)['\"]", open(d + f, encoding='utf-8').read()))
miss = [k for k in used if k not in en and k != 'theme.']
if miss: ok = False; print('USED-MISSING', sorted(miss))
print('OK' if ok else 'FAIL')
