// Docker: images + volumes tabs (split from docker.js).
function dkImages(info) {
  const body = $('dkBody');
  if (!body) return; // tab left before an async refresh landed — nothing to render into
  body.innerHTML = `<div class="sechead"><input id="dkImgSearch" class="field" placeholder="${esc(tr('dk.img_search'))}" style="max-width:220px" aria-label="${esc(tr('dk.img_search'))}" /><span class="sp"></span><button class="btn sm" id="dkPull">${tr('dk.pull_image')}</button><button class="btn sec sm" id="dkRefI">${tr('dk.refresh')}</button><button class="btn sec sm" id="dkAdv">${tr('dk.advanced')} ▾</button></div><div id="dkIList">` + loading() + '</div>';
  $('dkRefI').onclick = () => dkImages(info);
  $('dkPull').onclick = dkPullForm;
  mkHoverPanel($('dkAdv'), [
    { label: tr('dk.img_import'), fn: () => dkImportForm(info) },
    { label: tr('dk.pull_tasks'), fn: () => dkPullTasks() },
    { label: tr('dk.img_prune'), fn: () => confirmDanger(tr('dk.img_prune_confirm')).then((ok) => { if (!ok) return; op('docker', { op: 'prune_images' }).then((r) => { toast(tr('dk.img_pruned', { n: r.pruned || 0, size: fmtBytes(r.reclaimed || 0) }), 'ok'); dkImages(info); }).catch((e) => toast(e.message, 'err')); }) },
  ]);
  op('docker', { op: 'list_images' }).then((d) => {
    const list = d.images || [];
    const search = $('dkImgSearch');
    if (!list.length) { $('dkIList').innerHTML = `<div class="empty">${tr('dk.no_images')}</div>`; if (search) search.disabled = true; return; }

    // The backend returns one row per tag; collapse rows that share an image id
    // (the same image under multiple tags) into ONE card, gathering every tag.
    const byId = new Map();
    list.forEach((im) => {
      const key = im.id || im.name;
      let g = byId.get(key);
      if (!g) { g = { id: im.id, name: im.name, size: im.size, created_ts: im.created_ts, in_use: false, managed: false, tags: [] }; byId.set(key, g); }
      ((im.tags && im.tags.length) ? im.tags : [im.name]).forEach((t) => { if (t && !g.tags.includes(t)) g.tags.push(t); });
      g.in_use = g.in_use || !!im.in_use;
      g.managed = g.managed || !!im.managed;
      if (!g.size && im.size) g.size = im.size;
    });
    const groups = Array.from(byId.values());
    const gMatch = (g, q) => String(g.id || '').toLowerCase().includes(q) || g.tags.some((t) => String(t).toLowerCase().includes(q));

    // One image → one card. Title row: image id + in-use chip on the left, the
    // ⋯ menu (download / tag / delete) on the right. Then a tags line ("标签：" +
    // every tag as a chip, shown short, clamped to one line), then a size (left) /
    // created (right) meta line. When the chips overflow the line, wireCards
    // reveals a … and a hover popup listing the full tag set.
    const card = (g, i) => {
      const status = g.in_use
        ? `<span class="chip on"><span class="dot-s on"></span>${tr('dk.img_inuse')}</span>`
        : `<span class="chip">${tr('dk.img_idle')}</span>`;
      // Each tag as a chip, shown short (drop docker.io/library/).
      const chipsHtml = g.tags.map((t) => `<span class="imgtag">${esc(dockerShortRef(t))}</span>`).join('');
      return `<div class="imgcard" data-gi="${i}">
        <div class="imgcard-top">
          <div class="imgcard-title"><span class="imgcard-id" title="${esc(g.id)}">${esc(g.id)}</span>${status}</div>
          <button class="imgcard-menu" aria-label="${esc(tr('dk.col_actions'))}" title="${esc(tr('dk.col_actions'))}">⋯</button>
        </div>
        <div class="imgcard-tagline"><span class="imgcard-taglbl">${tr('dk.img_tags_label')}</span><span class="imgcard-tagchips">${chipsHtml}</span><span class="imgcard-tagmore" aria-hidden="true">…</span></div>
        <div class="imgcard-meta"><span>${esc(g.size)}</span><span>${esc(fmtDateTime(g.created_ts))}</span></div>
      </div>`;
    };

    // Delete removes the whole image = every tag (the last untag drops the image).
    const delImage = (g) => {
      if (g.managed) { toast(tr('dk.img_builtin_block'), 'err'); return; }
      if (g.in_use) { toast(tr('dk.img_in_use_block'), 'err'); return; }
      confirmDanger(tr('dk.confirm_rm_img', { name: g.tags.map(dockerShortRef).join(', ') })).then(async (ok) => {
        if (!ok) return;
        try { for (const t of g.tags) await op('docker', { op: 'remove_image', ref: t }); toast(tr('common.deleted'), 'ok'); }
        catch (e) { toast(e.message, 'err'); }
        dkImages(info);
      });
    };

    const wireCards = (shown) => {
      document.querySelectorAll('#dkIList .imgcard').forEach((cardEl) => {
        const g = shown[Number(cardEl.dataset.gi)];
        if (!g) return;
        const menu = cardEl.querySelector('.imgcard-menu');
        if (menu) mkHoverPanel(menu, [
          { label: tr('dk.img_download'), fn: () => dkImageDownload(g.name) },
          { label: tr('dk.tag_btn'), fn: () => dkTagForm(g.name, g.tags, info) },
          { sep: true },
          { label: tr('dk.delete'), cls: 'danger', fn: () => delImage(g) },
        ]);
        // Reveal the … and enable the full-tags hover popup only when the chips
        // actually overflow the one-line row (scrollWidth > clientWidth).
        const chipsEl = cardEl.querySelector('.imgcard-tagchips');
        const lineEl = cardEl.querySelector('.imgcard-tagline');
        if (chipsEl && lineEl && chipsEl.scrollWidth > chipsEl.clientWidth + 0.5) {
          lineEl.classList.add('truncated');
          const full = g.tags.map((t) => `<span class="imgtag">${esc(dockerShortRef(t))}</span>`).join('');
          lineEl.addEventListener('mouseenter', () => showImgTagPop(lineEl, full));
          lineEl.addEventListener('mouseleave', hideImgTagPop);
        }
      });
    };

    const render = () => {
      const q = (search.value || '').trim().toLowerCase();
      const shown = q ? groups.filter((g) => gMatch(g, q)) : groups;
      if (!shown.length) {
        $('dkIList').innerHTML = `<div class="empty">${esc(tr('dk.img_no_match'))}<div style="margin-top:10px"><button class="btn sec sm" id="dkImgClr">${tr('log.clear_filters')}</button></div></div>`;
        $('dkImgClr').onclick = () => { search.value = ''; render(); search.focus(); };
        return;
      }
      $('dkIList').innerHTML = `<div class="imgcards">${shown.map(card).join('')}</div>`;
      wireCards(shown);
    };
    search.oninput = render;
    render();
  }).catch((e) => { $('dkIList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// Body-anchored popup showing an image's full tag set (as chips) — revealed when
// a card's one-line tags row is truncated and hovered. One reused element,
// positioned below the row (flips above near the viewport bottom), mirroring the
// table cell tooltip (dkTipBox). Display-only, so it hides on the row's mouseleave.
function imgTagPop() {
  let p = $('imgTagPop');
  if (!p) { p = el('div', { id: 'imgTagPop', class: 'imgtag-pop' }); document.body.appendChild(p); }
  return p;
}
function showImgTagPop(anchor, html) {
  const p = imgTagPop(); p.innerHTML = html; p.style.display = 'flex';
  const r = anchor.getBoundingClientRect();
  const pw = p.offsetWidth, ph = p.offsetHeight;
  let left = Math.min(r.left, window.innerWidth - pw - 8); if (left < 8) left = 8;
  let top = r.bottom + 6; if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 6);
  p.style.left = left + 'px'; p.style.top = top + 'px';
}
function hideImgTagPop() { const p = $('imgTagPop'); if (p) p.style.display = 'none'; }

// Manage an image's tags: the box is pre-filled with the current tags as
// removable chips; add new ones with Enter, remove existing ones with ×. On
// save the backend reconciles the desired set (adds new tags, untags removed).
function dkTagForm(name, existing, info) {
  const orig = (existing || []).filter(Boolean);
  const chips = orig.slice();
  modal(tr('dk.tag_title') + dockerShortRef(name), `
    <label class="lbl">${tr('dk.tag_manage')}</label>
    <div class="taginput" id="tgBox"><input id="tgInput" placeholder="${tr('dk.tag_ph')}" /></div>
    <p class="formnote" style="margin-top:6px">${tr('dk.tag_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="tgGo" disabled>${tr('ng.save')}</button></div>
  `, (close, root) => {
    const box = $('tgBox'), input = $('tgInput'), go = $('tgGo'), mb = root.querySelector('.modal-b');
    const changed = () => { const a = chips.slice().sort(), b = orig.slice().sort(); return a.length !== b.length || a.some((x, i) => x !== b[i]); };
    const render = () => {
      box.querySelectorAll('.tagchip').forEach((e) => e.remove());
      chips.forEach((t, i) => {
        const c = el('span', { class: 'tagchip' });
        // Display short (drop registry-1.docker.io/library/); the chip's value
        // stays the full ref in `chips`, so the retag reconcile is unaffected.
        c.innerHTML = `<span title="${esc(t)}">${esc(dockerShortRef(t))}</span><button type="button">×</button>`;
        c.querySelector('button').onclick = () => { chips.splice(i, 1); render(); };
        box.insertBefore(c, input);
      });
      go.disabled = !changed();
      // Chips aren't form controls, so flag dirtiness by hand — modal() then
      // guards backdrop/X/Escape dismissal behind a discard confirm.
      mb.dataset.dirty = changed() ? '1' : '0';
      syncDirtyCount();
    };
    const add = () => { const v = input.value.trim(); if (v && !chips.includes(v)) { chips.push(v); input.value = ''; render(); } };
    input.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); }
      else if (e.key === 'Backspace' && !input.value && chips.length) { chips.pop(); render(); }
    };
    input.onblur = add;
    box.onclick = () => input.focus();
    render();
    go.onclick = () => {
      add();
      if (!chips.length) return toast(tr('dk.tag_empty'), 'err');
      op('docker', { op: 'retag_image', ref: name, tags: chips.slice() }).then(() => { toast(tr('dk.tag_done'), 'ok'); close(); dkImages(info); }).catch((e) => toast(e.message, 'err'));
    };
  });
}

// Trigger an image export (`docker save`) download via a one-time ticket.
function dkImageDownload(name) {
  ticket('download').then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&kind=image&ref=${encodeURIComponent(name)}`;
    const a = el('a', { href: '/api/docker/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}

// Import a local image archive (the output of `docker save`, optionally gzipped)
// by uploading it straight into the daemon's load API.
function dkImportForm(info) {
  let xhr = null; // in-flight upload; aborted if the modal is dismissed
  modal(tr('dk.img_import'), `
    <label class="lbl">${tr('dk.img_import_label')}</label>
    <label class="filedrop" id="iiDrop">
      <input id="iiFile" type="file" accept=".tar,.tar.gz,.tgz,.gz" />
      <span class="fd-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M5 20h14"/></svg></span>
      <span class="fd-main"><b id="iiName">${tr('dk.img_choose_file')}</b><span class="fd-sub">${tr('dk.img_import_formats')}</span></span>
    </label>
    <p class="formnote" style="margin-top:8px">${tr('dk.img_import_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="iiGo" disabled>${tr('dk.img_import_btn')}</button></div>
    <div class="hidden" id="iiJob" style="margin-top:12px"></div>`, (close, root) => {
    $('iiFile').onchange = () => {
      const f = $('iiFile').files[0];
      $('iiName').textContent = f ? f.name : tr('dk.img_choose_file');
      $('iiDrop').classList.toggle('has', !!f);
    };
    $('iiGo').onclick = () => {
      const f = $('iiFile').files[0]; if (!f) return toast(tr('dk.img_need_file'), 'err');
      $('iiGo').disabled = true; $('iiFile').disabled = true;
      $('iiJob').classList.remove('hidden');
      $('iiJob').innerHTML = `<div class="prog" id="iiBar"><i style="width:0%"></i></div><div class="job-line" id="iiLine">${tr('dk.img_uploading', { pct: 0 })}</div>`;
      const bar = $('iiBar'), barI = bar.querySelector('i');
      const fail = (msg) => {
        toast(msg, 'err');
        if (root.isConnected) { $('iiGo').disabled = false; $('iiFile').disabled = false; $('iiJob').classList.add('hidden'); $('iiJob').innerHTML = ''; }
      };
      xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/docker/image-upload');
      const headers = authHeaders();
      Object.keys(headers).forEach((k) => xhr.setRequestHeader(k, headers[k]));
      // Big archive uploads can take minutes — count them busy so a tab close /
      // reload mid-transfer gets the browser's are-you-sure prompt.
      Busy.inc();
      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable || !root.isConnected) return;
        const pct = Math.round((e.loaded / e.total) * 100);
        if (pct >= 100) { barI.style.width = ''; bar.classList.add('indet'); $('iiLine').textContent = tr('dk.img_importing'); }
        else { barI.style.width = pct + '%'; $('iiLine').textContent = tr('dk.img_uploading', { pct }); }
      };
      xhr.onerror = () => { Busy.dec(); xhr = null; fail(tr('dk.img_upload_failed')); };
      xhr.onabort = () => { Busy.dec(); xhr = null; };
      xhr.onload = () => {
        Busy.dec();
        const req = xhr; xhr = null;
        let b = {}; try { b = JSON.parse(req.responseText || '{}'); } catch (e) { b = {}; }
        if (req.status < 200 || req.status >= 300 || (b && b.ok === false)) return fail(srvMsg(b) || tr('common.request_failed', { status: req.status }));
        const d = (b && b.data) || {};
        // Docker `load` semantics: an identical image is a no-op; a same-tag but
        // different image takes over the tag — tell the user which happened.
        if (d.status === 'identical') toast(tr('dk.img_import_identical', { name: d.reference || '' }), 'ok');
        else if (d.status === 'replaced') toast(tr('dk.img_import_replaced', { name: d.reference || '', prev: fmtBytes(d.prev_size || 0), size: fmtBytes(d.size || 0) }), 'ok');
        else toast(tr('dk.img_imported'), 'ok');
        close();
        // The import can finish after the user has left the Docker tab — only
        // refresh the list if it's still mounted (else dkImages throws on a null
        // dkBody and trips the global crash banner despite a successful import).
        if ($('dkBody') && UI.tab === 'docker') dkImages(info);
      };
      xhr.send(f);
    };
    bindDirty('iiGo', root.querySelector('.modal-b'));
  }, { onDismiss: () => { if (xhr) xhr.abort(); } });
}

function dkPullForm() {
  modal(tr('dk.pull_image'), `
    <label class="lbl">${tr('dk.img_name_label')}</label>
    <div class="row" style="gap:8px;margin-bottom:12px"><input id="plImg" class="field" placeholder="alpine:latest" style="flex:1" /></div>
    <div class="row" style="justify-content:flex-end"><button class="btn" id="plGo">${tr('dk.pull_start')}</button></div>
    <div class="hidden" id="plJob" style="margin-top:14px"></div>`, (close) => {
    $('plGo').onclick = () => {
      const image = $('plImg').value.trim(); if (!image) return toast(tr('dk.need_image_name'), 'err');
      $('plGo').disabled = true; $('plJob').classList.remove('hidden');
      op('docker', { op: 'pull_image', image }).then((r) => renderJob($('plJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.pull_done'), 'ok'); close(); if (UI.tab === 'docker') renderDocker($('view')); }, onError: () => { $('plGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('plGo').disabled = false; });
    };
    bindDirty('plGo');
  });
}

// Pull tasks: a live history of every image pull (running + finished) read from
// the detached-op registry. Records persist for the session so the user can
// review progress and outcomes after a pull modal is closed.
function dkPullTasks() {
  modal(tr('dk.pull_tasks'), `
    <div class="row" style="align-items:center;margin-bottom:12px"><span class="formnote" style="margin:0">${tr('dk.pull_tasks_d')}</span><span class="sp" style="flex:1"></span><button class="btn sm" id="ptNew">${tr('dk.pull_image')}</button></div>
    <div id="ptList">${loading()}</div>`, (close, root) => {
    $('ptNew').onclick = () => { close(); dkPullForm(); };
    let stop = false;
    const num = (id) => parseInt(String(id).replace(/\D/g, ''), 10) || 0;
    const line = (s) => (s && s.charCodeAt(0) === 0x1e) ? '' : (s || '');
    const render = (ops) => {
      const pulls = (ops || []).filter((o) => o.kind === 'pull').sort((a, b) => num(a.op_id) - num(b.op_id));
      if (!pulls.length) { $('ptList').innerHTML = `<div class="empty">${tr('dk.pull_tasks_none')}</div>`; return; }
      $('ptList').innerHTML = pulls.map((o) => {
        const name = esc(o.result_image || o.target || '');
        let st, body = '';
        if (o.status === 'running') {
          st = `<span class="chip on"><span class="dot-s on"></span>${tr('dk.pt_running')}</span>`;
          body = o.pct >= 0
            ? `<div class="bar" style="margin-top:8px"><i style="width:${o.pct}%"></i></div>`
            : (line(o.last_line) ? `<div class="formnote pt-line">${esc(line(o.last_line))}</div>` : '');
        } else if (o.status === 'done') {
          st = `<span class="chip" style="color:var(--ok);border-color:var(--ok)">${tr('dk.pt_done')}</span>`;
        } else {
          st = `<span class="chip" style="color:var(--err);border-color:var(--err)">${tr('dk.pt_error')}</span>`;
          if (o.error) body = `<div class="formnote pt-line" style="color:var(--err)">${esc(codeMsg(o.error))}</div>`;
        }
        const x = o.status === 'running' ? '' : `<button class="pt-x" data-x="${esc(o.op_id)}" title="${tr('dk.delete')}">×</button>`;
        return `<div class="pt-row"><div class="pt-top"><b class="mono">${name}</b>${st}<span class="sp" style="flex:1"></span>${x}</div>${body}</div>`;
      }).join('');
      document.querySelectorAll('#ptList [data-x]').forEach((b) => b.onclick = () => op('docker', { op: 'dismiss_op', op_id: b.dataset.x }).then(tick).catch(() => {}));
    };
    const tick = () => {
      if (stop || !document.body.contains(root)) { stop = true; return; }
      op('docker', { op: 'list_ops' }).then((d) => {
        if (stop || !document.body.contains(root)) return;
        render(d.ops || []);
        const anyRun = (d.ops || []).some((o) => o.kind === 'pull' && o.status === 'running');
        setTimeout(tick, anyRun ? 1200 : 4000);
      }).catch(() => { if (!stop) setTimeout(tick, 4000); });
    };
    tick();
  });
}

// ---- Volumes tab ----
function dkVolumes() {
  const body = $('dkBody');
  if (!body) return; // tab left before an async refresh landed — nothing to render into
  body.innerHTML = `<div class="sechead"><span class="sp"></span><button class="btn sm" id="dkVolNew">${tr('dk.vol_new')}</button><button class="btn sec sm" id="dkRefV">${tr('dk.refresh')}</button></div><div id="dkVList">${loading()}</div>`;
  $('dkRefV').onclick = dkVolumes;
  $('dkVolNew').onclick = () => modal(tr('dk.vol_new'), `
    <label class="lbl">${tr('dk.vol_name')}</label>
    <input id="dvName" class="field" placeholder="myapp-data" />
    <label class="lbl" style="margin-top:14px">${tr('dk.vol_path')}${tr('dk.optional')}</label>
    <input id="dvPath" class="field mono" placeholder="/data/myvol" />
    <p class="formnote">${tr('dk.vol_path_d')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="dvGo" disabled>${tr('dk.create')}</button></div>`, (close) => {
    attachPathSuggest($('dvPath'));
    $('dvGo').onclick = () => {
      const name = $('dvName').value.trim(); if (!name) return toast(tr('dk.vol_need_name'), 'err');
      const path = $('dvPath').value.trim() || undefined;
      op('docker', { op: 'create_volume', name, path }).then(() => { close(); toast(tr('common.created'), 'ok'); dkVolumes(); }).catch((e) => toast(e.message, 'err'));
    };
    bindDirty('dvGo', 'dvName');
  });
  op('docker', { op: 'list_volumes' }).then((d) => {
    const list = d.volumes || [];
    if (!list.length) { $('dkVList').innerHTML = `<div class="empty">${tr('dk.no_volumes')}</div>`; return; }
    let h = `<table class="optable frztbl voltbl">`
      + `<colgroup><col style="width:240px"><col style="width:420px"><col style="width:180px"><col style="width:160px"></colgroup>`
      + `<tr><th>${tr('dk.vol_name')}</th><th>${tr('dk.vol_mount')}</th><th>${tr('dk.col_created')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
    list.forEach((v) => {
      const fileBtn = `<button class="btn sm sec" data-files="${esc(v.name)}" data-mp="${esc(v.mountpoint || '')}">${tr('dk.files')}</button>`;
      const builtin = v.managed ? ` <span class="chip">${tr('dk.builtin')}</span>` : '';
      const delBtn = v.managed
        ? `<button class="btn sm danger" data-rmbuiltin="1">${tr('dk.delete')}</button>`
        : `<button class="btn sm danger" data-rm="${esc(v.name)}">${tr('dk.delete')}</button>`;
      h += `<tr><td data-tip="${esc(v.name)}"><div class="clamp2"><b>${esc(v.name)}</b>${builtin}</div></td>`
        + `<td data-tip="${esc(v.mountpoint || '')}"><div class="clamp2 mono mut" style="font-size:11px">${esc(v.mountpoint || '-')}</div></td>`
        + `<td class="mut">${esc(fmtDateTime(v.created))}</td>`
        + `<td class="act"><div class="actions">${fileBtn}${delBtn}</div></td></tr>`;
    });
    $('dkVList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
    document.querySelectorAll('#dkVList [data-files]').forEach((b) => b.onclick = () => { const mp = b.dataset.mp; if (!mp) return toast(tr('dk.vol_no_mount'), 'err'); openFileBrowser(tr('dk.vol_files') + b.dataset.files, null, mp, mp); });
    document.querySelectorAll('#dkVList [data-rmbuiltin]').forEach((b) => b.onclick = () => toast(tr('dk.vol_builtin_block'), 'err'));
    document.querySelectorAll('#dkVList [data-rm]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.confirm_rm_vol', { name: b.dataset.rm }))) op('docker', { op: 'remove_volume', ref: b.dataset.rm }).then(() => { toast(tr('common.deleted'), 'ok'); dkVolumes(); }).catch((e) => toast(e.message, 'err')); });
    wireStickyShadows($('dkVList').querySelector('.tablewrap'));
    wireCellTips($('dkVList'));
  }).catch((e) => { $('dkVList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}
