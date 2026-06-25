// Docker: container manage (edit/upgrade/rename/commit/monitor/backups) (split from docker.js).
// ---- Edit (recreate with new config) ----
function dkEditForm(id, name) {
  Promise.all([
    op('docker', { op: 'info' }).catch(() => ({})),
    op('docker', { op: 'list_networks' }).catch(() => ({ networks: [] })),
    op('docker', { op: 'list_volumes' }).catch(() => ({ volumes: [] })),
    op('docker', { op: 'get_container_config', ref: id }),
  ]).then(([info, nd, vd, cd]) => {
    dkCreateModal(info || {}, (nd && nd.networks) || [], {
      volumes: (vd && vd.volumes) || [],
      prefill: cd.config || {}, replaceName: name,
      title: tr('dk.edit') + ' · ' + name, submitLabel: tr('dk.save'),
      confirmMsg: tr('dk.edit_confirm'), doneMsg: tr('dk.edited'),
    });
  }).catch((e) => toast(e.message, 'err'));
}

// ---- Upgrade (recreate keeping config, only the image changes) ----
function dkUpgradeForm(id, name) {
  op('docker', { op: 'get_container_config', ref: id }).then((d) => {
    const cfg = d.config || {};
    modal(tr('dk.upgrade') + ' · ' + name, `
      <p class="mut" style="margin:0 0 12px">${tr('dk.upgrade_cur')}: <span class="mono">${esc(cfg.image || '')}</span></p>
      <label class="lbl">${tr('dk.upgrade_target')}</label>
      <select id="ugImg" class="field" data-selx-search style="margin-bottom:6px"></select>
      <p class="formnote">${tr('dk.upgrade_hint')}</p>
      <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="ugGo">${tr('dk.upgrade')}</button></div>
      <div class="hidden" id="ugJob" style="margin-top:12px"></div>`, (close) => {
      op('docker', { op: 'list_images' }).then((im) => {
        const names = (im.images || []).map((x) => x.name).filter((n) => n && n !== '<none>:<none>');
        $('ugImg').innerHTML = `<option value="">${tr('dk.upgrade_pick')}</option>` + names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
      }).catch(() => {});
      $('ugGo').onclick = () => {
        const target = $('ugImg').value.trim();
        if (!target) return toast(tr('dk.need_image'), 'err');
        confirmDanger(tr('dk.upgrade_confirm')).then((ok) => {
          if (!ok) return;
          const body = Object.assign({}, cfg, { op: 'create_container', image: target, name, replace: name, start: true });
          $('ugGo').disabled = true; $('ugJob').classList.remove('hidden');
          op('docker', body).then((r) => renderJob($('ugJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.upgraded'), 'ok'); close(); switchTab('docker'); }, onError: () => { $('ugGo').disabled = false; } })).catch((e) => { toast(e.message, 'err'); $('ugGo').disabled = false; });
        });
      };
      bindDirty('ugGo');
    });
  }).catch((e) => toast(e.message, 'err'));
}

// ---- Rename ----
function dkRenameForm(id, name, reload) {
  modal(tr('dk.rename') + ' · ' + name, `<label class="lbl">${tr('dk.new_name')}</label><input id="rnName" class="field" value="${esc(name)}" style="margin-bottom:16px" /><div class="row" style="justify-content:flex-end"><button class="btn" id="rnGo">${tr('dk.rename')}</button></div>`, (close) => {
    $('rnGo').onclick = () => { const nn = $('rnName').value.trim(); if (!nn) return; op('docker', { op: 'rename_container', ref: id, new_name: nn }).then(() => { close(); toast(tr('dk.renamed'), 'ok'); reload && reload(); }).catch((e) => toast(e.message, 'err')); };
    bindDirty('rnGo');
  });
}

// ---- Commit container to image ----
function dkCommitForm(id, name) {
  modal(tr('dk.commit') + ' · ' + name, `
    <div class="formgrid">
      <div><label class="lbl">${tr('dk.commit_repo')}</label><input id="cmRepo" class="field" placeholder="my-image" value="${esc(name)}" /></div>
      <div><label class="lbl">${tr('dk.commit_tag')}</label><input id="cmTag" class="field" placeholder="latest" value="latest" /></div>
    </div>
    <p class="formnote" style="margin-top:8px">${tr('dk.commit_hint')}</p>
    <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="cmGo">${tr('dk.commit')}</button></div>`, (close) => {
    $('cmGo').onclick = () => {
      const repo = $('cmRepo').value.trim(); if (!repo) return toast(tr('dk.need_image_name'), 'err');
      op('docker', { op: 'commit_container', ref: id, repo, tag: $('cmTag').value.trim() || 'latest' }).then((r) => { close(); toast(tr('dk.committed', { image: r.image || '' }), 'ok'); }).catch((e) => toast(e.message, 'err'));
    };
  });
}

// ---- Monitor (live CPU / memory / network / block IO) ----
function dkMonitor(id, name) {
  modal(tr('dk.monitor') + ' · ' + name, `<div id="monBody">${loading()}</div>`, (close, root) => {
    let stop = false;
    const renderMon = (s) => {
      const cpu = s.cpu_pct || 0;
      const memPct = s.mem_limit > 0 ? (s.mem_used / s.mem_limit * 100) : 0;
      const upIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6 11l6-6 6 6"/><path d="M5 21h14"/></svg>';
      const dnIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v12"/><path d="M6 13l6 6 6-6"/><path d="M5 3h14"/></svg>';
      $('monBody').innerHTML = `
        <div class="mongrid">
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_cpu')}</div>
            <div class="mon-big">${cpu.toFixed(1)}<span class="mon-unit">%</span></div>
            <div class="mon-sub">${tr('dk.mon_cores', { n: s.cpu_online || 1 })}</div>
            <div class="mon-bar ${cpu > 85 ? 'warn' : ''}"><i style="width:${Math.min(100, cpu).toFixed(1)}%"></i></div>
          </div>
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_mem')}</div>
            <div class="mon-big">${dkHuman(s.mem_used)}<span class="mon-pct">${memPct.toFixed(1)}%</span></div>
            <div class="mon-sub">/ ${dkHuman(s.mem_limit)}</div>
            <div class="mon-bar ${memPct > 85 ? 'warn' : ''}"><i style="width:${Math.min(100, memPct).toFixed(1)}%"></i></div>
          </div>
          <div class="moncard netcard">
            <div class="mon-k">${tr('dk.mon_net')}</div>
            <div class="netsplit" style="margin-top:8px">
              <div class="netcell dn"><div class="nethdr"><span class="netic">${dnIcon}</span><span>${tr('dk.mon_rx')}</span></div><div class="netval">${dkHuman(s.net_rx)}</div></div>
              <div class="netcell up"><div class="nethdr"><span class="netic">${upIcon}</span><span>${tr('dk.mon_tx')}</span></div><div class="netval">${dkHuman(s.net_tx)}</div></div>
            </div>
          </div>
          <div class="moncard">
            <div class="mon-k">${tr('dk.mon_blk')}</div>
            <div class="mon-duo">
              <div><div class="mon-io-k">${tr('dk.mon_read')}</div><div class="mon-io-v">${dkHuman(s.blk_read)}</div></div>
              <div><div class="mon-io-k">${tr('dk.mon_write')}</div><div class="mon-io-v">${dkHuman(s.blk_write)}</div></div>
            </div>
          </div>
        </div>
        <p class="formnote" style="margin-top:14px">${tr('dk.mon_hint')}</p>`;
    };
    const tick = () => {
      if (stop || !document.body.contains(root)) { stop = true; return; }
      op('docker', { op: 'container_stats', ref: id }).then(renderMon).catch((e) => { if ($('monBody')) $('monBody').innerHTML = `<p class="err">${esc(e.message)}</p>`; })
        .finally(() => { if (!stop && document.body.contains(root)) setTimeout(tick, 2000); });
    };
    tick();
  });
}

// ---- Backups (commit + save to tar.gz; history, download, restore) ----
function dkBackups(id, name) {
  modal(tr('dk.backup') + ' · ' + name, `
    <div class="sechead" style="margin-top:0"><h3>${tr('dk.bk_history')}</h3><span class="sp"></span><button class="btn sm" id="bkNew">${tr('dk.bk_create')}</button></div>
    <div class="hidden" id="bkJob" style="margin:0 0 12px"></div>
    <div id="bkList">${loading()}</div>`, (close, root) => {
    const load = () => op('docker', { op: 'list_backups', name }).then((d) => {
      const list = d.backups || [];
      if (!list.length) { $('bkList').innerHTML = `<div class="empty">${tr('dk.bk_none')}</div>`; return; }
      let h = `<table class="optable"><tr><th>${tr('dk.bk_file')}</th><th>${tr('dk.col_size')}</th><th>${tr('dk.bk_time')}</th><th class="act">${tr('dk.col_actions')}</th></tr>`;
      list.forEach((b) => { h += `<tr><td class="mono" style="font-size:12px">${esc(b.file)}</td><td>${dkHuman(b.size)}</td><td class="mut">${dkFmtTime(b.created)}</td><td class="act"><div class="actions"><button class="btn sm sec" data-dl="${esc(b.file)}">${tr('dk.bk_download')}</button><button class="btn sm" data-rs="${esc(b.file)}">${tr('dk.bk_restore')}</button><button class="btn sm danger" data-del="${esc(b.file)}">${tr('dk.delete')}</button></div></td></tr>`; });
      $('bkList').innerHTML = '<div class="tablewrap">' + h + '</table></div>';
      document.querySelectorAll('#bkList [data-dl]').forEach((b) => b.onclick = () => dkBackupDownload(name, b.dataset.dl));
      document.querySelectorAll('#bkList [data-del]').forEach((b) => b.onclick = async () => { if (await confirmDanger(tr('dk.bk_confirm_del', { file: b.dataset.del }))) op('docker', { op: 'delete_backup', name, backup: b.dataset.del }).then(() => { toast(tr('common.deleted'), 'ok'); load(); }).catch((e) => toast(e.message, 'err')); });
      document.querySelectorAll('#bkList [data-rs]').forEach((b) => b.onclick = async () => { if (!await confirmDanger(tr('dk.bk_confirm_restore'))) return; $('bkJob').classList.remove('hidden'); op('docker', { op: 'restore_backup', name, backup: b.dataset.rs }).then((r) => renderJob($('bkJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.bk_restored'), 'ok'); switchTab('docker'); } })).catch((e) => toast(e.message, 'err')); });
    }).catch((e) => { $('bkList').innerHTML = `<p class="err">${esc(e.message)}</p>`; });
    $('bkNew').onclick = () => { $('bkJob').classList.remove('hidden'); op('docker', { op: 'backup_container', ref: id, name }).then((r) => renderJob($('bkJob'), 'docker', r.op_id, '', { onDone: () => { toast(tr('dk.bk_done'), 'ok'); load(); } })).catch((e) => toast(e.message, 'err')); };
    load();
  }, true);
}
function dkBackupDownload(name, file) {
  ticket('download').then((t) => {
    const qs = `ticket=${encodeURIComponent(t)}&kind=backup&name=${encodeURIComponent(name)}&backup=${encodeURIComponent(file)}`;
    const a = el('a', { href: '/api/docker/download?' + qs }); document.body.appendChild(a); a.click(); a.remove();
  }).catch((e) => toast(e.message, 'err'));
}

// Populate the create-form image dropdown with all local images (built-in ones
// included). Pre-selects `preselect` when given.
function loadImageOptions(preselect) {
  const sel = $('ccImg'); if (!sel) return;
  op('docker', { op: 'list_images' }).then((d) => {
    const names = (d.images || []).map((im) => im.name).filter((n) => n && n !== '<none>:<none>');
    if (!names.length) { sel.innerHTML = `<option value="">${tr('dk.no_images_pull')}</option>`; return; }
    sel.innerHTML = names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    if (preselect && names.includes(preselect)) sel.value = preselect;
  }).catch(() => {});
}

// Append a dynamic key/value row to list `id`. `cells` is an array of either
// { ph, val, grow } (an input) or { sep } (a literal separator). `opts` adds a
// proto select (ports) or a readonly checkbox (volumes).
function kvRow(id, cells, opts) {
  opts = opts || {};
  const wrap = $(id);
  const row = el('div', { class: 'kvrow' });
  cells.forEach((c) => {
    if (c.sep != null) { row.appendChild(el('span', { class: 'sep' }, c.sep)); return; }
    const i = el('input', { class: 'field' + (c.grow ? ' grow' : ''), placeholder: c.ph || '' });
    if (c.flex) i.style.flex = c.flex;
    else if (c.grow) i.style.flex = '1';
    if (c.val != null) i.value = c.val;
    row.appendChild(i);
  });
  if (opts.proto) {
    const sel = el('select', { class: 'field', style: 'flex:0 0 78px' });
    sel.innerHTML = '<option value="tcp">TCP</option><option value="udp">UDP</option>';
    if (opts.protoVal === 'udp') sel.value = 'udp';
    sel._proto = true;
    row.appendChild(sel);
  }
  if (opts.ipv6) {
    const lab = el('label', { class: 'tgl', title: tr('dk.ipv6_hint') });
    lab.innerHTML = '<input type="checkbox" /><span class="tglbox"></span><span class="tgltxt">IPv6</span>';
    const cb = lab.querySelector('input'); cb._ipv6 = true;
    if (opts.ipv6Val) cb.checked = true;
    row.appendChild(lab);
  }
  if (opts.ro) {
    const lab = el('label', { class: 'tgl' });
    lab.innerHTML = `<input type="checkbox" /><span class="tglbox"></span><span class="tgltxt">${tr('dk.readonly')}</span>`;
    lab.querySelector('input')._ro = true;
    row.appendChild(lab);
  }
  const rm = el('button', { class: 'rm', type: 'button' }, '×');
  rm.onclick = () => row.remove();
  row.appendChild(rm);
  wrap.appendChild(row);
}
// Read a dynamic kv list back: array of [v0, v1, ...] with .proto / .ro extras.
function readKv(id) {
  return Array.from($(id).querySelectorAll('.kvrow')).map((row) => {
    const vals = Array.from(row.querySelectorAll('input[type="text"], input:not([type])')).map((i) => i.value.trim());
    const out = vals;
    const proto = row.querySelector('select');
    if (proto && proto._proto) out.proto = proto.value;
    row.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
      if (cb._ro) out.ro = cb.checked;
      if (cb._ipv6) out.ipv6 = cb.checked;
    });
    return out;
  });
}
