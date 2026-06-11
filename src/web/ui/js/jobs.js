// =========================================================================
// Progress jobs — a detached panel op (install/pull/create/setup/backup) shown
// as a progress bar + status line + collapsible log. Survives leaving the page:
// the running op_id is stashed in localStorage per (kind), so re-entering the
// page re-attaches and keeps showing progress.
// =========================================================================
const JOBS_KEY = 'dn7_web_jobs';
function loadJobs() { try { return JSON.parse(localStorage.getItem(JOBS_KEY) || '{}'); } catch (e) { return {}; } }
function saveJob(slot, info) { const j = loadJobs(); if (info) j[slot] = info; else delete j[slot]; localStorage.setItem(JOBS_KEY, JSON.stringify(j)); }
function getJob(slot) { return loadJobs()[slot] || null; }

// Estimate 0..1 progress from docker pull status lines (counts layers that
// reached "Pull complete"/"Already exists" vs total seen). Returns null when it
// can't tell (→ indeterminate bar).
function parsePullPct(lines) {
  let total = 0, done = 0, sawLayer = false;
  const seen = {};
  lines.forEach((ln) => {
    // Lines look like "<status> <id>" or "<id>: <status>"; we just scan text.
    const m = ln.match(/^([0-9a-f]{6,}):?\s*(.*)$/i) || ln.match(/(Pull complete|Already exists|Downloading|Extracting|Waiting|Verifying)/i);
    if (/Pulling from|Digest:|Status:|Download complete/i.test(ln)) return;
    if (/(Downloading|Extracting|Waiting|Verifying|Pull complete|Already exists)/i.test(ln)) {
      sawLayer = true;
      // Track per-layer state by leading id when present.
      const idm = ln.match(/^([0-9a-f]{6,})/i);
      const key = idm ? idm[1] : ln;
      const complete = /(Pull complete|Already exists)/i.test(ln);
      if (!(key in seen)) { seen[key] = complete; total++; if (complete) done++; }
      else if (complete && !seen[key]) { seen[key] = true; done++; }
    }
  });
  if (!sawLayer || total === 0) return null;
  return Math.min(0.98, done / total);
}

// Render a job UI into `host` and poll it. `slot` is the persistence key
// (e.g. "docker:install"). Returns nothing; calls cb.onDone / cb.onError.
function renderJob(host, kind, opId, slot, cb) {
  cb = cb || {};
  host.innerHTML = `
    <div class="prog indet" id="jpBar"><i></i></div>
    <div class="job-line" id="jpLine">${tr('job.processing')}</div>
    <details class="job-log"><summary>${tr('job.log')}</summary><pre class="out" id="jpLog" style="margin-top:8px;max-height:30vh"></pre></details>`;
  const bar = host.querySelector('#jpBar'), line = host.querySelector('#jpLine'), log = host.querySelector('#jpLog');
  if (slot) saveJob(slot, { kind, opId });
  let stopped = false;
  const finish = (cls) => { stopped = true; bar.classList.remove('indet'); bar.classList.add(cls); if (slot) saveJob(slot, null); };
  const tick = () => {
    if (stopped) return;
    op(kind, { op: 'op_log', op_id: opId }).then((d) => {
      const lines = d.lines || [];
      log.textContent = lines.join('\n'); log.scrollTop = log.scrollHeight;
      line.textContent = lines.length ? lines[lines.length - 1] : tr('job.processing');
      // Prefer the server-computed percent; fall back to client-side parsing.
      const pct = (typeof d.pct === 'number' && d.pct >= 0) ? d.pct / 100 : parsePullPct(lines);
      if (pct != null) { bar.classList.remove('indet'); bar.querySelector('i').style.width = (pct * 100).toFixed(0) + '%'; }
      if (d.status === 'done') { finish('done'); line.textContent = tr('job.done'); op(kind, { op: 'dismiss_op', op_id: opId }).catch(() => {}); if (cb.onDone) cb.onDone(); }
      else if (d.status === 'error') { finish('err'); line.textContent = tr('job.failed') + (d.error || ''); op(kind, { op: 'dismiss_op', op_id: opId }).catch(() => {}); if (cb.onError) cb.onError(d.error); }
      else if (d.status === 'gone') { finish('err'); line.textContent = tr('job.ended'); if (slot) saveJob(slot, null); }
      else setTimeout(tick, 900);
    }).catch(() => setTimeout(tick, 1500));
  };
  tick();
}

// If a job for `slot` is still running (persisted), re-render it into `host`.
// Returns true if it re-attached. Used so leaving + returning to a page keeps
// showing progress.
function reattachJob(host, slot, cb) {
  const info = getJob(slot);
  if (!info) return false;
  renderJob(host, info.kind, info.opId, slot, cb);
  return true;
}
