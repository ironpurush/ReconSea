// ═══════════════════════════════════════════════════
// ReconSea — Scan Page JavaScript
// Live SSE progress + results rendering
// ═══════════════════════════════════════════════════

const SCAN_ID = window.location.pathname.split('/').pop();

const state = {
  subdomains: [], live_hosts: [], paths: [],
  parameters: [], technologies: [], js_files: [],
  secret_findings: [], startTime: Date.now(),
  scanComplete: false,
};

// ── Duration timer ───────────────────────────────
let durationTimer;
function startTimer() {
  durationTimer = setInterval(() => {
    const el = document.getElementById('scanDuration');
    if (el) el.textContent = fmtDuration((Date.now() - state.startTime) / 1000);
  }, 1000);
}
function stopTimer() { clearInterval(durationTimer); }

// ── Progress ring ────────────────────────────────
function setProgress(pct) {
  const circle = document.getElementById('progressCircle');
  const label = document.getElementById('progressPct');
  if (circle) circle.style.strokeDashoffset = 213.6 - (pct / 100) * 213.6;
  if (label) label.textContent = `${Math.round(pct)}%`;
}

// ── Module status ────────────────────────────────
function setModuleStatus(module, status) {
  const card = document.getElementById(`mstat-${module}`);
  if (!card) return;
  card.className = `module-status-card ${status}`;
  const badge = card.querySelector('.mstat-badge');
  if (badge) badge.textContent = status;
}

// ── Activity log ─────────────────────────────────
function addLog(message, type = 'info', timestamp = null) {
  const log = document.getElementById('activityLog');
  if (!log) return;

  // Remove initial placeholder
  const ph = log.querySelector('.log-entry');
  if (ph && ph.querySelector('.log-msg')?.textContent === 'Waiting for scan...') ph.remove();

  const now = timestamp ? new Date(timestamp) : new Date();
  const t = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const entry = document.createElement('div');
  entry.className = `log-entry log-${type}`;
  entry.innerHTML = `<span class="log-time">${t}</span><span class="log-msg">${escapeHtml(message)}</span>`;
  log.appendChild(entry);

  // Cap at 300 entries
  const entries = log.querySelectorAll('.log-entry');
  if (entries.length > 300) entries[0].remove();

  log.scrollTop = log.scrollHeight;
}

document.getElementById('clearLogBtn')?.addEventListener('click', () => {
  const log = document.getElementById('activityLog');
  if (log) log.innerHTML = '';
});

// ── Tabs ─────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const tab = document.getElementById(`tab-${btn.dataset.tab}`);
    if (tab) tab.classList.add('active');
  });
});

// ── KPI update ───────────────────────────────────
function updateKPI(id, value) {
  const el = document.getElementById(`kpi-${id}-val`);
  if (!el) return;
  if (value === null || value === undefined) { el.textContent = '—'; return; }
  el.textContent = value;
  const card = el.closest('.kpi-card');
  if (card) {
    card.classList.add('updated');
    setTimeout(() => card.classList.remove('updated'), 400);
    if (value > 0 && id === 'secrets') card.classList.add('has-data');
  }
}

function updateTabCount(tab, count) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.dataset.tab === tab) {
      let badge = btn.querySelector('.tab-count');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'tab-count';
        btn.appendChild(badge);
      }
      badge.textContent = count;
    }
  });
}

// ── Table renderers ──────────────────────────────
function renderSubdomains(data) {
  if (!data?.length) return;
  state.subdomains = data;
  updateKPI('subdomains', data.length);
  updateTabCount('subdomains', data.length);
  const tbody = document.getElementById('tbody-subdomains');
  if (!tbody) return;
  tbody.innerHTML = data.slice(0, 500).map(sd => `
    <tr>
      <td class="url-cell">${escapeHtml(sd.host)}</td>
      <td style="font-family:monospace;font-size:11px">${escapeHtml(sd.ip || '—')}</td>
      <td><span class="tag-chip">${escapeHtml(sd.source)}</span></td>
      <td>${sd.is_live === true ? '🟢' : sd.is_live === false ? '🔴' : '⚪'}</td>
    </tr>`).join('');
  setupTableSearch('search-subdomains', 'tbody-subdomains');
}

function renderLiveHosts(data) {
  if (!data?.length) return;
  state.live_hosts = data;
  updateKPI('live', data.length);
  updateTabCount('live_hosts', data.length);
  const tbody = document.getElementById('tbody-live_hosts');
  if (!tbody) return;
  tbody.innerHTML = data.slice(0, 200).map(lh => {
    const techs = (lh.technologies || []).slice(0, 4).map(t => `<span class="tag-chip">${escapeHtml(t)}</span>`).join('');
    return `<tr>
      <td class="url-cell"><a href="${escapeHtml(lh.url)}" target="_blank" rel="noopener">${escapeHtml(lh.url)}</a></td>
      <td>${scBadge(lh.status_code)}</td>
      <td>${escapeHtml(truncate(lh.title || '—', 52))}</td>
      <td style="font-family:monospace;font-size:11px">${escapeHtml(lh.server || '—')}</td>
      <td>${techs || '—'}</td>
    </tr>`;
  }).join('');
  setupTableSearch('search-live_hosts', 'tbody-live_hosts');
}

function renderPaths(data) {
  if (!data?.length) return;
  state.paths = data;
  updateKPI('paths', data.length);
  updateTabCount('paths', data.length);
  const tbody = document.getElementById('tbody-paths');
  if (!tbody) return;
  tbody.innerHTML = data.slice(0, 300).map(p => `
    <tr data-interesting="${p.interesting}">
      <td class="url-cell"><a href="${escapeHtml(p.url)}" target="_blank" rel="noopener">${p.interesting ? '⭐ ' : ''}${escapeHtml(p.path)}</a></td>
      <td>${scBadge(p.status_code)}</td>
      <td style="font-family:monospace;font-size:11px">${p.content_length || 0}</td>
      <td>${p.interesting ? severityBadge(p.severity) : '—'}</td>
    </tr>`).join('');
  setupTableSearch('search-paths', 'tbody-paths');
  document.getElementById('filter-interesting')?.addEventListener('change', function () {
    document.querySelectorAll('#tbody-paths tr:not(.empty-row)').forEach(row => {
      row.style.display = (!this.checked || row.dataset.interesting === 'True' || row.dataset.interesting === 'true') ? '' : 'none';
    });
  });
}

function renderParameters(data) {
  if (!data?.length) return;
  state.parameters = data;
  updateKPI('params', data.length);
  updateTabCount('parameters', data.length);
  const tbody = document.getElementById('tbody-parameters');
  if (!tbody) return;
  tbody.innerHTML = data.slice(0, 200).map(pu => `
    <tr>
      <td class="url-cell"><a href="${escapeHtml(pu.url)}" target="_blank" rel="noopener">${escapeHtml(truncate(pu.url, 65))}</a></td>
      <td style="font-family:monospace;font-size:11px">${escapeHtml((pu.parameters || []).slice(0, 8).join(', '))}</td>
      <td>${(pu.tags || []).map(t => tagChip(t)).join('') || '—'}</td>
    </tr>`).join('');
  setupTableSearch('search-parameters', 'tbody-parameters');
}

function renderTechnologies(data) {
  if (!data?.length) return;
  state.technologies = data;
  updateKPI('tech', data.length);
  updateTabCount('tech', data.length);
  const tbody = document.getElementById('tbody-tech');
  if (!tbody) return;
  const seen = new Set();
  const deduped = data.filter(t => {
    const k = `${t.host}:${t.name}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
  tbody.innerHTML = deduped.slice(0, 200).map(t => `
    <tr>
      <td style="font-family:monospace;font-size:11px">${escapeHtml(t.host)}</td>
      <td><strong>${escapeHtml(t.name)}</strong></td>
      <td><span class="tag-chip">${escapeHtml(t.category)}</span></td>
      <td>${confBadge(t.confidence)}</td>
    </tr>`).join('');
  setupTableSearch('search-tech', 'tbody-tech');
}

function renderJSIntelligence(jsFiles, secrets) {
  if (jsFiles?.length) {
    state.js_files = jsFiles;
    updateKPI('js', jsFiles.length);
    const countEl = document.getElementById('js-files-count');
    if (countEl) countEl.textContent = jsFiles.length;
    const tbody = document.getElementById('tbody-js-files');
    if (tbody) {
      tbody.innerHTML = jsFiles.slice(0, 100).map(jf => `
        <tr>
          <td class="url-cell"><a href="${escapeHtml(jf.url)}" target="_blank" rel="noopener">${escapeHtml(truncate(jf.url, 65))}</a></td>
          <td style="font-family:monospace;font-size:11px">${escapeHtml(jf.host)}</td>
          <td>${jf.size ? `${(jf.size / 1024).toFixed(1)} KB` : '—'}</td>
        </tr>`).join('');
    }
  }

  if (secrets?.length) {
    state.secret_findings = secrets;
    updateKPI('secrets', secrets.length);
    const countEl = document.getElementById('secrets-count');
    if (countEl) countEl.textContent = secrets.length;
    const tbody = document.getElementById('tbody-secrets');
    if (tbody) {
      tbody.innerHTML = secrets.slice(0, 100).map(sf => `
        <tr>
          <td class="url-cell"><a href="${escapeHtml(sf.url)}" target="_blank" rel="noopener">${escapeHtml(truncate(sf.url, 50))}</a></td>
          <td>${escapeHtml(sf.pattern)}</td>
          <td>${severityBadge(sf.severity)}</td>
          <td style="font-family:monospace;font-size:11px;word-break:break-all;max-width:240px;color:var(--dim)">${escapeHtml(sf.evidence || '—')}</td>
        </tr>`).join('');
    }
  }
}

// ── Overview / quick wins ────────────────────────
function updateOverview() {
  const prog = document.getElementById('overviewProgress');
  if (prog) {
    prog.innerHTML = [
      `Subdomains: <strong>${state.subdomains.length}</strong>`,
      `Live Hosts: <strong>${state.live_hosts.length}</strong>`,
      `Paths Found: <strong>${state.paths.length}</strong>`,
      `Parameters: <strong>${state.parameters.length}</strong>`,
      `Technologies: <strong>${state.technologies.length}</strong>`,
      `JS Files: <strong>${state.js_files.length}</strong>`,
      `Potential Findings: <strong>${state.secret_findings.length}</strong>`,
    ].map(s => `<p style="font-size:13px;color:var(--dim);line-height:1.9">${s}</p>`).join('');
  }

  const wins = document.getElementById('overviewQuickWins');
  if (!wins) return;
  const items = [];

  const adminPaths = state.paths.filter(p =>
    p.interesting && p.status_code >= 200 && p.status_code < 400 &&
    ['/admin', '/wp-admin', '/dashboard', '/panel', '/phpmyadmin'].some(a => p.path.includes(a))
  );
  if (adminPaths.length) items.push({ icon: '🚪', text: `${adminPaths.length} admin/login panel(s) found`, sev: 'high' });

  const highSecrets = state.secret_findings.filter(s => ['high', 'critical'].includes(s.severity));
  if (highSecrets.length) items.push({ icon: '🔑', text: `${highSecrets.length} high-severity JS finding(s)`, sev: 'critical' });

  const sensitiveFiles = state.paths.filter(p =>
    p.interesting && ['.env', 'config', 'backup', '.git', '.sql'].some(k => p.path.includes(k))
  );
  if (sensitiveFiles.length) items.push({ icon: '⚙️', text: `${sensitiveFiles.length} sensitive file(s) detected`, sev: 'high' });

  const idorCandidates = state.parameters.filter(p => (p.tags || []).includes('idor-candidate'));
  if (idorCandidates.length) items.push({ icon: '🎯', text: `${idorCandidates.length} IDOR candidate URL(s)`, sev: 'medium' });

  const redirectCandidates = state.parameters.filter(p => (p.tags || []).includes('open-redirect-candidate'));
  if (redirectCandidates.length) items.push({ icon: '↗️', text: `${redirectCandidates.length} open redirect candidate(s)`, sev: 'medium' });

  if (!items.length) {
    wins.innerHTML = `<p style="font-size:13px;color:var(--muted)">${state.scanComplete ? 'No obvious quick wins. Review full results.' : 'Will appear as scan progresses...'}</p>`;
    return;
  }

  wins.innerHTML = items.map(item => `
    <div class="quick-win">
      <span>${item.icon}</span>
      <span class="quick-win-text">${escapeHtml(item.text)}</span>
      ${severityBadge(item.sev)}
    </div>`).join('');
}

// ── Load results from API ────────────────────────
async function loadAllResults() {
  try {
    const res = await fetch(`/api/scan/${SCAN_ID}/results`);
    if (!res.ok) return;
    const data = await res.json();
    renderSubdomains(data.subdomains);
    renderLiveHosts(data.live_hosts);
    renderPaths(data.paths);
    renderParameters(data.parameters);
    renderTechnologies(data.technologies);
    renderJSIntelligence(data.js_files, data.secret_findings);
    updateOverview();
  } catch (e) {}
}

// ── Scan complete ────────────────────────────────
function onScanComplete(stats, message) {
  state.scanComplete = true;
  stopTimer();
  setProgress(100);

  const pill = document.getElementById('scanStatusPill');
  if (pill) {
    pill.className = 'scan-status-pill complete';
    const txt = document.getElementById('scanStatusText');
    if (txt) txt.textContent = 'Scan Complete';
  }
  document.getElementById('stopScanBtn').style.display = 'none';

  addLog('✓ Scan complete. Reports generated.', 'success');
  loadAllResults();

  const banner = document.getElementById('scanCompleteBanner');
  if (banner) {
    banner.style.display = '';
    const summary = stats
      ? `${stats.subdomains || 0} subdomains · ${stats.live_hosts || 0} live · ${stats.secret_findings || 0} findings`
      : (message || 'Scan finished');
    const s = document.getElementById('completeSummary');
    if (s) s.textContent = summary;
    const hl = document.getElementById('reportHtmlLink');
    const jl = document.getElementById('reportJsonLink');
    const cl = document.getElementById('reportCsvLink');
    if (hl) hl.href = `/api/report/${SCAN_ID}/html`;
    if (jl) jl.href = `/api/report/${SCAN_ID}/json`;
    if (cl) cl.href = `/api/report/${SCAN_ID}/csv`;
  }
  toast('Scan complete! Reports are ready.', 'success', 6000);
}

// ── SSE stream ───────────────────────────────────
function connectStream() {
  const es = new EventSource(`/api/scan/${SCAN_ID}/progress`);

  es.onopen = () => {
    addLog('Connected to scan stream', 'success');
    state.startTime = Date.now();
    startTimer();
    document.getElementById('stopScanBtn').style.display = '';
  };

  es.onmessage = e => {
    let event;
    try { event = JSON.parse(e.data); } catch { return; }
    const { event_type, module, message, data, progress_pct, timestamp } = event;

    if (event_type === 'heartbeat') return;
    if (progress_pct !== undefined) setProgress(progress_pct);

    switch (event_type) {
      case 'module_start':
        setModuleStatus(module, 'running');
        addLog(`▶ ${message}`, 'module', timestamp);
        break;
      case 'module_complete':
        setModuleStatus(module, 'complete');
        addLog(`✓ ${message}`, 'success', timestamp);
        break;
      case 'module_error':
        setModuleStatus(module, 'error');
        addLog(`✗ ${message}`, 'error', timestamp);
        break;
      case 'log':
        addLog(message, 'info', timestamp);
        break;
      case 'finding':
        addLog(`◆ ${message}`, 'finding', timestamp);
        loadAllResults();
        break;
      case 'scan_complete':
        es.close();
        onScanComplete(data, message);
        break;
    }
  };

  es.onerror = () => {
    if (!state.scanComplete) {
      es.close();
      addLog('Stream disconnected. Loading saved results...', 'warning');
      loadAllResults();
    }
  };
}

// ── Stop scan ────────────────────────────────────
document.getElementById('stopScanBtn')?.addEventListener('click', async () => {
  if (!confirm('Stop this scan? Partial results will be saved.')) return;
  try {
    await fetch(`/api/scan/${SCAN_ID}/stop`, { method: 'POST' });
    toast('Stop signal sent', 'info');
  } catch (e) { toast('Failed to send stop signal', 'error'); }
});

// ── Init ─────────────────────────────────────────
async function init() {
  document.getElementById('scanIdDisplay').textContent = SCAN_ID;
  document.getElementById('scanStarted').textContent = fmtDate(new Date().toISOString());

  try {
    const res = await fetch(`/api/scan/${SCAN_ID}/status`);
    if (res.ok) {
      const s = await res.json();
      document.getElementById('scanTarget').textContent = s.target || SCAN_ID;

      if (['completed', 'failed', 'stopped'].includes(s.status)) {
        setProgress(100);
        await loadAllResults();
        onScanComplete(null, `Scan ${s.status}`);
        return;
      }
    }
  } catch (e) {}

  connectStream();

  // Fetch target name after brief delay
  setTimeout(async () => {
    try {
      const res = await fetch(`/api/scan/${SCAN_ID}/status`);
      if (res.ok) {
        const s = await res.json();
        if (s.target) document.getElementById('scanTarget').textContent = s.target;
      }
    } catch (e) {}
  }, 1200);
}

init();
