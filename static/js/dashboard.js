// ═══════════════════════════════════════════════════
// ReconSea — Dashboard JavaScript
// ═══════════════════════════════════════════════════

document.getElementById('startScanBtn')?.addEventListener('click', startScan);
document.getElementById('targetInput')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

async function startScan() {
  const target = document.getElementById('targetInput')?.value?.trim();
  const engagement = document.getElementById('engagementInput')?.value?.trim() || '';

  if (!target) {
    toast('Please enter a target domain', 'error');
    document.getElementById('targetInput')?.focus();
    return;
  }

  const modules = [];
  document.querySelectorAll('.module-card input[type=checkbox]:checked').forEach(cb => {
    modules.push(cb.value);
  });

  if (!modules.length) {
    toast('Select at least one recon module', 'error');
    return;
  }

  const btn = document.getElementById('startScanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>⟳</span> Starting...';

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, modules, engagement_name: engagement })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to start scan' }));
      throw new Error(err.detail || 'Failed to start scan');
    }

    const data = await res.json();
    toast(`Scan started for ${target}`, 'success');
    window.location.href = `/scan/${data.scan_id}`;
  } catch (err) {
    toast(err.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<span>▶</span> Start Recon';
  }
}

async function loadRecentScans() {
  const container = document.getElementById('recentScans');
  if (!container) return;

  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    const scans = data.scans || [];

    if (!scans.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div style="font-size:32px;margin-bottom:12px">🔍</div>
          <div style="font-size:15px;font-weight:600;color:var(--dim);margin-bottom:6px">No scans yet</div>
          <div>Start your first reconnaissance scan above</div>
        </div>`;
      return;
    }

    container.innerHTML = scans.slice(0, 6).map(scan => {
      const date = fmtRelative(scan.created_at);
      const dur = scan.duration_seconds ? fmtDuration(scan.duration_seconds) : '—';
      const eng = scan.engagement_name
        ? `<div class="recent-engagement">${escapeHtml(scan.engagement_name)}</div>` : '';
      return `
        <a href="/scan/${scan.scan_id}" class="recent-card">
          <div class="recent-card-top">
            <div>
              <div class="recent-target">${escapeHtml(scan.target)}</div>
              ${eng}
            </div>
            ${statusPill(scan.status)}
          </div>
          <div class="recent-stats">
            <span class="recent-stat"><strong>${scan.subdomains || 0}</strong> subdomains</span>
            <span class="recent-stat"><strong>${scan.live_hosts || 0}</strong> live</span>
            <span class="recent-stat"><strong>${scan.secrets || 0}</strong> findings</span>
          </div>
          <div class="recent-footer">
            <span>${date} · ${dur}</span>
            <span class="btn-micro">View →</span>
          </div>
        </a>`;
    }).join('');
  } catch (e) {
    container.innerHTML = `<div class="loading-placeholder">Failed to load recent scans</div>`;
  }
}

loadRecentScans();
