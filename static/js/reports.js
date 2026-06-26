// ═══════════════════════════════════════════════════
// ReconSea — Reports Page
// ═══════════════════════════════════════════════════

let allScans = [];

async function loadReports() {
  const container = document.getElementById('reportsList');
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    allScans = data.scans || [];
    renderReports(allScans);
  } catch (e) {
    container.innerHTML = '<div class="loading-placeholder">Failed to load reports</div>';
  }
}

function renderReports(scans) {
  const container = document.getElementById('reportsList');
  if (!scans.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div style="font-size:32px;margin-bottom:12px">📋</div>
        <div style="font-size:15px;font-weight:600;color:var(--dim);margin-bottom:6px">No reports yet</div>
        <div><a href="/">Start a scan</a> to generate your first report</div>
      </div>`;
    return;
  }

  container.innerHTML = scans.map(scan => `
    <div class="report-row">
      <div>
        <div class="report-target">
          <a href="/scan/${escapeHtml(scan.scan_id)}">${escapeHtml(scan.target)}</a>
          ${scan.engagement_name ? `<span style="font-size:12px;font-weight:400;color:var(--muted);font-family:inherit;margin-left:8px">${escapeHtml(scan.engagement_name)}</span>` : ''}
        </div>
        <div class="report-meta">
          ${escapeHtml(scan.scan_id)} &nbsp;·&nbsp; ${fmtDate(scan.created_at)}
          ${scan.duration_seconds ? `&nbsp;·&nbsp; ${fmtDuration(scan.duration_seconds)}` : ''}
          &nbsp;·&nbsp; ${statusPill(scan.status)}
        </div>
      </div>
      <div class="report-stats">
        <span class="report-stat"><strong>${scan.subdomains || 0}</strong> subdomains</span>
        <span class="report-stat"><strong>${scan.live_hosts || 0}</strong> live</span>
        <span class="report-stat"><strong>${scan.secrets || 0}</strong> findings</span>
      </div>
      <div class="report-actions">
        <a href="/api/report/${scan.scan_id}/html" class="btn-primary btn-sm" target="_blank">HTML</a>
        <a href="/api/report/${scan.scan_id}/json" class="btn-ghost btn-sm" target="_blank">JSON</a>
        <a href="/api/report/${scan.scan_id}/csv" class="btn-ghost btn-sm" target="_blank">CSV</a>
        <button class="btn-ghost btn-sm" style="color:var(--red)" onclick="deleteScan('${scan.scan_id}')">Delete</button>
      </div>
    </div>`).join('');
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan and all reports? This cannot be undone.')) return;
  try {
    const res = await fetch(`/api/scan/${scanId}`, { method: 'DELETE' });
    if (res.ok) {
      toast('Scan deleted', 'success');
      loadReports();
    } else {
      toast('Failed to delete', 'error');
    }
  } catch (e) {
    toast('Error deleting scan', 'error');
  }
}

function applyFilters() {
  const q = (document.getElementById('searchReports')?.value || '').toLowerCase();
  const status = document.getElementById('filterStatus')?.value || '';
  const filtered = allScans.filter(s =>
    (!status || s.status === status) &&
    (s.target.toLowerCase().includes(q) || (s.engagement_name || '').toLowerCase().includes(q))
  );
  renderReports(filtered);
}

document.getElementById('searchReports')?.addEventListener('input', applyFilters);
document.getElementById('filterStatus')?.addEventListener('change', applyFilters);

loadReports();
