// ═══════════════════════════════════════════════════
// ReconSea — Shared Utilities
// ═══════════════════════════════════════════════════

function toast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.3s';
    setTimeout(() => el.remove(), 300);
  }, duration);
}

function fmtDuration(seconds) {
  if (!seconds) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function fmtDate(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
      + ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  } catch (e) { return isoStr; }
}

function fmtRelative(isoStr) {
  if (!isoStr) return '—';
  try {
    const diff = Date.now() - new Date(isoStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch (e) { return ''; }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(str, len = 60) {
  if (!str) return '';
  str = String(str);
  return str.length > len ? str.slice(0, len) + '…' : str;
}

function scBadge(code) {
  const c = parseInt(code) || 0;
  let cls = '';
  if (c >= 200 && c < 300) cls = 'sc-2xx';
  else if (c >= 300 && c < 400) cls = 'sc-3xx';
  else if (c >= 400 && c < 500) cls = 'sc-4xx';
  else if (c >= 500) cls = 'sc-5xx';
  return `<span class="sc-badge ${cls}">${c || '—'}</span>`;
}

function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase();
  return `<span class="sev-badge sev-${s}">${s.toUpperCase()}</span>`;
}

function confBadge(conf) {
  const c = (conf || 'low').toLowerCase();
  return `<span class="conf-badge conf-${c}">${c.toUpperCase()}</span>`;
}

function statusPill(status) {
  const s = (status || 'unknown').toLowerCase();
  return `<span class="status-pill status-${s}">${s}</span>`;
}

function tagChip(tag) {
  const key = tag.toLowerCase().replace(/-candidate$/, '').replace(/-/g, '');
  return `<span class="tag-chip tag-${key}">${escapeHtml(tag)}</span>`;
}

function copyColumn(tableId, colIdx) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr:not(.empty-row)');
  const vals = [];
  rows.forEach(row => {
    const cell = row.querySelectorAll('td')[colIdx];
    if (cell) {
      const link = cell.querySelector('a');
      vals.push((link ? link.textContent : cell.textContent).trim());
    }
  });
  if (!vals.length) { toast('Nothing to copy', 'info'); return; }
  navigator.clipboard.writeText(vals.join('\n'))
    .then(() => toast(`Copied ${vals.length} items`, 'success'))
    .catch(() => toast('Copy failed — try manual select', 'error'));
}

function setupTableSearch(inputId, tbodyId) {
  const input = document.getElementById(inputId);
  const tbody = document.getElementById(tbodyId);
  if (!input || !tbody) return;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase();
    tbody.querySelectorAll('tr:not(.empty-row)').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// Module card toggle
document.querySelectorAll('.module-card').forEach(card => {
  card.addEventListener('click', () => {
    const cb = card.querySelector('input[type=checkbox]');
    if (!cb) return;
    cb.checked = !cb.checked;
    card.classList.toggle('selected', cb.checked);
  });
});

document.getElementById('selectAllModules')?.addEventListener('click', () => {
  document.querySelectorAll('.module-card').forEach(card => {
    const cb = card.querySelector('input');
    if (cb) { cb.checked = true; card.classList.add('selected'); }
  });
});

document.getElementById('clearModules')?.addEventListener('click', () => {
  document.querySelectorAll('.module-card').forEach(card => {
    const cb = card.querySelector('input');
    if (cb) { cb.checked = false; card.classList.remove('selected'); }
  });
});

// Theme toggle (simple — just a hook, dark is default)
document.getElementById('themeToggle')?.addEventListener('click', () => {
  toast('Dark theme is the default for ReconSea', 'info', 2000);
});
