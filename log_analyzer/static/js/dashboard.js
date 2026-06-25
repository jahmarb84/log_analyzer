/* dashboard.js — LogSentinel frontend logic */

// ── Element refs ────────────────────────────────────────────────────────
const dropzone     = document.getElementById('dropzone');
const fileInput    = document.getElementById('fileInput');
const analyzeBtn   = document.getElementById('analyzeBtn');
const selectedFile = document.getElementById('selectedFile');
const logTypeSelect= document.getElementById('logTypeSelect');
const loading      = document.getElementById('loading');
const results      = document.getElementById('results');
const entrySearch  = document.getElementById('entrySearch');

let allEntries = [];  // cache for filtering

// ── File drag-and-drop / click ──────────────────────────────────────────
dropzone.addEventListener('click', (e) => {
  if (!e.target.closest('button') && !e.target.closest('select')) {
    fileInput.click();
  }
});

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('drag-over');
});
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

function setFile(file) {
  selectedFile.textContent = `📄 ${file.name} (${formatBytes(file.size)})`;
  selectedFile.classList.remove('hidden');
  analyzeBtn.disabled = false;
  analyzeBtn._file = file;
}

// ── Analyze uploaded file ───────────────────────────────────────────────
analyzeBtn.addEventListener('click', () => {
  const file = analyzeBtn._file;
  if (!file) return;

  const fd = new FormData();
  fd.append('logfile', file);
  fd.append('log_type', logTypeSelect.value);

  showLoading();
  fetch('/analyze', { method: 'POST', body: fd })
    .then(r => r.json())
    .then(renderResults)
    .catch(err => { hideLoading(); alert('Error: ' + err.message); });
});

// ── Sample log buttons ──────────────────────────────────────────────────
document.querySelectorAll('.btn-sample').forEach(btn => {
  btn.addEventListener('click', () => {
    showLoading();
    fetch('/analyze_sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample: btn.dataset.sample }),
    })
      .then(r => r.json())
      .then(renderResults)
      .catch(err => { hideLoading(); alert('Error: ' + err.message); });
  });
});

// ── Render results ──────────────────────────────────────────────────────
function renderResults(data) {
  hideLoading();
  if (data.error) { alert(data.error); return; }

  allEntries = data.entries || [];

  // Summary cards
  document.getElementById('statTotal').textContent    = data.total_entries.toLocaleString();
  document.getElementById('statThreats').textContent  = data.threats.length.toLocaleString();
  document.getElementById('statCritical').textContent = data.summary.critical;
  document.getElementById('statHigh').textContent     = data.summary.high;
  document.getElementById('statMedium').textContent   = data.summary.medium;
  document.getElementById('statLow').textContent      = data.summary.low;

  const badge = document.getElementById('logTypeBadge');
  badge.textContent = data.log_type.toUpperCase();

  // Threats
  renderThreats(data.threats);

  // Top IPs
  renderTopIPs(data.summary.top_ips);

  // Status breakdown
  renderStatusBreakdown(data.summary.status_breakdown);

  // Entry table
  renderEntryTable(allEntries);

  results.classList.remove('hidden');
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Threat cards ─────────────────────────────────────────────────────────
function renderThreats(threats) {
  const container = document.getElementById('threatList');
  if (!threats.length) {
    container.innerHTML = '<p style="color:var(--c-low);text-align:center;padding:2rem;">✓ No threats detected</p>';
    return;
  }
  container.innerHTML = threats.map(t => `
    <div class="threat-card sev-${t.severity}">
      <div class="threat-header">
        <span class="threat-type">${escHtml(t.type)}</span>
        <span class="sev-pill">${t.severity}</span>
      </div>
      <div class="threat-desc">${escHtml(t.description)}</div>
      ${t.count ? `<div style="font-size:.75rem;color:var(--text-muted)">Occurrences: <strong style="color:var(--text-head)">${t.count}</strong></div>` : ''}
      <div class="threat-rec"><strong>Recommendation:</strong> ${escHtml(t.recommendation || '')}</div>
    </div>
  `).join('');
}

// ── Top IPs ───────────────────────────────────────────────────────────────
function renderTopIPs(ips) {
  const container = document.getElementById('topIPs');
  if (!ips || !ips.length) { container.innerHTML = '<p style="color:var(--text-muted)">No IP data found.</p>'; return; }
  const max = ips[0].count;
  container.innerHTML = ips.map(row => `
    <div class="ip-row">
      <span class="ip-addr">${escHtml(row.ip)}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${Math.round(row.count/max*100)}%"></div></div>
      <span class="ip-count">${row.count}</span>
    </div>
  `).join('');
}

// ── Status breakdown ──────────────────────────────────────────────────────
function renderStatusBreakdown(breakdown) {
  const container = document.getElementById('statusBreakdown');
  if (!breakdown || !Object.keys(breakdown).length) { container.innerHTML = ''; return; }
  const max = Math.max(...Object.values(breakdown));
  container.innerHTML = Object.entries(breakdown)
    .sort((a, b) => b[1] - a[1])
    .map(([code, count]) => `
      <div class="status-row">
        <span class="status-code ${statusClass(code)}">${escHtml(code)}</span>
        <div class="ip-bar-wrap"><div class="ip-bar" style="width:${Math.round(count/max*100)}%;background:${statusColor(code)}"></div></div>
        <span class="ip-count">${count}</span>
      </div>
    `).join('');
}

function statusClass(code) {
  if (code.startsWith('2')) return 's2xx';
  if (code.startsWith('3')) return 's3xx';
  if (code.startsWith('4')) return 's4xx';
  if (code.startsWith('5')) return 's5xx';
  return 'sxxx';
}
function statusColor(code) {
  if (code.startsWith('2')) return 'var(--c-low)';
  if (code.startsWith('3')) return 'var(--c-info)';
  if (code.startsWith('4')) return 'var(--c-high)';
  if (code.startsWith('5')) return 'var(--c-critical)';
  return 'var(--text-muted)';
}

// ── Entry table ───────────────────────────────────────────────────────────
function renderEntryTable(entries) {
  const tbody = document.getElementById('entryBody');
  tbody.innerHTML = entries.map(e => {
    const detail = e.path
      ? `${escHtml(e.method || '')} ${escHtml(e.path)}`
      : escHtml((e.message || e.raw || '').substring(0, 160));
    const status = e.status ? `<span class="status-chip ${statusClass(String(e.status))}">${e.status}</span>` : '';
    return `
      <tr>
        <td class="ts">${escHtml(e.timestamp || '—')}</td>
        <td class="ip">${escHtml(e.ip || '—')}</td>
        <td>${detail}</td>
        <td>${status}</td>
      </tr>`;
  }).join('');
}

// ── Live filter ───────────────────────────────────────────────────────────
entrySearch.addEventListener('input', () => {
  const q = entrySearch.value.toLowerCase();
  const filtered = allEntries.filter(e => {
    const hay = ((e.raw || '') + (e.ip || '') + (e.path || '') + (e.message || '')).toLowerCase();
    return hay.includes(q);
  });
  renderEntryTable(filtered);
});

// ── Helpers ───────────────────────────────────────────────────────────────
function showLoading() {
  loading.classList.remove('hidden');
  results.classList.add('hidden');
}
function hideLoading() {
  loading.classList.add('hidden');
}
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}
