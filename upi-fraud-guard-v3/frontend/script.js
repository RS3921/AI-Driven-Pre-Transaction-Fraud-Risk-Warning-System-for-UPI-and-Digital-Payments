const $ = id => document.getElementById(id);
let currentRole = null;

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = sessionStorage.getItem('upiFraudGuardToken');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await window.fetch(url, { ...options, headers });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try { detail = (await response.clone().json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return response;
}

function applyRole(role) {
  currentRole = role;
  const analyst = role === 'super_admin' || role === 'fraud_analyst';
  const admin = role === 'super_admin';
  for (const id of ['trigger-collection-btn','train-candidate-btn','addThreatBtn']) {
    const button = $(id);
    if (button) button.hidden = !analyst;
  }
  document.querySelectorAll('[data-admin-action]').forEach(node => { node.hidden = !admin; });
  document.querySelectorAll('[data-analyst-action]').forEach(node => { node.hidden = !analyst; });
  $('session-role').textContent = role ? `Connected: ${role}` : 'Authentication required';
}

async function loadSession() {
  try {
    const session = await (await apiFetch('/session')).json();
    applyRole(session.role);
  } catch (error) {
    applyRole(null);
    $('session-role').textContent = error.message;
  }
}

const tokenInput = $('api-token');
if (tokenInput) tokenInput.value = sessionStorage.getItem('upiFraudGuardToken') || '';
$('save-api-token')?.addEventListener('click', async () => {
  const token = tokenInput.value.trim();
  if (token) sessionStorage.setItem('upiFraudGuardToken', token);
  else sessionStorage.removeItem('upiFraudGuardToken');
  await loadSession();
  if (currentRole) {
    loadAnalytics();
    if ($('cti').classList.contains('active')) loadCTIDashboard();
  }
});

const riskClass = verdict => verdict === 'High Risk' || verdict === 'Verified Malicious' ? 'danger' : verdict === 'Suspicious' || verdict === 'Reported Unverified' ? 'warning' : 'safe';

let currentRange = { type: 'preset', days: 7 };

document.querySelectorAll('.nav').forEach(button => {
  button.addEventListener('click', () => showTab(button.dataset.tab));
});

function showTab(id) {
  document.querySelectorAll('.tab, .nav').forEach(element => element.classList.remove('active'));
  const page = $(id);
  if (!page) return;
  page.classList.add('active');
  document.querySelectorAll(`.nav[data-tab="${id}"]`).forEach(nav => nav.classList.add('active'));

  if (id === 'overview') loadAnalytics();
  if (id === 'auie') loadAUIEDashboard();
  if (id === 'cti') loadCTIDashboard();
  if (id === 'feeds') loadFeeds();
  if (id === 'mule') loadMuleGraph();
  if (id === 'investigations') loadInvestigations();
  if (id === 'models') loadModelMonitoring();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function fmtBucketLabel(label, bucket) {
  if (bucket === 'hour') { const d = new Date(label + ':00:00Z'); return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  const d = new Date(label + 'T00:00:00Z'); return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function smoothPath(pts) {
  if (pts.length < 2) return '';
  if (pts.length === 2) return `M${pts[0][0]},${pts[0][1]} L${pts[1][0]},${pts[1][1]}`;
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

function chart(target, series, bucket) {
  bucket = bucket || 'day';
  if (!series.length) { target.innerHTML = '<div class="chart-empty">No checks in this window yet.</div>'; return; }
  const W = 100, H = 100, padTop = 6, padBottom = 18, plotH = H - padTop - padBottom;
  const rawMax = Math.max(1, ...series.map(x => Math.max(x.flagged, x.clear)));
  const niceMax = Math.ceil(rawMax / 4) * 4 || 4;
  const yAt = v => padTop + plotH - ((v / niceMax) * plotH);
  const yLabels = [4, 3, 2, 1, 0].map(i => Math.round(niceMax * i / 4));
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(v => `<line x1="0" x2="${W}" y1="${padTop + plotH - (v * plotH)}" y2="${padTop + plotH - (v * plotH)}" stroke="#2A1418" stroke-width="0.6" vector-effect="non-scaling-stroke"/>`).join('');
  const dot = (cxPct, cyPct, label, text, cls) => `<div class="chart-dot${cls ? ' ' + cls : ''}" style="left:${cxPct}%;top:${cyPct}%" title="${label} — ${text}"></div>`;

  const data = series;
  const xAt = i => i * (W / Math.max(data.length - 1, 1));
  const flaggedPts = data.map((x, i) => [xAt(i), yAt(x.flagged)]);
  const clearPts = data.map((x, i) => [xAt(i), yAt(x.clear)]);
  const flaggedCurve = smoothPath(flaggedPts);
  const clearCurve = smoothPath(clearPts);
  const areaD = `${flaggedCurve} L${flaggedPts[flaggedPts.length - 1][0]},${H - padBottom} L${flaggedPts[0][0]},${H - padBottom} Z`;
  const flaggedDots = data.map((x, i) => dot(xAt(i), yAt(x.flagged), fmtBucketLabel(x.label, bucket), `${x.flagged} flagged`, i === data.length - 1 ? 'last' : '')).join('');
  const clearDots = data.map((x, i) => dot(xAt(i), yAt(x.clear), fmtBucketLabel(x.label, bucket), `${x.clear} clear`, 'green' + (i === data.length - 1 ? ' last' : ''))).join('');

  target.innerHTML = `<div class="chart-yaxis">${yLabels.map(l => `<span>${l}</span>`).join('')}</div><div class="chart-body"><div class="chart-plot"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${gridLines}<defs><linearGradient id="fill" x1="0" x2="0" y1="0" y2="1"><stop stop-color="#FF3B5C" stop-opacity=".38"/><stop offset="1" stop-color="#FF3B5C" stop-opacity="0"/></linearGradient></defs><path d="${areaD}" fill="url(#fill)"/><path class="chart-line green" d="${clearCurve}" vector-effect="non-scaling-stroke"/><path class="chart-line" d="${flaggedCurve}" vector-effect="non-scaling-stroke"/></svg>${clearDots}${flaggedDots}</div></div>`;
}

function setDistribution(counts, total) {
  const safe = counts.Safe || 0, sus = counts.Suspicious || 0, high = counts['High Risk'] || 0;
  const p1 = total ? safe / total * 100 : 0, p2 = total ? sus / total * 100 : 0;
  $('donut').style.background = `conic-gradient(#34D399 0 ${p1}%,#FBBF24 ${p1}% ${p1 + p2}%,#F43F5E ${p1 + p2}% 100%)`;
  $('donut-total').textContent = total;
  $('legend').innerHTML = [['Safe', safe, 'green'], ['Suspicious', sus, 'orange'], ['High Risk', high, 'red']].map(x => `<p><i class="${x[2]}"></i>${x[0]} <b>${x[1]}</b></p>`).join('');
}

async function loadAnalytics() {
  try {
    const d = await (await apiFetch('/analytics?days=7')).json();
    $('metric-total').textContent = d.total;
    $('metric-flagged').textContent = (d.counts['Suspicious'] || 0) + (d.counts['High Risk'] || 0);
    $('metric-clear').textContent = d.counts['Safe'] || 0;
    $('metric-alerts').textContent = d.counts['High Risk'];
    $('donut-total').textContent = d.total;
    chart($('pulse-chart'), d.series, d.bucket);
    setDistribution(d.counts, d.total);
  } catch (err) { console.error('Analytics load error:', err); }
}

// --- AUTONOMOUS INTELLIGENCE CENTRE (PHASE 6) ---
async function loadCTIDashboard() {
  await Promise.all([
    loadCTIStatus(),
    loadCTISources(),
    loadCTIIndicators(),
    loadCTIPatterns(),
    loadCTIModels(),
    loadCTILogs(),
  ]);
}

async function loadCTIStatus() {
  try {
    const status = await (await apiFetch('/api/intelligence/status')).json();
    $('cti-total-indicators').textContent = status.total_indicators;
    $('cti-verified-count').textContent = status.verified_malicious_count;
    $('cti-suspicious-count').textContent = status.suspicious_count;
    $('cti-sources-count').textContent = status.total_sources;
  } catch (err) { console.error('CTI status error:', err); }
}

async function loadCTISources() {
  try {
    const sources = await (await apiFetch('/api/intelligence/sources')).json();
    $('cti-sources-list').innerHTML = sources.length ? `
      <div class="table">
        <div class="tr th"><span>SOURCE NAME</span><span>TYPE</span><span>STATUS</span><span>FETCHED</span><span>LAST SYNC</span></div>
        ${sources.map(s => `
          <div class="tr">
            <span><b>${escapeHtml(s.name)}</b></span>
            <span>${escapeHtml(s.source_type)}</span>
            <span><b class="badge ${s.status === 'Success' ? 'safe' : 'warning'}">${escapeHtml(s.status)}</b></span>
            <span>${s.records_fetched}</span>
            <span>${s.last_sync ? new Date(s.last_sync).toLocaleString() : 'Never'}</span>
          </div>
        `).join('')}
      </div>
    ` : '<p>No sources registered.</p>';
  } catch (err) { console.error('CTI sources error:', err); }
}

async function loadCTIIndicators() {
  try {
    const typeFilter = $('ctiTypeFilter') ? $('ctiTypeFilter').value : '';
    const statusFilter = $('ctiStatusFilter') ? $('ctiStatusFilter').value : '';
    const searchQuery = $('ctiSearch') ? $('ctiSearch').value.trim() : '';

    let url = `/api/intelligence/indicators?limit=50`;
    if (typeFilter) url += `&indicator_type=${encodeURIComponent(typeFilter)}`;
    if (statusFilter) url += `&verification_status=${encodeURIComponent(statusFilter)}`;
    if (searchQuery) url += `&search=${encodeURIComponent(searchQuery)}`;

    const res = await (await apiFetch(url)).json();
    const items = res.indicators || [];

    $('cti-indicators-list').innerHTML = items.length ? `
      <div class="table">
        <div class="tr th"><span>INDICATOR VALUE</span><span>TYPE / CAT</span><span>STATUS</span><span>CONFIDENCE</span><span>SOURCE</span><span>ACTION</span></div>
        ${items.map(i => `
          <div class="tr">
            <span><b>${escapeHtml(i.indicator_value)}</b></span>
            <span>${escapeHtml(i.indicator_type.toUpperCase())} / ${escapeHtml(i.threat_category)}</span>
            <span><b class="badge ${riskClass(i.verification_status)}">${escapeHtml(i.verification_status)}</b></span>
            <span><b>${i.confidence_score}%</b></span>
            <span>${escapeHtml(i.source_name)}</span>
            <span><button class="text-btn" onclick="reviewIndicatorPrompt('${i.indicator_id}', '${escapeHtml(i.verification_status)}')">Review</button></span>
          </div>
        `).join('')}
      </div>
    ` : '<p style="padding:16px">No threat indicators match filter parameters.</p>';
  } catch (err) { console.error('CTI indicators error:', err); }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function reviewIndicatorPrompt(indicatorId, currentStatus) {
  const newStatus = prompt(`Review Indicator ${indicatorId}\nCurrent Status: ${currentStatus}\nEnter new status (Verified Malicious, Reported Unverified, Suspicious, Allowlisted, Expired):`, currentStatus);
  if (!newStatus || newStatus === currentStatus) return;
  const notes = prompt("Enter optional review notes:", "") || "";

  try {
    const res = await (await apiFetch(`/api/intelligence/indicators/${indicatorId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_status: newStatus, review_notes: notes })
    })).json();
    alert(`Status updated to '${res.new_status}'`);
    loadCTIIndicators();
    loadCTIStatus();
  } catch (err) { alert(`Review update failed: ${err.message || err}`); }
}

async function loadCTIPatterns() {
  try {
    const patterns = await (await apiFetch('/api/intelligence/fraud-patterns')).json();
    $('cti-patterns-list').innerHTML = patterns.length ? `
      <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:12px">
        ${patterns.map(p => `
          <div style="padding:12px;border:1px solid #333;border-radius:8px;background:#111">
            <h4 style="color:#34D399;margin-bottom:4px">${escapeHtml(p.pattern_name)}</h4>
            <p style="font-size:12px;color:#aaa">${escapeHtml(p.description)}</p>
            <div style="margin-top:6px"><small><b>Keywords:</b> ${escapeHtml(p.keywords.slice(0, 3).join(', '))}</small></div>
          </div>
        `).join('')}
      </div>
    ` : '<p>No scam patterns extracted.</p>';
  } catch (err) { console.error('CTI patterns error:', err); }
}

async function loadCTIModels() {
  try {
    const models = await (await apiFetch('/api/intelligence/models')).json();
    $('cti-models-list').innerHTML = models.length ? `
      <div class="table">
        <div class="tr th"><span>MODEL ID & VERSION</span><span>ALGORITHM</span><span>STATUS</span><span>PRECISION / RECALL</span><span>ACTIONS</span></div>
        ${models.map(m => `
          <div class="tr">
            <span><b>${escapeHtml(m.model_id)}</b><br><small>Ver: ${escapeHtml(m.version)} | ${new Date(m.trained_at).toLocaleDateString()}</small></span>
            <span>${escapeHtml(m.model_name)}</span>
            <span>
              <b class="badge ${m.is_active ? 'safe' : m.approval_status === 'Approved' ? 'warning' : 'danger'}">
                ${m.is_active ? 'Active Production' : m.approval_status}
              </b>
            </span>
            <span>P: ${m.metrics.precision ? Math.round(m.metrics.precision * 100) + '%' : 'N/A'} | R: ${m.metrics.recall ? Math.round(m.metrics.recall * 100) + '%' : 'N/A'} | F1: ${m.metrics.f1_score ? Math.round(m.metrics.f1_score * 100) + '%' : 'N/A'}</span>
            <span>
              ${m.approval_status === 'Pending Approval' ? `<button class="text-btn primary" onclick="approveModelAction('${escapeHtml(m.model_id)}')">Approve</button>` : ''}
              ${m.approval_status === 'Approved' && !m.is_active ? `<button class="text-btn primary" onclick="deployModelAction('${escapeHtml(m.model_id)}')">Deploy</button>` : ''}
              ${m.is_active ? `<button class="text-btn danger" onclick="rollbackModelAction('${escapeHtml(m.model_id)}')">Rollback</button>` : ''}
            </span>
          </div>
        `).join('')}
      </div>
    ` : '<p style="padding:16px">No models registered in registry. Train a candidate model to begin.</p>';
  } catch (err) { console.error('CTI models error:', err); }
}

async function approveModelAction(modelId) {
  if (!confirm(`Are you sure you want to approve candidate model '${modelId}'?`)) return;
  try {
    await apiFetch(`/api/intelligence/models/${modelId}/approve`, { method: 'POST' });
    alert(`Model '${modelId}' Approved.`);
    loadCTIModels();
  } catch (err) { alert(`Approval failed: ${err}`); }
}

async function deployModelAction(modelId) {
  if (!confirm(`WARNING: Deploying model '${modelId}' will replace the current active production model. Continue?`)) return;
  try {
    await apiFetch(`/api/intelligence/models/${modelId}/deploy`, { method: 'POST' });
    alert(`Model '${modelId}' Deployed to Production!`);
    loadCTIModels();
  } catch (err) { alert(`Deployment failed: ${err}`); }
}

async function rollbackModelAction(modelId) {
  if (!confirm(`WARNING: Rolling back model '${modelId}' will restore the previous model version. Continue?`)) return;
  try {
    await apiFetch(`/api/intelligence/models/${modelId}/rollback`, { method: 'POST' });
    alert(`Model '${modelId}' Rolled Back.`);
    loadCTIModels();
  } catch (err) { alert(`Rollback failed: ${err}`); }
}

const trainCandidateBtn = $('train-candidate-btn');
if (trainCandidateBtn) {
  trainCandidateBtn.onclick = async () => {
    const algo = prompt("Select candidate training algorithm (RandomForest, GradientBoosting, LogisticRegression):", "RandomForest");
    if (!algo) return;
    try {
      trainCandidateBtn.disabled = true;
      trainCandidateBtn.textContent = "Training Candidate...";
      const res = await (await apiFetch('/api/intelligence/models/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm: algo, dataset_version: "v1.1.0" })
      })).json();
      alert(`Candidate Model Trained Successfully: ${res.candidate.model_id}`);
      loadCTIModels();
    } catch (err) { alert(`Training failed: ${err}`); }
    finally {
      trainCandidateBtn.disabled = false;
      trainCandidateBtn.textContent = "🏋️ Train Candidate Model";
    }
  };
}

const triggerCollectionBtn = $('trigger-collection-btn');
if (triggerCollectionBtn) {
  triggerCollectionBtn.onclick = async () => {
    try {
      triggerCollectionBtn.disabled = true;
      triggerCollectionBtn.textContent = "Collecting...";
      const res = await (await apiFetch('/api/intelligence/collect', { method: 'POST' })).json();
      alert(`Manual Collection Complete: ${res.sources_processed} sources processed.`);
      loadCTIDashboard();
    } catch (err) { alert(`Collection trigger failed: ${err}`); }
    finally {
      triggerCollectionBtn.disabled = false;
      triggerCollectionBtn.textContent = "⚡ Trigger Collection Now";
    }
  };
}

const refreshCtiBtn = $('refresh-cti-btn');
if (refreshCtiBtn) refreshCtiBtn.onclick = loadCTIDashboard;

const ctiSearch = $('ctiSearch');
if (ctiSearch) ctiSearch.oninput = loadCTIIndicators;

const ctiTypeFilter = $('ctiTypeFilter');
if (ctiTypeFilter) ctiTypeFilter.onchange = loadCTIIndicators;

const ctiStatusFilter = $('ctiStatusFilter');
if (ctiStatusFilter) ctiStatusFilter.onchange = loadCTIIndicators;

async function loadCTILogs() {
  try {
    const data = await (await apiFetch('/api/intelligence/collection-logs?limit=20')).json();
    const logs = data.logs || [];
    $('cti-logs-list').innerHTML = logs.length ? `
      <div class="table">
        <div class="tr th"><span>LOG ID</span><span>SOURCE</span><span>STATUS</span><span>FETCHED / NEW</span><span>TIMESTAMP</span></div>
        ${logs.map(l => `
          <div class="tr">
            <span>#${l.log_id}</span>
            <span><b>${escapeHtml(l.source_name)}</b></span>
            <span><b class="badge ${l.status === 'Success' ? 'safe' : 'warning'}">${escapeHtml(l.status)}</b></span>
            <span>Fetched: ${l.records_fetched} | New: ${l.new_indicators} | Dup: ${l.duplicate_indicators}</span>
            <span>${new Date(l.timestamp).toLocaleString()}</span>
          </div>
        `).join('')}
      </div>
    ` : '<p style="padding:16px">No collection logs recorded yet.</p>';
  } catch (err) { console.error('CTI logs error:', err); }
}

async function loadFeeds() {
  try {
    const d = await (await apiFetch('/feed-status')).json();
    $('threat-feed-info').innerHTML = `
      <p><b>Status:</b> ${d.threat_feed.healthy ? '🟢 Healthy' : '🔴 Unhealthy'}</p>
      <p><b>Known Threat VPAs:</b> ${d.threat_feed.vpa_threats_count}</p>
      <p><b>Phishing Repository URLs:</b> ${d.threat_feed.phishing_urls_count}</p>
      <p><b>Last Synced:</b> ${new Date(d.threat_feed.last_updated).toLocaleString()}</p>
    `;
    $('txn-feed-info').innerHTML = `
      <p><b>Status:</b> ${d.transaction_feed.healthy ? '🟢 Healthy' : '🔴 Unhealthy'}</p>
      <p><b>Monitoring:</b> Transaction metadata, amount limits, velocity spikes & recipient novelty</p>
      <p><b>Last Active:</b> ${new Date(d.transaction_feed.last_updated).toLocaleString()}</p>
    `;
  } catch (err) { console.error('Feed status error:', err); }
}

const addThreatBtn = $('addThreatBtn');
if (addThreatBtn) {
  addThreatBtn.onclick = async () => {
    const vpa = $('newThreatVpa').value.trim();
    if (!vpa) return;
    try {
      const res = await (await apiFetch('/threat-intelligence/add-vpa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vpa })
      })).json();
      $('threatAddStatus').textContent = `✓ ${res.status}`;
      $('newThreatVpa').value = '';
      loadFeeds();
    } catch (err) { $('threatAddStatus').textContent = 'Error adding VPA.'; }
  };
}

async function loadMuleGraph() {
  try {
    const d = await (await apiFetch('/mule-analysis')).json();
    $('mule-stats').innerHTML = `
      <p><b>Total Transaction Nodes:</b> ${d.total_nodes} | <b>Total Graph Edges:</b> ${d.total_edges} | <b>Suspicious Mule Candidates:</b> ${d.suspicious_mule_count}</p>
    `;
    $('mule-candidates-list').innerHTML = d.mule_candidates.length ? `
      <div class="table">
        <div class="tr th"><span>VPA NODE</span><span>MULE RISK</span><span>FAN-IN / FAN-OUT</span><span>REASONS</span></div>
        ${d.mule_candidates.map(x => `<div class="tr"><span><b>${escapeHtml(x.vpa)}</b></span><span><b class="badge danger">${Math.round(x.mule_risk_score * 100)}%</b></span><span>In: ${x.in_degree} | Out: ${x.out_degree}</span><span>${escapeHtml(x.reasons.join(' · '))}</span></div>`).join('')}
      </div>
    ` : '<p style="padding:12px">No suspicious mule account nodes detected in current graph.</p>';
  } catch (err) { console.error('Mule graph error:', err); }
}

async function loadInvestigations() {
  try {
    const rows = await (await apiFetch('/investigations')).json();
    $('cases-list').innerHTML = rows.length ? `
      <div class="table">
        <div class="tr th"><span>CASE ID</span><span>VERDICT / SCORE</span><span>STATUS</span><span>PRIORITY</span><span>RECIPIENT</span></div>
        ${rows.map(x => `<div class="tr"><span><b>${escapeHtml(x.case_id)}</b></span><span><b class="badge ${riskClass(x.verdict)}">${escapeHtml(x.verdict)} (${Math.round(x.risk_score * 100)}%)</b></span><span>${escapeHtml(x.status)}</span><span>${escapeHtml(x.priority)}</span><span>${escapeHtml(x.recipient || 'N/A')}</span></div>`).join('')}
      </div>
    ` : '<p style="padding:16px">No open investigation cases. Cases are automatically registered when suspicious or high-risk checks occur.</p>';
  } catch (err) { console.error('Investigations error:', err); }
}

const refreshCases = $('refresh-cases');
if (refreshCases) refreshCases.onclick = loadInvestigations;

async function loadModelMonitoring() {
  try {
    const d = await (await apiFetch('/model-monitoring')).json();
    const drift = d.drift_analysis;
    $('drift-details').innerHTML = `
      <p><b>Status:</b> ${escapeHtml(drift.drift_status)}</p>
      <p><b>Recent Mean Risk:</b> ${drift.recent_mean_risk} | <b>Baseline Mean Risk:</b> ${drift.baseline_mean_risk} (Diff: ${drift.mean_difference})</p>
    `;

    const metrics = d.performance.metrics;
    let html = '<div class="table"><div class="tr th"><span>MODEL</span><span>TEST PRECISION</span><span>TEST RECALL</span><span>F1-SCORE</span><span>ROC-AUC</span></div>';
    for (const [key, val] of Object.entries(metrics)) {
      if (val) {
        html += `<div class="tr"><span><b>${key.toUpperCase()}</b><br><small>${escapeHtml(val.model || 'Trained Ensemble')}</small></span><span>${val.precision !== undefined ? Math.round(val.precision * 100) + '%' : 'N/A'}</span><span>${val.recall !== undefined ? Math.round(val.recall * 100) + '%' : 'N/A'}</span><span>${val.f1_score !== undefined ? Math.round(val.f1_score * 100) + '%' : 'N/A'}</span><span>${val.roc_auc !== undefined ? Math.round(val.roc_auc * 100) + '%' : 'N/A'}</span></div>`;
      }
    }
    html += '</div>';
    $('model-metrics-container').innerHTML = html;
  } catch (err) { console.error('Model monitoring error:', err); }
}

// AUIE DASHBOARD FUNCTIONS
async function loadAUIEDashboard() {
  try {
    const trusted = await (await apiFetch('/api/auie/trusted-domains')).json();
    const health = await (await apiFetch('/api/auie/health')).json();
    let feedback = [];
    try { feedback = await (await apiFetch('/api/auie/feedback')).json(); } catch (_) {}

    // Update AUIE Metric Counters
    $('auie-trusted-count').textContent = trusted.length;
    const activeProviders = (health.providers || []).filter(p => p.status === 'ACTIVE').length;
    $('auie-provider-count').textContent = `${activeProviders} / ${(health.providers || []).length}`;

    // Render Trusted Domains Table
    const trustedTbody = $('trusted-domains-table-body');
    if (trustedTbody) {
      trustedTbody.innerHTML = trusted.length ? trusted.map(d => `
        <tr>
          <td><b>${escapeHtml(d.domain)}</b></td>
          <td><span class="chip safe">${escapeHtml(d.category)}</span></td>
          <td>${d.allow_subdomains ? '✓ Yes' : '✗ No'}</td>
          <td>${d.requires_path_check ? '⚠️ Path Check Required' : '✓ Full Domain'}</td>
          <td>${escapeHtml(d.added_by || 'system')}</td>
          <td>
            <button class="text-btn danger" data-admin-action onclick="deleteTrustedDomain('${escapeHtml(d.domain)}')">Remove</button>
          </td>
        </tr>
      `).join('') : '<tr><td colspan="6" style="text-align:center;padding:15px">No trusted domains registered.</td></tr>';
    }

    // Render Provider & Feed Health Table
    const providerTbody = $('provider-health-table-body');
    if (providerTbody) {
      const providers = health.providers || [];
      const feeds = health.feed_health || [];
      let rowsHtml = providers.map(p => `
        <tr>
          <td><b>${escapeHtml(p.provider_name)}</b><br><small>Provider Adapter</small></td>
          <td><span class="badge ${p.status === 'ACTIVE' ? 'safe' : p.status === 'UNCONFIGURED' ? 'warning' : 'danger'}">${escapeHtml(p.status)}</span></td>
          <td>${escapeHtml(p.last_successful_lookup || 'N/A')}</td>
          <td>${p.quota_remaining !== null && p.quota_remaining !== undefined ? p.quota_remaining : 'Unlimited / N/A'}</td>
        </tr>
      `).join('');

      rowsHtml += feeds.map(f => `
        <tr>
          <td><b>${escapeHtml(f.source_name)}</b><br><small>${escapeHtml(f.source_type)}</small></td>
          <td><span class="badge ${f.status === 'Success' ? 'safe' : f.status === 'Unconfigured' ? 'warning' : 'danger'}">${escapeHtml(f.status)}</span></td>
          <td>${escapeHtml(f.last_success || f.last_attempt || 'N/A')}</td>
          <td>${f.records_ingested || f.records_fetched || 0} records</td>
        </tr>
      `).join('');

      providerTbody.innerHTML = rowsHtml || '<tr><td colspan="4" style="text-align:center;padding:15px">No providers or feeds registered.</td></tr>';
    }

    // Render False-Positive Feedback Triage Table
    const feedbackTbody = $('auie-feedback-table-body');
    if (feedbackTbody) {
      feedbackTbody.innerHTML = feedback.length ? feedback.map(fb => `
        <tr>
          <td>#${fb.feedback_id}</td>
          <td><b>${escapeHtml(fb.url_or_domain)}</b></td>
          <td><span class="badge warning">${escapeHtml(fb.reported_verdict)}</span></td>
          <td><span class="badge safe">${escapeHtml(fb.claimed_verdict)}</span></td>
          <td>${escapeHtml(fb.reporter_id)}</td>
          <td>${escapeHtml(fb.reason)}</td>
          <td><span class="badge ${fb.status === 'APPROVED' ? 'safe' : fb.status === 'REJECTED' ? 'danger' : 'warning'}">${escapeHtml(fb.status)}</span></td>
          <td>
            ${fb.status === 'PENDING_REVIEW' ? `
              <button class="text-btn primary" onclick="reviewFeedback(${fb.feedback_id}, 'APPROVED')">Approve</button>
              <button class="text-btn danger" onclick="reviewFeedback(${fb.feedback_id}, 'REJECTED')">Reject</button>
            ` : `<small>${escapeHtml(fb.reviewed_by || 'Reviewed')}</small>`}
          </td>
        </tr>
      `).join('') : '<tr><td colspan="8" style="text-align:center;padding:15px">No false-positive feedback reports pending review.</td></tr>';
    }

    applyRole(currentRole);
  } catch (err) {
    console.error('AUIE dashboard error:', err);
  }
}

// AUIE Event Listeners & Actions
const refreshAuieBtn = $('refresh-auie-btn');
if (refreshAuieBtn) refreshAuieBtn.onclick = loadAUIEDashboard;

const auieLookupBtn = $('auie-lookup-btn');
if (auieLookupBtn) {
  auieLookupBtn.onclick = async () => {
    const url = $('auie-url-input').value.trim();
    if (!url) return;
    const resContainer = $('auie-lookup-result');
    resContainer.style.display = 'block';
    resContainer.innerHTML = '<p>Analyzing URL reputation & website behavior across AUIE providers...</p>';
    try {
      const data = await (await apiFetch(`/api/auie/reputation?url=${encodeURIComponent(url)}&bypass_cache=true`)).json();
      const exp = data.explanation || {};
      const stateBadge = data.reputation_state === 'CONFIRMED_MALICIOUS' ? 'danger' : data.reputation_state === 'SUSPICIOUS' ? 'warning' : data.reputation_state === 'KNOWN_BENIGN' ? 'safe' : 'neutral';

      let html = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
          <h4 style="margin:0">Target URL: <code>${escapeHtml(data.canonical_url || data.raw_url)}</code></h4>
          <div>
            <span class="chip" style="margin-right:8px">${escapeHtml(exp.category_description || exp.url_type || 'URL')}</span>
            <span class="badge ${stateBadge}" style="font-size:1.1em;padding:6px 12px">${escapeHtml(data.reputation_state)}</span>
          </div>
        </div>

        <div class="alert-box ${stateBadge}" style="margin-bottom:12px;padding:12px;border-radius:6px;background:${stateBadge === 'danger' ? '#f8d7da' : stateBadge === 'warning' ? '#fff3cd' : stateBadge === 'safe' ? '#d1e7dd' : '#e2e3e5'};color:#000">
          <p style="margin:0 0 6px 0"><b>HUMAN-READABLE ADVISORY:</b> ${escapeHtml(exp.human_readable_explanation || 'Analysis complete.')}</p>
          <p style="margin:0"><b>RECOMMENDED ACTION:</b> ${escapeHtml(exp.recommended_action || 'Proceed with normal payment precautions.')}</p>
        </div>

        <p><b>Domain:</b> ${escapeHtml(data.domain || 'N/A')} | <b>Risk Score:</b> ${(data.risk_score * 100).toFixed(1)}% | <b>Confidence:</b> ${(data.confidence_score * 100).toFixed(0)}% | <b>Latency:</b> ${data.latency_ms} ms</p>
      `;

      if (exp.positive_indicators && exp.positive_indicators.length) {
        html += `<p style="color:#198754;margin-bottom:4px"><b>✓ Positive Security Indicators:</b></p><ul>`;
        exp.positive_indicators.forEach(i => {
          html += `<li><b>${escapeHtml(i.name)}:</b> ${escapeHtml(i.finding)} <small>(${escapeHtml(i.why_it_matters)})</small></li>`;
        });
        html += `</ul>`;
      }

      if (exp.negative_indicators && exp.negative_indicators.length) {
        html += `<p style="color:#dc3545;margin-bottom:4px"><b>⚠️ Negative Risk Indicators:</b></p><ul>`;
        exp.negative_indicators.forEach(i => {
          html += `<li><b>${escapeHtml(i.name)}:</b> ${escapeHtml(i.finding)} <small>(${escapeHtml(i.why_it_matters)})</small></li>`;
        });
        html += `</ul>`;
      }

      // Technical Details Collapsible for Fraud Analysts
      html += `
        <details style="margin-top:12px;padding:8px;background:#fff;border:1px solid #ddd;border-radius:4px">
          <summary style="cursor:pointer;font-weight:bold">🔍 Technical Details & Raw Evidence Trace (for Fraud Analysts)</summary>
          <div style="margin-top:8px;font-size:0.9em">
            <p><b>URL Classification Type:</b> ${escapeHtml(exp.url_type || 'UNKNOWN')}</p>
            <p><b>Providers Consulted:</b> ${(data.providers_consulted || []).length ? escapeHtml(data.providers_consulted.join(', ')) : 'Local Verified CTI & Allowlist Cache'}</p>
            <p><b>Redirect Trace Hops:</b> ${exp.redirect_analysis && exp.redirect_analysis.hop_count ? exp.redirect_analysis.hop_count : 0} ${exp.redirect_analysis && exp.redirect_analysis.has_shortener ? '(Link Shortener Detected)' : ''}</p>
            ${exp.unavailable_checks && exp.unavailable_checks.length ? `<p><b>Unavailable / Unconfigured Checks:</b> ${escapeHtml(exp.unavailable_checks.join(' · '))}</p>` : ''}
          </div>
        </details>
      `;

      resContainer.innerHTML = html;
    } catch (err) {
      resContainer.innerHTML = `<p style="color:red">Lookup Error: ${escapeHtml(err.message)}</p>`;
    }
  };
}
        <p><b>Domain:</b> ${escapeHtml(data.domain || 'N/A')} | <b>Risk Score:</b> ${(data.risk_score * 100).toFixed(1)}% | <b>Confidence:</b> ${(data.confidence_score * 100).toFixed(0)}% | <b>Latency:</b> ${data.latency_ms} ms</p>
        <p><b>Reasons & Attribution:</b></p>
        <ul>${(data.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
        ${data.conflicting_evidence && data.conflicting_evidence.length ? `
          <p style="color:#d9534f"><b>Conflicting Evidence / Notices:</b></p>
          <ul>${data.conflicting_evidence.map(c => `<li>${escapeHtml(c.details || JSON.stringify(c))}</li>`).join('')}</ul>
        ` : ''}
        <p><b>Providers Consulted:</b> ${(data.providers_consulted || []).length ? escapeHtml(data.providers_consulted.join(', ')) : 'Local Verified CTI & Allowlist Cache'}</p>
      `;
    } catch (err) {
      resContainer.innerHTML = `<p style="color:red">Lookup Error: ${escapeHtml(err.message)}</p>`;
    }
  };
}

const addTrustedDomainBtn = $('add-trusted-domain-btn');
if (addTrustedDomainBtn) {
  addTrustedDomainBtn.onclick = async () => {
    const domain = prompt('Enter domain to trust (e.g. merchant-portal.com):');
    if (!domain) return;
    const category = prompt('Enter category (e.g. Merchant, Bank, Payment Gateway):', 'Legitimate Merchant') || 'Legitimate Merchant';
    try {
      await apiFetch('/api/auie/trusted-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, category, allow_subdomains: true, requires_path_check: false })
      });
      alert(`Domain '${domain}' added to trusted allowlist.`);
      loadAUIEDashboard();
    } catch (err) {
      alert(`Error adding domain: ${err.message}`);
    }
  };
}

async function deleteTrustedDomain(domain) {
  if (!confirm(`Are you sure you want to remove '${domain}' from the trusted domain allowlist?`)) return;
  try {
    await apiFetch(`/api/auie/trusted-domains/${encodeURIComponent(domain)}`, { method: 'DELETE' });
    loadAUIEDashboard();
  } catch (err) {
    alert(`Error removing domain: ${err.message}`);
  }
}

async function reviewFeedback(feedbackId, action) {
  const notes = prompt(`Enter review notes for feedback #${feedbackId} (${action}):`, 'Reviewed by analyst') || '';
  try {
    await apiFetch(`/api/auie/feedback/${feedbackId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, review_notes: notes })
    });
    loadAUIEDashboard();
  } catch (err) {
    alert(`Error reviewing feedback: ${err.message}`);
  }
}

loadAnalytics();
