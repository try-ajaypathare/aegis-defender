// Defender dashboard — professional SaaS design

const API_BASE = window.location.origin;
const WS_URL = (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + '/ws';

let ws = null;
let wsConnected = false;
let startTime = Date.now();
let lastMetricTs = 0;

// ============================================================
// Utilities
// ============================================================
function fmt(n, d = 1) {
    if (n === undefined || n === null || isNaN(n)) return '0.0';
    return Number(n).toFixed(d);
}
function fmtInt(n) { return n == null ? '0' : Math.round(n).toLocaleString(); }
function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}
function setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = value; }
function ic(name, cls = 'icon') {
    return `<svg class="${cls}"><use href="#i-${name}"/></svg>`;
}

// ============================================================
// Metric cards
// ============================================================
function updateMetricCards(m) {
    if (!m || Object.keys(m).length === 0) return;
    const cpu = m.cpu_percent || 0;
    const mem = m.memory_percent || 0;
    const disk = m.disk_percent || 0;
    const procs = m.process_count || 0;
    const threads = m.thread_count || 0;
    const netConn = m.network_connections || 0;
    const netSent = m.network_sent_mb || 0;
    const netRecv = m.network_recv_mb || 0;
    const score = m.anomaly_score || 0;

    setText('cpuValue', fmt(cpu));
    setText('memValue', fmt(mem));
    setText('diskValue', fmt(disk));
    setText('procValue', fmtInt(procs));
    setText('netValue', fmtInt(netConn));
    setText('aiScoreValue', fmt(score, 2));

    const bl = window._baseline || {};
    setText('cpuSub', bl.cpu != null ? `base ${fmt(bl.cpu)}% · Δ ${cpu - bl.cpu >= 0 ? '+' : ''}${fmt(cpu - bl.cpu)}` : `Δ ${fmt(m.cpu_delta)}%`);
    setText('memSub', bl.memory != null ? `base ${fmt(bl.memory)}% · ${fmt(m.memory_used_gb, 2)}/${fmt(m.memory_total_gb, 1)}GB` : `${fmt(m.memory_used_gb, 2)} / ${fmt(m.memory_total_gb, 1)} GB`);
    setText('diskSub', bl.disk != null ? `base ${fmt(bl.disk)}% · ${fmt(m.disk_free_gb, 1)}GB free` : `${fmt(m.disk_free_gb, 1)} GB free`);
    setText('procSub', bl.processes != null ? `base ${fmtInt(bl.processes)} · ${fmtInt(threads)} threads` : `${fmtInt(threads)} threads`);
    setText('netSub', bl.network_connections != null ? `base ${fmtInt(bl.network_connections)} · ↑${fmt(netSent, 2)} ↓${fmt(netRecv, 2)}MB/s` : `↑ ${fmt(netSent, 2)}  ↓ ${fmt(netRecv, 2)} MB/s`);
    setText('aiSub', score > 0 ? (m.is_anomaly ? 'anomaly detected' : 'normal') : 'not trained');

    setBar('cpuBar', cpu);
    setBar('memBar', mem);
    setBar('diskBar', disk);
    setBar('procBar', Math.min(100, procs / 5));
    setBar('netBar', Math.min(100, netConn / 3));
    setBar('aiBar', score * 100);

    setCardState('cpuCard', cpu);
    setCardState('memCard', mem);
    setCardState('diskCard', disk);
    setCardState('aiCard', score * 100, 50, 70);

    renderAIExplanation(m);
}

function setBar(id, pct) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.width = Math.min(100, Math.max(0, pct || 0)) + '%';
}

function setCardState(cardId, value, warnAt = 70, critAt = 85) {
    const el = document.getElementById(cardId);
    if (!el) return;
    el.classList.remove('warning', 'critical');
    if (value >= critAt) el.classList.add('critical');
    else if (value >= warnAt) el.classList.add('warning');
}

// ============================================================
// Uptime
// ============================================================
function updateUptime() {
    const secs = Math.floor((Date.now() - startTime) / 1000);
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    const span = document.querySelector('#uptime span');
    if (span) span.textContent = h ? `${h}h ${m}m` : `${m}m ${s}s`;
}

// ============================================================
// Events / actions / security
// ============================================================
function clearEmpty(listEl) {
    const empty = listEl.querySelector('.empty');
    if (empty) empty.remove();
}

function renderEvent(ev) {
    const list = document.getElementById('eventList');
    if (!list) return;
    clearEmpty(list);
    const li = document.createElement('li');
    const level = (ev.level || 'info').toLowerCase();
    li.className = 'event-item';
    const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    li.innerHTML = `
        <span class="event-time">${escapeHtml(ts)}</span>
        <span class="event-tag ${escapeHtml(level)}">${escapeHtml(ev.level || 'INFO')}</span>
        <span class="event-msg">${escapeHtml(ev.message || '')}</span>
    `;
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 50) list.removeChild(list.lastChild);
}

// Aegis solution counter — incremented on each successful auto-heal
let aegisSolutionsToday = 0;
let solutionsBannerTimeout = null;

// ============================================================
// LIVE DECISION FLOW — DETECT → ANALYZE → DECIDE → EXECUTE → VERIFY
// Each incident gets a card with step-by-step status as events flow in.
// ============================================================
let _currentIncidents = [];      // most recent first; max 4 kept
const MAX_INCIDENTS = 4;

function _flowIncidentKey(d) {
    // Match on source_type + source_id (or source_name)
    return `${d.source_type || 'x'}:${d.source_id || d.source_name || ''}:${d.threat_type || ''}`;
}

function _findOrCreateIncident(d) {
    const key = _flowIncidentKey(d);
    let inc = _currentIncidents.find(i => i.key === key);
    if (inc) return inc;
    inc = {
        key,
        startTs: Date.now(),
        category: d.source_type || '',
        target: d.source_name || d.source_id || '?',
        threatType: d.threat_type || '',
        severity: d.severity || '',
        decision: null,
        execute: null,
        verify: null,
        state: 'active',  // active | healed | failed
    };
    _currentIncidents.unshift(inc);
    while (_currentIncidents.length > MAX_INCIDENTS) _currentIncidents.pop();
    return inc;
}

function _renderFlowPanel() {
    const body = document.getElementById('flowBody');
    if (!body) return;
    if (_currentIncidents.length === 0) {
        body.innerHTML = `<div class="empty">${ic('shield-check', 'icon empty-icon')}<div>No active incident. Trigger an attack from the console.</div></div>`;
        document.getElementById('flowStatus').textContent = 'idle';
        return;
    }
    body.innerHTML = _currentIncidents.map(inc => _renderIncident(inc)).join('');
    document.getElementById('flowStatus').textContent = _currentIncidents.length === 1 ? '1 incident' : `${_currentIncidents.length} incidents`;
}

function _step(label, state, content) {
    const stateMap = { 'pending': '·', 'running': '⟳', 'done': '✓', 'failed': '✗' };
    return `
        <div class="flow-step ${state}">
            <div class="flow-step-icon">${stateMap[state] || '·'}</div>
            <div class="flow-step-label">${escapeHtml(label)}</div>
            <div class="flow-step-content">${content}</div>
        </div>`;
}

function _renderIncident(inc) {
    const elapsed = Math.round((Date.now() - inc.startTs) / 1000);

    // STEP 1: DETECT (always done if incident exists)
    const detect = `
        Incident detected on <code>${escapeHtml(inc.target)}</code> (${escapeHtml(inc.category)})
        <div class="flow-kvs">
            <span class="flow-kv">type=<strong>${escapeHtml(inc.threatType)}</strong></span>
            <span class="flow-kv">severity=<strong>${escapeHtml(inc.severity || '?')}</strong></span>
        </div>`;

    // STEP 2: ANALYZE (done if decision exists)
    const analyzeState = inc.decision ? 'done' : 'running';
    const analyze = inc.decision ? `
        Threat scored against <strong>rule + reputation + context</strong> factors
        <div class="flow-kvs">
            <span class="flow-kv">risk_score=<strong>${inc.decision.risk_score?.toFixed(0) || '?'}/100</strong></span>
            <span class="flow-kv">confidence=<strong>${inc.decision.confidence?.toFixed(2) || '?'}</strong></span>
            <span class="flow-kv">tier=<strong>${inc.decision.tier ?? '?'}</strong></span>
        </div>` : `Computing risk score and matching rules…`;

    // STEP 3: DECIDE
    const decideState = inc.decision ? 'done' : 'pending';
    const decide = inc.decision ? `
        <span style="color: var(--accent); font-weight: 600;">→ ${escapeHtml(inc.decision.action)}</span>
        <div class="flow-kvs">
            ${(inc.decision.reasoning || []).slice(0, 3).map(r =>
                `<span class="flow-kv">${escapeHtml(r)}</span>`
            ).join('')}
        </div>
        ${(inc.decision.rejected_alternatives && inc.decision.rejected_alternatives.length) ?
            `<div class="flow-rejected">Rejected: ${inc.decision.rejected_alternatives.slice(0, 2).map(alt =>
                `<span class="strike">${escapeHtml(alt.action)}</span>(${escapeHtml(alt.reason)})`
            ).join(' · ')}</div>` : ''}
        ` : `Awaiting decision…`;

    // STEP 4: EXECUTE
    const execState = inc.execute ? (inc.execute.success === false ? 'failed' : 'done')
                                   : (inc.decision ? 'running' : 'pending');
    const exec = inc.execute ? `
        ${escapeHtml(inc.execute.message || inc.execute.action || 'executed')}` :
        `Executing action…`;

    // STEP 5: VERIFY (HYBRID/AI only)
    const verifyState = inc.verify ? (inc.verify.outcome === 'healed' ? 'done' : 'failed') : 'pending';
    const verify = inc.verify ? `
        ${inc.verify.outcome === 'healed' ? '✓ State healed:' : '⚠ Not yet healed:'}
        <code>${escapeHtml(inc.verify.detail || '')}</code>` :
        `Pending verification…`;

    return `
        <div class="flow-incident ${inc.state}">
            <div class="flow-incident-header">
                <span style="color: var(--text);">${escapeHtml(inc.target)}</span>
                <span class="badge">${escapeHtml(inc.category)}</span>
                <span class="meta">T+${elapsed}s</span>
            </div>
            ${_step('DETECT',   'done', detect)}
            ${_step('ANALYZE',  analyzeState, analyze)}
            ${_step('DECIDE',   decideState, decide)}
            ${_step('EXECUTE',  execState, exec)}
            ${_step('VERIFY',   verifyState, verify)}
        </div>`;
}

function flowOnDecision(d) {
    const inc = _findOrCreateIncident(d);
    inc.decision = d;
    _renderFlowPanel();
}

function flowOnAction(a) {
    if (!_currentIncidents.length) return;
    const inc = _currentIncidents[0];   // attribute to most recent incident
    inc.execute = a;
    if (a.success === false) inc.state = 'failed';
    _renderFlowPanel();
}

function flowOnVerify(v) {
    if (!_currentIncidents.length) return;
    const inc = _currentIncidents[0];
    inc.verify = v;
    inc.state = (v.outcome === 'healed') ? 'healed' : 'failed';
    _renderFlowPanel();
}

function flowSetMode(mode) {
    const el = document.getElementById('flowMode');
    if (el) el.textContent = `mode: ${mode}`;
}

// Tick: update T+Xs counters + auto-prune old healed incidents
function flowTick() {
    if (!_currentIncidents.length) return;
    const now = Date.now();
    // Drop incidents healed > 60s ago
    const before = _currentIncidents.length;
    _currentIncidents = _currentIncidents.filter(inc => {
        if (inc.state === 'healed' && (now - inc.startTs) > 60000) return false;
        return true;
    });
    if (before !== _currentIncidents.length || _currentIncidents.length > 0) {
        _renderFlowPanel();
    }
}

// Map action_type → human-friendly description for the banner
const SOLUTION_LABELS = {
    restart_service:  { verb: 'Restarted',  what: 'service' },
    rotate_cert:      { verb: 'Rotated',    what: 'SSL certificate' },
    close_port:       { verb: 'Closed',     what: 'forbidden port' },
    block_ip_aegis:   { verb: 'Blocked',    what: 'attacker IP' },
    block_ip_temporary: { verb: 'Blocked',  what: 'IP (15 min)' },
    block_ip_permanent: { verb: 'Banned',   what: 'IP permanently' },
    retry_backup:     { verb: 'Retried',    what: 'failed backup' },
    sync_ntp:         { verb: 'Synchronized',what: 'NTP clock' },
    page_oncall:      { verb: 'Paged',      what: 'on-call engineer' },
    restart_uplink:   { verb: 'Restarted',  what: 'network uplink' },
    restart_dns:      { verb: 'Switched',   what: 'DNS resolver' },
    clear_hw_warning: { verb: 'Acknowledged',what: 'hardware warning' },
    throttle_cpu:     { verb: 'Throttled',  what: 'CPU' },
    throttle_network: { verb: 'Throttled',  what: 'network' },
    rate_limit_source:{ verb: 'Rate-limited',what: 'source IP' },
    sandbox_process:  { verb: 'Sandboxed',  what: 'process' },
    quarantine_files: { verb: 'Quarantined',what: 'files' },
    suspend_process:  { verb: 'Suspended',  what: 'process' },
    kill_process:     { verb: 'Terminated', what: 'process' },
    kill_and_capture: { verb: 'Terminated + dumped', what: 'process' },
    rollback_changes: { verb: 'Rolled back',what: 'file changes' },
    clear_temp:       { verb: 'Cleared',    what: 'temp files' },
    alert:            { verb: 'Alerted',    what: 'team' },
};

function showSolutionsBanner(actionType, details, target) {
    const banner = document.getElementById('solutionsBanner');
    if (!banner) return;

    const label = SOLUTION_LABELS[actionType] || { verb: actionType.replace(/_/g, ' '), what: '' };
    const message = `${label.verb} ${label.what}`.trim();

    document.getElementById('solutionsMessage').textContent = message;
    document.getElementById('solutionsMeta').textContent = details || target || actionType;

    aegisSolutionsToday++;
    document.getElementById('solutionsCountToday').textContent = aegisSolutionsToday;

    banner.style.display = 'grid';
    banner.classList.remove('fading');
    // Force reflow to restart animation
    void banner.offsetWidth;
    banner.classList.remove('fading');

    // Auto-fade after 6s
    if (solutionsBannerTimeout) clearTimeout(solutionsBannerTimeout);
    solutionsBannerTimeout = setTimeout(() => {
        banner.classList.add('fading');
        setTimeout(() => { banner.style.display = 'none'; banner.classList.remove('fading'); }, 600);
    }, 6000);
}

// De-dup tracking: only pop banner once per unique action (id or timestamp+type).
// fetchActions() polling re-renders the whole list every 5s — without this guard
// the banner would flash continuously.
const _seenActionKeys = new Set();
function _actionKey(a) {
    if (a.id !== undefined && a.id !== null) return `id:${a.id}`;
    return `${a.timestamp || ''}:${a.action_type || a.action || ''}:${a.target_id || a.target || ''}`;
}

function renderAction(a, opts = {}) {
    const list = document.getElementById('actionList');
    const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    const actionType = (a.action_type || a.action || 'ACTION').toLowerCase();
    const details = a.details || a.message || a.target || a.reason || 'executed';

    // ---- Pop the Solutions banner ONLY for new live actions (not every poll) ----
    const key = _actionKey(a);
    const isLive = opts.isLive === true;            // WS push → live
    const alreadySeen = _seenActionKeys.has(key);
    _seenActionKeys.add(key);
    // Cap the set size to avoid unbounded memory growth
    if (_seenActionKeys.size > 500) {
        const first = _seenActionKeys.values().next().value;
        _seenActionKeys.delete(first);
    }

    const trivial = ['none', 'log_only', 'noop', 'alert'];
    const success = a.success !== false;
    const shouldPop = isLive && success && !alreadySeen && !trivial.includes(actionType);
    if (shouldPop) {
        showSolutionsBanner(actionType, details, a.target || a.target_id);
        toast(`Aegis: ${(SOLUTION_LABELS[actionType]?.verb || actionType)} ${SOLUTION_LABELS[actionType]?.what || ''}`.trim(), 'success');
    }

    // ---- Append to Recent Actions list (always — shows historical too) ----
    if (!list) return;
    clearEmpty(list);
    const li = document.createElement('li');
    li.className = 'event-item';
    li.innerHTML = `
        <span class="event-time">${escapeHtml(ts)}</span>
        <span class="event-tag action">${escapeHtml(actionType.toUpperCase())}</span>
        <span class="event-msg">${escapeHtml(details)}</span>
    `;
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 30) list.removeChild(list.lastChild);
}

function renderSecurityEvent(sec) {
    const list = document.getElementById('securityList');
    if (!list) return;
    clearEmpty(list);
    let msg = '';
    if (sec.suspicious_reason) msg = `${sec.process_name || 'process'} (parent: ${sec.parent_name || '?'}) — ${sec.suspicious_reason}`;
    else if (sec.change) msg = `File ${sec.change}: ${sec.path || ''}`;
    else if (sec.type) msg = `USB ${sec.type}: ${sec.drive || ''}`;
    else if (sec.remote_address) msg = `${sec.process_name} → ${sec.remote_address}:${sec.remote_port}`;
    else msg = JSON.stringify(sec).slice(0, 120);

    const li = document.createElement('li');
    li.className = 'event-item';
    li.innerHTML = `
        <span class="event-time">${new Date().toLocaleTimeString()}</span>
        <span class="event-tag security">SEC</span>
        <span class="event-msg">${escapeHtml(msg)}</span>
    `;
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 30) list.removeChild(list.lastChild);
}

function renderAIExplanation(metric) {
    const el = document.getElementById('aiExplanation');
    if (!el) return;
    if (!metric.is_anomaly) {
        el.innerHTML = `<div class="empty">${ic('shield-check', 'icon empty-icon')}<div>System normal — score ${fmt(metric.anomaly_score || 0, 2)}</div></div>`;
        return;
    }
    let exps = [];
    try { exps = metric.ai_explanation ? (typeof metric.ai_explanation === 'string' ? JSON.parse(metric.ai_explanation) : metric.ai_explanation) : []; } catch { exps = []; }
    el.innerHTML = `
        <div class="ai-output action-card">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                ${ic('alert-triangle')}
                <strong>Anomaly score: ${fmt(metric.anomaly_score, 2)}</strong>
            </div>
            ${exps.map(e => `
                <div style="display: flex; justify-content: space-between; padding: 4px 0; font-size: 12.5px;">
                    <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">${escapeHtml(e.feature)}: ${fmt(e.value, 2)}</span>
                    <span style="font-weight: 600; color: ${e.direction === 'high' ? 'var(--warning)' : 'var(--info)'};">
                        ${e.direction === 'high' ? '↑' : '↓'} ${fmt(Math.abs(e.contribution || 0), 2)}
                    </span>
                </div>
            `).join('')}
        </div>`;
}

// ============================================================
// Top processes / connections
// ============================================================
async function fetchTopProcesses() {
    try {
        const r = await fetch(`${API_BASE}/api/system/top_processes?n=10`);
        const data = await r.json();
        const tbody = document.querySelector('#topProcTable tbody');
        document.getElementById('topProcCount').textContent = `${data.length}`;
        if (!data.length) { tbody.innerHTML = `<tr><td colspan="5"><div class="empty">No data</div></td></tr>`; return; }
        tbody.innerHTML = data.map(p => {
            const cpuCls = p.cpu_percent > 50 ? 'pill-hot' : p.cpu_percent > 15 ? 'pill-warm' : '';
            const memCls = p.memory_percent > 10 ? 'pill-hot' : p.memory_percent > 5 ? 'pill-warm' : '';
            return `<tr>
                <td>${escapeHtml(p.name)}</td>
                <td class="num">${p.pid}</td>
                <td class="num ${cpuCls}">${fmt(p.cpu_percent)}%</td>
                <td class="num ${memCls}">${fmt(p.memory_percent, 1)}%</td>
                <td>${escapeHtml(p.user || '—')}</td>
            </tr>`;
        }).join('');
    } catch { /* silent */ }
}

async function fetchConnections() {
    try {
        const r = await fetch(`${API_BASE}/api/system/network_connections?limit=15`);
        const data = await r.json();
        const tbody = document.querySelector('#connTable tbody');
        document.getElementById('connCount').textContent = `${data.length}`;
        if (!data.length) { tbody.innerHTML = `<tr><td colspan="3"><div class="empty">No connections</div></td></tr>`; return; }
        tbody.innerHTML = data.map(c => `<tr>
            <td>${escapeHtml(c.process || '—')}</td>
            <td>${escapeHtml(c.remote)}</td>
            <td>${escapeHtml(c.status)}</td>
        </tr>`).join('');
    } catch { /* silent */ }
}

// ============================================================
// System info + detection stats
// ============================================================
async function fetchSystemInfo() {
    try {
        const r = await fetch(`${API_BASE}/api/system/info`);
        const info = await r.json();
        const grid = document.getElementById('sysInfoGrid');
        const items = [
            ['Hostname', info.hostname],
            ['OS', info.os],
            ['Architecture', info.architecture],
            ['CPU', `${info.cpu_count_physical} / ${info.cpu_count_logical} logical`],
            ['CPU Frequency', info.cpu_freq_mhz ? `${info.cpu_freq_mhz} MHz` : '—'],
            ['Total RAM', `${info.memory_total_gb} GB`],
            ['Swap', `${info.swap_total_gb} GB (${info.swap_used_percent}%)`],
            ['Total Disk', `${info.disk_total_gb} GB`],
            ['System Uptime', info.uptime_human],
            ['Privilege', info.is_admin ? 'Administrator' : 'Standard'],
            ['Python', info.python_version],
        ];
        grid.innerHTML = items.map(([k, v]) => `
            <div class="info-item">
                <div class="info-item-label">${escapeHtml(k)}</div>
                <div class="info-item-value">${escapeHtml(String(v))}</div>
            </div>
        `).join('');
        const host = document.getElementById('brandHost');
        if (host && info.hostname) host.textContent = info.hostname;
    } catch { /* silent */ }
}

async function fetchDetectionStats() {
    try {
        const r = await fetch(`${API_BASE}/api/stats/detection`);
        const s = await r.json();
        const totalEvents = Object.values(s.events_24h || {}).reduce((a, b) => a + b, 0);
        const totalActions = Object.values(s.actions_24h || {}).reduce((a, b) => a + b, 0);
        setText('statEvents', fmtInt(totalEvents));
        setText('statActions', fmtInt(totalActions));
        setText('statAttacks', `${s.attack_stats?.detected || 0}/${s.attack_stats?.total_attacks || 0}`);
        setText('statSuspicious', fmtInt(s.suspicious_processes_24h));
        setText('statAvgCpu', (s.performance_1h?.avg_cpu || 0) + '%');
        setText('statPeakCpu', (s.performance_1h?.peak_cpu || 0) + '%');
    } catch { /* silent */ }
}

// ============================================================
// Baseline
// ============================================================
async function fetchBaseline() {
    try {
        const r = await fetch(`${API_BASE}/api/stats/baseline`);
        const d = await r.json();
        window._baseline = d.baseline || {};
        const el = document.getElementById('baselineStatus');
        if (!el) return;
        if (d.ready) {
            el.className = 'badge success';
            const b = d.baseline || {};
            el.innerHTML = `${ic('trending-up', 'icon')}<span>baseline · CPU ${fmt(b.cpu||0)}% · MEM ${fmt(b.memory||0)}%</span>`;
        } else {
            el.className = 'badge warning';
            el.innerHTML = `${ic('trending-up', 'icon')}<span>learning ${d.samples_collected || 0}/${d.samples_required || 10}</span>`;
        }
    } catch { /* silent */ }
}

// ============================================================
// Decision Engine rendering
// ============================================================
const TIER_COLORS = {0: 'var(--text-muted)', 1: 'var(--info)', 2: 'var(--warning)', 3: '#ff7849', 4: 'var(--danger)'};
const TIER_NAMES = {0: 'OBSERVE', 1: 'LIMIT', 2: 'CONTAIN', 3: 'SUSPEND', 4: 'TERMINATE'};
const TIER_BADGE = {0: 'info', 1: 'info', 2: 'warning', 3: 'warning', 4: 'danger'};

let _decisionStaleTimer = null;
function renderDecision(d) {
    const el = document.getElementById('decisionPanel');
    if (!el) return;
    const tier = d.tier || 0;
    const score = d.risk_score || 0;
    const color = TIER_COLORS[tier];

    // Auto-fade after 30s of no new decision
    if (_decisionStaleTimer) clearTimeout(_decisionStaleTimer);
    _decisionStaleTimer = setTimeout(() => {
        const cur = document.getElementById('decisionPanel');
        if (cur) cur.style.opacity = '0.5';
    }, 30000);
    el.style.opacity = '1';

    el.innerHTML = `
        <div class="decision-card">
            <div class="decision-score">
                <div class="decision-score-num" style="color: ${color};">${score.toFixed(0)}</div>
                <div class="decision-score-label">Risk</div>
            </div>
            <div class="decision-info">
                <div class="decision-action-row">
                    <span class="badge ${TIER_BADGE[tier]}">${escapeHtml(TIER_NAMES[tier] || ('TIER ' + tier))}</span>
                    <span class="decision-action-name">${escapeHtml(d.action || '?')}</span>
                    <span class="decision-target">→ ${escapeHtml(d.source_name || d.source_id || '?')}</span>
                </div>
                <div class="decision-outcome">${escapeHtml(d.expected_outcome || '')}</div>
            </div>
        </div>

        <div class="reasoning-block">
            <div class="reasoning-title">Reasoning Chain</div>
            ${(d.reasoning || []).map((r, i) => `
                <div class="reasoning-step">
                    <span class="num">${i + 1}.</span>
                    <span>${escapeHtml(r)}</span>
                </div>`).join('')}
        </div>

        ${(d.rejected_alternatives && d.rejected_alternatives.length) ? `
            <div class="reasoning-block">
                <div class="reasoning-title">Considered & Rejected</div>
                ${d.rejected_alternatives.map(alt => `
                    <div class="reasoning-step rejected">
                        <span class="num" style="min-width: 130px; font-family: 'JetBrains Mono', monospace;">${escapeHtml(alt.action)}</span>
                        <span>${escapeHtml(alt.reason)}</span>
                    </div>`).join('')}
            </div>` : ''}
    `;
}

async function showOffenders() {
    try {
        const r = await fetch(`${API_BASE}/api/defender/offenders?limit=20`);
        const d = await r.json();
        const list = d.offenders || [];
        const html = list.length ? `
            <table class="data-table">
                <thead><tr><th>Source</th><th>Type</th><th class="num">Total</th><th class="num">Last 5m</th><th>Threats</th><th>Status</th></tr></thead>
                <tbody>${list.map(o => `
                    <tr>
                        <td>${escapeHtml(o.source_name || o.source_id)}</td>
                        <td>${escapeHtml(o.source_type)}</td>
                        <td class="num pill-hot">${o.violations_total}</td>
                        <td class="num ${o.violations_recent_5m > 2 ? 'pill-hot' : ''}">${o.violations_recent_5m}</td>
                        <td>${(o.threat_types || []).map(t => `<span class="event-tag">${escapeHtml(t)}</span>`).join(' ')}</td>
                        <td>${o.is_blocked ? '<span class="badge danger">blocked</span>' : '<span class="badge info">tracked</span>'}</td>
                    </tr>`).join('')}</tbody>
            </table>` :
            `<div class="empty">${ic('shield-check', 'icon empty-icon')}<div>No repeat offenders</div></div>`;
        showInfoModal('Repeat Offenders', html, 'fingerprint');
    } catch (e) { toast('Failed to load: ' + e, 'danger'); }
}

async function showActionCatalog() {
    try {
        const r = await fetch(`${API_BASE}/api/defender/action_catalog`);
        const d = await r.json();
        const tiers = {};
        (d.actions || []).forEach(a => { (tiers[a.tier] ||= []).push(a); });
        const html = Object.keys(tiers).sort().map(t => `
            <div style="margin-bottom: 14px;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <div style="width: 4px; height: 18px; background: ${TIER_COLORS[t]}; border-radius: 2px;"></div>
                    <strong style="font-size: 13px;">Tier ${t}: ${TIER_NAMES[t] || ''}</strong>
                </div>
                ${tiers[t].map(a => `
                    <div style="padding: 7px 12px; background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 4px; display: flex; gap: 12px; font-size: 12.5px;">
                        <code style="color: ${TIER_COLORS[t]}; min-width: 180px; font-family: 'JetBrains Mono', monospace;">${escapeHtml(a.action)}</code>
                        <span style="color: var(--text-muted); flex: 1;">${escapeHtml(a.description)}</span>
                    </div>`).join('')}
            </div>`).join('');
        showInfoModal('Action Catalog (18 capabilities)', html, 'book', 'modal-lg');
    } catch (e) { toast('Failed: ' + e, 'danger'); }
}

function showInfoModal(title, htmlBody, iconName = 'info', extraClass = '') {
    let modal = document.getElementById('infoModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'infoModal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal ${extraClass}">
                <div class="modal-header">
                    <div class="modal-title">
                        <svg class="icon" id="infoModalIcon"><use href="#i-info"/></svg>
                        <span id="infoModalTitle"></span>
                    </div>
                    <button class="btn btn-ghost btn-icon" onclick="document.getElementById('infoModal').classList.remove('open')">
                        ${ic('x', 'icon icon-sm')}
                    </button>
                </div>
                <div class="modal-body" id="infoModalBody"></div>
            </div>`;
        document.body.appendChild(modal);
    }
    const m = modal.querySelector('.modal');
    if (extraClass) m.classList.add(extraClass);
    document.getElementById('infoModalIcon').innerHTML = `<use href="#i-${iconName}"/>`;
    document.getElementById('infoModalTitle').textContent = title;
    document.getElementById('infoModalBody').innerHTML = htmlBody;
    modal.classList.add('open');
}

// ============================================================
// AI Live Solve — step-by-step streaming demo
// ============================================================
const STAGE_META = {
    detect:  { icon: 'search',     label: 'Detect',  color: 'var(--info)' },
    analyze: { icon: 'brain',      label: 'Analyze', color: 'var(--accent)' },
    decide:  { icon: 'sliders',    label: 'Decide',  color: 'var(--warning)' },
    execute: { icon: 'zap',        label: 'Execute', color: '#ff7849' },
    verify:  { icon: 'eye',        label: 'Verify',  color: 'var(--info)' },
    report:  { icon: 'shield-check', label: 'Report', color: 'var(--success)' },
};

let solveSession = null;

function ensureSolveContainer() {
    const body = document.getElementById('solvePanelBody');
    if (!body) return null;
    let stepsEl = document.getElementById('solveSteps');
    if (!stepsEl) {
        body.innerHTML = '<div id="solveSteps"></div><div id="solveFinal"></div>';
        stepsEl = document.getElementById('solveSteps');
    }
    return stepsEl;
}

function renderSolveStep(step, index, isComplete) {
    const stepsEl = ensureSolveContainer();
    if (!stepsEl) return;
    const meta = STAGE_META[step.stage] || { icon: 'info', label: step.stage, color: 'var(--text-muted)' };

    let el = document.getElementById(`solve-step-${index}`);
    if (!el) {
        el = document.createElement('div');
        el.id = `solve-step-${index}`;
        el.style.cssText = 'display: grid; grid-template-columns: 36px 1fr auto; gap: 12px; padding: 12px 14px; border: 1px solid var(--border); background: var(--bg-elevated); border-radius: 9px; margin-bottom: 8px; align-items: start;';
        stepsEl.appendChild(el);
    }

    const statusBadge = isComplete
        ? `<span class="badge success">done${step.elapsed_ms ? ' · ' + step.elapsed_ms + 'ms' : ''}</span>`
        : `<span class="badge accent" style="animation: pulse 1s ease-in-out infinite;">running…</span>`;

    el.innerHTML = `
        <div style="width: 32px; height: 32px; border-radius: 8px; background: ${meta.color}22; color: ${meta.color}; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
            ${ic(meta.icon, 'icon icon-md')}
        </div>
        <div style="min-width: 0;">
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px; flex-wrap: wrap;">
                <strong style="text-transform: uppercase; letter-spacing: 0.6px; font-size: 11.5px; color: ${meta.color};">${escapeHtml(meta.label)}</strong>
                <span style="font-size: 13px; color: var(--text);">${escapeHtml(step.title || '')}</span>
            </div>
            <div style="font-size: 12.5px; color: var(--text-2); line-height: 1.5;">${escapeHtml(step.body || '')}</div>
        </div>
        <div style="flex-shrink: 0;">${statusBadge}</div>
    `;
    // Smooth scroll to latest step
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderSolveFinal(data) {
    const finalEl = document.getElementById('solveFinal');
    if (!finalEl) return;
    const ok = data.success;
    finalEl.innerHTML = `
        <div style="margin-top: 12px; padding: 14px 16px; background: ${ok ? 'var(--success-bg)' : 'var(--warning-bg)'}; border: 1px solid ${ok ? 'var(--success)' : 'var(--warning)'}; border-radius: 9px;">
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
                ${ic(ok ? 'check-circle' : 'alert-triangle', 'icon icon-md')}
                <strong style="font-size: 14px;">${ok ? 'Problem solved' : 'Partial — review needed'}</strong>
                <span style="margin-left: auto; color: var(--text-muted); font-size: 11.5px; font-family: 'JetBrains Mono', monospace;">${data.elapsed_seconds || ''}s</span>
            </div>
            <div style="font-size: 13px; color: var(--text); line-height: 1.55;">${escapeHtml(data.summary || '')}</div>
        </div>
    `;
    const status = document.getElementById('solveStatus');
    if (status) {
        status.className = ok ? 'badge success' : 'badge warning';
        status.textContent = ok ? 'solved' : 'partial';
    }
    const btn = document.getElementById('solveNowBtn');
    if (btn) btn.disabled = false;
}

function handleSolveEvent(data) {
    if (!data) return;

    if (data.event === 'session_start') {
        solveSession = data;
        const body = document.getElementById('solvePanelBody');
        if (body) body.innerHTML = '<div id="solveSteps"></div><div id="solveFinal"></div>';
        const status = document.getElementById('solveStatus');
        if (status) { status.className = 'badge accent'; status.textContent = 'running'; }
        const trigger = data.trigger || '';
        if (trigger) {
            const note = document.createElement('div');
            note.style.cssText = 'padding: 10px 12px; background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 7px; margin-bottom: 10px; font-size: 12.5px; color: var(--text-muted);';
            note.innerHTML = `${ic('info', 'icon icon-sm')} <strong>Trigger:</strong> ${escapeHtml(trigger)}`;
            note.style.display = 'flex';
            note.style.gap = '8px';
            note.style.alignItems = 'center';
            const stepsEl = document.getElementById('solveSteps');
            if (stepsEl) stepsEl.appendChild(note);
        }
    } else if (data.event === 'step_start') {
        renderSolveStep(data.step, data.step_index, false);
    } else if (data.event === 'step_done') {
        renderSolveStep(data.step, data.step_index, true);
    } else if (data.event === 'session_done') {
        renderSolveFinal(data);
    }
}

async function triggerSolve() {
    const btn = document.getElementById('solveNowBtn');
    if (btn) btn.disabled = true;
    const status = document.getElementById('solveStatus');
    if (status) { status.className = 'badge accent'; status.textContent = 'starting…'; }

    try {
        const r = await fetch(`${API_BASE}/api/ai/solve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ trigger: 'User clicked Solve with AI' }),
        });
        if (!r.ok) {
            toast('Solve failed: ' + r.status, 'danger');
            if (btn) btn.disabled = false;
        }
        // result also streams via WS, but we call so it returns the final state too
        await r.json();
    } catch (e) {
        toast('Solve error: ' + e, 'danger');
        if (btn) btn.disabled = false;
    }
}

// ============================================================
// Defense Mode toggle (AUTO / HYBRID / AI)
// ============================================================
async function fetchDefenseMode() {
    try {
        const r = await fetch(`${API_BASE}/api/defender/mode`);
        const d = await r.json();
        applyModeUI(d.mode);
    } catch { /* silent */ }
}

function applyModeUI(mode) {
    document.querySelectorAll('#defenseModeToggle button').forEach(b => {
        b.classList.toggle('active', b.dataset.mode === mode);
    });
    flowSetMode(mode);
}

async function setDefenseMode(mode) {
    const btn = document.querySelector(`#defenseModeToggle button[data-mode="${mode}"]`);
    if (btn?.classList.contains('active')) return;  // already active
    try {
        const r = await fetch(`${API_BASE}/api/defender/mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode }),
        });
        const d = await r.json();
        applyModeUI(d.mode);
        const labels = { auto: 'AUTO (rules only)', hybrid: 'HYBRID (rules + AI)', ai: 'AI (LLM picks all)' };
        toast(`Defense mode: ${labels[d.mode] || d.mode}`, 'info');
    } catch (e) { toast('Mode change failed: ' + e, 'danger'); }
}

// ============================================================
// Attack Detection Timeline
// ============================================================
const attackTimelineState = {
    items: [],            // array of {id, name, started_at, detected_at, action, risk, status, verify}
    seenAttackIds: new Set(),
};

function renderAttackTimeline() {
    const el = document.getElementById('attackTimeline');
    if (!el) return;
    const items = attackTimelineState.items;
    document.getElementById('timelineCount').textContent = `${items.length} attack${items.length !== 1 ? 's' : ''} observed`;

    if (!items.length) {
        el.innerHTML = `<div class="empty">${ic('shield-check', 'icon empty-icon')}<div>No attacks observed. Server clean.</div></div>`;
        return;
    }

    el.innerHTML = items.slice(0, 12).map(it => {
        const startedAt = new Date(it.started_at * 1000).toLocaleTimeString();
        const detectMs = it.detected_at ? Math.round((it.detected_at - it.started_at) * 1000) : null;
        const statusBadge = it.status === 'stopped' ? 'success' : 'danger';
        const statusLabel = it.status === 'stopped' ? 'resolved' : 'active';
        const dotCls = it.status === 'stopped' ? 'status-dot' : 'status-dot danger';

        return `
            <div style="display: grid; grid-template-columns: 14px 90px 1fr auto; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--border); align-items: center;">
                <span class="${dotCls}"></span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--text-muted);">${escapeHtml(startedAt)}</span>
                <div style="min-width: 0;">
                    <div style="font-weight: 600; font-size: 13px; margin-bottom: 2px;">
                        ${escapeHtml(it.name)}
                        ${detectMs !== null ? `<span style="color: var(--text-muted); font-size: 11.5px; margin-left: 8px;">detected in ${detectMs}ms</span>` : ''}
                    </div>
                    <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                        ${it.risk != null ? `<span class="badge ${it.risk >= 70 ? 'danger' : it.risk >= 40 ? 'warning' : 'info'}">risk ${it.risk}</span>` : ''}
                        ${it.action ? `<span class="badge">${escapeHtml(it.action)}</span>` : ''}
                        ${it.verify ? `<span class="badge ${it.verify.solved ? 'success' : 'warning'}">verify: ${it.verify.solved ? 'solved' : 'unresolved'} ${it.verify.confidence ? `(${(it.verify.confidence*100).toFixed(0)}%)` : ''}</span>` : ''}
                    </div>
                </div>
                <span class="badge ${statusBadge}">${statusLabel}</span>
            </div>
        `;
    }).join('');
}

function recordAttackStart(data) {
    if (!data || !data.id) return;
    if (attackTimelineState.seenAttackIds.has(data.id)) return;
    attackTimelineState.seenAttackIds.add(data.id);
    attackTimelineState.items.unshift({
        id: data.id,
        name: data.name || 'unknown',
        started_at: data.start_time || (Date.now() / 1000),
        detected_at: null,
        action: null,
        risk: null,
        status: 'active',
        verify: null,
    });
    if (attackTimelineState.items.length > 50) attackTimelineState.items.length = 50;
    renderAttackTimeline();
}

function recordAttackStop(data) {
    if (!data || !data.id) return;
    const item = attackTimelineState.items.find(i => i.id === data.id);
    if (item) {
        item.status = 'stopped';
        renderAttackTimeline();
    }
}

function recordDecisionForAttack(decision) {
    // If this decision targets an active attack, attach to its timeline entry
    if (!decision || decision.source_type !== 'process') return;
    const name = (decision.source_name || '').replace('sim_', '').replace('.exe', '');
    const item = attackTimelineState.items.find(i => i.name === name && !i.detected_at);
    if (item) {
        item.detected_at = decision.timestamp || (Date.now() / 1000);
        item.action = decision.action;
        item.risk = Math.round(decision.risk_score || 0);
        renderAttackTimeline();
    }
}

function recordVerifyForAttack(verdict) {
    if (!verdict) return;
    const item = attackTimelineState.items.find(i => i.detected_at && !i.verify);
    if (item) {
        item.verify = verdict;
        renderAttackTimeline();
    }
}

// ============================================================
// AI Investigation
// ============================================================
const investigationState = { current: null };

async function runInvestigation(triggerReason = null) {
    const btn = document.getElementById('investigateBtn');
    btn.disabled = true;
    const out = document.getElementById('investigationPanel');
    out.innerHTML = `<div style="padding: 16px; color: var(--text-muted);">${ic('search')} Investigating… AI is analyzing.</div>`;

    try {
        const r = await fetch(`${API_BASE}/api/ai/investigate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                trigger_reason: triggerReason || 'User-triggered investigation',
                max_steps: 4,
            }),
        });
        const data = await r.json();
        renderInvestigationFinal(data);
    } catch (e) {
        out.innerHTML = `<div class="ai-output" style="color: var(--danger);">Investigation failed: ${escapeHtml(String(e))}</div>`;
    } finally {
        btn.disabled = false;
    }
}

function renderInvestigationStart(data) {
    const out = document.getElementById('investigationPanel');
    if (!out) return;
    investigationState.current = { ...data, steps: [] };
    out.innerHTML = `
        <div class="ai-output action-card" style="margin-bottom: 12px;">
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
                <span class="badge accent">INVESTIGATING</span>
                <strong>${escapeHtml(data.trigger_reason || 'Investigation started')}</strong>
            </div>
            <div style="color: var(--text-muted); font-size: 12px;">
                ID: ${escapeHtml(data.id || '?')} · max ${data.max_steps || 4} steps
            </div>
        </div>
        <div id="investigationSteps"></div>
    `;
}

function renderInvestigationStep(payload) {
    const cur = investigationState.current;
    if (!cur || cur.id !== payload.investigation_id) return;
    const step = payload.step;
    cur.steps.push(step);

    const stepsEl = document.getElementById('investigationSteps');
    if (!stepsEl) return;

    const div = document.createElement('div');
    div.style.cssText = 'border-left: 2px solid var(--accent); padding: 8px 12px; margin-bottom: 8px; background: var(--bg-elevated); border-radius: 0 6px 6px 0;';
    div.innerHTML = `
        <div style="display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; margin-bottom: 4px;">
            <span class="badge accent" style="font-family: 'JetBrains Mono', monospace;">step ${step.step_num}</span>
            <code style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 12px;">${escapeHtml(step.tool)}(${escapeHtml(JSON.stringify(step.tool_args).slice(0, 80))})</code>
            <span style="color: var(--text-muted); font-size: 11px; margin-left: auto;">${step.elapsed_ms}ms</span>
        </div>
        <div style="font-size: 12.5px; color: var(--text-2); margin-bottom: 6px; font-style: italic;">
            ${ic('brain', 'icon icon-sm')} ${escapeHtml(step.thought || '')}
        </div>
        <pre style="font-size: 11.5px; color: var(--text-muted); margin: 0; padding: 6px 8px; background: var(--bg-canvas); border-radius: 4px; overflow-x: auto; max-height: 100px; white-space: pre-wrap; word-break: break-all;">${escapeHtml(JSON.stringify(step.observation, null, 0).slice(0, 400))}</pre>
    `;
    stepsEl.appendChild(div);
}

function renderInvestigationFinal(data) {
    const out = document.getElementById('investigationPanel');
    if (!out) return;
    investigationState.current = data;

    const conf = (data.confidence || 0) * 100;
    const actionCls = (data.final_action === 'terminate' || data.final_action === 'block_ip') ? 'danger' :
                      (data.final_action === 'sandbox' || data.final_action === 'suspend') ? 'warning' : 'info';

    const stepsHtml = (data.steps || []).map(step => `
        <div style="border-left: 2px solid var(--accent); padding: 8px 12px; margin-bottom: 8px; background: var(--bg-elevated); border-radius: 0 6px 6px 0;">
            <div style="display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; margin-bottom: 4px;">
                <span class="badge accent" style="font-family: 'JetBrains Mono', monospace;">step ${step.step_num}</span>
                <code style="font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 12px;">${escapeHtml(step.tool)}(${escapeHtml(JSON.stringify(step.tool_args).slice(0, 80))})</code>
                <span style="color: var(--text-muted); font-size: 11px; margin-left: auto;">${step.elapsed_ms}ms</span>
            </div>
            <div style="font-size: 12.5px; color: var(--text-2); margin-bottom: 6px; font-style: italic;">
                ${ic('brain', 'icon icon-sm')} ${escapeHtml(step.thought || '')}
            </div>
            <pre style="font-size: 11.5px; color: var(--text-muted); margin: 0; padding: 6px 8px; background: var(--bg-canvas); border-radius: 4px; overflow-x: auto; max-height: 100px; white-space: pre-wrap; word-break: break-all;">${escapeHtml(JSON.stringify(step.observation, null, 0).slice(0, 400))}</pre>
        </div>
    `).join('');

    out.innerHTML = `
        <div class="ai-output action-card" style="margin-bottom: 14px;">
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap;">
                <span class="badge ${data.status === 'done' ? 'success' : 'warning'}">${escapeHtml((data.status || 'running').toUpperCase())}</span>
                <span class="badge ${actionCls}">${escapeHtml(data.final_action || '?')}</span>
                <span style="color: var(--text-muted); font-size: 12px;">confidence ${conf.toFixed(0)}% · ${data.step_count || (data.steps||[]).length} steps · ${data.elapsed_seconds || '?'}s</span>
            </div>
            <div style="margin-bottom: 6px; font-size: 12.5px; color: var(--text-muted);">${escapeHtml(data.trigger_reason || '')}</div>
            <div style="font-weight: 500;">${escapeHtml(data.final_recommendation || '')}</div>
        </div>
        <div class="reasoning-title">Investigation Steps</div>
        <div>${stepsHtml || '<div class="empty">No steps</div>'}</div>
    `;
}

async function showInvestigationHistory() {
    try {
        const r = await fetch(`${API_BASE}/api/ai/investigations?limit=20`);
        const d = await r.json();
        const list = d.investigations || [];
        const html = list.length ? `
            <table class="data-table">
                <thead><tr><th>Time</th><th>Action</th><th class="num">Steps</th><th class="num">Confidence</th><th>Summary</th></tr></thead>
                <tbody>${list.map(inv => `
                    <tr>
                        <td>${escapeHtml(inv.timestamp.split(' ')[1] || inv.timestamp)}</td>
                        <td><span class="badge">${escapeHtml(inv.final_action || '?')}</span></td>
                        <td class="num">${inv.step_count || '?'}</td>
                        <td class="num">${((inv.confidence || 0) * 100).toFixed(0)}%</td>
                        <td>${escapeHtml((inv.summary || '').slice(0, 80))}</td>
                    </tr>`).join('')}</tbody>
            </table>` :
            `<div class="empty">${ic('clock', 'icon empty-icon')}<div>No investigations run yet</div></div>`;
        showInfoModal('Investigation History', html, 'fingerprint', 'modal-lg');
    } catch (e) { toast('Failed: ' + e, 'danger'); }
}

// ============================================================
// AI Assistant
// ============================================================
async function aiCall(endpoint, payload = null) {
    const out = document.getElementById('aiAssistantOutput');
    out.innerHTML = `<div class="ai-output"><span style="color: var(--text-muted);">Thinking…</span></div>`;
    try {
        const r = await fetch(`${API_BASE}/api/ai/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload ? JSON.stringify(payload) : '{}',
        });
        renderAiResponse(await r.json(), endpoint);
    } catch (e) {
        out.innerHTML = `<div class="ai-output" style="color: var(--danger);">Error: ${escapeHtml(String(e))}</div>`;
    }
}

function renderAiResponse(data, endpoint) {
    const out = document.getElementById('aiAssistantOutput');
    const provider = escapeHtml(data.provider || '?');
    const cached = data.cached ? ' (cached)' : '';
    const latency = data.latency_ms ? `${data.latency_ms}ms` : '';

    let body;
    if (endpoint === 'analyze' || data.action !== undefined) {
        const sev = data.severity || 'info';
        const badgeCls = sev === 'critical' || sev === 'high' ? 'danger' : sev === 'medium' ? 'warning' : 'info';
        body = `
            <div class="ai-output action-card">
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px; flex-wrap: wrap;">
                    <span class="badge ${badgeCls}">${escapeHtml(sev.toUpperCase())}</span>
                    <strong>${escapeHtml(data.action || '-')}</strong>
                    <span style="color: var(--text-muted); font-size: 12px;">confidence ${((data.confidence||0) * 100).toFixed(0)}%</span>
                </div>
                <div>${escapeHtml(data.reason || '-')}</div>
            </div>`;
    } else {
        body = `<div class="ai-output">${escapeHtml(data.text || data.summary || JSON.stringify(data))}</div>`;
    }
    out.innerHTML = body + `<div class="ai-meta">provider: ${provider}${cached}${latency ? ' · ' + latency : ''}</div>`;
}

async function aiChat() {
    const input = document.getElementById('aiChatInput');
    const msg = input.value.trim();
    if (!msg) return;
    input.value = '';
    await aiCall('chat', { message: msg });
}

async function fetchLlmStatus() {
    try {
        const r = await fetch(`${API_BASE}/api/ai/llm/status`);
        const d = await r.json();
        const el = document.getElementById('aiStatus');
        if (d.available) {
            el.className = 'badge success';
            el.innerHTML = `${ic('bot', 'icon')}<span class="btn-text">${escapeHtml((d.providers||[])[0] || 'AI')}</span>`;
        } else {
            el.className = 'badge';
            el.innerHTML = `${ic('cloud-off', 'icon')}<span class="btn-text">rule-based</span>`;
        }
        // Update usage badge
        const usage = d.usage || {};
        const total = usage.calls_total || 0;
        const cap = usage.soft_cap || 200;
        const usageEl = document.getElementById('aiUsage');
        if (usageEl) {
            const cls = usage.soft_cap_exceeded ? 'badge danger'
                       : usage.soft_cap_warn ? 'badge warning'
                       : 'badge';
            usageEl.className = cls;
            usageEl.innerHTML = `${ic('activity', 'icon')}<span>${total}/${cap} calls</span>`;
            usageEl.title = `LLM calls — total ${total}, cached ${usage.calls_cached||0}, errors ${usage.errors||0}, soft cap ${cap}`;
        }
    } catch { /* silent */ }
}

async function demoReset() {
    if (!confirm('Reset demo state?\n\nThis will:\n• Stop active attacks\n• Clear simulations\n• Reset offender tracker\n• Restart baseline learning\n• Delete events older than 5 minutes\n\nMode + trust list are kept.')) return;
    try {
        const r = await fetch(`${API_BASE}/api/defender/demo_reset`, { method: 'POST' });
        if (r.ok) {
            toast('Demo state cleared. Baseline relearning starts now.', 'success');
            // Clear UI state
            attackTimelineState.items = [];
            attackTimelineState.seenAttackIds.clear();
            renderAttackTimeline();
            const dec = document.getElementById('decisionPanel');
            if (dec) dec.innerHTML = `<div class="empty">${ic('sliders', 'icon empty-icon')}<div>Demo reset. Trigger something to see the engine respond.</div></div>`;
            const solve = document.getElementById('solvePanelBody');
            if (solve) solve.innerHTML = `<div class="empty">${ic('zap', 'icon empty-icon')}<div>Click <strong>Solve with AI</strong> to demo the AI flow.</div></div>`;
            const inv = document.getElementById('investigationPanel');
            if (inv) inv.innerHTML = `<div class="empty">${ic('fingerprint', 'icon empty-icon')}<div>No active investigation.</div></div>`;
            fetchEvents();
            fetchActions();
            fetchLlmStatus();
        }
    } catch (e) { toast('Reset failed: ' + e, 'danger'); }
}

// ============================================================
// WAF / fake requests
// ============================================================
async function wafSend(pattern = null, count = 1) {
    try {
        await fetch(`${API_BASE}/api/waf/send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern, count }),
        });
    } catch (e) { toast('WAF send failed: ' + e, 'danger'); }
}

function renderFakeRequest(data) {
    const list = document.getElementById('wafList');
    if (!list) return;
    const empty = list.querySelector('.empty');
    if (empty) empty.parentElement?.remove() ?? empty.remove();

    const req = data.request || {};
    const verdict = data.verdict || data.ai_verdict || {};
    const decision = data.decision || {};
    const finalAction = decision.action || verdict.verdict || 'allow';
    const tier = decision.tier ?? 0;
    const tagCls = tier >= 4 ? 'critical' : tier >= 3 ? 'warning' : tier >= 1 ? 'warn' : 'info';

    const li = document.createElement('li');
    li.className = 'event-item';
    li.innerHTML = `
        <span class="event-time">${escapeHtml(req.source_ip || '-')}</span>
        <span class="event-tag ${tagCls}">${escapeHtml(finalAction.toUpperCase())}</span>
        <span class="event-msg">
            <strong style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">${escapeHtml(req.method || '-')} ${escapeHtml((req.path || '').slice(0, 50))}</strong>
            <span style="color: var(--text-muted); margin-left: 8px;">${escapeHtml(verdict.threat_type || req.pattern || '-')}</span>
        </span>
    `;
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 30) list.removeChild(list.lastChild);
}

async function loadWafPatterns() {
    try {
        const r = await fetch(`${API_BASE}/api/waf/patterns`);
        const d = await r.json();
        const sel = document.getElementById('wafPatternSelect');
        sel.innerHTML = '<option value="">random</option>' +
            d.patterns.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('');
    } catch { /* silent */ }
}

function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.25s'; setTimeout(() => el.remove(), 250); }, 3000);
}

// ============================================================
// Connection indicator
// ============================================================
function setConnStatus(connected, text) {
    const el = document.getElementById('connIndicator');
    const txt = document.getElementById('connText');
    if (!el || !txt) return;
    el.classList.remove('connected', 'disconnected');
    el.classList.add(connected ? 'connected' : 'disconnected');
    txt.textContent = text;
    const dot = el.querySelector('.status-dot');
    if (dot) dot.className = connected ? 'status-dot' : 'status-dot danger';
}

// ============================================================
// WebSocket
// ============================================================
function connectWS() {
    try { ws = new WebSocket(WS_URL); }
    catch (e) { setConnStatus(false, 'WS error'); setTimeout(connectWS, 5000); return; }

    ws.onopen = () => { wsConnected = true; setConnStatus(true, 'live'); };
    ws.onclose = () => { wsConnected = false; setConnStatus(false, 'reconnecting…'); setTimeout(connectWS, 3000); };
    ws.onerror = () => { wsConnected = false; setConnStatus(false, 'WS error'); };
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'metric') {
                lastMetricTs = Date.now();
                updateMetricCards(msg.data);
                if (typeof pushToChart === 'function') pushToChart(msg.data);
            } else if (msg.type === 'action') {
                // WebSocket push → mark as LIVE so banner pops once
                const actionData = msg.data.result || msg.data;
                renderAction(actionData, { isLive: true });
                flowOnAction(actionData);  // feed Decision Flow EXECUTE step
            } else if (['security', 'suspicious_process', 'network_alert', 'usb'].includes(msg.type)) {
                renderSecurityEvent(msg.data);
            } else if (msg.type === 'fake_request') {
                renderFakeRequest(msg.data);
                if (msg.data && msg.data.decision) renderDecision(msg.data.decision);
            } else if (msg.type === 'defender_decision' || msg.type === 'decision') {
                renderDecision(msg.data);
                recordDecisionForAttack(msg.data);
                flowOnDecision(msg.data);  // feed Decision Flow ANALYZE+DECIDE
            } else if (msg.type === 'attack_started') {
                recordAttackStart(msg.data);
            } else if (msg.type === 'attack_stopped') {
                recordAttackStop(msg.data);
            } else if (msg.type === 'investigation_started') {
                renderInvestigationStart(msg.data);
            } else if (msg.type === 'investigation_step') {
                renderInvestigationStep(msg.data);
            } else if (msg.type === 'investigation_finished') {
                renderInvestigationFinal(msg.data);
            } else if (msg.type === 'defense_mode') {
                applyModeUI(msg.data.mode);
                flowSetMode(msg.data.mode);
            } else if (msg.type === 'ai_solve') {
                handleSolveEvent(msg.data);
            } else if (msg.type === 'ai_advice' || msg.type === 'ai_verify') {
                if (msg.type === 'ai_verify') {
                    recordVerifyForAttack(msg.data);
                    flowOnVerify(msg.data);   // feed Decision Flow VERIFY step
                }
            }
        } catch (e) { console.warn('WS parse:', e); }
    };
}

// ============================================================
// REST polling
// ============================================================
async function pollCurrentMetric() {
    try {
        const r = await fetch(`${API_BASE}/api/metrics/current`);
        const data = await r.json();
        if (data && Object.keys(data).length > 0) {
            updateMetricCards(data);
            if (typeof pushToChart === 'function') pushToChart(data);
        }
    } catch { /* silent */ }
}

async function fetchEvents() {
    try {
        const r = await fetch(`${API_BASE}/api/events?limit=30`);
        const data = await r.json();
        const list = document.getElementById('eventList');
        list.innerHTML = '';
        if (!data.length) list.innerHTML = `<li class="empty">${ic('clock', 'icon empty-icon')}<div>Waiting for events</div></li>`;
        else data.forEach(renderEvent);
    } catch { /* silent */ }
}

async function fetchActions() {
    try {
        const r = await fetch(`${API_BASE}/api/actions?limit=20`);
        const data = await r.json();
        const list = document.getElementById('actionList');
        list.innerHTML = '';
        if (!data.length) list.innerHTML = `<li class="empty">${ic('zap', 'icon empty-icon')}<div>No actions yet</div></li>`;
        else data.forEach(renderAction);
    } catch { /* silent */ }
}

async function fetchSecurity() {
    try {
        const r = await fetch(`${API_BASE}/api/security/suspicious_processes`);
        const data = await r.json();
        if (!data.length) return;
        const list = document.getElementById('securityList');
        list.innerHTML = '';
        data.slice(0, 30).forEach(renderSecurityEvent);
    } catch { /* silent */ }
}

async function fetchHistory(hours = 0.5) {
    try {
        const r = await fetch(`${API_BASE}/api/metrics/history?hours=${hours}`);
        const data = await r.json();
        if (typeof loadHistoryIntoChart === 'function') loadHistoryIntoChart(data);
    } catch { /* silent */ }
}

async function fetchAIStatus() { fetchLlmStatus(); }

// ============================================================
// AEGIS — Infrastructure Health (services / network / security / infra)
// ============================================================
function fmtUptime(s) {
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s/60) + 'm';
    return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

function tile(klass, name, sub, action) {
    const cls = ['aegis-tile', klass].filter(Boolean).join(' ');
    const dot = '<div class="aegis-tile-dot"></div>';
    const body = `<div><div class="aegis-tile-name">${escapeHtml(name)}</div><div class="aegis-tile-sub">${escapeHtml(sub)}</div></div>`;
    const btn = action ? `<button class="aegis-tile-action" onclick="${action.handler}">${escapeHtml(action.label)}</button>` : '';
    return `<div class="${cls}">${dot}${body}${btn}</div>`;
}

async function fetchAegisServices() {
    try {
        const r = await fetch(`${API_BASE}/api/services`);
        const d = await r.json();
        const tiles = (d.services || []).map(s => {
            const klass = s.is_simulated ? `${s.status} simulated` : s.status;
            const sub = s.status === 'up'
                ? `${Math.round(s.latency_ms)}ms · ${fmtUptime(s.uptime_seconds)} up`
                : (s.sim_reason || s.real_error || s.status);
            const action = (s.status !== 'up')
                ? { label: 'Restart', handler: `restartService('${s.id}')` }
                : null;
            return tile(klass, s.name, sub, action);
        });
        const grid = document.getElementById('serviceTiles');
        if (grid) grid.innerHTML = tiles.join('') || '<div class="aegis-tile placeholder">No services configured</div>';
        updateAegisHealthSummary(d.services || [], 'service');
    } catch (e) { /* silent */ }
}

async function restartService(sid) {
    try {
        const r = await fetch(`${API_BASE}/api/services/${sid}/restart`, { method: 'POST' });
        if (r.ok) {
            toast(`${sid} restarted`, 'success');
            fetchAegisServices();
        }
    } catch (e) { toast('Restart failed', 'danger'); }
}

async function fetchAegisNetwork() {
    try {
        const r = await fetch(`${API_BASE}/api/network`);
        const d = await r.json();
        const tiles = (d.links || []).map(l => {
            const klass = l.is_simulated ? `${l.status} simulated` : l.status;
            const sub = l.status === 'healthy' ? `${Math.round(l.latency_ms)}ms · ${l.target}` : (l.sim_reason || l.target);
            return tile(klass, l.name.toUpperCase(), sub, null);
        });
        const grid = document.getElementById('networkTiles');
        if (grid) grid.innerHTML = tiles.join('') || '<div class="aegis-tile placeholder">No network probes</div>';
    } catch (e) { /* silent */ }
}

async function fetchAegisSecurity() {
    try {
        const [authR, certsR, portsR] = await Promise.all([
            fetch(`${API_BASE}/api/security/auth_events?limit=10`).then(r => r.json()),
            fetch(`${API_BASE}/api/security/certs`).then(r => r.json()),
            fetch(`${API_BASE}/api/security/ports`).then(r => r.json()),
        ]);

        const activeFailed = authR.stats?.active_failed_5m ?? authR.stats?.failed_5m ?? 0;
        const totalFailed = authR.stats?.failed_5m || 0;
        const blocked = authR.stats?.blocked_ips || 0;
        const certWarn = (certsR.certs || []).filter(c => c.days_to_expiry < 30 && !c.is_expired).length;
        const certCrit = (certsR.certs || []).filter(c => c.is_expired || c.days_to_expiry < 7).length;
        const portCrit = (portsR.ports || []).filter(p => p.severity === 'critical').length;
        const portWarn = (portsR.ports || []).filter(p => p.severity === 'warning').length;

        // ACTIVE failures (excluding blocked IPs) drive the tile color
        const authClass = activeFailed > 30 ? 'critical' : (activeFailed > 10 ? 'warning' : 'ok');
        const certClass = certCrit > 0 ? 'critical' : (certWarn > 0 ? 'warning' : 'ok');
        const portClass = portCrit > 0 ? 'critical' : (portWarn > 0 ? 'warning' : 'ok');

        const authSub = (activeFailed === 0 && blocked > 0)
            ? `${blocked} attackers blocked · contained`
            : `${activeFailed} active · ${blocked} IPs blocked · ${totalFailed} total/5m`;

        const tiles = [
            tile(authClass, 'Auth Failures', authSub, null),
            tile(certClass, 'SSL Certificates', `${(certsR.certs || []).length} monitored · ${certWarn} expiring soon`, null),
            tile(portClass, 'Open Ports', `${(portsR.ports || []).filter(p => p.open).length}/${(portsR.ports || []).length} open · ${portCrit} forbidden`, null),
        ];
        const grid = document.getElementById('securityTiles');
        if (grid) grid.innerHTML = tiles.join('');
    } catch (e) { /* silent */ }
}

async function fetchAegisInfra() {
    try {
        const r = await fetch(`${API_BASE}/api/infra`);
        const d = await r.json();

        const backupClass = d.backup.last_status === 'failed' ? 'critical' : (d.backup.is_overdue ? 'warning' : 'ok');
        const ntpClass = d.ntp.is_drifted ? 'warning' : 'ok';
        const updClass = d.os_updates.security_count > 0 ? 'warning' : 'ok';
        const hwClass = d.hardware.has_warning ? 'warning' : 'ok';

        const tiles = [
            tile(backupClass, 'Backup', d.backup.last_status === 'failed'
                ? `Failed: ${d.backup.last_error || 'unknown'}`
                : `Last success ${d.backup.hours_since_last_success}h ago`,
                d.backup.last_status === 'failed' ? { label: 'Retry', handler: 'retryBackup()' } : null),
            tile(ntpClass, 'NTP Sync', `Drift ${d.ntp.drift_seconds}s · server ${d.ntp.server.split('.')[0]}`,
                d.ntp.is_drifted ? { label: 'Sync', handler: 'syncNtp()' } : null),
            tile(updClass, 'OS Updates', `${d.os_updates.pending_count} pending · ${d.os_updates.security_count} security`, null),
            tile(hwClass, 'Hardware', d.hardware.sim_warning || `SMART ${d.hardware.smart_status} · ${d.hardware.cpu_temp_c}°C`, null),
        ];
        const grid = document.getElementById('infraTiles');
        if (grid) grid.innerHTML = tiles.join('');
    } catch (e) { /* silent */ }
}

async function retryBackup() {
    await fetch(`${API_BASE}/api/infra/backup/retry`, { method: 'POST' });
    toast('Backup retry triggered', 'success');
    fetchAegisInfra();
}
async function syncNtp() {
    await fetch(`${API_BASE}/api/infra/ntp/sync`, { method: 'POST' });
    toast('NTP synced', 'success');
    fetchAegisInfra();
}

function updateAegisHealthSummary(items, kind) {
    const el = document.getElementById('aegisHealthSummary');
    if (!el) return;
    const bad = items.filter(i => ['down','critical','failed'].includes(i.status)).length;
    const warn = items.filter(i => ['degraded','warning'].includes(i.status)).length;
    if (bad > 0) {
        el.textContent = `${bad} critical · ${warn} warning`;
        el.className = 'badge danger';
    } else if (warn > 0) {
        el.textContent = `${warn} warning`;
        el.className = 'badge warning';
    } else {
        el.textContent = 'all systems healthy';
        el.className = 'badge success';
    }
}

async function fetchAuthFeed() {
    try {
        const r = await fetch(`${API_BASE}/api/security/auth_events?limit=30`);
        const d = await r.json();
        const events = d.events || [];
        const stats = d.stats || {};

        // Summary badge
        const badge = document.getElementById('authFeedSummary');
        if (badge) {
            if (stats.failed_5m > 0) {
                badge.textContent = `${stats.failed_5m} failures · ${stats.unique_ips} IPs · ${stats.blocked_ips} blocked`;
                badge.className = stats.failed_5m > 30 ? 'badge danger' : 'badge warning';
            } else {
                badge.textContent = 'No activity';
                badge.className = 'badge';
            }
        }

        // List
        const list = document.getElementById('authFeedList');
        if (!list) return;
        if (events.length === 0) return;

        // Render newest-first
        const rows = events.slice(-20).reverse().map(e => {
            const cls = `auth-event ${e.result}`;
            const flag = e.country || '--';
            const resultLabel = e.result === 'success' ? 'OK'
                              : e.result === 'fail_password' ? 'BAD PWD'
                              : e.result === 'fail_user' ? 'NO USER'
                              : 'FAIL';
            return `<div class="${cls}">
                <span class="ts">${escapeHtml(e.ts_human)}</span>
                <span class="svc">${escapeHtml(e.service)}</span>
                <span class="ip">${escapeHtml(e.source_ip)}</span>
                <span class="country">${escapeHtml(flag)}</span>
                <span class="user">${escapeHtml(e.username)}</span>
                <span class="result">${resultLabel}</span>
            </div>`;
        });
        list.innerHTML = rows.join('');
    } catch (e) { /* silent */ }
}

async function showThreatsModal() {
    try {
        const r = await fetch(`${API_BASE}/api/security/auth_events?limit=1`);
        const d = await r.json();
        const threats = d.threats || [];
        if (threats.length === 0) {
            toast('No threats tracked yet', 'info');
            return;
        }
        let html = `<table class="threats-tbl"><thead><tr>
            <th>IP</th><th>Country</th><th>Score</th><th>Failures</th><th>Status</th><th></th>
        </tr></thead><tbody>`;
        threats.sort((a, b) => b.threat_score - a.threat_score).forEach(t => {
            const blockBtn = t.blocked
                ? `<button class="btn btn-sm" onclick="unblockIp('${t.ip}')">Unblock</button>`
                : `<button class="btn btn-sm btn-danger" onclick="blockIp('${t.ip}')">Block</button>`;
            html += `<tr>
                <td><code>${escapeHtml(t.ip)}</code></td>
                <td>${escapeHtml(t.country || '--')}</td>
                <td><strong>${t.threat_score}</strong></td>
                <td>${t.failures_recent}</td>
                <td>${t.blocked ? '<span class="badge danger">BLOCKED</span>' : '<span class="badge">tracked</span>'}</td>
                <td>${blockBtn}</td>
            </tr>`;
        });
        html += '</tbody></table>';
        showInfoModal('IP Threat Tracker', html, 'lock');
    } catch (e) { console.error(e); }
}

async function blockIp(ip) {
    try {
        await fetch(`${API_BASE}/api/security/block_ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, duration_minutes: 15 }),
        });
        toast(`Blocked ${ip} for 15 minutes`, 'success');
        showThreatsModal();
        fetchAuthFeed();
    } catch (e) { toast('Block failed', 'danger'); }
}

async function unblockIp(ip) {
    try {
        await fetch(`${API_BASE}/api/security/block_ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, duration_minutes: 0 }),
        });
        toast(`Unblocked ${ip}`, 'success');
        showThreatsModal();
        fetchAuthFeed();
    } catch (e) { toast('Unblock failed', 'danger'); }
}

async function updatePillars() {
    // Aggregate data from all 4 endpoints to populate pillar KPI cards
    try {
        const [svcR, netR, certsR, portsR, authR, infraR] = await Promise.all([
            fetch(`${API_BASE}/api/services`).then(r => r.json()),
            fetch(`${API_BASE}/api/network`).then(r => r.json()),
            fetch(`${API_BASE}/api/security/certs`).then(r => r.json()),
            fetch(`${API_BASE}/api/security/ports`).then(r => r.json()),
            fetch(`${API_BASE}/api/security/auth_events?limit=1`).then(r => r.json()),
            fetch(`${API_BASE}/api/infra`).then(r => r.json()),
        ]);

        // ─── SERVICES PILLAR ───
        const services = svcR.services || [];
        const upCount = services.filter(s => s.status === 'up').length;
        const downCount = services.filter(s => s.status === 'down').length;
        const degCount = services.filter(s => s.status === 'degraded').length;
        setText('pillarServicesValue', upCount);
        setText('pillarServicesTotal', services.length);
        const svcCard = document.getElementById('pillarServices');
        if (svcCard) {
            svcCard.classList.remove('warning', 'critical');
            if (downCount > 0) {
                svcCard.classList.add('critical');
                setText('pillarServicesMeta', `${downCount} down · ${degCount} degraded`);
            } else if (degCount > 0) {
                svcCard.classList.add('warning');
                setText('pillarServicesMeta', `${degCount} degraded`);
            } else {
                setText('pillarServicesMeta', 'all healthy');
            }
        }
        setText('pillarServicesSub', services.map(s => s.id).join(' · ') || '— monitored');

        // ─── SECURITY PILLAR ───
        // Use active_failed_5m (excludes blocked IPs) — shows whether the threat
        // is currently mitigated. Once auto-block happens, this drops to ~0.
        const activeFailed = authR.stats?.active_failed_5m ?? authR.stats?.failed_5m ?? 0;
        const totalFailed = authR.stats?.failed_5m || 0;
        const blocked = authR.stats?.blocked_ips || 0;
        const certsExpiring = (certsR.certs || []).filter(c => c.days_to_expiry <= 30 && !c.is_expired).length;
        const certsCrit = (certsR.certs || []).filter(c => c.is_expired || c.days_to_expiry <= 7).length;
        const portsCrit = (portsR.ports || []).filter(p => p.severity === 'critical').length;
        const totalIssues = (activeFailed > 10 ? 1 : 0) + certsExpiring + portsCrit;
        setText('pillarSecurityValue', totalIssues);
        const secCard = document.getElementById('pillarSecurity');
        if (secCard) {
            secCard.classList.remove('warning', 'critical');
            if (portsCrit > 0 || activeFailed > 30 || certsCrit > 0) {
                secCard.classList.add('critical');
                setText('pillarSecurityMeta', portsCrit > 0
                    ? `${portsCrit} forbidden port open`
                    : (activeFailed > 30
                        ? `${activeFailed} active threats`
                        : `${certsCrit} certs expiring`));
            } else if (totalIssues > 0) {
                secCard.classList.add('warning');
                setText('pillarSecurityMeta', `${activeFailed} active · ${certsExpiring} certs · ${portsCrit} ports`);
            } else {
                setText('pillarSecurityMeta', blocked > 0
                    ? `${blocked} attackers blocked · contained`
                    : `all clean`);
            }
        }

        // ─── NETWORK PILLAR ───
        const links = netR.links || [];
        const linksOk = links.filter(l => l.status === 'healthy').length;
        const linksDown = links.filter(l => l.status === 'down').length;
        setText('pillarNetworkValue', `${linksOk}/${links.length}`);
        const netCard = document.getElementById('pillarNetwork');
        if (netCard) {
            netCard.classList.remove('warning', 'critical');
            if (linksDown > 0) {
                netCard.classList.add('critical');
                setText('pillarNetworkMeta', `${links.filter(l => l.status === 'down').map(l => l.name).join(', ')} down`);
            } else if (linksOk < links.length) {
                netCard.classList.add('warning');
                setText('pillarNetworkMeta', `${links.length - linksOk} degraded`);
            } else {
                setText('pillarNetworkMeta', 'all reachable');
            }
        }

        // ─── INFRA PILLAR ───
        const issues = [];
        if (infraR.backup?.last_status === 'failed') issues.push('backup');
        if (infraR.backup?.is_overdue) issues.push('backup overdue');
        if (infraR.ntp?.is_drifted) issues.push('NTP drift');
        if (infraR.hardware?.has_warning) issues.push('hardware');
        if (infraR.os_updates?.security_count > 0) issues.push(`${infraR.os_updates.security_count} sec updates`);
        const infraCard = document.getElementById('pillarInfra');
        setText('pillarInfraValue', issues.length === 0 ? 'OK' : issues.length);
        if (infraCard) {
            infraCard.classList.remove('warning', 'critical');
            if (infraR.backup?.last_status === 'failed') {
                infraCard.classList.add('critical');
            } else if (issues.length > 0) {
                infraCard.classList.add('warning');
            }
            setText('pillarInfraMeta', issues.length === 0 ? 'all systems nominal' : issues.join(' · '));
        }

        // Populate compact sysmetrics strip from latest metric (if exists)
        const cpu = parseFloat(document.getElementById('cpuValue')?.textContent || 0);
        const mem = parseFloat(document.getElementById('memValue')?.textContent || 0);
        const disk = parseFloat(document.getElementById('diskValue')?.textContent || 0);
        const net = document.getElementById('netValue')?.textContent || '0';
        const proc = document.getElementById('procValue')?.textContent || '0';
        const ai = document.getElementById('aiScoreValue')?.textContent || '0.00';
        const sm = document.getElementById('sysmetricStrip');
        if (sm) {
            sm.innerHTML = `
                <div class="sysmetric"><span class="sysmetric-label">CPU</span><span class="sysmetric-val">${cpu.toFixed(1)}%</span><div class="sysmetric-bar"><div class="sysmetric-bar-fill" style="width:${Math.min(100,cpu)}%"></div></div></div>
                <div class="sysmetric"><span class="sysmetric-label">Memory</span><span class="sysmetric-val">${mem.toFixed(1)}%</span><div class="sysmetric-bar"><div class="sysmetric-bar-fill" style="width:${Math.min(100,mem)}%"></div></div></div>
                <div class="sysmetric"><span class="sysmetric-label">Disk</span><span class="sysmetric-val">${disk.toFixed(1)}%</span><div class="sysmetric-bar"><div class="sysmetric-bar-fill" style="width:${Math.min(100,disk)}%"></div></div></div>
                <div class="sysmetric"><span class="sysmetric-label">Processes</span><span class="sysmetric-val">${proc}</span></div>
                <div class="sysmetric"><span class="sysmetric-label">Net Conn</span><span class="sysmetric-val">${net}</span></div>
                <div class="sysmetric"><span class="sysmetric-label">Anomaly</span><span class="sysmetric-val">${ai}</span></div>
            `;
        }
    } catch (e) { /* silent */ }
}

function fetchAegisAll() {
    fetchAegisServices();
    fetchAegisNetwork();
    fetchAegisSecurity();
    fetchAegisInfra();
    fetchAuthFeed();
    updatePillars();
}

// ============================================================
// Init
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    connectWS();
    pollCurrentMetric();
    fetchEvents();
    fetchActions();
    fetchSecurity();
    fetchHistory(0.5);
    fetchSystemInfo();
    fetchDetectionStats();
    fetchTopProcesses();
    fetchConnections();
    fetchLlmStatus();
    loadWafPatterns();
    fetchBaseline();
    fetchAegisAll();

    setInterval(updateUptime, 1000);
    setInterval(flowTick, 1000);
    fetchDefenseMode();
    setInterval(fetchLlmStatus, 60000);
    setInterval(fetchEvents, 5000);
    setInterval(fetchActions, 5000);
    setInterval(fetchSecurity, 10000);
    setInterval(fetchDetectionStats, 10000);
    setInterval(fetchTopProcesses, 5000);
    setInterval(fetchConnections, 10000);
    setInterval(fetchBaseline, 5000);
    setInterval(fetchAegisAll, 4000);  // Aegis tile refresh
    setInterval(() => {
        if (!wsConnected || Date.now() - lastMetricTs > 8000) pollCurrentMetric();
    }, 3000);

    // Decision panel buttons
    document.getElementById('showOffendersBtn')?.addEventListener('click', showOffenders);
    document.getElementById('showCatalogBtn')?.addEventListener('click', showActionCatalog);

    // Aegis Auth feed buttons
    document.getElementById('threatsModalBtn')?.addEventListener('click', showThreatsModal);

    // Investigation panel buttons
    document.getElementById('investigateBtn')?.addEventListener('click', () => runInvestigation());
    document.getElementById('showInvestigationsBtn')?.addEventListener('click', showInvestigationHistory);

    // Defense Mode toggle
    fetchDefenseMode();
    document.querySelectorAll('#defenseModeToggle button').forEach(b => {
        b.addEventListener('click', () => setDefenseMode(b.dataset.mode));
    });

    // AI Live Solve manual trigger
    document.getElementById('solveNowBtn')?.addEventListener('click', triggerSolve);

    // Demo Reset
    document.getElementById('demoResetBtn')?.addEventListener('click', demoReset);

    // AI Assistant
    document.getElementById('aiExplainBtn').addEventListener('click', () => aiCall('explain'));
    document.getElementById('aiAnalyzeBtn').addEventListener('click', () => aiCall('analyze'));
    document.getElementById('aiChatBtn').addEventListener('click', aiChat);
    document.getElementById('aiChatInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') aiChat(); });

    // WAF
    document.getElementById('wafSendOneBtn').addEventListener('click', () => wafSend(document.getElementById('wafPatternSelect').value || null, 1));
    document.getElementById('wafSendBurstBtn').addEventListener('click', () => wafSend(document.getElementById('wafPatternSelect').value || null, 5));

    // Retrain
    document.getElementById('retrainBtn').addEventListener('click', async () => {
        if (!confirm('Retrain anomaly model from collected samples?')) return;
        const btn = document.getElementById('retrainBtn');
        btn.disabled = true;
        try {
            const r = await fetch(`${API_BASE}/api/ai/retrain`, { method: 'POST' });
            const d = await r.json();
            toast('Retrain complete', 'success');
            console.log(d);
            fetchLlmStatus();
        } catch (e) { toast('Retrain failed', 'danger'); }
        btn.disabled = false;
    });

    document.getElementById('clearEventsBtn').addEventListener('click', fetchEvents);
    document.getElementById('refreshStatsBtn').addEventListener('click', () => { fetchDetectionStats(); fetchSystemInfo(); });

    document.querySelectorAll('[data-range]').forEach(btn => {
        btn.addEventListener('click', () => fetchHistory(parseFloat(btn.dataset.range)));
    });
});
