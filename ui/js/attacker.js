// Attacker dashboard — professional SaaS design

const API_BASE = window.location.origin;
const DEFENDER_API = 'http://127.0.0.1:8000';

const ATTACK_ICONS = {
    cpu_spike: 'cpu', ram_flood: 'memory', disk_fill: 'hard-drive',
    traffic_flood: 'network', combo: 'layers', fork_bomb: 'package',
    slow_creep: 'trending-up', memory_leak: 'database',
    cryptomining_sim: 'flame', ransomware_sim: 'lock',
};

const PRESETS = {
    cpu_spike:        { light: { cores: 1, duration: 30 }, medium: { cores: 2, duration: 60 }, heavy: { cores: 4, duration: 120 } },
    ram_flood:        { light: { size_mb: 300, duration: 30 }, medium: { size_mb: 1000, duration: 60 }, heavy: { size_mb: 2000, duration: 120 } },
    disk_fill:        { light: { size_mb: 200, duration: 30 }, medium: { size_mb: 500, duration: 60 }, heavy: { size_mb: 1000, duration: 120 } },
    traffic_flood:    { light: { requests_per_second: 100, duration: 30 }, medium: { requests_per_second: 500, duration: 60 }, heavy: { requests_per_second: 2000, duration: 120 } },
    combo:            { light: { intensity: 'low', duration: 60 }, medium: { intensity: 'medium', duration: 120 }, heavy: { intensity: 'high', duration: 180 } },
    fork_bomb:        { light: { count: 10, duration: 30 }, medium: { count: 20, duration: 60 }, heavy: { count: 30, duration: 90 } },
    slow_creep:       { light: { duration: 90 }, medium: { duration: 180 }, heavy: { duration: 300 } },
    memory_leak:      { light: { leak_rate_mb_per_sec: 5, duration: 60 }, medium: { leak_rate_mb_per_sec: 10, duration: 120 }, heavy: { leak_rate_mb_per_sec: 20, duration: 180 } },
    cryptomining_sim: { light: { cores: 1, duration: 60 }, medium: { cores: 2, duration: 120 }, heavy: { cores: 4, duration: 180 } },
    ransomware_sim:   { light: { duration: 20 }, medium: { duration: 40 }, heavy: { duration: 60 } },
};

const ATTACK_PARAM_META = {
    cpu_spike:        [{ name: 'cores', label: 'CPU Cores', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    ram_flood:        [{ name: 'size_mb', label: 'RAM (MB)', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    disk_fill:        [{ name: 'size_mb', label: 'Disk (MB)', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    traffic_flood:    [{ name: 'requests_per_second', label: 'Req/sec', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    combo:            [{ name: 'intensity', label: 'Intensity (low/medium/high)', type: 'text' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    fork_bomb:        [{ name: 'count', label: 'Process count', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    slow_creep:       [{ name: 'duration', label: 'Duration (sec)', type: 'number' }],
    memory_leak:      [{ name: 'leak_rate_mb_per_sec', label: 'Leak rate (MB/sec)', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    cryptomining_sim: [{ name: 'cores', label: 'CPU cores', type: 'number' }, { name: 'duration', label: 'Duration (sec)', type: 'number' }],
    ransomware_sim:   [{ name: 'duration', label: 'Duration (sec)', type: 'number' }],
};

const CATEGORY_META = {
    performance:         { icon: 'activity',  label: 'Performance' },
    resource_exhaustion: { icon: 'package',   label: 'Resource Exhaustion' },
    io:                  { icon: 'hard-drive',label: 'I/O' },
    ai_test:             { icon: 'brain',     label: 'AI Evasion Tests' },
    advanced:            { icon: 'terminal',  label: 'Advanced' },
    security_threat:     { icon: 'skull',     label: 'Security Threat Sims' },
};

let allAttacks = [];
let selectedAttackType = null;
let currentPreset = 'medium';

function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}
function fmt(n, d = 1) { if (n == null || isNaN(n)) return '0.0'; return Number(n).toFixed(d); }
function ic(name, cls = 'icon') { return `<svg class="${cls}"><use href="#i-${name}"/></svg>`; }

function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.25s'; setTimeout(() => el.remove(), 250); }, 3000);
}

// ============================================================
// Live defender preview
// ============================================================
async function pollDefenderMetrics() {
    try {
        const r = await fetch(`${DEFENDER_API}/api/metrics/current`);
        if (!r.ok) throw new Error('not ok');
        const m = await r.json();
        if (!m || Object.keys(m).length === 0) return;
        updateTargetBars(m);
    } catch {
        const sub = document.getElementById('cpuSub');
        if (sub) sub.textContent = 'defender offline';
    }
}

function updateTargetBars(m) {
    const cpu = m.cpu_percent || 0;
    const mem = m.memory_percent || 0;
    const disk = m.disk_percent || 0;
    document.getElementById('cpuValue').textContent = fmt(cpu);
    document.getElementById('memValue').textContent = fmt(mem);
    document.getElementById('diskValue').textContent = fmt(disk);
    document.getElementById('memSub').textContent = `${fmt(m.memory_used_gb, 2)} / ${fmt(m.memory_total_gb, 1)} GB`;
    document.getElementById('diskSub').textContent = `${fmt(m.disk_free_gb, 1)} GB free`;
    setBar('cpuBar', cpu); setBar('memBar', mem); setBar('diskBar', disk);
    setCardState('cpuCard', cpu); setCardState('memCard', mem); setCardState('diskCard', disk);
}

function setBar(id, pct) {
    const el = document.getElementById(id); if (!el) return;
    el.style.width = Math.min(100, Math.max(0, pct || 0)) + '%';
}
function setCardState(cardId, value, warnAt = 70, critAt = 85) {
    const el = document.getElementById(cardId); if (!el) return;
    el.classList.remove('warning', 'critical');
    if (value >= critAt) el.classList.add('critical');
    else if (value >= warnAt) el.classList.add('warning');
}

// ============================================================
// Fetch
// ============================================================
async function fetchAttacks() {
    try {
        const r = await fetch(`${API_BASE}/api/attacks/list`);
        allAttacks = await r.json();
        renderCategories();
    } catch { toast('Failed to load attacks', 'danger'); }
}

async function fetchActive() {
    try {
        const r = await fetch(`${API_BASE}/api/attacks/active`);
        const data = await r.json();
        const el = document.getElementById('activeAttacks');
        const countEl = document.getElementById('activeCount');
        countEl.textContent = `${data.length} running`;
        countEl.className = data.length > 0 ? 'badge danger' : 'badge';

        document.getElementById('attackCount').textContent = data.length;
        document.getElementById('attackCountSub').textContent = data.length === 0 ? 'none active' : `${data.length} attack${data.length > 1 ? 's' : ''}`;
        setBar('attackBar', Math.min(100, data.length * 20));

        if (data.length === 0) {
            el.innerHTML = `<div class="empty">${ic('pause', 'icon empty-icon')}<div>No attacks running. Pick one below.</div></div>`;
            return;
        }
        el.innerHTML = data.map(a => `
            <div class="active-attack">
                <div class="active-attack-icon">${ic(ATTACK_ICONS[a.name] || 'target')}</div>
                <div class="active-attack-info">
                    <div class="active-attack-name">${escapeHtml(a.name)}</div>
                    <div class="active-attack-meta">${a.duration}s / ${a.max_duration}s · ${escapeHtml(JSON.stringify(a.params))}</div>
                </div>
                <button class="btn btn-danger btn-sm" onclick="stopAttack('${a.id}')">
                    ${ic('stop-circle', 'icon icon-sm')}<span class="btn-text">Stop</span>
                </button>
            </div>
        `).join('');
    } catch { /* silent */ }
}

async function fetchHistory() {
    try {
        const r = await fetch(`${API_BASE}/api/attacks/history?limit=30`);
        const data = await r.json();
        const list = document.getElementById('historyList');
        if (!data.length) {
            list.innerHTML = `<li class="empty">${ic('clock', 'icon empty-icon')}<div>No attack history</div></li>`;
            return;
        }
        list.innerHTML = data.map(a => {
            const tagCls = a.detected_by_defender ? 'action' : 'info';
            return `
                <li class="event-item">
                    <span class="event-time">${new Date(a.timestamp).toLocaleTimeString()}</span>
                    <span class="event-tag ${tagCls}">${escapeHtml((a.attack_type || '').toUpperCase())}</span>
                    <span class="event-msg">
                        ${a.duration_seconds || 0}s — stopped by ${escapeHtml(a.stopped_by || 'unknown')}
                        ${a.detected_by_defender ? ' · detected' : ''}
                    </span>
                </li>`;
        }).join('');
    } catch { /* silent */ }
}

function renderCategories() {
    const grouped = {};
    allAttacks.forEach(a => { (grouped[a.category] ||= []).push(a); });
    const order = ['performance', 'resource_exhaustion', 'io', 'ai_test', 'advanced', 'security_threat'];
    const container = document.getElementById('attackCategories');
    container.innerHTML = order.filter(c => grouped[c]).map(cat => {
        const attacks = grouped[cat];
        const meta = CATEGORY_META[cat] || { icon: 'grid', label: cat };
        return `
            <div>
                <div class="section-header">
                    ${ic(meta.icon, 'icon')}
                    <span class="section-title">${escapeHtml(meta.label)}</span>
                    <span class="section-count">${attacks.length} attacks</span>
                </div>
                <div class="attack-grid">
                    ${attacks.map(a => `
                        <button class="attack-btn" onclick="openModal('${a.type}')">
                            <div class="attack-name">
                                ${ic(ATTACK_ICONS[a.type] || 'target', 'icon')}
                                ${escapeHtml(a.name)}
                            </div>
                            <div class="attack-desc">${escapeHtml(a.description.replace(/^\[SIM\]\s*/, ''))}</div>
                        </button>
                    `).join('')}
                </div>
            </div>`;
    }).join('');
}

// ============================================================
// Modal
// ============================================================
function openModal(attackType) {
    selectedAttackType = attackType;
    currentPreset = 'medium';
    const attack = allAttacks.find(a => a.type === attackType);
    if (!attack) return;
    document.getElementById('modalTitle').textContent = attack.name;
    document.getElementById('modalDesc').textContent = attack.description.replace(/^\[SIM\]\s*/, '');
    applyPreset('medium');
    document.getElementById('modal').classList.add('open');
    setTimeout(() => {
        const first = document.getElementById('modalFields').querySelector('input');
        if (first) first.focus();
    }, 100);
}

function applyPreset(presetName) {
    currentPreset = presetName;
    document.querySelectorAll('.preset-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.preset === presetName);
    });
    const preset = (PRESETS[selectedAttackType] || {})[presetName] || {};
    const paramMeta = ATTACK_PARAM_META[selectedAttackType] || [{ name: 'duration', label: 'Duration (sec)', type: 'number' }];
    const fields = document.getElementById('modalFields');
    fields.innerHTML = paramMeta.map(p => {
        const value = preset[p.name] !== undefined ? preset[p.name] : (p.type === 'number' ? 60 : '');
        return `
            <div class="form-group">
                <label class="form-label">${escapeHtml(p.label)}</label>
                <input class="form-input" type="${p.type}" id="param_${p.name}" value="${escapeHtml(String(value))}" />
            </div>`;
    }).join('');
}

function closeModal() {
    document.getElementById('modal').classList.remove('open');
    selectedAttackType = null;
}

async function startAttack() {
    if (!selectedAttackType) return;
    const paramMeta = ATTACK_PARAM_META[selectedAttackType] || [];
    const body = {};
    paramMeta.forEach(p => {
        const el = document.getElementById(`param_${p.name}`);
        if (!el) return;
        body[p.name] = p.type === 'number' ? parseFloat(el.value) : el.value;
    });
    const btn = document.getElementById('modalStart');
    btn.disabled = true;
    try {
        const r = await fetch(`${API_BASE}/api/attacks/${selectedAttackType}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await r.json();
        if (!r.ok) toast('Failed: ' + (data.detail || 'unknown'), 'danger');
        else { toast(`${data.name} started (${currentPreset})`, 'success'); closeModal(); fetchActive(); }
    } catch (e) { toast('Network error: ' + e.message, 'danger'); }
    btn.disabled = false;
}

async function stopAttack(id) {
    try {
        const r = await fetch(`${API_BASE}/api/attacks/${id}/stop`, { method: 'POST' });
        if (r.ok) { toast('Attack stopped', 'success'); fetchActive(); }
    } catch (e) { toast('Stop failed', 'danger'); }
}

async function stopAll() {
    if (!confirm('Stop ALL active attacks?')) return;
    try {
        const r = await fetch(`${API_BASE}/api/attacks/stop_all`, { method: 'POST' });
        const d = await r.json();
        toast(`Stopped ${d.stopped} attack(s)`, 'success');
        fetchActive();
    } catch { toast('Stop-all failed', 'danger'); }
}

// ============================================================
// Init
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    fetchAttacks();
    fetchActive();
    fetchHistory();
    pollDefenderMetrics();

    setInterval(fetchActive, 2000);
    setInterval(fetchHistory, 8000);
    setInterval(pollDefenderMetrics, 2500);

    document.getElementById('killSwitchBtn').addEventListener('click', stopAll);
    document.getElementById('modalCancel').addEventListener('click', closeModal);
    document.getElementById('modalCloseX').addEventListener('click', closeModal);
    document.getElementById('modalStart').addEventListener('click', startAttack);
    document.getElementById('refreshHistoryBtn').addEventListener('click', fetchHistory);
    document.querySelectorAll('.preset-btn').forEach(b => b.addEventListener('click', () => applyPreset(b.dataset.preset)));

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
        if (e.key === 'Enter' && document.getElementById('modal').classList.contains('open')) startAttack();
    });

    // Connection indicator
    const conn = document.getElementById('connIndicator');
    if (conn) { conn.classList.add('connected'); document.getElementById('connText').textContent = 'ready'; }
});

window.stopAttack = stopAttack;
window.openModal = openModal;
