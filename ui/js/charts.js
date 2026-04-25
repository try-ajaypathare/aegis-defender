// Chart.js — corporate palette (CSS variable driven for theme support)

let metricsChart = null;
const MAX_POINTS = 120;

function cssVar(name, fallback) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function makeAlphaGradient(ctx, hex, alpha = 0.18) {
    const g = ctx.createLinearGradient(0, 0, 0, 300);
    g.addColorStop(0, hex + Math.round(alpha * 255).toString(16).padStart(2, '0'));
    g.addColorStop(1, hex + '00');
    return g;
}

function initChart() {
    const canvas = document.getElementById('metricsChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Corporate palette pulled from CSS vars (works in both themes)
    const accent  = cssVar('--accent', '#6366f1');
    const warn    = cssVar('--warning', '#f59e0b');
    const danger  = cssVar('--danger', '#ef4444');
    const success = cssVar('--success', '#10b981');
    const text    = cssVar('--text', '#e6e8eb');
    const text2   = cssVar('--text-muted', '#6b7280');
    const border  = cssVar('--border', '#1f2433');

    metricsChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'CPU',
                    data: [],
                    borderColor: accent,
                    backgroundColor: makeAlphaGradient(ctx, accent, 0.18),
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                },
                {
                    label: 'Memory',
                    data: [],
                    borderColor: success,
                    backgroundColor: makeAlphaGradient(ctx, success, 0.14),
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                },
                {
                    label: 'Disk',
                    data: [],
                    borderColor: warn,
                    backgroundColor: makeAlphaGradient(ctx, warn, 0.10),
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                },
                {
                    label: 'Anomaly',
                    data: [],
                    borderColor: danger,
                    backgroundColor: 'transparent',
                    fill: false,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                    borderDash: [4, 4],
                    yAxisID: 'y2',
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: {
                        color: text,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 14,
                        font: { family: 'Inter', size: 12, weight: '500' },
                    },
                },
                tooltip: {
                    backgroundColor: cssVar('--bg-elevated', '#161a26'),
                    borderColor: border,
                    borderWidth: 1,
                    titleColor: text,
                    bodyColor: text,
                    padding: 10,
                    titleFont: { family: 'Inter', weight: '600' },
                    bodyFont: { family: 'JetBrains Mono', size: 11 },
                    cornerRadius: 6,
                    displayColors: true,
                },
            },
            scales: {
                x: {
                    ticks: { color: text2, maxTicksLimit: 8, font: { family: 'JetBrains Mono', size: 10 } },
                    grid: { color: border, drawOnChartArea: false },
                    border: { display: false },
                },
                y: {
                    min: 0, max: 100,
                    ticks: { color: text2, font: { family: 'JetBrains Mono', size: 10 }, callback: v => v + '%' },
                    grid: { color: border },
                    border: { display: false },
                },
                y2: {
                    position: 'right',
                    min: 0, max: 1,
                    ticks: { color: danger, font: { family: 'JetBrains Mono', size: 10 } },
                    grid: { drawOnChartArea: false },
                    border: { display: false },
                },
            },
        },
    });
}

function pushToChart(metric) {
    if (!metricsChart) return;
    const ts = new Date(metric.timestamp || Date.now());
    const label = ts.toLocaleTimeString();
    metricsChart.data.labels.push(label);
    metricsChart.data.datasets[0].data.push(metric.cpu_percent);
    metricsChart.data.datasets[1].data.push(metric.memory_percent);
    metricsChart.data.datasets[2].data.push(metric.disk_percent);
    metricsChart.data.datasets[3].data.push(metric.anomaly_score || 0);
    if (metricsChart.data.labels.length > MAX_POINTS) {
        metricsChart.data.labels.shift();
        metricsChart.data.datasets.forEach(ds => ds.data.shift());
    }
    metricsChart.update('none');
}

function loadHistoryIntoChart(metrics) {
    if (!metricsChart || !Array.isArray(metrics)) return;
    metricsChart.data.labels = metrics.map(m => new Date(m.timestamp).toLocaleTimeString());
    metricsChart.data.datasets[0].data = metrics.map(m => m.cpu_percent);
    metricsChart.data.datasets[1].data = metrics.map(m => m.memory_percent);
    metricsChart.data.datasets[2].data = metrics.map(m => m.disk_percent);
    metricsChart.data.datasets[3].data = metrics.map(m => m.anomaly_score || 0);
    metricsChart.update();
}
