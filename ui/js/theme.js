// Theme management — dark/light toggle with localStorage persistence

const THEME_KEY = 'argus-theme';

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.querySelectorAll('[data-theme-set]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.themeSet === theme);
    });
    try { localStorage.setItem(THEME_KEY, theme); } catch {}
}

function initTheme() {
    let saved;
    try { saved = localStorage.getItem(THEME_KEY); } catch {}
    const theme = saved || 'dark';
    applyTheme(theme);

    document.querySelectorAll('[data-theme-set]').forEach(btn => {
        btn.addEventListener('click', () => {
            applyTheme(btn.dataset.themeSet);
            // Trigger chart redraw if present
            if (typeof metricsChart !== 'undefined' && metricsChart) {
                try { metricsChart.destroy(); if (typeof initChart === 'function') initChart(); } catch {}
            }
        });
    });
}

// Apply theme ASAP to avoid flash
(function () {
    try {
        const saved = localStorage.getItem(THEME_KEY);
        if (saved) document.documentElement.setAttribute('data-theme', saved);
    } catch {}
})();

document.addEventListener('DOMContentLoaded', initTheme);
