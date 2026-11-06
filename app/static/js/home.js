'use strict';
(function () {
  initPrefs();
  const blob = document.getElementById('chart-data');
  if (!blob || typeof Chart === 'undefined') return;
  const data = JSON.parse(blob.textContent);
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const LEVEL_COLORS = { DEBUG: '--mut', INFO: '--lo', WARNING: '--me', ERROR: '--hi', CRITICAL: '--cr' };
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.color = css('--mut');
  const grid = { color: css('--bd') };

  const shortLabel = (iso) => (iso && iso.length >= 16 ? iso.slice(5, 16).replace('T', ' ') : iso);
  const el = (id) => document.getElementById(id);
  if (el('chart-timeline')) new Chart(el('chart-timeline'), {
    type: 'line',
    data: { labels: data.timeline.map((b) => shortLabel(b.label)),
            datasets: [{ label: 'Événements', data: data.timeline.map((b) => b.count), borderColor: css('--ac'),
                         backgroundColor: css('--acs'), fill: true, tension: 0.25, pointRadius: 2 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
               scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, grid } } },
  });
  if (data.timeline_interval && el('timeline-sub')) {
    document.getElementById('timeline-sub').textContent = 'Intervalle automatique : ' + data.timeline_interval + ' (UTC).';
  }
  if (el('chart-levels')) new Chart(el('chart-levels'), {
    type: 'doughnut',
    data: { labels: data.levels.map((l) => l.label),
            datasets: [{ data: data.levels.map((l) => l.count), borderColor: css('--sf'),
                         backgroundColor: data.levels.map((l) => css(LEVEL_COLORS[l.label] || '--mut')) }] },
    options: { maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom' } } },
  });
  if (el('chart-services')) new Chart(el('chart-services'), {
    type: 'bar',
    data: { labels: data.services.map((s) => s.label),
            datasets: [{ label: 'Événements', data: data.services.map((s) => s.count), backgroundColor: css('--ac'), borderRadius: 6 }] },
    options: { maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } },
               scales: { x: { beginAtZero: true, grid }, y: { grid: { display: false } } } },
  });
})();

function initPrefs() {
  const box = document.getElementById('customize');
  if (!box) return;
  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  const msg = document.getElementById('prefs-msg');
  const send = async (method, body) => {
    const res = await fetch('/api/dashboard/prefs', { method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) { msg.textContent = 'Enregistrement impossible (HTTP ' + res.status + ').'; return false; }
    return true;
  };
  box.querySelectorAll('input[data-widget]').forEach((input) => {
    input.addEventListener('change', async () => {
      if (await send('PUT', { widgets: { [input.dataset.widget]: input.checked } })) window.location.reload();
    });
  });
  document.getElementById('prefs-reset').addEventListener('click', async () => {
    if (await send('DELETE')) window.location.reload();
  });
}
