'use strict';
(function () {
  const blob = document.getElementById('chart-data');
  if (!blob || typeof Chart === 'undefined') return;
  const data = JSON.parse(blob.textContent);
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const LEVEL_COLORS = { DEBUG: '--mut', INFO: '--lo', WARNING: '--me', ERROR: '--hi', CRITICAL: '--cr' };
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.color = css('--mut');
  const grid = { color: css('--bd') };

  const shortLabel = (iso) => (iso && iso.length >= 16 ? iso.slice(5, 16).replace('T', ' ') : iso);
  new Chart(document.getElementById('chart-timeline'), {
    type: 'line',
    data: { labels: data.timeline.map((b) => shortLabel(b.label)),
            datasets: [{ label: 'Événements', data: data.timeline.map((b) => b.count), borderColor: css('--ac'),
                         backgroundColor: css('--acs'), fill: true, tension: 0.25, pointRadius: 2 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
               scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, grid } } },
  });
  if (data.timeline_interval) {
    document.getElementById('timeline-sub').textContent = 'Intervalle automatique : ' + data.timeline_interval + ' (UTC).';
  }
  new Chart(document.getElementById('chart-levels'), {
    type: 'doughnut',
    data: { labels: data.levels.map((l) => l.label),
            datasets: [{ data: data.levels.map((l) => l.count), borderColor: css('--sf'),
                         backgroundColor: data.levels.map((l) => css(LEVEL_COLORS[l.label] || '--mut')) }] },
    options: { maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom' } } },
  });
  new Chart(document.getElementById('chart-services'), {
    type: 'bar',
    data: { labels: data.services.map((s) => s.label),
            datasets: [{ label: 'Événements', data: data.services.map((s) => s.count), backgroundColor: css('--ac'), borderRadius: 6 }] },
    options: { maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } },
               scales: { x: { beginAtZero: true, grid }, y: { grid: { display: false } } } },
  });
})();
