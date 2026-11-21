'use strict';
/* Centre de pilotage: synthesis charts (Chart.js, data embedded as JSON: no inline script) + customisation panel. */
(function () {
  const blob = document.getElementById('chart-data');
  if (blob && typeof Chart !== 'undefined') {
    const data = JSON.parse(blob.textContent);
    const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const LEVEL = { DEBUG: '--mut', INFO: '--lo', WARNING: '--me', ERROR: '--hi', CRITICAL: '--cr' };
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.color = css('--mut');
    const short = (iso) => (iso && iso.length >= 16 ? iso.slice(5, 16).replace('T', ' ') : iso);
    const tl = document.getElementById('chart-timeline');
    if (tl) {
      const ctx = tl.getContext('2d');
      const fill = ctx.createLinearGradient(0, 0, 0, 180);
      fill.addColorStop(0, 'rgba(10,169,160,.32)'); fill.addColorStop(1, 'rgba(106,76,240,.02)');
      new Chart(tl, {
        type: 'line',
        data: { labels: data.timeline.map((b) => short(b.label)),
                datasets: [{ label: 'Événements', data: data.timeline.map((b) => b.count), borderColor: css('--cyan') || css('--ac'),
                             backgroundColor: fill, fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
                   scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 6 } }, y: { beginAtZero: true, grid: { color: css('--bd') } } } },
      });
    }
    const lv = document.getElementById('chart-levels');
    if (lv) new Chart(lv, {
      type: 'doughnut',
      data: { labels: data.levels.map((l) => l.label),
              datasets: [{ data: data.levels.map((l) => l.count), borderWidth: 2, borderColor: css('--sf'),
                           backgroundColor: data.levels.map((l) => css(LEVEL[l.label] || '--mut')) }] },
      options: { maintainAspectRatio: false, cutout: '64%', plugins: { legend: { position: 'right' } } },
    });
  }

  const box = document.getElementById('customize');
  if (!box) return;
  const { api } = window.Sentinel;
  const msg = document.getElementById('prefs-msg');
  const send = async (method, body) => {
    const res = await api('/api/dashboard/prefs', { method, headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined });
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
})();
