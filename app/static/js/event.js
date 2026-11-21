'use strict';
(function () {
  const { api, eventRows } = window.Sentinel;
  const app = document.getElementById('event-app');
  if (!app) return;
  (async () => {
    const { ok, data } = await api('/api/events/' + encodeURIComponent(app.dataset.eventId));
    if (!ok) {
      const box = document.getElementById('event-error');
      box.textContent = data.message || 'Événement introuvable.';
      box.classList.remove('hidden');
      return;
    }
    const s = data.summary;
    document.getElementById('event-title').textContent = (s.action || 'événement') + ' · ' + (s.outcome || 'inconnu');
    document.getElementById('event-fields').replaceChildren(...eventRows(data));
    document.getElementById('event-message').textContent = s.message;
    document.getElementById('event-source').textContent = JSON.stringify(data.source, null, 2);
    document.getElementById('event-card').classList.remove('hidden');
  })();
})();
