'use strict';
(function () {
  const { el, api, fmtDate } = window.Sentinel;
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
    const rows = [['Horodatage (UTC)', fmtDate(s.timestamp)], ['Niveau', s.level], ['Service', s.service], ['IP source', s.ip],
      ['Utilisateur', s.user], ['Catégorie', s.category], ['Origine du temps', s.time_mode === 'ingest' ? 'heure de réception (pas de temps source)' : 'temps source'],
      ['Import', s.upload_id], ['Index', data.index], ['Identifiant', data.id]];
    const dl = document.getElementById('event-fields');
    dl.replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v || '—' })]));
    document.getElementById('event-message').textContent = s.message;
    document.getElementById('event-source').textContent = JSON.stringify(data.source, null, 2);
    document.getElementById('event-card').classList.remove('hidden');
  })();
})();
