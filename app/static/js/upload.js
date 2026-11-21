'use strict';
(function () {
  const { el, api, csrf, fmtDate, fmtBytes } = window.Sentinel;
  const app = document.getElementById('upload-app');
  if (!app) return;
  const canUpload = app.dataset.canUpload === 'true';
  const maxBytes = Number(app.dataset.maxMb) * 1048576;
  const $ = (id) => document.getElementById(id);
  let current = null;       // upload being previewed
  let pollTimer = null;

  function notify(text, kind) {
    const box = $('message');
    if (!box) return;
    box.className = 'alert ' + (kind || 'info');
    box.textContent = text;
  }

  function stateClass(state) { return 'pl state-' + state; }

  async function refreshList() {
    const { ok, data } = await api('/api/uploads');
    if (!ok) return;
    const body = document.querySelector('#uploads-table tbody');
    body.replaceChildren();
    $('uploads-empty').classList.toggle('hidden', data.uploads.length > 0);
    let needsPolling = false;
    data.uploads.forEach((u) => {
      if (u.state === 'ingesting') needsPolling = true;
      const detail = u.failure_reason || (u.stalled ? u.stalled_hint : '');
      body.append(el('tr', {},
        el('td', {}, u.original_name, detail ? el('br') : null, detail ? el('small', { class: 'sub', text: detail }) : null),
        el('td', { text: u.source_type.toUpperCase() }),
        el('td', { text: u.uploaded_by }),
        el('td', {}, el('span', { class: stateClass(u.state), text: u.state_label })),
        el('td', { text: u.stats ? String(u.stats.valid_rows) : '—' }),
        el('td', { text: String(u.indexed_count) }),
        el('td', { text: String(u.rejected_count) }),
        el('td', {}, u.state === 'indexed' || u.state === 'partial'
          ? el('a', { class: 'btn s', href: '/search?q=&upload_id=' + u.id, text: 'Voir dans l’explorateur' }) : null)));
    });
    clearTimeout(pollTimer);
    if (needsPolling) pollTimer = setTimeout(refreshList, 3000);
  }

  function renderPreview(doc) {
    $('preview-card').classList.remove('hidden');
    const s = doc.stats;
    const summary = $('summary');
    summary.replaceChildren(
      el('div', {}, el('b', { text: doc.original_name }), 'Fichier (' + doc.source_type.toUpperCase() + ', ' + fmtBytes(doc.size_bytes) + ')'),
      el('div', {}, el('b', { text: String(s.valid_rows) }), 'lignes valides'),
      el('div', {}, el('b', { text: String(s.invalid_rows) }), 'lignes invalides'),
      el('div', {}, el('b', { text: doc.sha256.slice(0, 12) + '…' }), 'SHA-256'));
    $('warnings').replaceChildren(...doc.warnings.map((w) => el('div', { class: 'alert warn', text: w })));
    $('raw-preview').textContent = doc.preview.raw_lines.join('\n');
    const body = document.querySelector('#events-table tbody');
    body.replaceChildren(...doc.preview.events.map((e) => el('tr', {},
      el('td', { text: String(e.line) }), el('td', { text: fmtDate(e.timestamp) }), el('td', { text: e.ip || '—' }),
      el('td', { text: e.user || '—' }), el('td', { text: e.level }), el('td', { text: e.outcome }),
      el('td', { text: e.service }), el('td', { class: 'msg', text: e.message }))));
    const errs = $('errors');
    errs.replaceChildren();
    if (doc.errors.length) {
      errs.append(el('h3', { text: 'Lignes invalides (ignorées à l’ingestion)' }),
        el('ul', {}, ...doc.errors.slice(0, 20).map((e) => el('li', { text: 'Ligne ' + e.line + ' : ' + e.reason }))));
    }
    $('confirm-btn').disabled = false;
  }

  function showRejected(doc) {
    $('preview-card').classList.add('hidden');
    notify('Fichier rejeté : ' + doc.failure_reason, 'err');
    if (doc.errors && doc.errors.length) {
      notify('Fichier rejeté : ' + doc.failure_reason + ' — exemple : ligne ' + doc.errors[0].line + ' : ' + doc.errors[0].reason, 'err');
    }
  }

  function send(file) {
    $('preview-card').classList.add('hidden');
    $('message').className = 'alert hidden';
    if (!/\.(csv|json|jsonl|ndjson|txt|log)$/i.test(file.name)) { notify('Extension non prise en charge (csv, json, jsonl, ndjson, txt, log).', 'err'); return; }
    if (file.size > maxBytes) { notify('Fichier trop volumineux (maximum ' + app.dataset.maxMb + ' Mo).', 'err'); return; }
    const form = new FormData();
    form.append('file', file);
    form.append('source_type', $('source-type').value);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/uploads');
    xhr.setRequestHeader('X-CSRF-Token', csrf());
    $('progress').classList.remove('hidden');
    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      const pct = Math.round((ev.loaded / ev.total) * 100);
      $('progress-bar').style.width = pct + '%';
      $('progress-label').textContent = pct < 100 ? 'Envoi… ' + pct + ' %' : 'Validation en cours…';
    };
    xhr.onload = () => {
      $('progress').classList.add('hidden');
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
      if (xhr.status === 201) { current = data; renderPreview(data); refreshList(); }
      else if (xhr.status === 422 && data.state === 'rejected') { showRejected(data); refreshList(); }
      else if (xhr.status === 401) { window.location.href = '/login'; }
      else notify(data.message || ('Erreur HTTP ' + xhr.status), 'err');
    };
    xhr.onerror = () => { $('progress').classList.add('hidden'); notify('Erreur réseau pendant l’envoi.', 'err'); };
    xhr.send(form);
  }

  if (canUpload) {
    const input = $('file-input');
    const zone = $('dropzone');
    input.addEventListener('change', () => { if (input.files[0]) send(input.files[0]); input.value = ''; });
    ['dragover', 'dragenter'].forEach((n) => zone.addEventListener(n, (e) => { e.preventDefault(); }));
    zone.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) send(e.dataTransfer.files[0]); });
    zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });

    $('confirm-btn').addEventListener('click', async () => {
      if (!current) return;
      $('confirm-btn').disabled = true;
      const { ok, data } = await api('/api/uploads/' + current.id + '/confirm', { method: 'POST' });
      if (ok) { notify('Ingestion lancée : Logstash traite le fichier. L’état passera à « Indexé » après comptage dans Elasticsearch.', 'info'); $('preview-card').classList.add('hidden'); current = null; }
      else notify(data.message || 'Impossible de lancer l’ingestion.', 'err');
      refreshList();
    });
    $('cancel-btn').addEventListener('click', async () => {
      if (!current) return;
      await api('/api/uploads/' + current.id, { method: 'DELETE' });
      $('preview-card').classList.add('hidden'); current = null; notify('Import annulé.', 'info');
      refreshList();
    });
  }
  refreshList();
})();
