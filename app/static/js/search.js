'use strict';
(function () {
  const { el, api, fmtDate, eventRows } = window.Sentinel;
  const form = document.getElementById('search-form');
  if (!form) return;
  const $ = (id) => document.getElementById(id);
  const FIELDS = ['q', 'start', 'end', 'level', 'service', 'outcome', 'ip', 'user', 'upload_id', 'query', 'dsl', 'sort', 'sort_by'];
  let page = 1;
  let pages = 1;

  function params(extra) {
    const p = new URLSearchParams();
    const skip = mode() === 'dsl' ? 'query' : 'dsl';            // the hidden advanced mode is ignored
    FIELDS.forEach((f) => { const v = form.elements[f].value.trim(); if (v && f !== skip) p.set(f, v); });
    Object.entries(extra || {}).forEach(([k, v]) => p.set(k, v));
    return p;
  }

  function fillFromUrl() {
    const p = new URLSearchParams(window.location.search);
    FIELDS.forEach((f) => { if (p.has(f)) form.elements[f].value = p.get(f); });
    page = Math.max(1, Number(p.get('page') || 1));
    openAdvancedIfUsed();
  }

  /* Advanced query (Lucene or Query DSL): only the visible mode is sent. */
  const adv = $('advanced');
  const mode = () => form.querySelector('input[name="adv_mode"]:checked').value;
  function setMode(m) {
    form.querySelector('input[name="adv_mode"][value="' + m + '"]').checked = true;
    adv.querySelectorAll('[data-mode]').forEach((d) => d.classList.toggle('hidden', d.dataset.mode !== m));
  }
  function openAdvancedIfUsed() {
    if (form.elements.dsl.value) { adv.open = true; setMode('dsl'); } else if (form.elements.query.value) { adv.open = true; setMode('query'); }
  }
  form.querySelectorAll('input[name="adv_mode"]').forEach((r) => r.addEventListener('change', () => setMode(mode())));
  adv.querySelectorAll('[data-example]').forEach((b) => b.addEventListener('click', () => {
    setMode(b.dataset.exampleMode);
    const target = form.elements[b.dataset.exampleMode];
    target.value = b.dataset.exampleMode === 'dsl' ? JSON.stringify(JSON.parse(b.dataset.example), null, 2) : b.dataset.example;
    target.focus();
  }));
  adv.querySelectorAll('[data-field]').forEach((c) => c.addEventListener('click', () => {
    const target = form.elements[mode()];
    const insert = mode() === 'dsl' ? '"' + c.dataset.field + '"' : c.dataset.field + ':';
    const at = target.selectionStart ?? target.value.length;
    target.value = target.value.slice(0, at) + insert + target.value.slice(target.selectionEnd ?? at);
    target.focus();
    target.selectionStart = target.selectionEnd = at + insert.length;
  }));
  form.elements.query.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });

  function option(select, items) {
    items.forEach((i) => select.append(el('option', { value: i.value, text: i.value + ' (' + i.count + ')' })));
  }

  async function loadFacets() {
    const { ok, data } = await api('/api/search/facets');
    if (!ok) return;
    option(form.elements.level, data.levels);
    option(form.elements.service, data.services);
    fillFromUrl();
    if (window.location.search) run();
  }

  async function loadHistory() {
    const { ok, data } = await api('/api/search/history?limit=5');
    if (!ok) return;
    $('history').replaceChildren(...data.history.map((h) => {
      const label = h.filters.q || h.filters.query || (h.filters.dsl ? 'DSL : ' + h.filters.dsl.slice(0, 40) : '') || Object.keys(h.filters).join(', ');
      return el('button', { class: 'chip', type: 'button', text: label, onclick: () => {
        FIELDS.forEach((f) => { form.elements[f].value = ''; });
        Object.entries(h.filters).forEach(([k, v]) => { if (form.elements[k]) form.elements[k].value = Array.isArray(v) ? v.join(',') : v; });
        openAdvancedIfUsed();
        page = 1; run();
      } });
    }));
  }

  async function run() {
    $('status').textContent = 'Recherche en cours…';
    const q = params({ page: page, size: 50 });
    history.replaceState(null, '', '?' + q.toString());
    const { ok, data } = await api('/api/search?' + q.toString());
    const body = document.querySelector('#results tbody');
    body.replaceChildren();
    if (!ok) {
      $('status').textContent = (data.details ? data.details.join(' ') : data.message) || 'Erreur de recherche.';
      $('status').classList.add('err-text');
      return;
    }
    $('status').classList.remove('err-text');
    $('es-query').textContent = JSON.stringify(data.es_query, null, 2);
    $('es-query-box').classList.remove('hidden');
    pages = data.pages;
    $('status').textContent = data.total.toLocaleString('fr-FR') + (data.total_exact ? '' : '+') + ' événement(s)' +
      (data.cached ? ' · résultat en cache (≤ 30 s)' : '') + ' · ' + (data.took_ms ?? '?') + ' ms';
    data.hits.forEach((h) => {
      const row = el('tr', { class: 'clickable', tabindex: '0' },
        el('td', { text: fmtDate(h.timestamp) }),
        el('td', {}, el('span', { class: 'pl ' + (h.level === 'ERROR' || h.level === 'CRITICAL' ? 'cr' : h.level === 'WARNING' ? 'me2' : 'mu'), text: h.level || '—' })),
        el('td', { text: h.service || '—' }), el('td', { class: 'mono', text: h.ip || '—' }),
        el('td', { text: h.user || '—' }),
        el('td', { text: h.outcome || '—' }), el('td', { class: 'msg', text: h.message }),
        el('td', {}, el('a', { class: 'btn s', href: '/events/' + encodeURIComponent(h.id), text: 'Détails',
          onclick: (e) => { if (e.ctrlKey || e.metaKey || e.shiftKey) { e.stopPropagation(); return; } e.preventDefault(); e.stopPropagation(); openDetail(h.id, row); } })));
      const open = () => openDetail(h.id, row);
      row.addEventListener('click', open);
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
      body.append(row);
    });
    if (!data.hits.length) body.append(el('tr', {}, el('td', { colspan: '8', text: 'Aucun résultat pour ces critères.' })));
    markSort();
    $('page-info').textContent = 'Page ' + data.page + ' / ' + pages;
    $('prev').disabled = page <= 1;
    $('next').disabled = page >= pages;
    const exp = params();
    $('export-link').href = '/api/search/export?' + exp.toString();
    loadHistory();
  }

  /* Detail modal (KAN-44): same data as /events/<id>, without leaving the result list. */
  const dlg = $('event-dialog');
  let lastRow = null;
  async function openDetail(id, row) {
    lastRow = row;
    $('dlg-error').classList.add('hidden');
    $('dlg-fields').replaceChildren(); $('dlg-message').textContent = 'Chargement…'; $('dlg-source').textContent = '';
    $('dlg-page').href = '/events/' + encodeURIComponent(id);
    if (typeof dlg.showModal === 'function') dlg.showModal(); else { window.location.href = $('dlg-page').href; return; }
    const { ok, data } = await api('/api/events/' + encodeURIComponent(id));
    if (!ok) {
      $('dlg-error').textContent = data.message || 'Événement introuvable.';
      $('dlg-error').classList.remove('hidden'); $('dlg-message').textContent = '';
      return;
    }
    const s = data.summary;
    $('dlg-title').textContent = (s.action || 'événement') + ' · ' + (s.outcome || 'inconnu');
    $('dlg-fields').replaceChildren(...eventRows(data));
    $('dlg-message').textContent = s.message;
    $('dlg-source').textContent = JSON.stringify(data.source, null, 2);
    $('dlg-ip').classList.toggle('hidden', !s.ip);
    if (s.ip) $('dlg-ip').href = '/search?ip=' + encodeURIComponent(s.ip);
  }
  $('dlg-close').addEventListener('click', () => dlg.close());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });       // click on the backdrop
  dlg.addEventListener('close', () => { if (lastRow) lastRow.focus(); });             // focus back to the row

  function markSort() {
    document.querySelectorAll('.thbtn').forEach((b) => {
      const active = b.dataset.sort === form.elements.sort_by.value;
      const asc = form.elements.sort.value === 'asc';
      b.parentElement.setAttribute('aria-sort', active ? (asc ? 'ascending' : 'descending') : 'none');
      b.textContent = b.textContent.replace(/ [▲▼]$/, '') + (active ? (asc ? ' ▲' : ' ▼') : '');
    });
  }
  document.querySelectorAll('.thbtn').forEach((b) => b.addEventListener('click', () => {
    if (form.elements.sort_by.value === b.dataset.sort) form.elements.sort.value = form.elements.sort.value === 'asc' ? 'desc' : 'asc';
    else { form.elements.sort_by.value = b.dataset.sort; form.elements.sort.value = b.dataset.sort === 'timestamp' ? 'desc' : 'asc'; }
    page = 1; run();
  }));
  form.addEventListener('submit', (e) => { e.preventDefault(); page = 1; run(); });
  $('reset-btn').addEventListener('click', () => { setTimeout(() => { page = 1; history.replaceState(null, '', location.pathname); $('status').textContent = 'Lancez une recherche.'; document.querySelector('#results tbody').replaceChildren(); setMode('query'); $('es-query-box').classList.add('hidden'); }, 0); });
  $('prev').addEventListener('click', () => { if (page > 1) { page -= 1; run(); } });
  $('next').addEventListener('click', () => { if (page < pages) { page += 1; run(); } });
  $('prev').disabled = true; $('next').disabled = true;
  loadHistory();
  loadFacets();
})();
