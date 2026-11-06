'use strict';
(function () {
  const { el, api, fmtDate } = window.Sentinel;
  const form = document.getElementById('search-form');
  if (!form) return;
  const $ = (id) => document.getElementById(id);
  const FIELDS = ['q', 'start', 'end', 'level', 'service', 'outcome', 'ip', 'user', 'upload_id', 'sort', 'sort_by'];
  let page = 1;
  let pages = 1;

  function params(extra) {
    const p = new URLSearchParams();
    FIELDS.forEach((f) => { const v = form.elements[f].value.trim(); if (v) p.set(f, v); });
    Object.entries(extra || {}).forEach(([k, v]) => p.set(k, v));
    return p;
  }

  function fillFromUrl() {
    const p = new URLSearchParams(window.location.search);
    FIELDS.forEach((f) => { if (p.has(f)) form.elements[f].value = p.get(f); });
    page = Math.max(1, Number(p.get('page') || 1));
  }

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
      const label = h.filters.q || Object.keys(h.filters).join(', ');
      return el('button', { class: 'chip', type: 'button', text: label, onclick: () => {
        FIELDS.forEach((f) => { form.elements[f].value = ''; });
        Object.entries(h.filters).forEach(([k, v]) => { if (form.elements[k]) form.elements[k].value = Array.isArray(v) ? v.join(',') : v; });
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
      return;
    }
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
        el('td', {}, el('a', { class: 'btn s', href: '/events/' + encodeURIComponent(h.id), text: 'Détails', onclick: (e) => e.stopPropagation() })));
      const open = () => { window.location.href = '/events/' + encodeURIComponent(h.id); };
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
  $('reset-btn').addEventListener('click', () => { setTimeout(() => { page = 1; history.replaceState(null, '', location.pathname); $('status').textContent = 'Lancez une recherche.'; document.querySelector('#results tbody').replaceChildren(); }, 0); });
  $('prev').addEventListener('click', () => { if (page > 1) { page -= 1; run(); } });
  $('next').addEventListener('click', () => { if (page < pages) { page += 1; run(); } });
  $('prev').disabled = true; $('next').disabled = true;
  loadHistory();
  loadFacets();
})();
