'use strict';
/* Flux en direct : WebSocket /ws/live (poussé par le serveur), reconnexion automatique, tail -f filtrable. */
(function () {
  const MAX_ROWS = 500;
  const $ = (id) => document.getElementById(id);
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const consoleEl = $('console');
  const state = { paused: false, pending: [], levels: new Set(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
                  service: '', text: '', services: new Set(), received: 0, retry: 0 };

  // ---------------------------------------------------------------- connexion
  const conn = $('conn');
  const connText = $('conn-text');
  function setConn(s, label) { conn.dataset.state = s; connText.textContent = label; }
  let ws = null;
  let lastBeat = 0;
  function connect() {
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/live';
    setConn('connecting', state.retry ? 'Reconnexion…' : 'Connexion…');
    ws = new WebSocket(url);
    ws.onopen = () => { state.retry = 0; lastBeat = Date.now(); setConn('live', 'Connecté · en direct'); };
    ws.onmessage = (e) => { lastBeat = Date.now(); handle(JSON.parse(e.data)); };
    ws.onclose = () => {
      const delay = Math.min(15000, 1000 * 2 ** state.retry) + Math.random() * 400;
      state.retry += 1;
      setConn('down', 'Déconnecté · nouvel essai dans ' + Math.round(delay / 1000) + ' s');
      setTimeout(connect, delay);
    };
    ws.onerror = () => ws.close();
  }
  // Pas de message depuis 5 s alors que le serveur en envoie un par seconde : la liaison est coupée sans le dire.
  setInterval(() => { if (ws && ws.readyState === 1 && Date.now() - lastBeat > 5000) { setConn('stale', 'Liaison silencieuse…'); ws.close(); } }, 2000);

  function handle(msg) {
    if (msg.type === 'logs') msg.items.forEach(receive);
    else if (msg.type === 'metrics') metrics(msg);
    else if (msg.type === 'alert') toast(msg.alert);
  }

  // ---------------------------------------------------------------- lignes
  const visible = (it) => state.levels.has(it.level) && (!state.service || it.service === state.service) &&
    (!state.text || [it.message, it.ip, it.user, it.action].join(' ').toLowerCase().includes(state.text));

  function receive(it) {
    state.received += 1;
    if (!state.services.has(it.service)) {
      state.services.add(it.service);
      const o = document.createElement('option'); o.value = o.textContent = it.service; $('f-service').appendChild(o);
    }
    if (state.paused) {
      state.pending.push(it);
      if (state.pending.length > MAX_ROWS) state.pending.shift();
      $('pending').textContent = state.pending.length + ' ligne(s) en attente (pause)';
      return;
    }
    append(it);
  }

  function row(it) {
    const r = document.createElement('div');
    r.className = 'ln lv-' + (it.level || 'INFO').toLowerCase();
    r.dataset.level = it.level; r.dataset.service = it.service;
    r.dataset.search = [it.message, it.ip, it.user, it.action].join(' ').toLowerCase();
    const t = document.createElement('time'); t.textContent = (it.ts || '').slice(11, 23); r.appendChild(t);
    const l = document.createElement('b'); l.textContent = it.level; r.appendChild(l);
    const s = document.createElement('span'); s.className = 'svc'; s.textContent = it.service; r.appendChild(s);
    if (it.ip) {
      const a = document.createElement('a'); a.className = 'ip'; a.href = '/search?ip=' + encodeURIComponent(it.ip);
      a.textContent = it.ip + (it.country ? ' · ' + it.country : ''); r.appendChild(a);
    }
    const m = document.createElement('span'); m.className = 'msg'; m.textContent = it.message; r.appendChild(m);
    if (it.outcome === 'failure') r.classList.add('fail');
    if (it.latency_ms != null) r.title = 'Latence : ' + it.latency_ms + ' ms';
    return r;
  }

  function append(it) {
    const empty = $('console-empty'); if (empty) empty.remove();
    const atBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 40;
    const r = row(it);
    if (!visible(it)) r.hidden = true;
    consoleEl.appendChild(r);
    while (consoleEl.childElementCount > MAX_ROWS) consoleEl.firstElementChild.remove();
    if ($('f-scroll').checked && atBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
    countShown();
  }
  function countShown() { $('shown').textContent = consoleEl.querySelectorAll('.ln:not([hidden])').length; }
  function refilter() {
    consoleEl.querySelectorAll('.ln').forEach((r) => {
      r.hidden = !(state.levels.has(r.dataset.level) && (!state.service || r.dataset.service === state.service) &&
                   (!state.text || r.dataset.search.includes(state.text)));
    });
    countShown();
  }

  $('levels').addEventListener('click', (e) => {
    const b = e.target.closest('[data-level]'); if (!b) return;
    const on = !state.levels.has(b.dataset.level);
    if (on) state.levels.add(b.dataset.level); else state.levels.delete(b.dataset.level);
    b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); refilter();
  });
  $('f-service').addEventListener('change', (e) => { state.service = e.target.value; refilter(); });
  $('f-text').addEventListener('input', (e) => { state.text = e.target.value.trim().toLowerCase(); refilter(); });
  $('b-pause').addEventListener('click', (e) => {
    state.paused = !state.paused;
    e.target.textContent = state.paused ? 'Reprendre' : 'Pause';
    e.target.setAttribute('aria-pressed', String(state.paused));
    e.target.classList.toggle('p', state.paused);
    if (!state.paused) { state.pending.splice(0).forEach(append); $('pending').textContent = ''; }
  });
  $('b-clear').addEventListener('click', () => { consoleEl.querySelectorAll('.ln').forEach((r) => r.remove()); countShown(); });

  // ---------------------------------------------------------------- métriques
  const fmtMs = (v) => (v == null ? '—' : v < 1000 ? v + ' ms' : (v / 1000).toFixed(1) + ' s');
  function tween(el, value, fmt) {
    const from = parseFloat(el.dataset.v || '0');
    const to = Number(value) || 0;
    el.dataset.v = to;
    const t0 = performance.now();
    const step = (t) => {
      const k = Math.min(1, (t - t0) / 400);
      el.textContent = fmt(from + (to - from) * k);
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  const rateChart = mkChart('c-rate', [
    { label: 'logs/s', color: '--cyan' }, { label: 'erreurs/min', color: '--cr' }]);
  const latChart = mkChart('c-lat', [{ label: 'médiane', color: '--uv' }, { label: 'p95', color: '--hi' }]);
  function mkChart(id, series) {
    if (typeof Chart === 'undefined') return null;
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.color = css('--mut');
    return new Chart($(id), {
      type: 'line',
      data: { labels: [], datasets: series.map((s) => ({ label: s.label, data: [], borderColor: css(s.color), backgroundColor: css(s.color),
                                                         pointRadius: 0, borderWidth: 2, tension: 0.3 })) },
      options: { animation: { duration: 250 }, maintainAspectRatio: false, plugins: { legend: { position: 'top', align: 'end', labels: { boxWidth: 10 } } },
                 scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: css('--bd') } } } },
    });
  }
  function push(chart, values) {
    if (!chart) return;
    chart.data.labels.push('');
    values.forEach((v, i) => chart.data.datasets[i].data.push(v));
    if (chart.data.labels.length > 120) { chart.data.labels.shift(); chart.data.datasets.forEach((d) => d.data.shift()); }
    chart.update('none');
  }
  function metrics(m) {
    tween($('m-rate'), m.logs_per_s, (v) => v.toFixed(1));
    tween($('m-errors'), m.errors_per_min, (v) => Math.round(v));
    $('m-p50').textContent = fmtMs(m.latency_p50_ms);
    $('m-p95').textContent = 'p95 ' + fmtMs(m.latency_p95_ms);
    $('m-p50').classList.toggle('warn', m.latency_p50_ms != null && m.latency_p50_ms >= 1000);
    tween($('m-active'), m.active_requests, (v) => Math.round(v));
    tween($('m-users'), m.connected_users, (v) => Math.round(v));
    $('m-viewers').textContent = (m.live_viewers || 0) + ' écran(s) « Flux en direct » ouvert(s)';
    $('m-total').textContent = state.received + ' reçue(s) depuis l’ouverture';
    push(rateChart, [m.logs_per_s, m.errors_per_min]);
    push(latChart, [m.latency_p50_ms, m.latency_p95_ms]);
  }

  // ---------------------------------------------------------------- alertes
  function toast(a) {
    const t = document.createElement('a');
    t.className = 'toast sev-' + (a.severity || 'medium'); t.href = '/alerts';
    const b = document.createElement('b'); b.textContent = (a.severity_label || a.severity || '').toUpperCase(); t.appendChild(b);
    t.appendChild(document.createTextNode(' ' + (a.rule_name || 'Alerte') + (a.group ? ' — ' + a.group : '')));
    $('toasts').prepend(t);
    setTimeout(() => t.classList.add('out'), 12000);
    setTimeout(() => t.remove(), 12600);
  }

  connect();
})();
