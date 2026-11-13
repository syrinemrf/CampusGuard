'use strict';
/* Alerts page: acknowledge / resolve, run the rules now, manual block / unblock. Reloads the page after an action
   (the server renders the tables; this file only sends the actions). */
(function () {
  const root = document.getElementById('alerts-app');
  if (!root) return;
  const { api } = window.Sentinel;
  const msg = document.getElementById('alerts-msg');
  const show = (text, kind) => { msg.textContent = text; msg.className = 'alert ' + (kind || 'info'); };
  const post = (url, body, method) => api(url, { method: method || 'POST', headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined });
  const done = (res, okText) => {
    if (res.ok) { show(okText, 'ok'); setTimeout(() => window.location.reload(), 600); }
    else show((res.data.details ? res.data.details.join(' ') : res.data.message) || ('Erreur HTTP ' + res.status), 'err');
  };

  document.querySelectorAll('.daybar i').forEach((bar) => { bar.style.height = Math.max(2, Number(bar.dataset.h)) + '%'; });

  document.querySelectorAll('[data-ack]').forEach((b) => b.addEventListener('click', async () => {
    done(await post('/api/alerts/' + b.dataset.ack + '/acknowledge'), 'Alerte prise en compte.');
  }));

  const dlg = document.getElementById('resolve-dialog');
  let target = null;
  document.querySelectorAll('[data-resolve]').forEach((b) => b.addEventListener('click', () => {
    target = b.dataset.resolve;
    document.getElementById('resolve-note').value = '';
    dlg.showModal();
  }));
  document.getElementById('resolve-cancel').addEventListener('click', () => dlg.close());
  document.getElementById('resolve-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    dlg.close();
    done(await post('/api/alerts/' + target + '/resolve', { note: document.getElementById('resolve-note').value }), 'Alerte résolue.');
  });

  const run = document.getElementById('run-now');
  if (run) run.addEventListener('click', async () => {
    run.disabled = true;
    const res = await post('/api/alerts/run');
    run.disabled = false;
    done(res, res.ok ? `Cycle terminé : ${res.data.rules} règle(s), ${res.data.created} nouvelle(s) alerte(s), ` +
      `${res.data.updated} mise(s) à jour, ${res.data.suppressed} en cooldown, ${res.data.errors} erreur(s).` : '');
  });

  document.querySelectorAll('[data-unblock]').forEach((b) => b.addEventListener('click', async () => {
    done(await post('/api/blocklist/' + encodeURIComponent(b.dataset.unblock), null, 'DELETE'), 'IP débloquée.');
  }));
  const form = document.getElementById('block-form');
  if (form) form.addEventListener('submit', async (e) => {
    e.preventDefault();
    done(await post('/api/blocklist', { ip: form.elements.ip.value.trim(), minutes: Number(form.elements.minutes.value),
      reason: form.elements.reason.value.trim() }), 'IP bloquée.');
  });
  if (window.location.hash) {
    const row = document.querySelector(window.location.hash);
    if (row) row.classList.add('flash-row');
  }
})();
