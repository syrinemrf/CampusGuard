'use strict';
/* Rule editor: fill from a row, test without saving (POST /api/alerts/rules/test), save (admin), toggle, delete,
   and the demo webhook inbox. Dynamic text through textContent only. */
(function () {
  const root = document.getElementById('rules-app');
  if (!root) return;
  const { el, api, fmtDate } = window.Sentinel;
  const isAdmin = root.dataset.admin === 'true';
  const rules = JSON.parse(document.getElementById('rules-data').textContent);
  const form = document.getElementById('rule-form');
  const msg = document.getElementById('rules-msg');
  const show = (text, kind) => { msg.textContent = text; msg.className = 'alert ' + (kind || 'info'); msg.scrollIntoView({ block: 'nearest' }); };
  const errText = (res) => (res.data.details ? res.data.details.join(' ') : res.data.message) || ('Erreur HTTP ' + res.status);
  const send = (url, method, body) => api(url, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  let editing = null;

  function syncType() {
    if (!form) return;
    const t = form.elements.type.value;
    form.querySelectorAll('[data-for]').forEach((f) => f.classList.toggle('hidden', f.dataset.for !== t));
  }

  function read() {
    const f = form.elements;
    const hours = f.outside_hours.value.trim();
    const m = hours.match(/^(\d{1,2})\s*[-–]\s*(\d{1,2})$/);
    return { id: f.id.value.trim(), name: f.name.value.trim(), description: f.description.value.trim(), type: f.type.value,
      query: f.query.value.trim(), window: f.window.value, group_by: f.group_by.value, threshold: Number(f.threshold.value),
      distinct_field: f.distinct_field.value, pattern: f.pattern.value, outside_hours: m ? [Number(m[1]), Number(m[2])] : null,
      severity: f.severity.value, cooldown_minutes: Number(f.cooldown_minutes.value), enabled: f.enabled.checked,
      actions: { email: f.email.checked, webhook: f.webhook.checked, block_ip: f.block_ip.checked } };
  }

  function fill(r) {
    const f = form.elements;
    editing = r.id;
    f.id.value = r.id; f.id.readOnly = true; f.name.value = r.name; f.description.value = r.description || '';
    f.type.value = r.type; f.query.value = r.query || ''; f.window.value = r.window; f.group_by.value = r.group_by || '';
    f.threshold.value = r.threshold; f.distinct_field.value = r.distinct_field || 'user.name'; f.pattern.value = r.pattern || '';
    f.outside_hours.value = r.outside_hours ? r.outside_hours.join('-') : ''; f.severity.value = r.severity;
    f.cooldown_minutes.value = r.cooldown_minutes; f.enabled.checked = r.enabled;
    f.email.checked = r.actions.email; f.webhook.checked = r.actions.webhook; f.block_ip.checked = r.actions.block_ip;
    document.getElementById('editor-title').textContent = (isAdmin ? 'Modifier : ' : 'Tester : ') + r.name;
    syncType();
    document.getElementById('editor').scrollIntoView({ behavior: 'smooth' });
  }

  document.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => fill(rules.find((r) => r.id === b.dataset.edit))));
  if (form) {
    form.elements.type.addEventListener('change', syncType);
    syncType();
    document.getElementById('rule-new').addEventListener('click', () => {
      editing = null; form.elements.id.readOnly = false;
      document.getElementById('editor-title').textContent = 'Nouvelle règle';
      setTimeout(syncType, 0);
    });
    document.getElementById('rule-test').addEventListener('click', async () => {
      const res = await send('/api/alerts/rules/test', 'POST', read());
      const box = document.getElementById('test-result');
      box.classList.remove('hidden');
      if (!res.ok) {
        document.getElementById('test-summary').textContent = errText(res);
        document.getElementById('test-groups').replaceChildren();
        document.getElementById('test-query').textContent = '';
        return;
      }
      document.getElementById('test-summary').textContent = res.data.would_trigger
        ? `La règle déclencherait maintenant ${res.data.would_trigger} alerte(s) :`
        : 'La règle ne déclencherait aucune alerte sur les données actuelles (fenêtre glissante).';
      document.getElementById('test-groups').replaceChildren(...res.data.descriptions.map((d) => el('li', { text: '• ' + d })));
      document.getElementById('test-query').textContent = JSON.stringify(res.data.es_query, null, 2);
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!isAdmin) return;
      const body = read();
      const res = editing ? await send('/api/alerts/rules/' + editing, 'PUT', body) : await send('/api/alerts/rules', 'POST', body);
      if (res.ok) { show('Règle enregistrée.', 'ok'); setTimeout(() => window.location.reload(), 600); } else show(errText(res), 'err');
    });
  }
  document.querySelectorAll('[data-toggle]').forEach((b) => b.addEventListener('click', async () => {
    const enabled = b.getAttribute('aria-checked') !== 'true';
    const res = await send('/api/alerts/rules/' + b.dataset.toggle + '/enabled', 'POST', { enabled });
    if (res.ok) { b.classList.toggle('on', enabled); b.setAttribute('aria-checked', String(enabled)); show(enabled ? 'Règle activée.' : 'Règle désactivée.', 'ok'); }
    else show(errText(res), 'err');
  }));
  document.querySelectorAll('[data-delete]').forEach((b) => b.addEventListener('click', async () => {
    const res = await send('/api/alerts/rules/' + b.dataset.delete, 'DELETE');
    if (res.ok) { show('Règle supprimée.', 'ok'); setTimeout(() => window.location.reload(), 600); } else show(errText(res), 'err');
  }));

  const inbox = document.getElementById('inbox');
  if (inbox) (async () => {
    const res = await api('/api/notifications/demo');
    if (!res.ok) { inbox.replaceChildren(el('li', { class: 'sub', text: errText(res) })); return; }
    if (!res.data.webhooks.length) { inbox.replaceChildren(el('li', { class: 'sub', text: 'Aucun webhook reçu pour le moment.' })); return; }
    inbox.replaceChildren(...res.data.webhooks.map((w) => el('li', {},
      el('small', { class: 'mu', text: fmtDate(w.received_at) + ' UTC' }),
      el('pre', { class: 'raw', text: JSON.stringify(w.payload, null, 2) }))));
  })();
})();
