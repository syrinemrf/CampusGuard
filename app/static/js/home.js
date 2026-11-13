'use strict';
/* Centre de pilotage: only the customisation panel needs JavaScript (everything else is server-rendered). */
(function () {
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
