'use strict';
/* Shared helpers. All dynamic text is inserted with textContent (no innerHTML) to avoid XSS. */
window.Sentinel = (function () {
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    });
    children.flat().forEach((c) => {
      if (c === null || c === undefined) return;
      node.append(c.nodeType ? c : document.createTextNode(String(c)));
    });
    return node;
  }

  async function api(path, options) {
    const opts = Object.assign({ method: 'GET', headers: {}, credentials: 'same-origin' }, options || {});
    if (opts.method !== 'GET') opts.headers['X-CSRF-Token'] = csrf();
    const response = await fetch(path, opts);
    let data = null;
    try { data = await response.json(); } catch (e) { /* non-JSON body */ }
    if (response.status === 401) { window.location.href = '/login'; }
    return { ok: response.ok, status: response.status, data: data || {} };
  }

  const fmtDate = (iso) => (iso ? iso.replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '') : '—');
  const fmtBytes = (n) => (n < 1024 ? n + ' o' : n < 1048576 ? (n / 1024).toFixed(1) + ' Ko' : (n / 1048576).toFixed(1) + ' Mo');

  // Theme (per-viewer convenience only; works without storage).
  const root = document.documentElement;
  try { const t = localStorage.getItem('sentinel-theme'); if (t) root.setAttribute('data-theme', t); } catch (e) { /* ignore */ }
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.addEventListener('click', () => {
      const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('sentinel-theme', next); } catch (e) { /* ignore */ }
    });
  });

  return { csrf, el, api, fmtDate, fmtBytes };
})();
