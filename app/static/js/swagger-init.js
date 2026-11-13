'use strict';
window.addEventListener('load', () => {
  const token = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  window.SwaggerUIBundle({
    url: '/api/openapi.json', dom_id: '#swagger', deepLinking: false, persistAuthorization: false,
    requestInterceptor: (req) => { req.headers['X-CSRF-Token'] = token; req.credentials = 'same-origin'; return req; },
  });
});
