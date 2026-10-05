// Anexa o token CSRF (meta csrf-token) a toda requisição same-origin que altera estado.
(function () {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) return;
  const token = meta.getAttribute('content');
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];

  const originalFetch = window.fetch.bind(window);
  window.fetch = function (input, init = {}) {
    const method = (init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const url = new URL(input instanceof Request ? input.url : input, window.location.href);

    if (!safeMethods.includes(method) && url.origin === window.location.origin) {
      const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      headers.set('X-CSRFToken', token);
      init = { ...init, headers };
    }
    return originalFetch(input, init);
  };

  // Formulários POST criados dinamicamente, sem o campo no template.
  document.addEventListener('submit', function (event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.method.toUpperCase() !== 'POST') return;
    if (form.querySelector('input[name="csrf_token"]')) return;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'csrf_token';
    input.value = token;
    form.appendChild(input);
  }, true);
})();
