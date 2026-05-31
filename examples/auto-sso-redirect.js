/*
 * Jellyfin OIDC — auto-redirect the login page to your OIDC provider.
 * Designed for the "JS Injector" Jellyfin plugin (runs on every page).
 *
 * What it does:
 *   1. On the Jellyfin login route, redirect to the OIDC Start URL.
 *   2. Fail safe: if we bounce back to login too quickly, we're looping —
 *      stop redirecting and show a manual sign-in link instead.
 *   3. React to client-side navigation (hash/history) and session changes
 *      (login completing, credentials cleared) without a full reload.
 *
 * Escape hatch: append ?nosso=1 to the URL (works in the query or the hash,
 *   e.g. /web/?nosso=1#/login.html) to suppress auto-redirect for that tab.
 */
(function () {
  'use strict';

  const PROVIDER_ID = 'authentik';
  const START_URL   = '/sso/OIDC/Start/' + PROVIDER_ID;
  const STORAGE_KEY = 'oidc-auto-sso';

  // If we redirect, land back on login, and would redirect again all within
  // this window, that's a loop — bail. One honest round-trip takes longer.
  const LOOP_WINDOW_MS = 10 * 1000;

  // Never run on the OIDC callback routes themselves — they set credentials
  // then redirect to '/'. Interfering there is what causes real loops.
  if (/^\/sso\/OIDC\//i.test(location.pathname)) return;

  // --- state ----------------------------------------------------------------

  function readLastRedirect() {
    const v = parseInt(sessionStorage.getItem(STORAGE_KEY), 10);
    return isNaN(v) ? 0 : v;
  }
  function markRedirect() {
    try { sessionStorage.setItem(STORAGE_KEY, String(Date.now())); } catch (e) {}
  }
  function clearRedirect() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
  }

  // --- predicates -----------------------------------------------------------

  function onLoginRoute() {
    // jellyfin-web is a hash-routed SPA. Older builds use #/login.html,
    // newer builds use #/login; both may carry ?serverid=...&url=...
    return /^#\/?login(\.html)?(\?|$)/i.test(location.hash || '');
  }

  function hasSession() {
    try {
      const parsed = JSON.parse(localStorage.getItem('jellyfin_credentials'));
      return !!(parsed && parsed.Servers &&
                parsed.Servers.some(function (s) { return s.AccessToken; }));
    } catch (e) { return false; }
  }

  function userBailed() {
    // Jellyfin stuffs query params inside the hash, so check both.
    return /[?&]nosso=1\b/.test(location.search) ||
           /[?&]nosso=1\b/.test(location.hash || '');
  }

  function looping() {
    const last = readLastRedirect();
    return last !== 0 && (Date.now() - last) < LOOP_WINDOW_MS;
  }

  // --- fallback UI ----------------------------------------------------------

  function showFallback() {
    if (document.getElementById('oidc-auto-sso-notice')) return;

    const div = document.createElement('div');
    div.id = 'oidc-auto-sso-notice';
    div.style.cssText = 'margin:1em auto;padding:0.8em 1em;max-width:420px;' +
      'background:#332;color:#fda;border-radius:4px;text-align:center;' +
      'font-size:0.9em;position:relative;z-index:9999;';

    const msg = document.createElement('div');
    msg.textContent = 'Automatic SSO is paused (loop detected or manually skipped).';

    const a = document.createElement('a');
    a.href = START_URL;
    a.textContent = 'Sign in with ' + PROVIDER_ID;
    a.style.cssText = 'display:inline-block;margin-top:0.5em;color:#9cf;' +
      'text-decoration:underline;';
    a.addEventListener('click', clearRedirect);

    div.appendChild(msg);
    div.appendChild(a);
    (document.body || document.documentElement).appendChild(div);
  }

  function hideFallback() {
    const el = document.getElementById('oidc-auto-sso-notice');
    if (el) el.remove();
  }

  // --- main -----------------------------------------------------------------

  function evaluate() {
    // A live session means login is done: clear loop state and any notice.
    if (hasSession()) { clearRedirect(); hideFallback(); return; }

    if (!onLoginRoute()) return;

    if (userBailed() || looping()) { showFallback(); return; }

    markRedirect();
    location.replace(START_URL);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', evaluate, { once: true });
  } else {
    evaluate();
  }

  // Client-side navigation into/out of the login route.
  window.addEventListener('hashchange', evaluate);
  window.addEventListener('popstate', evaluate);

  // Session changes from another tab (login completes, or credentials cleared).
  window.addEventListener('storage', function (e) {
    if (e.key === 'jellyfin_credentials' || e.key === null) evaluate();
  });
})();
