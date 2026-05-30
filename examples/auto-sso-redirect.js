/*
 * Jellyfin OIDC — auto-redirect to authentik on the login page.
 * Designed for the "JS Injector" Jellyfin plugin (script runs on every page).
 *
 * Loop protection:
 *   - Skips on any /sso/OIDC/* path (so the callback page can finish its work).
 *   - Bails if URL contains ?nosso=1 — manual escape hatch, bookmark
 *     https://your-jellyfin/web/?nosso=1#/login.html if you ever get stuck.
 *   - sessionStorage attempt counter: >= MAX_ATTEMPTS inside COOLDOWN_MS = stop
 *     auto-redirecting and show a manual fallback link.
 *   - Cleared once a valid Jellyfin session is detected.
 */
(function () {
  'use strict';

  const PROVIDER_ID  = 'authentik';
  const START_URL    = '/sso/OIDC/Start/' + PROVIDER_ID;
  const COOLDOWN_MS  = 60 * 1000;
  const MAX_ATTEMPTS = 2;
  const STORAGE_KEY  = 'oidc-auto-sso';

  // Never run on the OIDC routes themselves — the callback page sets
  // credentials then redirects to '/'. Interfering here causes real loops.
  if (/^\/sso\/OIDC\//i.test(location.pathname)) return;

  function onLoginRoute() {
    // Jellyfin-web is a hash-routed SPA. Older builds use #/login.html,
    // newer builds use #/login (both may carry ?serverid=...&url=...).
    return /^#\/?login(\.html)?(\?|$)/i.test(location.hash || '');
  }

  function hasSession() {
    try {
      const raw = localStorage.getItem('jellyfin_credentials');
      if (!raw) return false;
      const parsed = JSON.parse(raw);
      return !!(parsed && parsed.Servers && parsed.Servers.some(function (s) { return s.AccessToken; }));
    } catch (e) { return false; }
  }

  function userBailed() {
    // Check both the real query string and the hash (Jellyfin puts query
    // params inside the hash, e.g. #/login?serverid=...&nosso=1).
    return /[?&]nosso=1\b/.test(location.search) ||
           /[?&]nosso=1\b/.test(location.hash || '');
  }

  function readState() {
    try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY)) || { n: 0, t: 0 }; }
    catch (e) { return { n: 0, t: 0 }; }
  }
  function writeState(s) {
    try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch (e) {}
  }
  function clearState() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
  }

  function tooManyAttempts() {
    const s = readState();
    if (Date.now() - s.t > COOLDOWN_MS) return false;
    return s.n >= MAX_ATTEMPTS;
  }
  function recordAttempt() {
    const s = readState();
    const now = Date.now();
    if (now - s.t > COOLDOWN_MS) s.n = 0;
    s.n += 1;
    s.t = now;
    writeState(s);
  }

  function showFallback() {
    if (document.getElementById('oidc-auto-sso-notice')) return;
    const div = document.createElement('div');
    div.id = 'oidc-auto-sso-notice';
    div.style.cssText = 'margin:1em auto;padding:0.8em 1em;max-width:420px;background:#332;color:#fda;border-radius:4px;text-align:center;font-size:0.9em;position:relative;z-index:9999;';
    const msg = document.createElement('div');
    msg.textContent = 'Automatic SSO is paused (loop detected or manually skipped).';
    const a = document.createElement('a');
    a.href = START_URL;
    a.textContent = 'Sign in with ' + PROVIDER_ID;
    a.style.cssText = 'display:inline-block;margin-top:0.5em;color:#9cf;text-decoration:underline;';
    a.addEventListener('click', function () { clearState(); });
    div.appendChild(msg);
    div.appendChild(a);
    (document.body || document.documentElement).appendChild(div);
  }

  function maybeRedirect() {
    if (hasSession()) { clearState(); return; }
    if (!onLoginRoute()) return;
    if (userBailed()) { showFallback(); return; }
    if (tooManyAttempts()) { showFallback(); return; }

    recordAttempt();
    location.replace(START_URL);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', maybeRedirect, { once: true });
  } else {
    maybeRedirect();
  }
  // SPA navigation into #/login.html after the page is already loaded.
  window.addEventListener('hashchange', maybeRedirect);
})();
