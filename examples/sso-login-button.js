/*
 * Jellyfin OIDC — inject an SSO button above the password form on /web/#/login.html.
 * Designed for the "JS Injector" plugin (runs on every page).
 *
 * Pairs with auto-sso-redirect.js but works standalone too.
 */
(function () {
  'use strict';

  var PROVIDER_ID  = 'authentik';
  var BUTTON_TEXT  = 'Sign in with authentik';
  var BUTTON_COLOR = '#fd4b2d';
  var START_URL    = '/sso/OIDC/Start/' + PROVIDER_ID;
  var BTN_ID       = 'oidc-sso-button';

  if (/^\/sso\/OIDC\//i.test(location.pathname)) return;

  function onLoginRoute() {
    return /(^|#)\/?login\.html\b/i.test(location.hash || '');
  }

  function injectButton() {
    if (!onLoginRoute()) { removeButton(); return; }
    if (document.getElementById(BTN_ID)) return;

    var form = document.querySelector(
      '.manualLoginForm, #loginPage form, .padded-left.padded-right form, [data-role="page"] form'
    );
    if (!form) return;

    var wrap = document.createElement('div');
    wrap.id = BTN_ID;
    wrap.style.cssText = 'margin:1em 0;text-align:center;';

    var btn = document.createElement('a');
    btn.href = START_URL;
    btn.textContent = BUTTON_TEXT;
    btn.style.cssText =
      'display:block;margin:0 auto;padding:0.8em 1.5em;background:' + BUTTON_COLOR +
      ';color:#fff;text-decoration:none;border-radius:4px;font-size:1em;max-width:320px;' +
      'font-weight:600;letter-spacing:0.02em;';

    var sep = document.createElement('div');
    sep.textContent = '— or sign in with password —';
    sep.style.cssText = 'margin:1em 0 0.5em;color:#888;font-size:0.9em;';

    wrap.appendChild(btn);
    wrap.appendChild(sep);
    form.parentNode.insertBefore(wrap, form);
  }

  function removeButton() {
    var el = document.getElementById(BTN_ID);
    if (el) el.remove();
  }

  // The login form mounts asynchronously and re-mounts on SPA navigation,
  // so observe the DOM rather than relying on a single DOMContentLoaded fire.
  var observer = new MutationObserver(injectButton);
  observer.observe(document.documentElement, { childList: true, subtree: true });

  window.addEventListener('hashchange', injectButton);
  injectButton();
})();
