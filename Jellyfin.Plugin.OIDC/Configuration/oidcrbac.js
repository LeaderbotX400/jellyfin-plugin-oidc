var pluginId = 'd4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90';
var cfg = null;
var libs = {};

function esc(str) {
    var d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function gval(view, id) {
    var el = view.querySelector('#' + id);
    return el ? el.value : '';
}

function gchk(view, id) {
    var el = view.querySelector('#' + id);
    return el ? el.checked : false;
}

// ── Render helpers — emit Jellyfin's stock dashboard markup ───────────────────

// Standard text/number/password input — Jellyfin's <input is="emby-input">
// renders the label itself via the label="" attribute.
function fld(label, type, id, value, placeholder, fullwidth) {
    return '<div class="inputContainer' + (fullwidth ? ' oidc-grid-full' : '') + '">' +
        '<input is="emby-input" type="' + type + '" id="' + id + '"' +
        ' label="' + esc(label) + '"' +
        ' value="' + esc(String(value == null ? '' : value)) + '"' +
        (placeholder ? ' placeholder="' + esc(placeholder) + '"' : '') +
        ' />' +
        '</div>';
}

// Color input — native <input type="color">, can't use emby-input.
function fldColor(label, id, value) {
    return '<div class="inputContainer">' +
        '<label class="inputLabel inputLabelUnfocused" for="' + id + '">' + esc(label) + '</label>' +
        '<div><input class="oidc-color-input" type="color" id="' + id + '" value="' + esc(value || '#4285F4') + '" /></div>' +
        '</div>';
}

// Description-bearing input: same as fld() with a fieldDescription appended.
function fldDesc(label, type, id, value, desc, fullwidth) {
    return '<div class="inputContainer' + (fullwidth ? ' oidc-grid-full' : '') + '">' +
        '<input is="emby-input" type="' + type + '" id="' + id + '"' +
        ' label="' + esc(label) + '"' +
        ' value="' + esc(String(value == null ? '' : value)) + '" />' +
        '<div class="fieldDescription">' + esc(desc) + '</div>' +
        '</div>';
}

function chk(id, label, checked) {
    return '<div class="checkboxContainer">' +
        '<label>' +
        '<input is="emby-checkbox" type="checkbox" id="' + id + '"' + (checked ? ' checked' : '') + ' />' +
        '<span>' + esc(label) + '</span>' +
        '</label>' +
        '</div>';
}

// Checkbox with a short description rendered beneath the label.
// Title + description live in a single flex column inside the <label> so the
// column is vertically centered against the checkbox (see CSS in configPage.html).
function chkDesc(id, label, checked, desc) {
    return '<div class="checkboxContainer checkboxContainer-withDescription">' +
        '<label>' +
        '<input is="emby-checkbox" type="checkbox" id="' + id + '"' + (checked ? ' checked' : '') + ' />' +
        '<span class="oidc-chk-text">' +
            '<span class="oidc-chk-title">' + esc(label) + '</span>' +
            '<span class="fieldDescription oidc-chk-desc">' + esc(desc) + '</span>' +
        '</span>' +
        '</label>' +
        '</div>';
}

function subsection(title, body) {
    return (title ? '<div class="oidc-subsection-title">' + esc(title) + '</div>' : '') + body;
}

function addLibChip(container, libId) {
    var chip = document.createElement('span');
    chip.className = 'oidc-library-chip';
    chip.setAttribute('data-lib-id', libId);
    chip.innerHTML = esc(libs[libId] || libId) + ' <span class="remove">&times;</span>';
    container.appendChild(chip);
}

// ── Transform rows ────────────────────────────────────────────────────────────

function transformRowHtml(from, to) {
    return '<div class="inputContainer">' +
        '<input is="emby-input" type="text" class="xform-from" placeholder="From (exact)" value="' + esc(from || '') + '" />' +
        '</div>' +
        '<span class="oidc-xform-arrow material-icons" aria-hidden="true">arrow_forward</span>' +
        '<div class="inputContainer">' +
        '<input is="emby-input" type="text" class="xform-to" placeholder="To (empty=drop)" value="' + esc(to || '') + '" />' +
        '</div>' +
        '<button type="button" is="emby-button" class="oidc-btn-danger" data-action="remove-xform" title="Remove">' +
        '<span class="material-icons" aria-hidden="true">close</span></button>';
}

function renderTransformRows(container, transforms) {
    container.innerHTML = '';
    (transforms || []).forEach(function (t) {
        var row = document.createElement('div');
        row.className = 'oidc-transform-row';
        row.innerHTML = transformRowHtml(t.FromValue, t.ToValue);
        container.appendChild(row);
    });
}

function collectTransforms(container) {
    var rows = container.querySelectorAll('.oidc-transform-row');
    var result = [];
    rows.forEach(function (row) {
        var from = row.querySelector('.xform-from').value.trim();
        if (from) {
            result.push({ FromValue: from, ToValue: row.querySelector('.xform-to').value.trim() });
        }
    });
    return result;
}

// ── Provider cards ────────────────────────────────────────────────────────────

function statusPill(enabled) {
    var cls = enabled ? 'oidc-status-on' : 'oidc-status-off';
    var lbl = enabled ? 'Enabled' : 'Disabled';
    return '<span class="oidc-status ' + cls + '"><span class="oidc-status-dot"></span>' + lbl + '</span>';
}

function renderProviders(view) {
    var container = view.querySelector('#providerList');
    container.innerHTML = '';
    cfg.Providers.forEach(function (p, idx) {
        var card = document.createElement('div');
        card.className = 'oidc-card listItem';
        card.innerHTML =
            '<div class="oidc-card-header">' +
                '<div class="oidc-card-title">' +
                    '<span>' + esc(p.DisplayName || 'New Provider') + '</span>' +
                    (p.ProviderId ? '<span class="oidc-chip">' + esc(p.ProviderId) + '</span>' : '') +
                '</div>' +
                statusPill(p.Enabled !== false) +
            '</div>' +
            subsection('Identity',
                '<div class="oidc-grid">' +
                    fld('Provider ID', 'text', 'prov_id_' + idx, p.ProviderId, 'Unique identifier (e.g. keycloak)') +
                    fld('Display Name', 'text', 'prov_name_' + idx, p.DisplayName, 'Shown on login button') +
                    fld('Authority URL', 'text', 'prov_authority_' + idx, p.Authority, 'https://idp.example.com/realms/myrealm', true) +
                    fld('Client ID', 'text', 'prov_clientid_' + idx, p.ClientId) +
                    fld('Client Secret', 'password', 'prov_secret_' + idx, p.ClientSecret,
                        p.ClientSecret === '__UNCHANGED__' ? 'leave unchanged to keep existing secret' : '') +
                    fld('Scopes', 'text', 'prov_scopes_' + idx, p.Scopes || 'openid profile email', '', true) +
                '</div>'
            ) +
            subsection('Claims',
                '<div class="oidc-grid">' +
                    fld('Role Claim Path', 'text', 'prov_roleclaim_' + idx, p.RoleClaim || 'groups', 'e.g. groups or realm_access.roles') +
                    fld('Username Claim', 'text', 'prov_userclaim_' + idx, p.UsernameClaim || 'preferred_username') +
                    fld('Display Name Claim', 'text', 'prov_displayclaim_' + idx, p.DisplayNameClaim || 'name') +
                    fld('Email Claim', 'text', 'prov_emailclaim_' + idx, p.EmailClaim || 'email', 'Used by Auto-link by verified email') +
                    fld('Entitlement Claim', 'text', 'prov_entclaim_' + idx, p.EntitlementClaim || 'entitlements', 'Authentik-style entitlements') +
                    fld('Entitlement Prefix', 'text', 'prov_entprefix_' + idx, p.EntitlementPrefix || 'jellyfin:') +
                '</div>'
            ) +
            subsection('Display',
                '<div class="oidc-grid">' +
                    fldColor('Button Color', 'prov_color_' + idx, p.ButtonColor || '#4285F4') +
                    fld('Additional Params', 'text', 'prov_params_' + idx, p.AdditionalParameters || '', 'key=val&key2=val2') +
                '</div>'
            ) +
            subsection('Options',
                chk('prov_enabled_' + idx, 'Enabled', p.Enabled !== false) +
                chk('prov_entitlements_' + idx, 'Enable entitlements', p.EnableEntitlements !== false) +
                chk('prov_emailverified_' + idx, 'Require email_verified claim', p.RequireEmailVerified) +
                chk('prov_autolinkemail_' + idx, 'Auto-link to local user by verified email (DANGEROUS — see docs)', p.AutoLinkByVerifiedEmail) +
                chk('prov_enforcessolink_' + idx, 'Enforce SSO-only on auto-link (disables local password)', p.EnforceSsoOnLink)
            ) +
            subsection('Security',
                fldDesc('Allowed Signing Algorithms', 'text', 'prov_algs_' + idx,
                    (p.AllowedSigningAlgorithms || ['RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512']).join(','),
                    'Comma-separated. Adding HS256/HS384/HS512 is DANGEROUS (relies on client_secret strength).', true) +
                chk('prov_allowinsecure_' + idx, 'Allow insecure authority (dev/test only)', p.AllowInsecureAuthority) +
                '<div class="fieldDescription"><strong>DANGER:</strong> HTTPS is required for Authority / JWKS / token endpoints. The "Allow insecure" toggle relaxes this for localhost only and must never be enabled in production.</div>'
            ) +
            '<details class="verticalSection"><summary>Role Transforms (' + (p.RoleTransforms || []).length + ')</summary>' +
                '<div class="oidc-transform-list" id="prov_transforms_' + idx + '"></div>' +
                '<button type="button" is="emby-button" data-action="add-transform" data-idx="' + idx + '"><span>Add Transform</span></button>' +
                '<div class="fieldDescription">Map raw IdP role values before matching. Empty "To" drops the value.</div>' +
            '</details>' +
            '<div class="oidc-card-actions">' +
                '<button type="button" is="emby-button" class="raised" data-action="test-provider" data-idx="' + idx + '"><span>Test Connection</span></button>' +
                '<button type="button" is="emby-button" class="raised oidc-btn-danger" data-action="remove-provider" data-idx="' + idx + '"><span>Remove</span></button>' +
                '<span class="oidc-test-result" data-idx="' + idx + '"></span>' +
            '</div>';
        container.appendChild(card);
        renderTransformRows(view.querySelector('#prov_transforms_' + idx), p.RoleTransforms);
    });
}

// ── Role mapping cards ────────────────────────────────────────────────────────

function renderRoleMappings(view) {
    var container = view.querySelector('#roleMappingList');
    container.innerHTML = '';
    cfg.RoleMappings.forEach(function (m, idx) {
        var card = document.createElement('div');
        card.className = 'oidc-card listItem' + (m.IsExplicitDeny ? ' oidc-card-deny' : '');
        var libOpts = Object.keys(libs).map(function (id) {
            return '<option value="' + esc(id) + '">' + esc(libs[id]) + '</option>';
        }).join('');
        var selectedLibs = (m.LibraryIds || []).concat(
            (m.LibraryNames || []).map(function (name) {
                var f = Object.keys(libs).find(function (id) {
                    return libs[id].toLowerCase() === name.toLowerCase();
                });
                return f || name;
            })
        );
        var badge = m.IsExplicitDeny
            ? '<span class="oidc-badge oidc-badge-deny">DENY</span>'
            : '<span class="oidc-badge oidc-badge-grant">GRANT</span>';
        card.innerHTML =
            '<div class="oidc-card-header">' +
                '<div class="oidc-card-title">' +
                    '<span>' + esc(m.RoleName || 'New Role') + '</span>' +
                    badge +
                '</div>' +
            '</div>' +
            subsection('Match',
                '<div class="oidc-grid">' +
                    fld('Role Name', 'text', 'role_name_' + idx, m.RoleName, 'Must match IdP role claim value') +
                    fld('Priority', 'number', 'role_priority_' + idx, m.Priority || 0, 'Higher = takes precedence') +
                    fld('Provider Scope', 'text', 'role_provider_' + idx, m.ProviderId || '', 'Empty = all providers', true) +
                '</div>' +
                '<div class="oidc-deny-toggle checkboxContainer">' +
                    '<label>' +
                        '<input is="emby-checkbox" type="checkbox" id="role_deny_' + idx + '"' + (m.IsExplicitDeny ? ' checked' : '') + ' />' +
                        '<span><strong>Explicit Deny</strong> — strips these permissions after grants are applied</span>' +
                    '</label>' +
                '</div>'
            ) +
            subsection('Permissions',
                (m.IsExplicitDeny ? '<div class="fieldDescription">Only <strong>checked</strong> permissions will be stripped. Unchecked = this deny rule leaves the permission alone.</div>' : '') +
                '<div class="oidc-grid">' +
                chkDesc('role_admin_' + idx, 'Administrator', m.IsAdmin,
                    'Full server access — settings, users, plugins, libraries.') +
                chkDesc('role_alllibs_' + idx, 'Access all libraries', m.EnableAllLibraries,
                    'Grant every library. If off, pick specific libraries below.') +
                chkDesc('role_livetv_' + idx, 'Watch Live TV', m.EnableLiveTv,
                    'View Live TV channels and recordings.') +
                chkDesc('role_livetvmgmt_' + idx, 'Manage Live TV', m.EnableLiveTvManagement,
                    'Schedule recordings and edit DVR settings. Implies watch access.') +
                // For deny mappings: null means "not set" → unchecked (explicit true required to strip).
                // For allow mappings: null means "default true" → checked (backward compat).
                chkDesc('role_playback_' + idx, 'Play media', m.IsExplicitDeny ? m.EnableMediaPlayback === true : m.EnableMediaPlayback !== false,
                    'Required to stream anything. Off = account cannot play media.') +
                chkDesc('role_remote_' + idx, 'Remote access', m.IsExplicitDeny ? m.EnableRemoteAccess === true : m.EnableRemoteAccess !== false,
                    'Allow connections from outside the local network.') +
                chkDesc('role_transcode_' + idx, 'Allow transcoding', m.IsExplicitDeny ? m.EnableTranscoding === true : m.EnableTranscoding !== false,
                    'Permit server-side transcoding for this user. Off = direct play / remux only.') +
                chkDesc('role_delete_' + idx, 'Delete media', m.EnableContentDeletion,
                    'Permanently remove items from libraries.') +
                chkDesc('role_collections_' + idx, 'Manage collections', m.EnableCollectionManagement,
                    'Create, edit, and delete collections.') +
                chkDesc('role_subtitles_' + idx, 'Manage subtitles', m.EnableSubtitleManagement,
                    'Download and edit subtitles for library items.') +
                chkDesc('role_download_' + idx, 'Download media', m.EnableDownload,
                    'Save media to client devices for offline playback.') +
                chkDesc('role_syncplay_' + idx, 'Join SyncPlay', m.EnableSyncplay,
                    'Participate in synchronized group playback sessions.') +
                chkDesc('role_syncplayhost_' + idx, 'Host SyncPlay', m.EnableSyncplayGroupCreation,
                    'Create SyncPlay groups. Implies join.') +
                '</div>'
            ) +
            subsection('Libraries',
                '<div class="fieldDescription">Used when "All Libraries" is unchecked.</div>' +
                '<div class="oidc-lib-controls">' +
                    '<div class="inputContainer"><select is="emby-select" id="role_libadd_' + idx + '" label="Library">' +
                        '<option value="">-- Select library --</option>' + libOpts +
                    '</select></div>' +
                    '<button type="button" is="emby-button" class="raised" data-action="add-lib" data-idx="' + idx + '"><span>Add</span></button>' +
                '</div>' +
                '<div id="role_libs_' + idx + '" class="oidc-library-list"></div>' +
                '<div class="inputContainer" style="max-width:20em;margin-top:0.8em;">' +
                    '<input is="emby-input" type="number" id="role_maxrating_' + idx + '"' +
                    ' label="Max Parental Rating (empty = unrestricted)"' +
                    ' value="' + (m.MaxParentalRating != null ? m.MaxParentalRating : '') + '" />' +
                '</div>'
            ) +
            '<div class="oidc-card-actions">' +
                '<button type="button" is="emby-button" class="raised oidc-btn-danger" data-action="remove-role" data-idx="' + idx + '"><span>Remove</span></button>' +
            '</div>';
        container.appendChild(card);
        var libCont = view.querySelector('#role_libs_' + idx);
        selectedLibs.forEach(function (libId) { addLibChip(libCont, libId); });
    });
}

// ── SAML provider cards ───────────────────────────────────────────────────────

function renderSamlProviders(view) {
    var container = view.querySelector('#samlProviderList');
    if (!container) return;
    container.innerHTML = '';
    (cfg.SamlProviders || []).forEach(function (p, idx) {
        var card = document.createElement('div');
        card.className = 'oidc-card listItem';
        card.innerHTML =
            '<div class="oidc-card-header">' +
                '<div class="oidc-card-title">' +
                    '<span>' + esc(p.DisplayName || 'New SAML Provider') + '</span>' +
                    (p.Id ? '<span class="oidc-chip">' + esc(p.Id) + '</span>' : '') +
                '</div>' +
                statusPill(p.Enabled !== false) +
            '</div>' +
            subsection('Identity',
                '<div class="oidc-grid">' +
                    fld('Provider ID', 'text', 'saml_id_' + idx, p.Id, 'Unique identifier') +
                    fld('Display Name', 'text', 'saml_name_' + idx, p.DisplayName, 'Shown on login button') +
                    fld('Entity ID (SP)', 'text', 'saml_entity_' + idx, p.EntityId, 'https://jellyfin.example.com', true) +
                    fld('IdP Entity ID', 'text', 'saml_idpentity_' + idx, p.IdpEntityId, 'Expected IdP issuer (e.g. https://idp.example.com)', true) +
                    fld('IdP SSO URL', 'text', 'saml_sso_' + idx, p.SsoUrl, 'https://idp.example.com/sso/saml', true) +
                '</div>'
            ) +
            subsection('Claims',
                '<div class="oidc-grid">' +
                    fld('Username Claim', 'text', 'saml_user_' + idx, p.UsernameClaim || 'NameID', 'NameID or attribute name') +
                    fld('Role Claim', 'text', 'saml_role_' + idx, p.RoleClaim || 'groups', 'Attribute name for groups/roles') +
                '</div>'
            ) +
            subsection('Display',
                '<div class="oidc-grid">' +
                    fldColor('Button Color', 'saml_color_' + idx, p.ButtonColor || '#4285F4') +
                '</div>'
            ) +
            subsection('IdP Signing Certificate',
                '<textarea id="saml_cert_' + idx + '" rows="5" class="oidc-cert" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----">' +
                    esc(p.IdpCertificate || '') +
                '</textarea>' +
                '<div class="fieldDescription">PEM or base64 DER.</div>'
            ) +
            subsection('Options',
                chk('saml_enabled_' + idx, 'Enabled', p.Enabled !== false) +
                chk('saml_idpinit_' + idx, 'Allow IdP-initiated SSO', p.AllowIdpInitiated) +
                '<div class="fieldDescription">IdP-initiated SSO skips the in-flight request check; only enable if your IdP requires it.</div>'
            ) +
            '<div class="oidc-card-actions">' +
                '<button type="button" is="emby-button" class="raised oidc-btn-danger" data-action="remove-saml" data-idx="' + idx + '"><span>Remove</span></button>' +
            '</div>';
        container.appendChild(card);
    });
}

// ── Preview panel ─────────────────────────────────────────────────────────────

function runPreview(view) {
    var providerId = gval(view, 'previewProvider');
    var roles = gval(view, 'previewRoles');
    var entitlements = gval(view, 'previewEntitlements');
    var resultEl = view.querySelector('#previewResult');
    resultEl.textContent = 'Loading...';

    var params = new URLSearchParams();
    if (providerId) params.set('providerId', providerId);
    if (roles) params.set('roles', roles);
    if (entitlements) params.set('entitlements', entitlements);

    ApiClient.ajax({
        type: 'GET',
        url: ApiClient.getUrl('sso/OIDC/Config/PreviewPermissions?' + params.toString()),
        dataType: 'json'
    }).then(function (result) {
        var grants = (result.MatchedGrantMappings || []).join(', ') || '(none)';
        var denies = (result.MatchedDenyMappings || []).join(', ') || '(none)';
        var lines = [
            'Admin: ' + result.IsAdmin,
            'Playback: ' + result.EnableMediaPlayback,
            'Remote: ' + result.EnableRemoteAccess,
            'Transcoding: ' + result.EnableTranscoding,
            'Live TV: ' + result.EnableLiveTv + (result.EnableLiveTvManagement ? ' (manage)' : ''),
            'Download: ' + result.EnableDownload,
            'SyncPlay: ' + (result.EnableSyncplayGroupCreation ? 'host' : result.EnableSyncplay ? 'join' : 'none'),
            'Libraries: ' + (result.EnableAllLibraries ? 'ALL' : (result.Libraries && result.Libraries.length ? result.Libraries.join(', ') : 'none')),
            'Max Rating: ' + (result.MaxParentalRating != null ? result.MaxParentalRating : 'unrestricted'),
            '',
            'Matched grants: ' + grants,
            'Matched denies: ' + denies,
        ];
        resultEl.textContent = lines.join('\n');
    }).catch(function (err) {
        resultEl.textContent = 'Error: ' + ((err && err.statusText) || err.message || 'unknown');
    });
}

// ── Provider test ─────────────────────────────────────────────────────────────

function testProvider(view, idx) {
    var authority = gval(view, 'prov_authority_' + idx);
    var scopes = gval(view, 'prov_scopes_' + idx);
    var allowInsecure = gchk(view, 'prov_allowinsecure_' + idx);
    var resultEl = view.querySelector('.oidc-test-result[data-idx="' + idx + '"]');
    function setResult(color, text) {
        if (!resultEl) return;
        resultEl.style.color = color;
        resultEl.textContent = text;
    }
    if (!authority) {
        setResult('var(--theme-error-color, #c62828)', 'Authority URL is required');
        return;
    }
    setResult('', 'Testing...');

    ApiClient.ajax({
        type: 'POST',
        url: ApiClient.getUrl('sso/OIDC/Config/TestProvider'),
        data: JSON.stringify({ Authority: authority, Scopes: scopes, AllowInsecureAuthority: allowInsecure }),
        contentType: 'application/json',
        dataType: 'json'
    }).then(function (result) {
        if (result.Success) {
            var msg = 'OK — issuer ' + result.Issuer;
            if (result.UnsupportedRequestedScopes && result.UnsupportedRequestedScopes.length > 0) {
                msg += ' (unsupported scopes: ' + result.UnsupportedRequestedScopes.join(', ') + ')';
                setResult('var(--theme-warning-color, #ff9800)', msg);
            } else {
                setResult('var(--theme-accent-color, #4caf50)', msg);
            }
        } else {
            setResult('var(--theme-error-color, #c62828)', 'Failed: ' + result.Error);
        }
    }).catch(function (err) {
        var msg = (err && (err.statusText || err.message)) || 'Network error';
        setResult('var(--theme-error-color, #c62828)', 'Failed: ' + msg);
    });
}

// ── Collect ───────────────────────────────────────────────────────────────────

function collectProviders(view) {
    var result = [];
    view.querySelectorAll('#providerList .oidc-card').forEach(function (card, idx) {
        result.push({
            ProviderId: gval(view, 'prov_id_' + idx),
            DisplayName: gval(view, 'prov_name_' + idx),
            Authority: gval(view, 'prov_authority_' + idx),
            ClientId: gval(view, 'prov_clientid_' + idx),
            ClientSecret: gval(view, 'prov_secret_' + idx),
            Scopes: gval(view, 'prov_scopes_' + idx),
            RoleClaim: gval(view, 'prov_roleclaim_' + idx),
            UsernameClaim: gval(view, 'prov_userclaim_' + idx),
            DisplayNameClaim: gval(view, 'prov_displayclaim_' + idx),
            EmailClaim: gval(view, 'prov_emailclaim_' + idx) || 'email',
            ButtonColor: gval(view, 'prov_color_' + idx),
            AdditionalParameters: gval(view, 'prov_params_' + idx),
            EntitlementClaim: gval(view, 'prov_entclaim_' + idx) || 'entitlements',
            EntitlementPrefix: gval(view, 'prov_entprefix_' + idx) || 'jellyfin:',
            EnableEntitlements: gchk(view, 'prov_entitlements_' + idx),
            RequireEmailVerified: gchk(view, 'prov_emailverified_' + idx),
            AutoLinkByVerifiedEmail: gchk(view, 'prov_autolinkemail_' + idx),
            EnforceSsoOnLink: gchk(view, 'prov_enforcessolink_' + idx),
            Enabled: gchk(view, 'prov_enabled_' + idx),
            ButtonIcon: '',
            RoleTransforms: collectTransforms(view.querySelector('#prov_transforms_' + idx)),
            AllowInsecureAuthority: gchk(view, 'prov_allowinsecure_' + idx),
            AllowedSigningAlgorithms: gval(view, 'prov_algs_' + idx)
                .split(',').map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; })
        });
    });
    return result;
}

function collectRoleMappings(view) {
    var result = [];
    view.querySelectorAll('#roleMappingList .oidc-card').forEach(function (card, idx) {
        var chips = view.querySelectorAll('#role_libs_' + idx + ' .oidc-library-chip');
        var libIds = [];
        chips.forEach(function (c) { libIds.push(c.getAttribute('data-lib-id')); });
        var mr = gval(view, 'role_maxrating_' + idx);
        result.push({
            RoleName: gval(view, 'role_name_' + idx),
            ProviderId: gval(view, 'role_provider_' + idx),
            Priority: parseInt(gval(view, 'role_priority_' + idx)) || 0,
            IsExplicitDeny: gchk(view, 'role_deny_' + idx),
            IsAdmin: gchk(view, 'role_admin_' + idx),
            EnableAllLibraries: gchk(view, 'role_alllibs_' + idx),
            LibraryIds: libIds, LibraryNames: [],
            EnableLiveTv: gchk(view, 'role_livetv_' + idx),
            EnableLiveTvManagement: gchk(view, 'role_livetvmgmt_' + idx),
            EnableMediaPlayback: gchk(view, 'role_playback_' + idx),
            EnableRemoteAccess: gchk(view, 'role_remote_' + idx),
            EnableTranscoding: gchk(view, 'role_transcode_' + idx),
            EnableContentDeletion: gchk(view, 'role_delete_' + idx),
            EnableCollectionManagement: gchk(view, 'role_collections_' + idx),
            EnableSubtitleManagement: gchk(view, 'role_subtitles_' + idx),
            EnableDownload: gchk(view, 'role_download_' + idx),
            EnableSyncplay: gchk(view, 'role_syncplay_' + idx),
            EnableSyncplayGroupCreation: gchk(view, 'role_syncplayhost_' + idx),
            MaxParentalRating: mr ? parseInt(mr) : null
        });
    });
    return result;
}

function collectSamlProviders(view) {
    var container = view.querySelector('#samlProviderList');
    if (!container) return [];
    var result = [];
    container.querySelectorAll('.oidc-card').forEach(function (card, idx) {
        var certEl = view.querySelector('#saml_cert_' + idx);
        result.push({
            Id: gval(view, 'saml_id_' + idx),
            DisplayName: gval(view, 'saml_name_' + idx),
            EntityId: gval(view, 'saml_entity_' + idx),
            IdpEntityId: gval(view, 'saml_idpentity_' + idx),
            SsoUrl: gval(view, 'saml_sso_' + idx),
            UsernameClaim: gval(view, 'saml_user_' + idx) || 'NameID',
            RoleClaim: gval(view, 'saml_role_' + idx) || 'groups',
            ButtonColor: gval(view, 'saml_color_' + idx) || '#4285F4',
            IdpCertificate: certEl ? certEl.value.trim() : '',
            Enabled: gchk(view, 'saml_enabled_' + idx),
            AllowIdpInitiated: gchk(view, 'saml_idpinit_' + idx)
        });
    });
    return result;
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function (view) {
    function loadAndRender() {
        Dashboard.showLoadingMsg();
        return ApiClient.getJSON(ApiClient.getUrl('sso/OIDC/Config/Libraries')).then(function (data) {
            libs = data || {};
        }).catch(function () {
            libs = {};
        }).then(function () {
            return ApiClient.getJSON(ApiClient.getUrl('sso/OIDC/Config'));
        }).then(function (config) {
            cfg = config;
            cfg.Providers = cfg.Providers || [];
            cfg.RoleMappings = cfg.RoleMappings || [];
            cfg.SamlProviders = cfg.SamlProviders || [];
            renderProviders(view);
            renderRoleMappings(view);
            renderSamlProviders(view);
            view.querySelector('#defaultProvider').value = cfg.DefaultProvider || '';
            view.querySelector('#defaultRoleName').value = cfg.DefaultRoleName || '';
            view.querySelector('#autoCreateUsers').checked = cfg.AutoCreateUsers !== false;
            view.querySelector('#rbacBehavior').value = cfg.RbacBehavior || 'EntitlementsAuthoritative';
            var alEl = view.querySelector('#allowLastAdminDemotion');
            if (alEl) alEl.checked = cfg.AllowLastAdminDemotion === true;
            var vclEl = view.querySelector('#verboseClaimLogging');
            if (vclEl) vclEl.checked = cfg.VerboseClaimLogging === true;
            Dashboard.hideLoadingMsg();
        }).catch(function (err) {
            Dashboard.hideLoadingMsg();
            console.error('OIDC RBAC: failed to load config', err);
        });
    }

    view._oidcReload = loadAndRender;
    view.addEventListener('viewshow', loadAndRender);

    // Tabs
    view.querySelectorAll('.oidc-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            view.querySelectorAll('.oidc-tab').forEach(function (t) {
                t.classList.remove('oidc-tab-active');
            });
            view.querySelectorAll('.oidc-tab-content').forEach(function (c) {
                c.style.display = 'none';
            });
            this.classList.add('oidc-tab-active');
            view.querySelector('#tab-' + this.getAttribute('data-tab')).style.display = '';
        });
    });

    // Add OIDC provider
    view.querySelector('#btnAddProvider').addEventListener('click', function () {
        if (!cfg) return;
        cfg.Providers.push({
            ProviderId: '', DisplayName: 'New Provider', Authority: '',
            ClientId: '', ClientSecret: '', Scopes: 'openid profile email',
            RoleClaim: 'groups', UsernameClaim: 'preferred_username',
            DisplayNameClaim: 'name', EmailClaim: 'email', Enabled: true, ButtonColor: '#4285F4',
            ButtonIcon: '', AdditionalParameters: '',
            EntitlementClaim: 'entitlements', EntitlementPrefix: 'jellyfin:',
            EnableEntitlements: true, RequireEmailVerified: false,
            AutoLinkByVerifiedEmail: false, EnforceSsoOnLink: false,
            RoleTransforms: [],
            AllowInsecureAuthority: false,
            AllowedSigningAlgorithms: ['RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512']
        });
        renderProviders(view);
    });

    // Add role mapping
    view.querySelector('#btnAddRoleMapping').addEventListener('click', function () {
        if (!cfg) return;
        // EnableMediaPlayback / EnableRemoteAccess / EnableTranscoding use null to mean:
        //   - allow mapping: "default true" (backward compat)
        //   - deny mapping:  "this rule doesn't touch this permission" (safe default)
        // The UI renders null correctly per-context in renderRoleMappings.
        cfg.RoleMappings.push({
            RoleName: '', ProviderId: '', Priority: 0, IsExplicitDeny: false,
            IsAdmin: false, EnableAllLibraries: false,
            LibraryIds: [], LibraryNames: [], EnableLiveTv: false,
            EnableLiveTvManagement: false, EnableMediaPlayback: null,
            EnableRemoteAccess: null, EnableTranscoding: null,
            EnableContentDeletion: false, EnableCollectionManagement: false,
            EnableSubtitleManagement: false, EnableDownload: false,
            EnableSyncplay: false, EnableSyncplayGroupCreation: false,
            MaxParentalRating: null
        });
        renderRoleMappings(view);
    });

    // Add SAML provider
    var btnAddSaml = view.querySelector('#btnAddSamlProvider');
    if (btnAddSaml) {
        btnAddSaml.addEventListener('click', function () {
            if (!cfg) return;
            cfg.SamlProviders = cfg.SamlProviders || [];
            cfg.SamlProviders.push({
                Id: 'saml-' + Date.now(),
                DisplayName: 'New SAML Provider',
                EntityId: '', IdpEntityId: '', SsoUrl: '', IdpCertificate: '',
                UsernameClaim: 'NameID', RoleClaim: 'groups',
                ButtonColor: '#4285F4', Enabled: true, AllowIdpInitiated: false
            });
            renderSamlProviders(view);
        });
    }

    // Preview button
    var btnPreview = view.querySelector('#btnPreview');
    if (btnPreview) {
        btnPreview.addEventListener('click', function () { runPreview(view); });
    }

    // Save
    view.querySelector('#btnSave').addEventListener('click', function () {
        if (!cfg) return;
        Dashboard.showLoadingMsg();
        cfg.Providers = collectProviders(view);
        cfg.RoleMappings = collectRoleMappings(view);
        cfg.SamlProviders = collectSamlProviders(view);
        cfg.DefaultProvider = gval(view, 'defaultProvider');
        cfg.DefaultRoleName = gval(view, 'defaultRoleName');
        cfg.AutoCreateUsers = gchk(view, 'autoCreateUsers');
        cfg.RbacBehavior = view.querySelector('#rbacBehavior').value || 'EntitlementsAuthoritative';
        cfg.AllowLastAdminDemotion = gchk(view, 'allowLastAdminDemotion');
        cfg.VerboseClaimLogging = gchk(view, 'verboseClaimLogging');

        // Client-side provider id check — must match server regex ^[A-Za-z0-9_-]{1,64}$.
        // The server's UpdateConfiguration validates again as the source of truth; this just
        // gives a faster, friendlier error message before the round-trip.
        var providerIdPattern = /^[A-Za-z0-9_-]{1,64}$/;
        var badProviders = (cfg.Providers || [])
            .filter(function (p) { return !providerIdPattern.test(p.ProviderId || ''); })
            .map(function (p) { return p.DisplayName || '(unnamed)'; });
        var badSaml = (cfg.SamlProviders || [])
            .filter(function (p) { return !providerIdPattern.test(p.Id || ''); })
            .map(function (p) { return p.DisplayName || '(unnamed)'; });
        if (badProviders.length || badSaml.length) {
            Dashboard.hideLoadingMsg();
            var names = badProviders.concat(badSaml).join(', ');
            Dashboard.alert('Provider id must be letters, digits, underscore, or hyphen (1-64 chars). Fix: ' + names);
            return;
        }

        // Run config validation before saving. Warnings are non-blocking — save proceeds regardless,
        // but any warnings are shown prominently so the admin can make an informed decision.
        ApiClient.ajax({
            type: 'POST',
            url: ApiClient.getUrl('sso/OIDC/Config/ValidateConfig'),
            data: JSON.stringify(cfg),
            contentType: 'application/json',
            dataType: 'json'
        }).then(function (validation) {
            var warnings = (validation && validation.Warnings) || [];
            var warningBanner = view.querySelector('#oidcConfigWarnings');
            if (warningBanner) {
                if (warnings.length > 0) {
                    warningBanner.innerHTML = '<strong>Configuration Warnings:</strong><ul>' +
                        warnings.map(function (w) { return '<li>' + esc(w) + '</li>'; }).join('') +
                        '</ul>';
                    warningBanner.style.display = 'block';
                } else {
                    warningBanner.style.display = 'none';
                    warningBanner.innerHTML = '';
                }
            }
            return ApiClient.ajax({
                type: 'POST',
                url: ApiClient.getUrl('sso/OIDC/Config'),
                data: JSON.stringify(cfg),
                contentType: 'application/json'
            });
        }).then(function () {
            // Re-fetch from the server so the UI reflects the persisted (and possibly
            // normalized) values — e.g. NormalizeAuthority stripping /.well-known/...,
            // masked secrets resetting to the sentinel, migration changes.
            return loadAndRender();
        }).then(function () {
            Dashboard.alert('Settings saved.');
        }).catch(function (err) {
            Dashboard.hideLoadingMsg();
            Dashboard.alert('Failed to save: ' + ((err && err.message) || err));
        });
    });

    // Event delegation — provider list
    view.querySelector('#providerList').addEventListener('click', function (e) {
        var btn = e.target.closest('[data-action]');
        if (!btn) return;
        var action = btn.getAttribute('data-action');
        if (action === 'remove-xform') {
            var row = btn.closest('.oidc-transform-row');
            if (row) row.remove();
            return;
        }
        var idx = parseInt(btn.getAttribute('data-idx'));
        if (action === 'remove-provider') {
            cfg.Providers.splice(idx, 1);
            renderProviders(view);
        } else if (action === 'test-provider') {
            testProvider(view, idx);
        } else if (action === 'add-transform') {
            var container = view.querySelector('#prov_transforms_' + idx);
            if (container) {
                var row = document.createElement('div');
                row.className = 'oidc-transform-row';
                row.innerHTML = transformRowHtml('', '');
                container.appendChild(row);
            }
        }
    });

    // Event delegation — role mapping list (clicks)
    view.querySelector('#roleMappingList').addEventListener('click', function (e) {
        if (e.target.classList.contains('remove')) {
            e.target.parentElement.remove();
            return;
        }
        var btn = e.target.closest('[data-action]');
        if (!btn) return;
        var idx = parseInt(btn.getAttribute('data-idx'));
        if (btn.getAttribute('data-action') === 'remove-role') {
            cfg.RoleMappings.splice(idx, 1);
            renderRoleMappings(view);
        } else if (btn.getAttribute('data-action') === 'add-lib') {
            var sel = view.querySelector('#role_libadd_' + idx);
            if (!sel || !sel.value) return;
            var cont = view.querySelector('#role_libs_' + idx);
            var chips = cont.querySelectorAll('.oidc-library-chip');
            for (var i = 0; i < chips.length; i++) {
                if (chips[i].getAttribute('data-lib-id') === sel.value) return;
            }
            addLibChip(cont, sel.value);
            sel.value = '';
        }
    });

    // Event delegation — toggling "Explicit Deny" clears all permission checkboxes
    // on the card so the deny only strips what the admin explicitly opts in to.
    // Without this, RoleMapping's default-true flags (Playback/Remote/Transcoding)
    // would silently extend the deny to permissions the admin never selected.
    view.querySelector('#roleMappingList').addEventListener('change', function (e) {
        if (!e.target.id || e.target.id.indexOf('role_deny_') !== 0) return;
        if (!e.target.checked) return;
        var idx = e.target.id.substring('role_deny_'.length);
        var perms = ['admin', 'alllibs', 'livetv', 'livetvmgmt', 'playback', 'remote',
                     'transcode', 'delete', 'collections', 'subtitles', 'download',
                     'syncplay', 'syncplayhost'];
        perms.forEach(function (p) {
            var cb = view.querySelector('#role_' + p + '_' + idx);
            if (cb) cb.checked = false;
        });
    });

    // Event delegation — SAML provider list
    var samlList = view.querySelector('#samlProviderList');
    if (samlList) {
        samlList.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-action]');
            if (!btn) return;
            var idx = parseInt(btn.getAttribute('data-idx'));
            if (btn.getAttribute('data-action') === 'remove-saml') {
                cfg.SamlProviders.splice(idx, 1);
                renderSamlProviders(view);
            }
        });
    }
}
