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

function fld(label, type, id, value, placeholder, full) {
    return '<div class="oidc-field' + (full ? ' full' : '') + '">' +
        '<label for="' + id + '">' + esc(label) + '</label>' +
        '<input type="' + type + '" id="' + id + '" value="' + esc(String(value || '')) + '"' +
        (placeholder ? ' placeholder="' + esc(placeholder) + '"' : '') + ' />' +
        '</div>';
}

function chk(id, label, checked) {
    return '<label><input type="checkbox" id="' + id + '"' + (checked ? ' checked' : '') + ' /> ' + esc(label) + '</label>';
}

function addLibChip(container, libId) {
    var chip = document.createElement('span');
    chip.className = 'oidc-library-chip';
    chip.setAttribute('data-lib-id', libId);
    chip.innerHTML = esc(libs[libId] || libId) + ' <span class="remove">&times;</span>';
    container.appendChild(chip);
}

// ── Transform rows ────────────────────────────────────────────────────────────

function renderTransformRows(container, transforms) {
    container.innerHTML = '';
    (transforms || []).forEach(function (t, i) {
        var row = document.createElement('div');
        row.className = 'oidc-transform-row';
        row.innerHTML =
            '<input type="text" class="xform-from" placeholder="From (exact)" value="' + esc(t.FromValue || '') + '" />' +
            '<span style="margin:0 0.3em;">→</span>' +
            '<input type="text" class="xform-to" placeholder="To (empty=drop)" value="' + esc(t.ToValue || '') + '" />' +
            '<button type="button" class="oidc-btn-remove" style="padding:0.1em 0.5em;margin-left:0.3em;">&times;</button>';
        row.querySelector('button').addEventListener('click', function () { row.remove(); });
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

function renderProviders(view) {
    var container = view.querySelector('#providerList');
    container.innerHTML = '';
    cfg.Providers.forEach(function (p, idx) {
        var card = document.createElement('div');
        card.className = 'oidc-card';
        card.innerHTML = '<h4>' + esc(p.DisplayName || 'New Provider') +
            (p.Enabled ? ' <span style="color:#4caf50">&#9679;</span>' : ' <span style="color:#888">&#9679;</span>') +
            '</h4>' +
            '<div class="oidc-grid">' +
            fld('Provider ID', 'text', 'prov_id_' + idx, p.ProviderId, 'Unique identifier (e.g. keycloak)') +
            fld('Display Name', 'text', 'prov_name_' + idx, p.DisplayName, 'Shown on login button') +
            fld('Authority URL', 'text', 'prov_authority_' + idx, p.Authority, 'https://idp.example.com/realms/myrealm', true) +
            fld('Client ID', 'text', 'prov_clientid_' + idx, p.ClientId, '') +
            fld('Client Secret', 'password', 'prov_secret_' + idx, p.ClientSecret, '') +
            fld('Scopes', 'text', 'prov_scopes_' + idx, p.Scopes || 'openid profile email', '') +
            fld('Role Claim Path', 'text', 'prov_roleclaim_' + idx, p.RoleClaim || 'groups', 'e.g. groups or realm_access.roles') +
            fld('Username Claim', 'text', 'prov_userclaim_' + idx, p.UsernameClaim || 'preferred_username', '') +
            fld('Display Name Claim', 'text', 'prov_displayclaim_' + idx, p.DisplayNameClaim || 'name', '') +
            fld('Button Color', 'color', 'prov_color_' + idx, p.ButtonColor || '#4285F4', '') +
            fld('Additional Params', 'text', 'prov_params_' + idx, p.AdditionalParameters || '', 'key=val&key2=val2', true) +
            fld('Entitlement Claim', 'text', 'prov_entclaim_' + idx, p.EntitlementClaim || 'entitlements', 'Claim for Authentik-style entitlements', true) +
            fld('Entitlement Prefix', 'text', 'prov_entprefix_' + idx, p.EntitlementPrefix || 'jellyfin:', 'Prefix for Jellyfin entitlements') +
            '<div class="oidc-field"><label><input type="checkbox" id="prov_entitlements_' + idx + '"' +
            (p.EnableEntitlements !== false ? ' checked' : '') + '/> Enable Entitlements</label></div>' +
            '<div class="oidc-field"><label><input type="checkbox" id="prov_emailverified_' + idx + '"' +
            (p.RequireEmailVerified ? ' checked' : '') + '/> Require email_verified claim</label></div>' +
            '<div class="oidc-field"><label><input type="checkbox" id="prov_enabled_' + idx + '"' +
            (p.Enabled !== false ? ' checked' : '') + '/> Enabled</label></div>' +
            '</div>' +
            '<details style="margin-top:0.5em;"><summary style="cursor:pointer;color:#aaa;font-size:0.9em;">Role Transforms (' + (p.RoleTransforms || []).length + ')</summary>' +
            '<div class="oidc-transform-list" id="prov_transforms_' + idx + '" style="margin:0.5em 0;"></div>' +
            '<button type="button" class="oidc-btn-secondary" style="width:fit-content;font-size:0.85em;" data-action="add-transform" data-idx="' + idx + '">+ Add Transform</button>' +
            '<p style="font-size:0.8em;color:#aaa;margin:0.2em 0 0;">Map raw IdP role values before matching. Empty "To" drops the value.</p>' +
            '</details>' +
            '<div style="margin-top:0.5em;display:flex;gap:0.5em;align-items:center;">' +
            '<button type="button" class="oidc-btn-secondary" data-action="test-provider" data-idx="' + idx + '">Test Connection</button>' +
            '<button type="button" class="oidc-btn-remove" data-action="remove-provider" data-idx="' + idx + '">Remove</button>' +
            '<span class="oidc-test-result" data-idx="' + idx + '" style="font-size:0.9em;"></span>' +
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
        card.className = 'oidc-card' + (m.IsExplicitDeny ? ' oidc-card-deny' : '');
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
        var denyBadge = m.IsExplicitDeny ? ' <span style="background:#c62828;color:#fff;padding:0 0.4em;border-radius:3px;font-size:0.8em;">DENY</span>' : '';
        card.innerHTML = '<h4>Role: ' + esc(m.RoleName || 'New Role') + denyBadge + '</h4>' +
            '<div class="oidc-grid">' +
            fld('Role Name', 'text', 'role_name_' + idx, m.RoleName, 'Must match IdP role claim value') +
            fld('Priority', 'number', 'role_priority_' + idx, m.Priority || 0, 'Higher = takes precedence') +
            fld('Provider Scope', 'text', 'role_provider_' + idx, m.ProviderId || '', 'Leave empty for all providers') +
            '</div>' +
            '<div class="oidc-field" style="margin-bottom:0.5em;">' +
            '<label><input type="checkbox" id="role_deny_' + idx + '"' + (m.IsExplicitDeny ? ' checked' : '') + ' /> ' +
            '<strong>Explicit Deny</strong> — strips these permissions after grants are applied</label>' +
            '</div>' +
            '<div class="oidc-checkbox-row">' +
            chk('role_admin_' + idx, 'Administrator', m.IsAdmin) +
            chk('role_alllibs_' + idx, 'All Libraries', m.EnableAllLibraries) +
            chk('role_livetv_' + idx, 'Live TV', m.EnableLiveTv) +
            chk('role_livetvmgmt_' + idx, 'Live TV Mgmt', m.EnableLiveTvManagement) +
            chk('role_playback_' + idx, 'Playback', m.EnableMediaPlayback !== false) +
            chk('role_remote_' + idx, 'Remote Access', m.EnableRemoteAccess !== false) +
            chk('role_transcode_' + idx, 'Transcoding', m.EnableTranscoding !== false) +
            chk('role_delete_' + idx, 'Delete Content', m.EnableContentDeletion) +
            chk('role_collections_' + idx, 'Collections', m.EnableCollectionManagement) +
            chk('role_subtitles_' + idx, 'Subtitles', m.EnableSubtitleManagement) +
            chk('role_download_' + idx, 'Downloads', m.EnableDownload) +
            chk('role_syncplay_' + idx, 'SyncPlay (join)', m.EnableSyncplay) +
            chk('role_syncplayhost_' + idx, 'SyncPlay (host)', m.EnableSyncplayGroupCreation) +
            '</div>' +
            '<div class="oidc-field" style="margin-top:0.5em;">' +
            '<label>Libraries (when "All Libraries" is unchecked)</label>' +
            '<select id="role_libadd_' + idx + '"><option value="">-- Select library --</option>' + libOpts + '</select>' +
            '<button type="button" class="oidc-btn-secondary" style="margin-top:0.3em;width:fit-content;" data-action="add-lib" data-idx="' + idx + '">Add Library</button>' +
            '<div id="role_libs_' + idx + '" class="oidc-library-list"></div>' +
            '</div>' +
            '<div class="oidc-field" style="margin-top:0.5em;">' +
            '<label>Max Parental Rating (empty = unrestricted)</label>' +
            '<input type="number" id="role_maxrating_' + idx + '" value="' + (m.MaxParentalRating != null ? m.MaxParentalRating : '') + '" />' +
            '</div>' +
            '<div style="margin-top:0.5em;">' +
            '<button type="button" class="oidc-btn-remove" data-action="remove-role" data-idx="' + idx + '">Remove</button>' +
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
        card.className = 'oidc-card';
        card.innerHTML = '<h4>' + esc(p.DisplayName || 'New SAML Provider') +
            (p.Enabled ? ' <span style="color:#4caf50">&#9679;</span>' : ' <span style="color:#888">&#9679;</span>') +
            '</h4>' +
            '<div class="oidc-grid">' +
            fld('Provider ID', 'text', 'saml_id_' + idx, p.Id, 'Unique identifier') +
            fld('Display Name', 'text', 'saml_name_' + idx, p.DisplayName, 'Shown on login button') +
            fld('Entity ID (SP)', 'text', 'saml_entity_' + idx, p.EntityId, 'https://jellyfin.example.com', true) +
            fld('IdP SSO URL', 'text', 'saml_sso_' + idx, p.SsoUrl, 'https://idp.example.com/sso/saml', true) +
            fld('Username Claim', 'text', 'saml_user_' + idx, p.UsernameClaim || 'NameID', 'NameID or attribute name') +
            fld('Role Claim', 'text', 'saml_role_' + idx, p.RoleClaim || 'groups', 'Attribute name for groups/roles') +
            fld('Button Color', 'color', 'saml_color_' + idx, p.ButtonColor || '#4285F4', '') +
            '<div class="oidc-field"><label><input type="checkbox" id="saml_enabled_' + idx + '"' +
            (p.Enabled !== false ? ' checked' : '') + '/> Enabled</label></div>' +
            '</div>' +
            '<div class="oidc-field full" style="margin-top:0.5em;">' +
            '<label>IdP Signing Certificate (PEM or base64 DER)</label>' +
            '<textarea id="saml_cert_' + idx + '" rows="4" style="width:100%;font-family:monospace;font-size:0.85em;" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----">' +
            esc(p.IdpCertificate || '') + '</textarea>' +
            '</div>' +
            '<div style="margin-top:0.5em;">' +
            '<button type="button" class="oidc-btn-remove" data-action="remove-saml" data-idx="' + idx + '">Remove</button>' +
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
        var lines = [
            'Admin: ' + result.isAdmin,
            'Playback: ' + result.enableMediaPlayback,
            'Remote: ' + result.enableRemoteAccess,
            'Transcoding: ' + result.enableTranscoding,
            'Live TV: ' + result.enableLiveTv + (result.enableLiveTvManagement ? ' (manage)' : ''),
            'Download: ' + result.enableDownload,
            'SyncPlay: ' + (result.enableSyncplayGroupCreation ? 'host' : result.enableSyncplay ? 'join' : 'none'),
            'Libraries: ' + (result.enableAllLibraries ? 'ALL' : (result.libraries && result.libraries.length ? result.libraries.join(', ') : 'none')),
            'Max Rating: ' + (result.maxParentalRating != null ? result.maxParentalRating : 'unrestricted'),
            '',
            'Matched grants: ' + (result.matchedGrantMappings || []).join(', ') || '(none)',
            'Matched denies: ' + (result.matchedDenyMappings || []).join(', ') || '(none)',
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
    var resultEl = view.querySelector('.oidc-test-result[data-idx="' + idx + '"]');
    if (!authority) {
        if (resultEl) { resultEl.style.color = '#c62828'; resultEl.textContent = 'Authority URL is required'; }
        return;
    }
    if (resultEl) { resultEl.style.color = '#888'; resultEl.textContent = 'Testing...'; }

    ApiClient.ajax({
        type: 'POST',
        url: ApiClient.getUrl('sso/OIDC/Config/TestProvider'),
        data: JSON.stringify({ Authority: authority, Scopes: scopes }),
        contentType: 'application/json',
        dataType: 'json'
    }).then(function (result) {
        if (result.Success) {
            if (resultEl) {
                resultEl.style.color = '#4caf50';
                var msg = 'OK — issuer ' + result.Issuer;
                if (result.UnsupportedRequestedScopes && result.UnsupportedRequestedScopes.length > 0) {
                    msg += ' (unsupported scopes: ' + result.UnsupportedRequestedScopes.join(', ') + ')';
                    resultEl.style.color = '#ff9800';
                }
                resultEl.textContent = msg;
            }
        } else {
            if (resultEl) { resultEl.style.color = '#c62828'; resultEl.textContent = 'Failed: ' + result.Error; }
        }
    }).catch(function (err) {
        var msg = (err && (err.statusText || err.message)) || 'Network error';
        if (resultEl) { resultEl.style.color = '#c62828'; resultEl.textContent = 'Failed: ' + msg; }
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
            ButtonColor: gval(view, 'prov_color_' + idx),
            AdditionalParameters: gval(view, 'prov_params_' + idx),
            EntitlementClaim: gval(view, 'prov_entclaim_' + idx) || 'entitlements',
            EntitlementPrefix: gval(view, 'prov_entprefix_' + idx) || 'jellyfin:',
            EnableEntitlements: gchk(view, 'prov_entitlements_' + idx),
            RequireEmailVerified: gchk(view, 'prov_emailverified_' + idx),
            Enabled: gchk(view, 'prov_enabled_' + idx),
            ButtonIcon: '',
            RoleTransforms: collectTransforms(view.querySelector('#prov_transforms_' + idx))
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
            SsoUrl: gval(view, 'saml_sso_' + idx),
            UsernameClaim: gval(view, 'saml_user_' + idx) || 'NameID',
            RoleClaim: gval(view, 'saml_role_' + idx) || 'groups',
            ButtonColor: gval(view, 'saml_color_' + idx) || '#4285F4',
            IdpCertificate: certEl ? certEl.value.trim() : '',
            Enabled: gchk(view, 'saml_enabled_' + idx)
        });
    });
    return result;
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function (view) {
    view.addEventListener('viewshow', function () {
        Dashboard.showLoadingMsg();

        ApiClient.getJSON(ApiClient.getUrl('sso/OIDC/Config/Libraries')).then(function (data) {
            libs = data || {};
        }).catch(function () {
            libs = {};
        }).then(function () {
            return ApiClient.getPluginConfiguration(pluginId);
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
            Dashboard.hideLoadingMsg();
        }).catch(function (err) {
            Dashboard.hideLoadingMsg();
            console.error('OIDC RBAC: failed to load config', err);
        });
    });

    // Tabs
    view.querySelectorAll('.oidc-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            view.querySelectorAll('.oidc-tab').forEach(function (t) {
                t.style.borderBottomColor = 'transparent';
                t.style.color = '#aaa';
            });
            view.querySelectorAll('.oidc-tab-content').forEach(function (c) {
                c.style.display = 'none';
            });
            this.style.borderBottomColor = '#00a4dc';
            this.style.color = '#00a4dc';
            view.querySelector('#tab-' + this.getAttribute('data-tab')).style.display = 'block';
        });
    });

    // Add OIDC provider
    view.querySelector('#btnAddProvider').addEventListener('click', function () {
        if (!cfg) return;
        cfg.Providers.push({
            ProviderId: '', DisplayName: 'New Provider', Authority: '',
            ClientId: '', ClientSecret: '', Scopes: 'openid profile email',
            RoleClaim: 'groups', UsernameClaim: 'preferred_username',
            DisplayNameClaim: 'name', Enabled: true, ButtonColor: '#4285F4',
            ButtonIcon: '', AdditionalParameters: '',
            EntitlementClaim: 'entitlements', EntitlementPrefix: 'jellyfin:',
            EnableEntitlements: true, RequireEmailVerified: false, RoleTransforms: []
        });
        renderProviders(view);
    });

    // Add role mapping
    view.querySelector('#btnAddRoleMapping').addEventListener('click', function () {
        if (!cfg) return;
        cfg.RoleMappings.push({
            RoleName: '', ProviderId: '', Priority: 0, IsExplicitDeny: false,
            IsAdmin: false, EnableAllLibraries: false,
            LibraryIds: [], LibraryNames: [], EnableLiveTv: false,
            EnableLiveTvManagement: false, EnableMediaPlayback: true,
            EnableRemoteAccess: true, EnableTranscoding: true,
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
                EntityId: '', SsoUrl: '', IdpCertificate: '',
                UsernameClaim: 'NameID', RoleClaim: 'groups',
                ButtonColor: '#4285F4', Enabled: true
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
        ApiClient.updatePluginConfiguration(pluginId, cfg).then(function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            Dashboard.hideLoadingMsg();
        }).catch(function (err) {
            Dashboard.hideLoadingMsg();
            Dashboard.alert('Failed to save: ' + (err.message || err));
        });
    });

    // Event delegation — provider list
    view.querySelector('#providerList').addEventListener('click', function (e) {
        var btn = e.target.closest('[data-action]');
        if (!btn) return;
        var idx = parseInt(btn.getAttribute('data-idx'));
        var action = btn.getAttribute('data-action');
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
                row.innerHTML =
                    '<input type="text" class="xform-from" placeholder="From (exact)" />' +
                    '<span style="margin:0 0.3em;">→</span>' +
                    '<input type="text" class="xform-to" placeholder="To (empty=drop)" />' +
                    '<button type="button" class="oidc-btn-remove" style="padding:0.1em 0.5em;margin-left:0.3em;">&times;</button>';
                row.querySelector('button').addEventListener('click', function () { row.remove(); });
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
