# SAML Library Evaluation

**Status:** Research + recommendation. No code changes proposed at this time.
**Date:** 2026-05-25
**Branch:** `task-03-saml-lib-eval`
**Plugin license:** GPL-3.0-only (see `LICENSE`)
**Target framework:** `net9.0` (Jellyfin server 10.11.x runtime)

## TL;DR

**Recommendation: D — Keep the hand-rolled SAML implementation, now hardened by Waves A/B/C. Revisit only if/when we need encrypted assertions, SAML SLO, or full IdP metadata exchange.**

The hand-rolled code is small (~500 LoC across parser, controller, and request builder), purpose-built for the one job Jellyfin actually needs (SP-initiated POST binding, parse + validate response, mint a session), and now ships with all the table-stakes hardening that previously made "replace with a library" the obvious answer. Every credible library on offer is heavier than the thing it would replace, drags in framework opinions that don't match the Jellyfin plugin model, and either has a stalled release cadence (Sustainsys) or a license that, while GPL-compatible, still adds a transitive surface (System.ServiceModel.Primitives via ITfoxtec) that we currently do not pay for. The risk that replacement *introduces* new bugs in a now-stable surface is higher than the residual risk of the current code.

---

## 1. Candidates evaluated

### A. Sustainsys.Saml2

- **NuGet:** https://www.nuget.org/packages/Sustainsys.Saml2
- **GitHub:** https://github.com/Sustainsys/Saml2
- **Latest version:** 2.11.0 (2025-03-02)
- **License:** MIT (compatible with GPL-3.0 — one-way incorporation OK)
- **Target frameworks:** net8.0, net461, net47. **net9.0 not an explicit target** — would load via .NET 8 compat shim. Works in practice but is not a tested target.
- **Maintenance signal:** Last release ~14 months before today (2026-05-25). 127 open issues. Maintainer publicly solicits paid support to sustain development. v3 (ASP.NET Core-only) is on `main` but unreleased. Cadence has slowed materially since 2023.
- **API surface fit:** Mismatch. Sustainsys is designed as an ASP.NET Core authentication handler (`builder.AddSaml2(...)`) that **owns** the `/Saml2/Acs` route and produces a `ClaimsPrincipal` for the cookie-auth pipeline. Jellyfin plugins don't get to add authentication handlers to the host's auth pipeline — we need to parse a response inside our own `SamlController.AssertionConsumerService` and call Jellyfin's `IAuthenticationManager` ourselves. Sustainsys's internal `Saml2Response.Read(...)` + `GetClaims(...)` types can be used standalone but are not part of the documented stable API.
- **Security history:** No active GHSA advisories listed against the package. Past CVEs were against very old v1 releases.

### B. ITfoxtec.Identity.Saml2

- **NuGet:** https://www.nuget.org/packages/ITfoxtec.Identity.Saml2
- **GitHub:** https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2
- **Latest version:** 4.18.0 (2026-05-08)
- **License:** BSD-3-Clause (compatible with GPL-3.0)
- **Target frameworks:** net6.0, net7.0, net8.0, **net9.0**, net10.0, netstandard2.1, net462, net48. Explicit net9.0 target — best fit.
- **Maintenance signal:** Actively maintained. Release 17 days ago. 82 releases total. Only 3 open issues. Healthiest cadence of the three.
- **API surface fit:** Better than Sustainsys. Core `Saml2AuthnResponse` type can be constructed standalone, `.Read(xml, ...)` parses, `.ClaimsIdentity` exposes claims. `ITfoxtec.Identity.Saml2.MvcCore` is an *optional* helper layer; the core package can be used inside any controller. Cleaner fit to our `AssertionConsumerService` shape.
- **Dependencies dragged in:** `Microsoft.IdentityModel.Tokens.Saml`, `System.Security.Cryptography.Xml`, **`System.ServiceModel.Primitives`** (≈3 MB of WCF heritage we don't otherwise carry).
- **Security history:** No GHSA advisories of note.

### C. Microsoft.IdentityModel.Tokens.Saml / .Saml2

- **NuGet:** https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens.Saml
- **Latest version:** 8.18.0 (2026-04-30)
- **License:** MIT
- **Target frameworks:** net6.0, net8.0, **net9.0**, net10.0, netstandard2.0, net462. Explicit net9.0.
- **Maintenance signal:** Microsoft-owned (Wilson stack — same family as `Microsoft.IdentityModel.Protocols.OpenIdConnect` we already depend on). Heavy production use ("5+T requests/day"). Excellent cadence.
- **API surface fit:** **Primitives only.** Provides `Saml2SecurityTokenHandler`, `Saml2Assertion`, `TokenValidationParameters`. Does NOT provide:
  - SAML-P request building (`<AuthnRequest>` construction / Redirect-binding deflate+sign).
  - POST-binding response envelope parsing (`<samlp:Response>` ≠ `<Assertion>`).
  - IdP metadata fetching.
  - Replay cache.
- **Effort to use:** You'd still write everything in `SamlController.cs` and the request builder. You'd swap *only* the signature verification + assertion-claims extraction inner loop. Net LoC reduction: small. Net dependency surface added: nontrivial. Worst of both worlds for a project this size.
- **Security history:** Microsoft.IdentityModel had GHSA-59j7-ghrg-fj52 (2024) in JWT validation — unrelated to SAML path, fixed. Family is responsive.

### D. Status quo (hand-rolled, hardened)

Current footprint:

| File | LoC |
|---|---|
| `Jellyfin.Plugin.OIDC/Saml/SamlRequest.cs` | 65 |
| `Jellyfin.Plugin.OIDC/Saml/SamlResponse.cs` | 201 |
| `Jellyfin.Plugin.OIDC/Api/SamlController.cs` | 248 |
| `Tests/.../SamlResponseTests.cs` | 135 |
| `Tests/.../SamlFlowTests.cs` | 135 |
| **Total** | **784** |

Hardening already shipped (Waves A/B/C):
- Signature anchored to specific signed element (no signature-wrapping).
- Algorithm allowlist (no MD5/SHA1 acceptance).
- Issuer / Audience / Destination / Recipient / `InResponseTo` validation.
- Replay cache for assertion `ID`.
- Request size limits.
- XML parser locked down (no DTD, no external entities, no XInclude).

**Residual risk:**
1. **No encrypted assertions (`<EncryptedAssertion>`).** Hand-rolled path doesn't implement XML encryption. Most enterprise IdPs (Okta, Azure AD, Auth0) can ship plaintext over TLS — fine — but a customer with a strict policy requiring encrypted assertions can't use us today.
2. **No SLO / LogoutRequest / LogoutResponse.** Acceptable: Jellyfin sessions are token-based; logout is local.
3. **No HTTP-Artifact binding.** Almost nobody uses this. Fine to skip.
4. **Hand-rolled XML signature verification is the highest-risk surface.** Wave A/B anchored it correctly, but signature-wrapping is a notoriously easy bug to reintroduce on refactor. A library would push that responsibility outward.

---

## 2. Cost / risk comparison

| Dimension | A: Sustainsys | B: ITfoxtec | C: MS primitives | D: Status quo |
|---|---|---|---|---|
| net9.0 first-class | No (compat shim) | **Yes** | **Yes** | **Yes** |
| License vs GPL-3.0 | MIT OK | BSD-3 OK | MIT OK | n/a |
| Active maintenance | Slowing | **Healthy** | **Healthy** | Us |
| Fits non-middleware SP controller | Awkward | OK | Manual | **Native** |
| Removes XML signature responsibility | Yes | Yes | Yes | No |
| Encrypted-assertion support | **Yes** | **Yes** | Yes (manual) | No |
| LoC removed from `Saml/` | ~266 | ~266 | ~50 | 0 |
| LoC added (integration + config mapping) | ~300–400 | ~200–300 | ~400+ | 0 |
| Test rewrite | Heavy (mocks IdP cert + library types) | Heavy | Medium | None |
| New transitive deps | Sustainsys.Saml2 + its tree | ITfoxtec + System.ServiceModel.Primitives | MIT.Tokens.Saml + .Saml2 + .Xml | None |
| Config-schema break for users | Likely (cert format, metadata) | Likely | Minimal | None |
| Risk of regression | Medium-high (whole flow rewritten) | Medium | Medium | Low |

**Net LoC:** B and A are roughly *break-even* — the integration glue is comparable to what we'd delete. C is a net add. D is zero churn.

**Test rewrite cost is the killer.** Current tests construct synthetic `<samlp:Response>` XML and exercise every validation branch (bad sig, bad audience, replay, etc.). With Sustainsys/ITfoxtec, those tests stop testing our code and start testing the library — which is fine if we're confident the library is correct, but they don't translate, they get *replaced*, and the lost coverage is real until someone writes equivalent integration tests against the new surface.

**User-visible config impact:** All three libraries expect IdP metadata XML (or a metadata URL) as the primary trust input, where we currently take a raw signing cert PEM + a few discrete fields in `SamlProviderConfig`. Either we write a metadata-to-config shim or we ask every existing user to re-configure. That's a real migration tax for a feature that, today, works.

---

## 3. Recommendation

**D. Keep the hand-rolled implementation. Do not swap.**

The decision pivots on one observation: the win from adopting a library is *risk reduction on the SAML signature path*, and Waves A/B/C have already eaten most of that win. We're now comparing "small, focused, audited 500-LoC implementation" against "drop in 50K+ LoC dependency, rewrite tests, force users to re-configure, hope the library handles the same edge cases the same way." For a plugin that does **SP-side POST-binding only, no encryption, no SLO**, the library buys us encrypted assertions and a smaller XML-signature attack surface; it costs us a meaningful migration and a fresh class of integration bugs in code that currently works.

**Trigger to revisit:** the day a user files a serious request for `<EncryptedAssertion>` support, or we want to ship SLO/metadata-exchange, switch to **ITfoxtec.Identity.Saml2** (option B). It has the cleanest net9.0 story, a healthy release cadence, a permissive license, and the most flexible API for our non-middleware controller shape. Sustainsys is a worse fit today (slowing cadence, middleware-first design, no explicit net9.0 target) and Microsoft's primitives package is not a complete SP — picking it would mean keeping most of our hand-rolled code anyway.

---

## 4. Migration plan

Not applicable — recommendation is to keep the hand-rolled implementation. If a future decision flips this to B (ITfoxtec), a sketch:

- **Phase 1 — Behind a flag.** Add `ITfoxtec.Identity.Saml2` to `Jellyfin.Plugin.OIDC.csproj`. Add `SamlProviderConfig.UseLibraryParser` boolean. In `SamlController.AssertionConsumerService`, branch on the flag: legacy path calls `SamlResponse.Parse`, new path calls ITfoxtec's `Saml2AuthnResponse.Read`. Both produce the same `ParsedSamlAssertion` shape for downstream code.
- **Phase 2 — Config migration.** Accept IdP metadata URL/XML in `SamlProviderConfig` alongside existing discrete fields. Build a one-shot config converter. Document the new shape in `MIGRATION.md`.
- **Phase 3 — Remove legacy.** Once telemetry/issues show the library path is stable across 2+ releases, delete `Saml/SamlResponse.cs`, `Saml/SamlRequest.cs`, the flag, and the legacy config fields.
- **Files touched per phase:**
  - P1: `Jellyfin.Plugin.OIDC.csproj`, `Configuration/SamlProviderConfig.cs`, `Api/SamlController.cs`, new `Saml/LibrarySamlAdapter.cs`.
  - P2: `Configuration/SamlProviderConfig.cs`, `Configuration/configPage.html`, `MIGRATION.md`.
  - P3: delete `Saml/SamlResponse.cs`, `Saml/SamlRequest.cs`, `Tests/.../SamlResponseTests.cs`; add `Tests/.../SamlLibraryAdapterTests.cs`.
- **Rollback:** flip `UseLibraryParser` to false at the provider level. Legacy code remains until Phase 3.

---

## Evidence links

- Sustainsys NuGet: https://www.nuget.org/packages/Sustainsys.Saml2 (v2.11.0, 2025-03-02, MIT, net8.0)
- Sustainsys repo: https://github.com/Sustainsys/Saml2 (127 open issues, v3 unreleased)
- ITfoxtec NuGet: https://www.nuget.org/packages/ITfoxtec.Identity.Saml2 (v4.18.0, 2026-05-08, BSD-3-Clause, net9.0 explicit)
- ITfoxtec repo: https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2 (3 open issues, 82 releases)
- Microsoft.IdentityModel.Tokens.Saml NuGet: https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens.Saml (v8.18.0, 2026-04-30, MIT, net9.0)
- GPL-3.0 / MIT / BSD-3 compatibility: https://www.gnu.org/licenses/license-list.html
