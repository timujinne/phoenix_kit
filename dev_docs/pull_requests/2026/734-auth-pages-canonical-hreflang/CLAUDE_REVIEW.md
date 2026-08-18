# CLAUDE_REVIEW — PR #734

**Title:** Add canonical/hreflang to the stable auth pages
**Branch:** feature/auth-pages-canonical-hreflang
**Author:** timujinne
**Merge commit:** fcd2cb3130f83a4ca4478226e343d2a9a0d2ce38

## Summary

Adds `PhoenixKitWeb.Users.AuthSEO.seo_assigns/1`, which computes
`canonical_url` / `hreflang_links` for the three stable, token-free auth
LiveViews (`/users/register`, `/users/log-in`,
`/users/register/magic-link`) and assigns them in `mount/3`. Rendering is
the host app's responsibility (mirrors `phoenix_kit_ecommerce`'s
`SEOHelpers` contract); this library only sets the assigns.

## Findings

None at CRITICAL/HIGH/MEDIUM. This is a small, well-scoped, well-tested
addition that reuses existing, already-hardened primitives (`Routes.path/2`,
`Routes.base_url/0`, `Languages.enabled?/0`, `DialectMapper.extract_base/1`)
rather than reimplementing them.

### NITPICK — `resolve_canonical_host/1` is keyed on the base language code only

`enabled_languages()` maps each enabled language to its `DialectMapper`
*base* code before calling the resolver (`extract_base(&1.code)` then
`Enum.uniq()`), so a host with two enabled dialects of the same base
language (e.g. `es-ES` and `es-MX`) collapses to a single `es` hreflang
entry, and `canonical_host_resolver` is only ever invoked with base codes,
never full dialect codes. This is consistent with `current_language/0`
(which also extracts the base before use) and appears to be the intended
design — a host that wants dialect-level hosts/hreflang can't express that
today. Not a regression from this PR and not clearly wrong (dialect-level
hreflang is a rarer need), just worth flagging since it's not called out in
the moduledoc. No fix needed unless the maintainer wants dialect-level
granularity.

### NITPICK — assigns computed in `mount/3`, not `handle_params/3`

`elixir:phoenix-thinking`'s Iron Law is "no DB queries in mount." This calls
`Languages.enabled?/0` / `get_enabled_languages/0` from `mount/3`, which read
through `PhoenixKit.Settings`'s cache (ETS-backed, not a raw `Repo` call per
request) — the same pattern `login.ex`/`registration.ex` already use for
`allow_registration`, `magic_link_login_enabled`, etc. in the same `mount/3`.
Not a new violation, and the moduledoc explicitly documents *why* it has to
run before the locale `handle_params` hook (it depends on the HTTP-layer
Gettext locale already being set, not on URL params). No fix needed.

## Verification performed

- Read `auth_seo.ex` in full, including the `rescue`/`catch :exit` pair on
  `resolve_canonical_host/1` — correctly catches both a raising resolver
  and one that exits (e.g. a dead DB pool), consistent with the same
  raise-vs-exit gotcha documented in `AGENTS.md` for other soft-failure
  paths in this codebase.
- Confirmed all three call sites (`login.ex`, `registration.ex`,
  `magic_link_registration_request.ex`) assign `canonical_url` /
  `hreflang_links` only on the success/rendering path — when a gate
  (`allow_registration`, `magic_link_registration_enabled?`) fails, the
  LiveView redirects instead of rendering, so no SEO assigns are needed or
  set there. Correct.
- Confirmed by grep that no template/layout in this repo renders
  `@canonical_url`/`@hreflang_links` — rendering is genuinely left to the
  host app as documented, so there's no HEEx double-escaping or
  interpolation risk to check here (HEEx auto-escapes `href={...}` anyway).
- Confirmed the excluded, token-bearing auth pages (confirm, password
  reset, magic-link verify, QR-login confirm) do not call
  `AuthSEO.seo_assigns/1` — only the three stable paths do.
- Read both new test files (`auth_seo_test.exs`,
  `auth_seo_mount_test.exs`) — good coverage: disabled-languages
  self-reference, 2-language hreflang set, single-enabled-language empty
  set, a disabled language excluded, resolver absent/configured/raising/
  exiting, and a mount-level test proving each of the three LiveViews
  actually wires the helper's output into `socket.assigns` (not just that
  the helper itself is correct).

## Verdict

Release-safe as-is. No fixes applied.
