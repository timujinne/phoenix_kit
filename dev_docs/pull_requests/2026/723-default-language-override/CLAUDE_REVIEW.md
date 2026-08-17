# Review: PR #723 — Request-scoped default-language override for multi-domain hosts

Merge commit: `46f45b93` (merges `6dee4538`, author timujinne)
Files: `lib/modules/languages/languages.ex`, `lib/phoenix_kit_web/integration.ex`,
`test/integration/languages/request_default_language_test.exs` (test lives under
`test/integration/`, not `test/modules/` — the task description's path was
slightly off).

## What the PR actually ships

Contrary to the "domain resolution" framing this might suggest, PR #723 ships
no host→domain→language mapping at all. It ships two independent pieces of
plumbing that a host app wires together itself:

1. `PhoenixKit.Modules.Languages.put_request_default_language/1` +
   `request_default_language/0` — a `Process`-dictionary-scoped override that
   `get_default_language/0` now consults before falling back to the
   `is_default` flag. Explicitly process-scoped, explicitly not inherited by
   `Task`/Oban.
2. `PhoenixKitWeb.Integration.extra_on_mount/0`, read from
   `config :phoenix_kit, :extra_live_session_on_mount`, PREPENDED to the
   `on_mount` list of every `live_session` PhoenixKit generates (public,
   admin, authenticated dashboard, deprecated user-dashboard, maintenance —
   all confirmed covered, three of the five via the shared
   `build_live_surface/5`, two patched directly).

There is no `conn.host`-trust question to raise about this PR specifically —
it never reads `conn.host` itself. Whether a host's own `DomainLanguageHook`
trusts the host header for anything security-sensitive is outside this PR's
diff; every existing consumer of `get_default_language/0` found
(`multilang.ex`, `settings.ex`, `routes.ex`, sitemap `shop.ex`/`publishing.ex`,
`language.ex`) is content/URL generation, not an auth or access-control
decision, so the blast radius of a spoofed override is "wrong language is
shown/generated," not a security boundary. Confirmed no unscoped DB read in
`mount/3` — the override is a `Process.get/2`, not a query, and none of the
touched `on_mount` wiring adds one.

**Relationship to PR #724 (per-domain sitemap):** checked for a shared or
conflicting source of truth. #724's `Sitemap.Generator`/`DomainMode` resolves
per-host sitemap content by filtering already-collected entries by language
and writing to per-host files (`DomainMode.rebuild_for_domains/2`,
`FileStorage.write_domain_sitemap/3`) — it never calls
`put_request_default_language/1` and doesn't run through a
LiveView/on_mount path at all (it's a batch/background generator, and per
this PR's own docs, Oban-style background jobs don't inherit the
process-scoped override anyway). The two PRs are consistent by not
overlapping — #723's mechanism is unused by #724 rather than conflicting with
it.

## Findings

### BUG - MEDIUM: exact-code override could lose to a same-base dialect earlier in the list

`get_default_language/0`'s override resolution used a single `Enum.find/2`
pass that OR'd "exact code match" and "base code match" into one predicate.
`Enum.find/2` returns the first list element satisfying the predicate, not
the most specific match — so with two enabled dialects sharing a base (e.g.
`fr-FR` and `fr-CA` both enabled, `fr-FR` earlier in the configured order), an
override of the exact code `"fr-CA"` incorrectly resolved to `fr-FR` because
`fr-FR` satisfied the predicate first via the base-code branch
(`extract_base("fr-FR") == extract_base("fr-CA")`). This is a real,
demonstrable case for any host with 2+ enabled dialects of one language
(`en-US`/`en-GB`, `pt-BR`/`pt-PT`, `fr-FR`/`fr-CA` — all reachable via
`add_language/1` against `BeamLabCountries.Languages.all_locales/0`, which
lists multiple dialects per base). Not caught by the shipped tests because
the fixture only ever has one enabled language per base.

**Fix applied:** replaced the single OR'd predicate with two sequential
passes in a new `find_request_override/2` — exact-code match first (over
enabled languages), base-code match only as a fallback when no exact match
exists. Locked in with a new test using a `fr-FR`/`fr-CA` fixture, overriding
`"fr-CA"` and asserting it (not `fr-FR`) wins.

### BUG - MEDIUM: empty-string override silently resolves to English instead of "no override"

`put_request_default_language(nil)` correctly clears the override, and an
unknown/disabled code correctly falls back to `is_default` (both were already
tested). But `put_request_default_language("")` fell through to the
`is_binary(code)` clause and was stored as a real override, because
`DialectMapper.extract_base("")` is documented/defined to default to `"en"`
(for its other callers, parsing possibly-blank Gettext locales) — so an
empty-string override silently matched any enabled English dialect via the
base-code branch, on installs whose actual default might be e.g. `fr-FR`.
This is exactly the shape of bug a naive host plug produces:
`Map.get(domain_map, host, "")` before calling `put_request_default_language/1`
would trip it on any unmapped host, silently forcing English instead of
falling back to the site default the way every other invalid input does.

**Fix applied:** added a `put_request_default_language("")` clause that
delegates to the `nil` (clear) behavior, so `""` is "no override" like every
other unrecognized input, and updated the moduledoc to say so explicitly.
Locked in with a new test asserting `request_default_language() == nil` and
`get_default_language()` returns the configured default (`en-US`), not just
"an English dialect."

### IMPROVEMENT - HIGH: the moduledoc under-documents where the companion Plug must run

Every `get_default_language/0` caller was traced to confirm there isn't a
second, inconsistent source of truth for default language — there isn't; this
override is the sole injection point and every URL generator (`Routes`),
Gettext-locale-selection, and sitemap source reads through it consistently.

However, one specific caller matters for correctness of the documented
integration pattern: `PhoenixKitWeb.Users.Auth.validate_and_set_locale/2` (the
`:phoenix_kit_locale_validation` pipeline plug, present in every
`build_live_surface/5`-generated pipeline) already calls
`get_default_language/0` — via `Routes.get_default_admin_locale/0` — to pick
the Gettext locale *and* decide locale-prefix redirects for the initial
(dead-render) response. Plug pipelines run to completion before Phoenix
dispatches to a LiveView and runs any `on_mount` hook, extra or built-in, on
that same request/process. The PR's own moduledoc says to "set it per conn (a
Plug) and per LiveView socket (an on_mount hook)" but gave no guidance on
*where in the pipeline* the conn-level plug must sit — the on_mount ordering
got a full paragraph of rationale (why `extra_on_mount` is prepended, not
appended) but the Plug side got none. A host that adds its per-domain plug
after `phoenix_kit_routes()`'s own `pipe_through` (or relies solely on the
on_mount hook, assuming it covers "the request") gets a real, confusing bug:
the dead-render HTML comes back in the site-wide default language (wrong
Gettext locale baked into the initial response, wrong redirect decision for
prefix-less URLs) while anything resolved after mount uses the per-domain
override — a visibly inconsistent page that's hard to trace back to plug
ordering.

**Fix applied (documentation only — no behavior change, avoids scope creep
into shipping a new plug-injection mechanism the PR didn't ask for):**
expanded `put_request_default_language/1`'s moduledoc with an explicit ⚠️
section naming `validate_and_set_locale/2` and stating the ordering
requirement (host plug must run inside the host's own `:browser` pipeline,
before `phoenix_kit_routes()`), and added a matching note next to
`extra_on_mount/0` in `integration.ex` cross-referencing the same caveat.
Not adding a core-shipped Plug/hook-point for the conn side: unlike the
LiveView `on_mount` list (which core owns end-to-end and must merge
correctly), the conn-level plug lives entirely in the host's own,
host-owned `:browser` pipeline where the host already has full control over
ordering — a core-provided plug would just be reinventing something the host
can already do correctly by placement, and the actual mechanism (the
override function) is only two lines. Documentation was the leverage point,
not more code.

## Not fixed / judged non-issues

- **No host-header trust issue introduced.** This PR contains no `conn.host`
  reads; that responsibility sits entirely in the host's own hook/plug code,
  which is out of core's diff and out of scope for a review of this PR.
- **No router-macro test for `extra_on_mount` wiring.** Verified by direct
  inspection that all three `build_live_surface/5` call sites (public, admin,
  authenticated) plus the two directly-patched live_sessions (maintenance,
  deprecated user-dashboard) correctly prepend `extra_on_mount()`. Did not add
  a macro-expansion/compile-time test for this: `PhoenixKitWeb.Router` (the
  library's own dev/test router) bakes `Application.get_env(:phoenix_kit,
  :extra_live_session_on_mount, [])` in at the *library's own* compile time,
  which is empty in this repo's config — there's no existing pattern in the
  suite for flexing macro-generated `on_mount` lists at runtime (the closest
  precedent, `route_precedence_test.exs`, tests route *declaration order* via
  small hand-built `Phoenix.Router` modules, not `live_session` `on_mount`
  merging), and building one from scratch for a two-line `++` is more
  scaffolding than the risk warrants. Flagged here rather than silently
  skipped.
- **Ambiguity when 2+ enabled languages share a base and the override itself
  is a bare base code** (e.g. override `"fr"` with both `fr-FR` and `fr-CA`
  enabled) is inherent to using base codes at all, not a regression — the
  first list match wins, same as before this PR for any other base-code
  lookup in this module. Not fixed; a host that cares about a specific
  dialect should pass the full code, which now works correctly per the fix
  above.
