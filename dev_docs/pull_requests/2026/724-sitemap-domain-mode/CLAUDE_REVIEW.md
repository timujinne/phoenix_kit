# PR #724 — Per-domain sitemap generation, storage, cache and serving

Merge commit: `c250374f` · Author: timujinne · Reviewed by: Claude

Files in scope: `lib/modules/sitemap/cache.ex`, `lib/modules/sitemap/domain_mode.ex` (new),
`lib/modules/sitemap/file_storage.ex`, `lib/modules/sitemap/generator.ex`,
`lib/modules/sitemap/web/controller.ex`, plus the three new integration test files.

## Summary

DomainMode lets a host app map several domains to distinct languages (one domain =
one canonical language) and serve a per-domain `sitemap.xml`/`sitemaps/*` set built by
re-hosting each language's already-collected entries and computing cross-domain
hreflang alternates once per canonical group. Overall the design is careful: host
strings are validated and normalized in one place (`DomainMode.domains/0`), file
paths are re-validated with the same regex in `FileStorage` as defense in depth, and
`Cache.invalidate/0` / `cleanup_stale_domain_dirs/0` correctly sweep per-host
directories so stale/renamed domains don't linger.

One real bug was found and fixed (below). Everything else is either already-existing
project-wide behavior this PR doesn't change, or minor.

---

## BUG - HIGH: Domain-mode generation force-collected in INDEX mode, leaking disabled sources into public per-domain files

**File:** `lib/modules/sitemap/generator.ex`, `generate_domain_sitemaps/5`

Before the fix:

```elixir
entries =
  entries || collect_all_entries(Keyword.put(opts, :force, true), get_sources())
```

`generate_domain_sitemaps/5` is called from both `do_generate_index/5` (passing
`entries: nil`, so it re-collects here) and `do_generate_flat/5` (passing its
already-collected `entries` through). The `nil`-entries (index-mode) branch was
unconditionally forcing `:force, true` before collecting.

`Source.safe_collect/2` treats `force: true` as "skip the source's own `enabled?/0`
gate and collect anyway":

```elixir
force = Keyword.get(opts, :force, false)
if valid_source?(source_module) and (force or source_module.enabled?()) do
  source_module.collect(opts)
```

This is the same mechanism behind the already-documented, accepted "flat mode
force-collects, bypassing `enabled?/0`" issue — but that one is scoped to flat mode,
where `force: true` is intentional (flat mode always merges everything into one
`<urlset>`, entries key open flag documented in `do_generate_flat/5`). **Index mode
never had this problem**: `do_generate_index/5` builds per-module files via
`generate_module/2`, which correctly gates on `Source.valid_source?(mod) and
mod.enabled?()` with no force — a disabled source has never appeared in the legacy
`sitemapindex` output.

By forcing collection for the *domain* files even when running in index mode, this
PR introduced a **new** instance of the same bug class in a place that was
previously safe: turning on domain mode while the site runs in (default) index mode
would let a disabled source's URLs appear in the public, crawlable per-domain
sitemap files, even though those exact URLs are correctly absent from
`/sitemap.xml` and every per-module file. For any source whose `collect/1` relies on
the outer `enabled?/0` gate (a legitimate pattern — see `Static`, which has no
internal re-check since it has no "disabled" state, or a third-party module
contributed via `sitemap_sources/0`), this is a real content leak: a shop/blog/etc.
source an operator explicitly disabled shows up on a live, indexed domain.

**Fix:** dropped the forced `:force, true` in the index-mode (`entries == nil`)
branch — it now calls `collect_all_entries(opts, get_sources())` with no
override, so domain-file collection honors `enabled?/0` exactly like the legacy
per-module path. Flat mode is untouched: its own pre-existing force-collect (a
separate, already-documented, deliberately-unfixed trade-off) still reaches this
function, but only via the already-collected `entries` argument it passes through —
this function's own `force: true` no longer additionally re-widens it.

**Test added:** `test/integration/sitemap/domain_generation_test.exs` —
`"index mode domain files exclude disabled sources (no force-collect leak)"`. Adds
a `DomainGenerationDisabledSourceStub` source (`enabled?/0` returns `false`,
`collect/1` returns a URL unconditionally — the "outer gate only" pattern), swaps it
in as the site's only source via `config :phoenix_kit, sitemap: sources:`, disables
router discovery so generation takes the index path, and asserts the generated
`gen.example.com` domain file does **not** contain the stub's URL. This test fails
against the pre-fix code and passes after.

---

## Findings verified as NOT bugs (checked per the review brief)

- **Cache key collisions / cross-domain leakage** — none found. `DomainMode.domains/0`
  downcases and validates hosts once; `FileStorage` re-validates the same string with
  an identical regex before ever touching the filesystem. Per-host XML is written to
  `sitemaps/domains/{host}/...`, one directory per host, so there's no shared key
  between domains. `Cache.put({:domain_xml, host, filename}, xml)` keys are already
  host-namespaced (see IMPROVEMENT-MEDIUM below re: this cache actually being dead).
- **Path traversal via domain string** — `FileStorage.domain_file_path/2` and
  `DomainMode`'s own `@host_re` both anchor on
  `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`, which rejects
  `/`, `..`, and empty labels outright. The `domain_mode_test.exs` suite already
  covers this directly (`malformed_host` case using `"../etc/passwd"` as a host).
  `conn.host` is never used to build a filesystem path directly — the controller only
  ever looks up an exact match against the pre-validated `DomainMode.domains()` list
  (`domain_host/1`), so a forged `Host` header can select an existing mapped host at
  most, never traverse.
- **Controller cross-domain serving leak** — `domain_host/1` matches the request host
  against the validated domain list only; an unmapped host correctly falls through to
  the legacy index/module serving path (`domain_serving_test.exs` covers "unmapped
  host keeps the legacy set"). No domain-A-on-domain-B scenario is reachable.
- **Domain normalization consistency** — all three files (`domain_mode.ex`,
  `file_storage.ex`, `controller.ex`) agree: hosts are lowercased once in
  `DomainMode.validate/1` and never re-cased elsewhere; `domain_host/1` also
  lowercases the *incoming* `conn.host` before comparing, so casing can't cause a
  cache-miss/wrong-file mismatch either direction.
- **Test coverage for cross-domain isolation** — `domain_mode_test.exs`'s
  `rebuild_for_domains/2` tests do assert real isolation (`"untranslated group
  appears only on its language's domain"` asserts the *other* domain's list is
  `[]`), not just "runs without erroring." The gap was specifically the
  `enabled?/0`-bypass path, now covered by the added test above.

## IMPROVEMENT - MEDIUM: `Cache.put({:domain_xml, ...})` is written but never read

`write_domain_files/4` in `generator.ex` caches every per-host XML payload
(`Cache.put({:domain_xml, host, filename}, xml)`), but nothing in the codebase ever
calls `Cache.get({:domain_xml, ...})` — `controller.ex`'s `serve_domain_file/4`
always reads from disk via `File.exists?`/`File.read`. This mirrors an existing,
equally-unused pattern already present for legacy per-module files
(`Cache.put_module/2` / `Cache.get_module/1`, also never read anywhere), so it's not
a regression this PR introduces — just an extension of a pre-existing "write it in
case something wants it later" convention. Left as-is: removing it would touch a
project-wide pattern out of scope for this PR, and it doesn't cause incorrect
behavior (just doubles ETS memory for very large multi-domain sites, bounded by the
same `Cache.invalidate/0` sweep as everything else in the table).

## NITPICK: `home_url/5` hardcodes `https://`

`DomainMode.home_url/5` always builds `"https://#{host}#{rel}"` regardless of the
scheme used by the configured `base_url` (`site_url` setting). In practice sitemap
URLs should always be `https://` in production, but a site intentionally running
plain HTTP (e.g. local/staging testing without TLS) would get scheme-mismatched
domain URLs while the legacy index correctly follows `base_url`'s own scheme. Low
impact, not fixed (would need a design decision on whether per-domain URLs should
ever be non-HTTPS).

## NITPICK: File writes are not atomic (pre-existing pattern, not new)

`FileStorage.write_domain_sitemap/3` (and the pre-existing `save_module/2`,
`save/1`) write directly with `File.write/2` — no temp-file-then-rename. A request
racing a regeneration could theoretically read a partially-written file. This is
identical to the existing legacy-file behavior and not something this PR changes or
worsens; flagged for awareness only, not fixed here.

## NITPICK: Minor redundant `domain_host(conn)` call (fixed, trivial)

`Controller.xml/2`'s `cond` called `domain_host(conn)` twice (once as the guard,
once to pass into `serve_domain_file/4`). Changed to `host = domain_host(conn) ->`
so it's evaluated once and reused — no behavior change, just avoids a redundant
`DomainMode.domains/0` + `Enum.find/2` per request.
