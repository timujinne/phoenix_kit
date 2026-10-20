# PR #944 — Public API guide at /mcp, RFC 9727 API catalog, discovery links

**Author:** timujinne · **Reviewer:** Claude · **State at review:** open, `CONFLICTING` (merged by hand)

## Merge conflict

Thirteen files, all textual overlap with what landed after the branch point (#940–#943, #945):

- **Ten gettext catalogs** — both sides appended at the end of the file. Resolved by taking main's catalog
  and appending the PR's 22 new entries that main lacks (the PR only adds; it changes no existing entry,
  checked against the merge base). Not by `gettext.extract --merge` (see the #945 review: it churns
  references and marks 27 entries per locale fuzzy on today's main).
- **`AGENTS.md`** — the "Strings" line lists both new translation tests (`ApiGuideTranslationsTest` from
  #945, `PublicDiscoveryTranslationsTest` from this PR).
- **`dev_docs/guides/2026-10-11-shop-api.md`** — upgrade step 6 keeps main's `:trusted_proxies` wording
  (#943), step 7 keeps the PR's `GET /mcp` and `/.well-known/api-catalog` claim; "Connecting a client"
  keeps #945's admin-guide paragraph and gets the PR's pointer to *Public discovery*.
- **`MCP.Shape.instructions(:public)`** — main's "(an unknown tool name is a JSON-RPC error, -32602)"
  (#941) and the PR's "Answers follow the language and currency of the domain you call" are both kept;
  the PR's pinned-wording test in `mcp_shape_test.exs` is updated to the merged text.

After the merge: `mix compile --warnings-as-errors` clean; `test/phoenix_kit/api`, `test/phoenix_kit_web`,
`test/integration/api`, `test/integration/sitemap`, `test/mix`, `test/modules/crawlers` — 4032 tests +
10 doctests, 0 failures.

## Review

Sound and carefully fenced. The single predicate `PublicDiscovery.check/1` (switch, website gate, at least
one visible public tool) gates every document and header; a hidden guide answers the API's own 404 and
never names the MCP server; the order 404 → 405 → 406 → 200 is deliberate and tested. The "never name the
admin API" rule is enforced by a leak scan whose banned list is built from the admin registry.
`PublicDiscovery.origin/1` does not trust the `Host` header (grammar + membership in `known_hosts/1`, else
the canonical origin; scheme and port always canonical) and I confirmed the host-grammar regex does not
backtrack badly on a 16 KB hostile `Host` value. `put_link/2` de-duplicates. `/mcp` is routed beside
`/llms.txt` (no session, no CSRF) and carries `sitemap: false` metadata so it stays out of the sitemap.

- **IMPROVEMENT - MEDIUM (not changed)** — `/llms.txt` used to be a cheap settings read; it now also
  walks `Registry.visible_tools(:public, :all)` and the gate check on every request, and `/mcp` and the
  catalog do the same, with no rate-limit unit ("not API calls"). They are unauthenticated, so this is
  the cost an anonymous client can make us pay per request. `public, max-age=300` helps behind a CDN but
  not on a bare install. Worth a short-lived (a few seconds) cache of the tool list if it ever shows up
  in a profile; the PR deliberately caches nothing so a switched-off module vanishes at once.
- **NITPICK** — a host that already serves its own `/mcp` after `phoenix_kit_routes()` is now shadowed;
  documented in upgrade step 7 and checked by the doctor (`Fix the doctor to report a host route at /mcp`).
- **NITPICK** — `Origin.fallback_origin/0` warns once per boot through `:persistent_term`; a node that
  fixes `site_url` at runtime keeps the flag set (harmless: the flag only suppresses a log line).

No fixes needed beyond the merge.
