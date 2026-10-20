# PR #939 — Add Routes helpers that build per-language public URLs through the canonical host resolver

**Author:** timujinne · **Merged:** 2026-10-19 (ef77f9613) · **Reviewer:** Claude

## Summary

`Routes.canonical_host/1`, `canonical_origin/1`, `canonical_url/2`, `canonical_absolute/2`, `canonical_absolute_or_nil/2`:
one place that calls the host's `:canonical_host_resolver` (rescue + `catch :exit/:throw`, bare-host validation, one warning
per kind per process per minute), then builds the URL on that host or on the site base. `AuthSEO` now uses it instead of its
private copy.

Verdict: sound. The resolver answer is validated (scheme, path, credentials, whitespace, empty labels, port range), the
fallback is always the site base, `canonical_origin` takes the scheme from the explicit `site_url` rather than hard-coding
`https`, and the dialect-segment rules of `canonical_absolute/2` are pinned by tests. `canonical_origin_test` passes.

## Findings

- **IMPROVEMENT - MEDIUM (documented, not changed):** `canonical_url/2` builds the language segment from the language's BASE code
  (`path(url_path, locale: language_base(language))`), while `canonical_absolute/2` keeps the segment of the path it is given.
  For a site that serves `en` and `en-GB` as separate languages, `canonical_url("/pages", "en-GB")` on the site base is
  `/en/pages` — the sibling's page — although the shop-API guide said a dialect code could be passed "as stored". The base code
  is what `AuthSEO` always passed, so nothing in core is affected. Not changed because the right segment for a dialect depends on
  how the host routes it; the `canonical_url/2` doc and the guide now say which function to use for a dialect that has its own
  segment (`path/2` + `canonical_absolute/2`).
- **NITPICK (not changed):** `AuthSEO` canonical URLs used a hard-coded `https` for a resolved host before; they now follow the
  `site_url` scheme (documented in the PR). A staging site with an `http` `site_url` gets `http` canonicals — correct, but a
  visible change for such installs.
- **NITPICK (not changed):** `warn_once/2` rate-limits through the process dictionary, so every request process warns once a
  minute rather than the VM. Acceptable (a failing resolver is loud by design) and avoids a shared counter on the hot path.
