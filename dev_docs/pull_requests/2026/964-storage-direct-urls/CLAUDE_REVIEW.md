# PR #964 — Storage: direct bucket URLs for many file variants (direct_urls/1)

**Author:** timujinne · **Merged:** 2026-10-24 (2671e928f) · **Reviewer:** Claude

## Summary

`Storage.direct_urls/1` maps `{file_uuid, variant}` pairs to permanent public
object URLs in a fixed number of queries (instances, `Libraries.private_among/1`,
`Locations.ranked_all/1`, buckets outside the cached pool), so a page with many
images links them to the bucket/CDN instead of through `/file/...` and its 302.
`Locations.ranked/2`'s ranking moved into a shared `rank/1`; `with_owned_buckets/2`
now dedups the uuids it looks up.

Verdict: correct. Checked each rule against what the file route does for the same
pair, and they agree:

- refused by the route → left out here: `system_managed`, trashed, private
  library (`private_among/1` is the batch form of `private_file?/1`, hidden
  system libraries included), edit `pending`/`failed`;
- route redirects only for an inline type (`FileController.disposition_for/1`,
  reused rather than copied) and only from a public bucket — same here;
  local / private / signed buckets and R2 without `cdn_url` give `nil`
  (`Local.public_url/2` and `S3.public_url/2` both return `nil` there);
- bucket choice follows `read_order/4` for `:serve`: backups dropped, first
  located bucket in the enabled pool or an enabled user-owned bucket; a
  disabled site bucket stays out because `with_owned_buckets/2` keeps only
  enabled, owned rows;
- a pending variant (the route's stand-in) is left out rather than pointed at
  the original — the right call for a permanent URL.

The cross-product in `ranked_all/1` (`path in keys and file_uuid in uuids`) is
narrowed back to the wanted pairs, so a key shared with a cross-user copy is
ranked by its own file's profile, as `ranked/2` does with a `file_uuid`.

## Findings

- **IMPROVEMENT - MEDIUM (fixed)** — a pair whose variant is not a string
  (`{uuid, :medium}`, `{uuid, nil}`) reached `i.variant_name in ^variants` and
  raised `Ecto.Query.CastError` for the whole batch, while a bad uuid is
  quietly left out. An atom variant is an easy host mistake. Such pairs are now
  dropped when the wanted set is built; test added (fails without the fix).
- **IMPROVEMENT - MEDIUM (fixed, test only)** — no test had a copy recorded
  only on a disabled bucket (the query-count block's disabled bucket always has
  an enabled one to fall through to). Added. A *deleted* bucket cannot still
  have location rows (the location FK is RESTRICT), so the docstring's
  "or deleted" is defensive only.
- **NITPICK (not changed)** — `Locations.ranked_all/1` says "never raises" and
  has `rescue` but no `catch :exit` (a dead pool exits). Same as `ranked/2`,
  and `Storage.direct_urls/1`'s own instance query has no guard at all, so a
  dead DB fails the call either way; left as is.

## Verification

`direct_urls_test.exs` + `validators_test.exs`: 121 tests, 0 failures.
