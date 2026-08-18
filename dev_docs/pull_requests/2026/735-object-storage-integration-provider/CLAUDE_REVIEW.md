# CLAUDE_REVIEW — PR #735: Add `object_storage` integration provider (S3-compatible)

**Merge commit:** `7f41b34b858a7dc680ce1824e7aea9e5a52e369d`
**Author:** timujinne
**Files:** `lib/phoenix_kit/integrations/{integrations,providers,validators}.ex`,
`test/phoenix_kit/integrations/{providers,validators}_test.exs` (+501/-0, all net-new)

## Summary

Registers a new `object_storage` integration provider (`key_secret` auth:
access key / secret key / optional region / optional endpoint) covering AWS
S3, Cloudflare R2, Backblaze B2, Tigris, and self-hosted S3-compatible
endpoints. Validates credentials with a real `ListBuckets` call, with a
confirm-before-reject retry for transient `InvalidAccessKeyId` /
`SignatureDoesNotMatch` (mirrors the existing `aws_ses` validator's
confirm-retry). This is the integration-side half of a two-PR feature —
`lib/modules/storage/providers/s3.ex` (already merged, an earlier PR) added
`Bucket.integration_uuid` and `resolve_credentials/1` to consume exactly this
provider's `access_key`/`secret_key` shape; that code comment explicitly
named this PR as "a parallel branch." Confirmed the wiring lines up
end-to-end: `Providers.object_storage/0`'s `setup_fields` keys
(`access_key`, `secret_key`) match what `S3.resolve_credentials/1` reads from
`Integrations.get_credentials/1`.

## Verification performed

- Read the full diff plus `Bucket.resolve_credentials/1` and
  `Providers.with_capability/1` to confirm the cross-PR wiring is real, not
  just claimed by the inline comments.
- Confirmed `secret_key` is already in the global
  `Encryption.@sensitive_fields` / `Events.@sensitive_fields` lists (added
  before this PR) — no encryption-at-rest gap; this provider needed no
  changes there and the test asserts it (`providers_test.exs:88`).
- Confirmed `scopes: [:system, :personal]` matches every other `key_secret`
  provider in the file (13 matches, all identical).
- Ran `mix test test/phoenix_kit/integrations/providers_test.exs
  test/phoenix_kit/integrations/validators_test.exs`: 74 tests, 0 failures.
- Traced `interpret_object_storage_error/1`'s `aws_error_code/1` dependency —
  regex-based, returns `nil` on any unparseable body rather than raising;
  the catch-all `interpret_object_storage_error(_reason)` clause covers
  non-`:http_error` reasons (timeouts, `:econnrefused`, etc.).
- Confirmed the `il-central-1`/`mx-central-1` ExAws host-resolution gap and
  the R2 scheme-prefixed-endpoint `MatchError` claims in the code comments
  are consistent with the tests added for exactly those cases
  (`object_storage_config/1` tests, "an endpoint pasted with its scheme"
  test) — didn't independently re-derive them against a live AWS account,
  but the reasoning and test coverage are internally consistent.

## Findings

No BUG or IMPROVEMENT-HIGH findings.

### NITPICK — integration-level `region`/`endpoint` are validation-time only, not consumed by a bucket

`Providers.object_storage/0`'s `setup_fields` exposes `region` and
`endpoint` on the integration connection, and `Validators.object_storage/1`
uses them to run the `ListBuckets` connectivity check. But
`S3.resolve_credentials/1` (the consumer, in
`lib/modules/storage/providers/s3.ex`) only pulls `access_key`/`secret_key`
off the integration — `bucket.region`/`bucket.endpoint` (the `Bucket`
schema's own fields) are what's actually used once a bucket is wired to the
integration via `integration_uuid`. This is a defensible design (one
credential connection can back several buckets with different regions/
endpoints), but an operator who fills in region/endpoint on the integration
setup form — reasonably, since the form has fields for them right next to
the credentials — may expect those values to carry through to the bucket
rather than being test-only. Not a bug (nothing is silently wrong; the
bucket form has its own region/endpoint fields that do take effect), just a
UX surprise worth a form help-text note if this comes up in practice. Not
fixing — outside this PR's diff and the underlying design is intentional
per `Bucket`'s moduledoc.

## Verdict

**Release-safe as-is.** No fixes applied or needed.
