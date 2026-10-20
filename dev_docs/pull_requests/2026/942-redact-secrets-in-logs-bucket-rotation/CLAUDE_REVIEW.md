# PR #942 — Keep integration secrets out of logs and re-encrypt bucket secrets on key rotation

**Author:** timujinne · **Merged:** 2026-10-19 (28b8125f8) · **Reviewer:** Claude

## Summary

Three threads in one PR:

1. **Logs.** `log: false` on every write that carries a secret (bucket insert/update, the `Settings` batch `Multi`, the key
   rotation's row updates), `redact: true` on `Setting.value` / `value_json` and `Bucket.secret_access_key`, the integration save
   error log prints `changeset.errors` instead of the changeset, and the integration picker masks all but the last 4 characters.
2. **Rotation.** `KeyRotation` / `mix phoenix_kit.integrations.rotate_key` now also re-encrypt `phoenix_kit_buckets.secret_access_key`
   in the same transaction, locked `FOR NO KEY UPDATE`.
3. **Plaintext visibility.** `Encryption.encrypt_fields/1` logs one warning per VM when it is about to store a credential as
   plaintext; `PhoenixKit.boot/1` logs the key report for the plaintext states unless `integration_encryption_warn_on_boot` is an
   explicit `false`.

Verdict: sound; no bug found. All 168 tests across the PR's files pass against the real DB.

## What was verified

- **Rotation covers every writer of the shared key.** `rg Encryption.(encrypt|decrypt)_(value|fields)` over `lib/`: the only
  callers are `Integrations` (value_json), `Setting.changeset` (restricted `value`) and `Bucket.changeset`. All three are now
  rotated, so no row is stranded under the old key.
- **`Events` redaction did not narrow.** The old local list was the six `Encryption` fields plus `oauth_state`; the new
  `Encryption.sensitive_fields() ++ ~w(oauth_state)` is the same set, now derived rather than copied.
- **Every secret-bearing write is silenced.** Every `Setting.changeset` / `update_changeset` site goes through
  `Queries.insert_setting/update_setting` (`log: false`) or the batch `Multi` (now `log: false`); every bucket write goes through
  `create_bucket`, `create_owned_bucket` or `update_bucket_row`, and `BucketCredentials` writes through `update_bucket`. The
  settings-history row stores no value for a restricted key.
- **Lock order is consistent.** Rotation locks settings rows, then buckets; `BucketCredentials.move_to_integration/2` touches the
  connection (settings) row, then the bucket — no cycle. `FOR NO KEY UPDATE` is right because a file insert takes `FOR KEY SHARE`
  on the bucket.
- **The rotation query is unfiltered by owner on purpose.** A user's own bucket (V206) is included, which is correct: the point is
  that no row is left under the old key (it is never listed through `list_buckets/0`).
- **The 5-minute bucket cache claim in the docs is true** (`@buckets_cache_ttl 300_000`, `Storage.Manager`).
- **`Encryption.status/0` at boot never touches the DB**, so resolving it when the flag is unset adds no failure mode beyond the
  existing `rescue`.
- `filter_parameters` already covers `secret_access_key` (the `secret` substring), so the LiveView event log is not a second leak.

## Findings

- **NITPICK (fixed):** `warn_if_insecure/0`'s doc still said the boot flag defaults to `false`; it is unset by default now (unset =
  report only the plaintext states). Doc text corrected.
- **NITPICK (not changed):** the one-time "stored as PLAINTEXT" warning lives in `encrypt_fields/1` only. The other two writers
  (`encrypt_value/1` for a bucket secret or a restricted setting) stay silent at write time; the boot report covers them. Widening
  it would put a log line on every `Bucket.changeset/2` in installs with no key, for a state the boot log already reports.
- **NITPICK (not changed):** the once-per-VM flag is check-then-put on `:persistent_term`, so two concurrent first writes can both
  log. Harmless, and `put` is deliberately called once.
- **NITPICK (not changed):** `warn_plaintext_write_once/1` calls `key_report/0`, which reads the key store a second time on the
  write path (just after `encryption_key/0` did). Only until the warning has been logged once, so the cost is one extra read.
