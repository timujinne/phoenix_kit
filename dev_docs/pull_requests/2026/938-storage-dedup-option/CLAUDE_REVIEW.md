# PR #938 — Add `dedup: false` option to `Storage.store_file_in_buckets/7`

**Author:** timujinne · **Merged:** 2026-10-18 (`1383ea354`) · **Reviewer:** Claude

Adds `dedup: false` to `store_file_in_buckets/7` (a row of its own with a `"nodedup:<uuid>"` dedup key,
no cross-user clone), inserts such a row under the object directory's advisory lock, and makes
`delete_stored_objects/2` leave a key a recent `processing` row is still writing
(`in_flight_keys/3`, `ignore_uploads_of:`).

## Verdict

Sound design; the in-flight hold is a real improvement (it closes the "delete the object between the
upload's write and its record" window) and the tests are thorough. One real bug in the new locked
insert, fixed below.

## Findings

### BUG - HIGH — `dedup: false` raised `MatchError` when the database refused the row (FIXED)

`create_file_locked/2` wrapped `create_file/1` in `repo().transaction/1` and matched the result with
`{:ok, created} = ...`. A *validation* error is fine (the changeset comes back as the transaction's
value), but a constraint the **database** enforces — the uploader deleted between the request and the
upload (`fk_files_user_uuid`), a dropped library (`library_uuid` FK) — aborts the Postgres
transaction: the changeset is still produced, but the commit answers `{:error, :rollback}` and the
match raised `%MatchError{term: {:error, :rollback}}`. The default path returns
`{:error, %Ecto.Changeset{}}` for the same input, so `dedup: false` broke the function's contract. Inside a
caller's transaction the failed insert would also leave *their* transaction aborted, the opposite of
what the code comment promises ("an invalid row does not spoil a transaction the caller opened").

The PR's tests only exercised `store(%{uuid: nil}, …)`, which is rejected by the changeset before any
SQL runs, so it never reached the aborted-transaction path. Reproduced with a random non-existent
`user_uuid`: `dedup: true` → `{:error, changeset}`, `dedup: false` → `MatchError {:error, :rollback}`.

**Fix:** the insert runs with `mode: :savepoint`, so a refused insert rolls back to the savepoint and
the surrounding transaction (ours or the caller's) stays healthy; the lock taken before it is kept.
Tests added: the database-refused case answers with a changeset for both modes, and a caller's
transaction is still usable afterwards.

### NITPICK — the ChecksumBackfill job can rewrite a `nodedup:` key (not fixed, on record)

`ChecksumBackfillJob.md5_query/1` selects every non-system file whose `file_checksum` is a 32-hex MD5
and rewrites `user_file_checksum` to the real dedup key. `dedup: false` stores `file_checksum` "as
given", so a legacy caller passing an MD5 would have its `nodedup:` row folded back into dedup by the
next pass (a second such row of the same bytes hits the unique index and is left as `:duplicate`). The
upload API has been SHA-256 for a long time and the docs say the checksum is the content SHA-256, so
this needs a caller already doing the wrong thing; not worth a special case in the backfill.

### Checked and fine

- `in_flight_keys/3` keeps the old `upload_in_flight?/2` semantics (processing row of the directory
  without an instance for the key) plus the grace-period and ignore filters; `not in ^[]` is true for an
  empty ignore list. `key_needed_on?/2` callers pass `nil` and still behave the same, now with the
  one-hour cut-off (intended).
- All four `delete_stored_objects` callers that delete a still-living file's own keys
  (`ImageEditing`, `VariantGenerator` ×2, `ApplyImageEditJob`, `delete_file_completely`) pass
  `ignore_uploads_of: [file.uuid]`; without it a processing file would hold its own stale keys.
- `repo().delete(file)` before the cleanup in the instance-failure path is correct: the row itself
  would otherwise hold the key it is cleaning up.
- Image edit / revert give a `nodedup:` row the edited / original bytes' key only when no other row of
  the uploader has it (`duplicate?/3`) — matches the docstring.
- Plain (locked-less) uploads racing a delete are documented as unprotected; accepted.

## Follow-up — Codex's corrections (`b5ae6da42`), re-checked

- **Checksum backfill keeps `nodedup:` keys — confirmed.** This is the nitpick above, now fixed.
  `record/2` keeps a `nodedup:` key and the update is guarded on the key read earlier. Run against
  the pre-fix worker, both new `checksum_backfill_test.exs` tests fail; with the fix all 7 pass.
- **Invalid root can no longer restore an added account — confirmed.** The previous commit makes the
  remembered active account the session token before the plug resolves it, so the root's own
  validation was bypassed. `do_restore/2` now requires the root to resolve to an active user, else
  `live = []` and the persisted cookie is dropped (via `prune_persisted` → `forget_persisted_accounts`),
  leaving the plug to reject the root as before. The three new `session_multi_test.exs` tests
  (revoked, expired, deactivated root) fail on the pre-fix `multi_session.ex`; all 25 pass with it.
- No new issues found. The extra `root_user_from_token/1` lookup runs only when a non-empty,
  root-bound mirror exists, i.e. at remember-me recovery.
