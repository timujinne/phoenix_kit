# PR #988 — Storage: linked copies across libraries, and a module library shown in Media read-only

**Author:** timujinne · **Reviewer:** Claude · **Verdict:** approve, no code changes

Read: `Libraries` (listing/managed/`check_managed`), every `check_managed` site in `storage.ex`,
`link_copy/3` / `relink_file/3` and their helpers, the Media LiveViews and `MediaBrowser` read-only
forcing. Ran `managed_library_test`, `link_copy_test`, `relink_file_test` (110 tests, green).

## Checked and sound

- **Listing gate is the access gate.** `Live.Users.Media` resolves `/library/<slug>` only from
  `list_system_libraries_for/1`, so a hidden library not offered to the viewer is `:not_found`; no
  separate lookup bypasses `listed_for?/2`.
- **Managed check ordering.** Every user operation runs `check_managed` before the scope/owner branches;
  `trash_folder`/`restore_*`/`trash_file` take no `managed: :owner` on purpose (no trash).
  `do_delete_folder_completely` uses the unchecked `delete_file_and_objects/1`, so the owner's folder
  delete is not refused halfway.
- **`purge_row/1` refusing a managed file is unreachable**: `trash_library`/`restore_library` are
  user-library only and `managed?/1` is system-only, so a managed library is never purged. The
  `{:error, reason}` branch is harmless.
- **`link_copy` / `relink_file`.** Refusals come back as values (no rollback poisoning a caller's
  transaction); donor row `FOR SHARE` then directory lock then re-read; sharing is per `spec_hash`,
  burned thumbnails never shared; `delete_old:` refused inside a transaction.

## Findings

- **IMPROVEMENT - MEDIUM — `link_copy/3` does not check the *target* library for `managed`.**
  `donor_managed_fit/3` guards only a managed *donor* leaving its library. A copy of a Media file
  *into* a managed library succeeds with no `managed: :owner` (AGENTS.md says a function that links must
  start with `check_managed`). Not changed: the PR's own test
  (`"the owner's delete takes the record…"`) and the module-owner flow call it exactly that way, and the
  contract says the caller checks access. I tried adding the check and it broke that test. If it should
  be enforced, make it an explicit decision (a `managed: :owner` requirement is a breaking change for the
  mail module), and document the current behaviour in the `link_copy/3` "Errors" section either way.
- **IMPROVEMENT - MEDIUM — object I/O under locks.** `key_usable?/2` for the `thumbnail` slot calls
  `Manager.retrieve_file` and hashes the object while holding the donor's `FOR SHARE` row lock and the
  directory advisory lock, inside the transaction. On a remote bucket that is a network round trip per
  link copy (a few KB, bounded to one slot). Fine today; if link copies become bulk, read the
  thumbnail before opening the transaction and re-verify only the row facts under the lock.
- **NITPICK** — `do_purge`'s "kept their objects on the user's own bucket" warning is also what a
  refused (managed) file would log; wording only.
- **NITPICK** — `Live.Users.Media` loads `libraries` once per mount, so a changed `media_listing` or a
  revoked `media` permission applies on the next mount, not live. Same pattern as before this PR.

No version bump or CHANGELOG touched (release commit's job).
