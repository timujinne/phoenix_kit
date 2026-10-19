# Review — public user libraries, personal libraries, Media-tab rework (direct commits on main)

**Commits:** `387d740e8` (profile Media tab: core components, bucket listing, several integrations per
library), `4c3c17129` (`Libraries.ensure_personal_library/2`), `5d66b48ed` (public user libraries, phase 1).
No PRs: pushed straight to main. **Reviewer:** Claude · **Date:** 2026-10-18

## Verdict

Careful work: authorization is re-checked in `Libraries` (never trusted to the component), the new
`public?/1` predicate is the one place that decides, the site-media exclusion is applied at every
listing, and the tests are broad. One real gap (fixed) and one phase-2 gap to close before anyone is
granted the new permission.

## Findings

### BUG - MEDIUM — a trashed public library kept serving its files (FIXED)

`do_trash/1` only stamps the library's `trashed_at`; its files stay `active`. A private library's
files are still safe because they answer `private?` (time-window tokens, minted only after `can?/3`,
which refuses a trashed library). A public library's files are *not* `private?`, so their permanent
links kept working while the library sat in the trash, until the purge. The plan's item 6 ("trash
already removes the files") is not what the code does, and the PR's own test ("a public library in
the trash is not public") only asserted `can?/3`/`public?/1`, never what `FileController.show` decides
from `private_file?/1`.

**Fix:** `private_condition/0` also holds for a library with `trashed_at` set, exactly like a
suspended one: a trashed public library answers as private (permanent tokens refused) and is public
again on restore. Test added (`private_file?/1` and `private_among/1` across trash and restore).

### IMPROVEMENT - HIGH — originals and GPS of a public library are not yet gated (not fixed; phase 2)

The plan's decisions D1/D2 say originals and locations are **off by default** for a public library
and enforced "where the viewer and metadata responses are". Phase 1 widens `Libraries.can?/3` `:read`
to everyone, and the core callers of `:read` now pass for any signed-in user on a public library —
`FileController.info/2` (`authorize_file_read/2`) lists **every** variant of the file with a permanent
signed URL, `original` included, and `Storage.authorized_url/3` mints one for any variant. The original
keeps everything the camera wrote, GPS included. The anonymous/Photos path is not built yet, so nothing
is exposed unless a site grants `storage.public_library` (granted to nobody by default) — but granting
it today publishes originals and locations, contrary to D1/D2. Before the permission is granted
anywhere: refuse (or omit) the `original` variant, and the metadata with location, for a reader who
can read *only because the library is public*, unless the library allows it. Needs a predicate for
"reads as member/uploader/admin" beside `public?/1`.

Checked and fine: `GET /api/files/:uuid/unedited` is gated by `ImageEditing.can_edit?/2` (`:edit`),
not widened, so a redaction's hidden original stays closed.

### NITPICK — suspension writes a stale `settings` map

`set_suspended/5` merges into the `settings` of the struct the caller holds (the admin page's loaded
row) and writes the whole map back, so a concurrent change to another per-library setting is lost,
and `unsuspend_library/2` decides from the stale `suspended?`. The other settings writes in this module
use atomic `jsonb ||` / `-`. Rare (an admin action vs. an owner toggling a setting); not worth a change
now. The component also trusts the mount-time scope for the Owner/Admin check, like the rest of the
admin pages.

### Checked and fine

- `create_user_library/3`: only `"public"`/`"private"` are accepted from the caller; `"site"` and
  anything else is `:not_allowed`; `public` needs `storage.public_library`; the changeset reads the
  request from attrs because the struct default is `"site"`. Publishing is audited.
- `exclude_user_libraries/1` replaces `exclude_private/1` at every site-media caller (browser,
  pickers, folder listing, orphan cleanup); the old name delegates.
- `ensure_personal_library/2`: one per user under the per-user lock (a trashed or renamed one still
  counts), private, no permission/limit needed because the system acts, nothing calls it.
- Several integrations per library: owner is passed to credential resolution, the endpoint is
  re-resolved under the `:personal` policy per request (also for `ListBuckets`), at most
  `max_user_buckets/0` targets and probes, every event re-asks `Libraries` (`probe_own_storage`,
  `list_own_buckets`, `create_user_library`), `String.to_existing_atom/1` only after the allow-list.
