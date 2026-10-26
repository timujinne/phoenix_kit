# PR #986 — Folder cover picker showed other users' files to a restricted viewer

**Author:** timujinne · **Reviewer:** Claude · **Verdict:** approve, no changes

- Two-sided fix: the modal gets `user_uuid={@viewer_uuid}` (listing) and `media_selected`, which
  arrives via `update/2` past the `handle_event` gate, re-checks the pick (`pickable_file?/2`:
  valid uuid, not system-managed, not trashed, in the browser's library, `viewer_can_see_file?/2`).
  The comment explains why it is not `fetch_viewable_file/2` (linked files, image regardless of the
  type lock). Correct.
- Failure paths now log and flash through `parent_flash/3` instead of a component-local flash.
- `pickable_file?/2` depended on `in_browser_library?/2` returning `true` for a browser that names no
  library; #987 tightened exactly that, so the two compose.
- Tests (219 lines) cover the listing and the forged pick.
