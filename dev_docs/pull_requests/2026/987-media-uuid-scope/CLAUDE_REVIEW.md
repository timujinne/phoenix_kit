# PR #987 — MediaBrowser: check what an event names and what the selection holds

**Author:** timujinne · **Reviewer:** Claude · **Verdict:** approve, no changes

- The library gate now covers browsers that name no library (previously `is_binary(library_uuid)`
  guard skipped them): "outside" is what `exclude_user_libraries/1` leaves out. `Libraries.user_or_hidden_among/1`
  was widened to the same rule (it now includes trashed/suspended libraries via `private_condition/0`);
  verified that `among/2` skips the Media library and nil, so default-library files stay allowed.
- Bulk handlers (`move_selected`, `delete_selected`, `restore_selected`) no longer trust
  `selected_files`/`selected_folders`: `shown_selection/1` reloads in bulk (≤2 queries per list) and
  filters with `shown_only/2` (library + viewer). Removes N `repo.get` calls as a side effect.
- Cost: every event naming a uuid in a library-less browser now does 2 extra reads; acceptable.
- NITPICK: the "deleted N" flash counts the shown selection, not the items actually removed
  (`removable_here?` can still skip some). Same imprecision as before; left as is.
- A malformed uuid in the selection still raises a cast error in `load_by_uuid/2`, as `repo.get` did before.
- 558 lines of tests cover forged selections across the three bulk handlers.
