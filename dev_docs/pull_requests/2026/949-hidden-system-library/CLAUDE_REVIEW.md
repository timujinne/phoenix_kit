# PR #949 — Opt-in hidden system libraries for a module's own files

**Author:** timujinne · **Reviewer:** Claude · **State at review:** merged

## Review

No defects found. A hidden library is a system library with `visibility: "private"`, set only by
the `hidden: true` option (a `"visibility"` in attrs is ignored). I checked every reader of
`kind == "system"` / `list_system_libraries` / `get_system_library*`: the switcher, Settings
pages, stats helpers, URL lookups, profile/bucket/Health listings, job titles, the Storage
history (creation only, `audit: false` to skip) and the repair log (`Audit.site_file?/1` goes
through `private_file?/1`, so nothing is written) all leave it out or count it with the private
libraries. `can?/3` grants its files to the uploader and Owner/Admin only, URLs need the
time-window token, and the dedup key folds the library in.

No fixes needed.
