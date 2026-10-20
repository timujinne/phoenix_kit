# PR #946 — Add an Approvals menu entry with a badge and a readable approvals page

**Author:** timujinne · **Reviewer:** Claude · **State at review:** merged

## Review

The page is gated by `api` (`permission_key_for_admin_view`, with a test), re-reads the
person's rights on every event (`Access.fresh_scope/1`) and leaves the final say to
`Approvals.approve/3` / `reject/3`, whose error atoms are all covered by `error_text/1`.
Approve runs in a `Task.Supervisor.async_nolink` task awaited from `start_async/3`, so a closed
tab cannot stop a batch half-way and a crashing task lands in `handle_async(:approve, {:exit, _})`.
`pending_count/1` is now one grouped query per viewer instead of loading every row. The preview is
rendered through HEEx escapes only (no `raw`), and `PkHashHighlight` only toggles a data attribute
on an element inside its own root.

- **BUG - MEDIUM (fixed)** — `Approvals.View.delta_pct/2` ran `Decimal.parse/1` on any string
  and then compared / subtracted. `"1e999999999"` parses, and `Decimal` lines the exponents up
  with a power of ten of that size. The "becomes" text of a preview is a key holder's own input
  and is shown to the Owner who approves it, so a low-privilege key could make the approvals page
  (and the process rendering it) spin or exhaust memory. Decimal 3.2 refuses the extreme exponents
  in its parser, but core does not pin Decimal and a host on 2.x does not. Strings are now only
  taken as plain decimal notation (`[+-]?\d{1,30}(\.\d{1,30})?`), which is what the docstring
  ("a plain number") already promised. Test added.
- **NITPICK** — `mount/3` calls `load/1`, so the disconnected render and the connected mount each
  read the lists. The tests render the page statically and the lists are small, so it is left.
