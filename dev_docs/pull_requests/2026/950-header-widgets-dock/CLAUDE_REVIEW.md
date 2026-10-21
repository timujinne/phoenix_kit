# PR #950 — Header widgets for modules and an optional dock column

**Author:** timujinne · **Reviewer:** Claude · **State at review:** merged

## Review

The contract is careful: entries are validated (`check_live_view`, reserved ids, string-keyed
session), duplicate ids keep the first widget, reserved cookie-session keys are dropped from the
widget session, a nil session renders nothing, and without a socket and a user the layout is
byte-identical to before (snapshot test). The moduledoc is explicit that `session_fun` runs for
every signed-in user and that the module must check the permission there and again in `mount/3`.

- **BUG - MEDIUM (fixed)** — the warnings for a failing widget logged `Exception.message/1`,
  `inspect({kind, reason})` and `inspect(other)` of the session function's return. The function
  receives the layout's assigns (the signed-in user and scope among them) and `User` / `Scope`
  have no `Inspect` derive, so a `KeyError`, a `MatchError` or a thrown assign printed the user's
  email and profile into the log; a function returning a struct had it inspected too. The
  warnings now name the exception module (or the throw kind) and the type of a bad return, never a
  value (the rule `PhoenixKit.API.LogSafe` already sets for the API). Tests pin it with a sentinel
  that must not appear in the log.
- **IMPROVEMENT - MEDIUM (fixed)** — `mix precommit` was red on `main`: dialyzer reported
  `contract_with_opaque` for the `@spec`s of `AdminDock.open/1`, `close/1` and `toggle/1`
  (`Phoenix.LiveView.JS.t()` has an opaque `ops` field). Added the file-level ignore beside the
  other `contract_with_opaque` entry in `.dialyzer_ignore.exs`; the specs stay as documentation.
- **NITPICK** — `header_widgets_for/1` runs `header_widgets/0` of every module that defines it on
  every layout render. Documented ("keep it a cheap list of literals"); a cache would be
  premature.
