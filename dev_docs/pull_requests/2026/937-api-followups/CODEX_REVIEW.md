# PR #937 — held approval replies: follow-up review

Reviewer: Codex · Date: 2026-10-17 · Author: timujinne
Merge: `2538d0b3c` · Baseline including documentation fixes: `0f66cea4f`

Rechecked all changed execution-flow code and the REST/MCP/OpenAPI descriptions.
`held_again?` is initialized before the flow sets it, the header is added only
when the approval store returns `:existing`, and this flag does not suppress
auditing or make the answer eligible for idempotency storage.

No new code defect found. The existing documentation correction is necessary:
a changed fingerprint supersedes the pending row, so the replacement approval
has a new id and must not carry a replay header.

Added a regression driving exactly that transition across transports with the
same idempotency key: REST queues the original, changed values cause MCP to
create a replacement with a fresh preview and no replay header, and a REST
repeat reuses the replacement with the header. It also checks that the old row
is expired and the operation has not executed.

## Validation

- `mix precommit`: exit 0, including warnings-as-errors compilation, unused
  dependency check, test-file compilation, formatting, strict Credo, Dialyzer
  (using the existing ignore file), and all **377 JavaScript tests**.
- Full repository run:
  `PGDATABASE=phoenix_kit_codex_review_20261017 PGPOOL=12 mix test --max-cases 8`
  — exit 0; **89 doctests, 11,270 tests, 0 failures, 10 skipped (1 excluded)**.
  PostgreSQL integration tests ran in a fresh, separate database; the test role
  lacks `CREATEROLE`, accounting for the privileged-test exclusion.
- `git diff --check`: clean.
