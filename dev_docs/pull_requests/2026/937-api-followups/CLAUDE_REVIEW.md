# Claude review — PR #937: mark a repeated held answer as a replay; document the held answer and JSON body decoding

**Author:** timujinne · **Merge:** `2538d0b3c` · **Reviewed:** 2026-10-17 · **Size:** 9 files, +139/−25

**Verdict:** sound. No BUG finding. The change is small and the claims hold against the code.

## Verified

- `held_again?` is a key of the executor's initial state (`new_state/5`), so the `%{state | held_again?: …}` update in
  `Flow.request_approval/1` cannot raise `KeyError`; it is set only from the `:existing` tag `Approvals.request/2` returns.
  Public tools never reach `request_approval` (no key actor), so the public audience never gets the header.
- Two simultaneous first requests are serialised by the per-key advisory lock in `Approvals.in_lock/3`: the loser gets
  `:existing` and is marked a replay, which is correct.
- The header is applied in `replay_headers/1` only; `audit?/1` still keys on `replayed?`, so a held repeat **is** audited, as the
  guide says (`pending_approval` rows per repeat; bounded by the rate limiter, noted, not changed).
- With an `Idempotency-Key`, the held answer has `store?: false`, so `Flow.finish/1` releases the claim — the guide's
  "key is free after an unstored answer" row is accurate.
- "The body is always read as JSON, whatever its Content-Type says" matches the `BodyGuard` moduledoc and clauses.
- Tests cover REST (`executor_gate_test`) and MCP (`combined_mcp_flow_test`), keyed and unkeyed, plus a different-input control.

## Findings

### IMPROVEMENT - MEDIUM: "same `approval_id`" was promised without the supersede exception (fixed)
`Approvals.supersede/3` closes a pending approval for the same key/tool/input whose **fingerprint** changed, and the repeat
gets a *new* row — a new `approval_id`, no replay header. The guide row, the OpenAPI description and the MCP instructions all
said that asking again returns the same `approval_id`; an agent holding the old id would then poll a row that is `expired`.
Each of the three now states the exception ("unless the values it touches changed meanwhile …"); the doc tests assert the new
phrase.

### NITPICK: the replay header on a freshly computed answer
`Idempotent-Replayed: true` now also marks an answer that was *looked up again*, not stored — the OpenAPI header description
and the guide say so, so clients reading the header as "this was stored" are told otherwise. Left as designed.
