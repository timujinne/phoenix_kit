# PR #974 — Let a live session write after the person confirms each change (V222)

**Author:** timujinne · **Merged:** 2026-10-23 (867f79567) · **Reviewer:** Claude

## Summary

`Executor.execute_as/5` gets `allow: :all`: a write tool of a module listed in `api_session_write_modules` (the "Agent may act" box, off by default) is not
run but held in a `phoenix_kit_api_confirmations` row bound to the person (`actor_user_uuid`, new in **V222**, FK `ON DELETE CASCADE`, actor CHECK widened,
`(actor_user_uuid, status)` index) and answered `confirmation_required` with the row's uuid, never a code. `Executor.redeem_as/6` repeats the whole request
path with the rights of the confirming session, then `Flow.redeem_for_session/2` checks the row (the person's, same tool and arguments, still waiting), takes
a fresh dry-run fingerprint and spends the row atomically; changed values replace the row (`reissue_for_user/7`, old row to `expired` in the same
transaction) and re-prompt. `Confirm.get_for_user/3` / `reject_for_user/3`, `Executor.tool_availability/1`, a shared `OperationPreview` component, an audit
entry per charged session write.

Verdict: sound; the properties the project insists on hold.

- Fails closed: unreadable `api_session_write_modules` reads as `[]`; a tool without a module key never matches; `session_writes/1` refuses before validation
  and before anything is stored; `no_control` refuses `dry_run` / `confirm_token` / `idempotency_key` on redeem (a `dry_run` would otherwise burn the row).
- Atomic transitions: claim, reject and reissue are single `UPDATE ... WHERE status = 'unused'` statements; the reissue loser of a race gets `expired`.
  An unknown uuid and another person's uuid are the same `{:error, :unknown}`.
- Log hygiene: inserts and updates use `log: false` (the preview is the person's data); the audit entry carries via/tool/outcome/code/uuid, never input or
  preview; `session_row/2` logs through `LogSafe.shape`.
- V222 follows the prefix rules: the FK existence check is anchored on `pg_namespace`, `information_schema` on `table_schema`, bare index name on CREATE and
  qualified on DROP, CHECK dropped and re-added in one `ALTER`, `status` CHECK of V220 already allows `rejected`. `ExpectedSchema` gets the column/FK/index
  and a `{222, …}` revision for the CHECK; `v222_test` (313 lines) green.
- Ran `executor_session_confirm_test`, `v222_test`, `executor_tool_availability_test`, the settings LiveView tests: green against a real DB.

## Findings

- **NITPICK (not changed):** the PR title still says V221 (the number the branch had before the user-country migration took it); the code, the migration
  and the docs say V222. Worth correcting if the title is quoted in a changelog.
- **NITPICK (not changed):** `Confirm.reject_for_user/3`'s spec lists `:changed`, which the `UPDATE ... expires_at > now` form cannot return.
- **Process note:** no CHANGELOG entry with the PR (new migration, new setting `api_session_write_modules`, new FlowConfig field `api_user_confirm_ttl_seconds`,
  new problem code `module_write_disabled`); it belongs in the release entry. The guide states the caller's duty to refuse an impersonated session before
  `allow: :all` / `redeem_as/6` / `get_for_user/3`; a host wiring this up must do so.
