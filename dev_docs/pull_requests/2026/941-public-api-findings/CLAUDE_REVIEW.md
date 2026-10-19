# PR #941 — Fix public API findings: no idempotency key on a tool that cannot replay, token_in_url wording, MCP unknown tool error

**Author:** timujinne · **Merged:** 2026-10-19 (b3e31d9ff) · **Reviewer:** Claude

## Summary

`Tool.replay: false` removes `idempotency_key` (schema, MCP, OpenAPI, the `Idempotency-Key` header) from a write tool whose answer
carries a credential and is therefore never stored; the public `token_in_url` problem no longer talks about an Authorization header;
an unknown tool name in `tools/call` is JSON-RPC `-32602` instead of an `isError` result.

Verdict: sound. `ControlFields.replay_tool?/1` is the one predicate behind the schema, `Flow.merge_header/1` and OpenAPI, so the three
cannot drift; the unknown-tool test asks the registry again only on the failure path, after the public charge, and a tool's own
`not_found` (a missing record) stays a tool result. A tool that is hidden or whose module is `module_disabled` keeps its own code.

## Findings

- **NITPICK (not changed):** a switched-off module (PR #940) now answers `-32602`, a disabled module still answers an `isError`
  `module_disabled` result. That follows the rule written in `Registry.find/2` (a module switched off by the install is
  "like a name nobody has"; a module disabled by the admin is told apart on purpose) — noting it because the two kinds of
  "off" now differ in transport shape.
- The stale #940 test this PR collided with is fixed in the #940 review.
