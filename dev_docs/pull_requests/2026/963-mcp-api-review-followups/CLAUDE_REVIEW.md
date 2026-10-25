# PR #963 — Clip the MCP "Method not found" text by code points; test a dangerous tool with replay: false

**Author:** timujinne · **Merged:** 2026-10-23 (51b017cc0) · **Reviewer:** Claude

## Summary

`String.slice(method, 0, 80)` counts graphemes, so a method name of one letter plus 200 000 combining marks is a single grapheme and was echoed whole.
It now goes through `LogSafe.take_codepoints/2` (as `unknown_tool_text/1` and the executor's `clip/1` already did). The new `flowkit.drop_session` test tool
(dangerous, public, `replay: false`) pins the code-then-run flow for a tool that cannot replay.

Verdict: correct; both tests assert the actual property (81 code points in one grapheme; keyed call is 422 and stores no row, code redeemed once, second
redeem 409).

## Findings

- **IMPROVEMENT - MEDIUM (fixed):** the same grapheme-slice survived in `mcp.ex` `unsupported/2` (`inspect(String.slice(given, 0, 40))` of the
  `MCP-Protocol-Version` header). The header is bounded by the server's header limit, so the blow-up is small, but it is the exact class this PR closes
  and the value is echoed to the client. Now `LogSafe.take_codepoints(given, 40)`; test added (8000 combining marks, answer stays short).
- **NITPICK (not changed):** `PhoenixKit.API.Approvals.View` (`String.slice(text, 0, @max_text - 1)`) also slices by grapheme. That is display text of a
  preview for a person, where grapheme-safe cutting is the right behaviour, and it is bounded by the tool's own output.
