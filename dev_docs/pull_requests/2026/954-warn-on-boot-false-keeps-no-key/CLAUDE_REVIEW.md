# PR #954 — Keep reporting a missing encryption key when warn_on_boot is false; log encrypt_value/1 plaintext once

**Author:** timujinne · **Merged:** 2026-10-21 (7beba7ca8) · **Reviewer:** Claude

## Summary

`integration_encryption_warn_on_boot: false` used to silence every plaintext state. It now silences only `:disabled_explicit` (the
operator turned encryption off); `:disabled_no_key` (encryption on, key material gone) is reported whatever the flag says, at boot
and on the first plaintext write. `encrypt_value/1` warned on every call; it now shares the once-per-VM latch machinery with
`encrypt_fields/1` (one latch each, so a plaintext bucket secret is still reported after an integration write was).

Verdict: correct. The boot `cond` falls through to the status clause when the flag is `false` and the state is `:disabled_no_key`;
`plaintext_warning_silenced?/0` evaluates `status/0` only when the flag is `false` (short-circuit), so the common path pays nothing.

## Findings

- **NITPICK (not changed):** with the flag `false`, boot now resolves the key (`Encryption.status/0`) where it used not to, so the
  one-time "key store configured but secret unreadable" error can appear for those installs too. The moduledocs were updated to say so.
- Tests: `encryption_test.exs`, `phoenix_kit_test.exs` — green (366 tests across #954–#958 run together, 0 failures).
