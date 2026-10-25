# PR #962 — Let a module that contributes an integration provider supply its connection check

**Author:** timujinne · **Merged:** 2026-10-23 (570ba3211) · **Reviewer:** Claude

## Summary

A provider contributed by another module (`integration_providers/0`) could not add a named strategy to `Integrations.do_validate/2`, so "Test Connection"
could only answer "not verified". It now declares `validation: %{strategy: :module, module: Mod}`; `Mod` implements the new
`PhoenixKit.Integrations.Validator` (`validate_connection/1`). The clause runs ahead of the auth-type clauses, through `Probe.run/1` (own process, hard
deadline, operator's locale), after a required-fields gate, and the answer is normalised by `module_verdict/1`. `:unverified` joins the `Probe.check` type.

Verdict: correct. The 20 new tests pass (`PGDATABASE=beamlab_test mix test test/phoenix_kit/integrations/module_validation_test.exs`) and cover every
verdict, raise/throw/exit, the deadline, the log (no credentials, no answer body), locale, the pre-save path and the three "cannot check" shapes.

## Verified

- Clause order: `do_validate/3` (object_storage, smtp) only matches those strategies, so a `:module` provider falls through to `/2` and the `:module` clause
  runs before `:oauth2` and the `api_key`/`bot_token` generic clause. Nothing else in `lib/` reads `provider.validation.url`/`auth_header`, so a
  `validation` map without them breaks no other consumer.
- A saved row with `"status" => "connected"` passes `has_credentials?/1` with no key at all; `required_fields_filled?/2` is what stops it reaching the
  module. (The first version of this review said a test pinned that. It did not: the existing test only built an empty connection, which
  `has_credentials?/1` refuses earlier. Codex added the real regression.)
- `module_check/2` rescues and catches inside the `Probe.run` process, so the credentials in the call arguments never reach a crash report; only
  `LogSafe.exception_label/1` is logged. `Probe`'s own `:DOWN` branch covers an untrappable kill.
- ~~Required setup fields are all stored as strings, so `present?/1` is the right test.~~ **Wrong.** `setup_attrs/2` stringifies, but `save_setup/4`
  and `validate_credentials/3` take caller maps, and `field_present?/1` (numbers count as present) already existed for exactly this. See Codex's fix below.
- Gettext: the one new string is in `default.pot` and all nine `.po` files, none fuzzy.

## Findings

- **NITPICK (fixed):** the `Validator` moduledoc said the module gets "the setup fields". On the saved path it gets the whole stored data map
  (`"status"`, `"provider"`, ... sit beside the fields; `has_credentials?/1` reads them from the same map). Reworded so a module author matches the
  keys they need and ignores the rest.
- **IMPROVEMENT - MEDIUM (not changed, documented in the moduledoc):** the module is not told whose connection it checks, so a provider with
  `scopes: [:personal]` whose check dials a host typed into a setup field cannot apply the personal policy (`Storage.Endpoint.check/3` `:personal`,
  `SmtpEndpointPolicy`). The limitation is stated and the provider author controls the check, so no fix here. If a contributing module needs it, add an
  optional `validate_connection/2` taking `owner:` rather than widening `/1`.
- **NITPICK (not changed):** `module_check?/1` logs a warning on every validation of a provider whose module has no `validate_connection/1`. That is
  deliberate (a misdeclared provider should be loud) and the volume is one line per operator click.

## Recheck after Codex (`268572cf6`)

Codex's follow-up (`GPT_REVIEW.md`) is right on both points where this review was wrong, and its owner-aware callback is sound.

- **BUG - MEDIUM (fixed by Codex, confirmed):** `required_fields_filled?/2` used the binary-only `present?/1`, so a required `:number` field holding `587` was
  "No credentials configured" and never reached the module. It now uses `field_present?/1`; tests cover 0, 587, 587.0, "587", nil and "".
- **IMPROVEMENT - MEDIUM (done by Codex, confirmed):** optional `validate_connection/2` with `owner:`; `/2` wins when both exist. Saved checks and `reading/2`
  use the row's owner (`owner_of/1`), so an owner-agnostic `:any` read no longer becomes the policy context; pre-save uses the caller's `owner:` and ignores
  owner fields inside the submitted attrs. Stricter than before for built-in SMTP/object-storage reads of a personal row, never laxer.
- Re-verified here: `mix precommit` exit 0 (Dialyzer: no issues, 473 JS tests); `test/phoenix_kit/integrations`, `test/phoenix_kit/api`, `test/integration/api` and
  `approvals_test` 2309 tests, 0 failures; `test/integration/integrations*` 193 tests, 0 failures.
- **NITPICK (not changed):** a pre-save call with `owner: :any` would hand the module `:any`, which the moduledoc does not list. No caller in `lib/` does that.
