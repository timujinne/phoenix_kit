# PR #784 — dev_docs: module table-extraction guide

**Author:** timujinne · **Merged:** 2026-09-05 · **Base:** `main` · **Merge:** `9db92288`
**Diff:** one added file, `dev_docs/guides/2026-09-05-module-table-extraction-guide.md` (41 lines).

Documentation only — no code, no schema, no migration. The review is therefore
an accuracy audit: every pointer and every claim checked against the workspace
as it stands today.

## Verdict

Accurate and useful. It is a pointer document by design — it deliberately does
not restate the protocol, it names where the protocol lives — and every pointer
resolves. Three findings, none blocking; one is a real correctness problem in
the Phase 1 sentence.

## Verified correct

| Claim | Checked against |
|---|---|
| V135 is the squash baseline | `lib/phoenix_kit/migrations/postgres/v135.ex:4` — *"squash baseline — consolidation of V01..V135"* |
| V135 creates `phoenix_kit_shop_*`, `phoenix_kit_cat_*`, `phoenix_kit_entities*` | all three families present in v135.ex |
| `@excluded_exact` in `dev_docs/squash/generate_baseline.exs` | `:1056`, with `excluded_exact/0` at `:1131` |
| `ExpectedSchema` | `lib/phoenix_kit/migrations/expected_schema.ex` |
| `mix phoenix_kit.repair` | `lib/mix/tasks/phoenix_kit.repair.ex` |
| hello_world README heading path (3 levels, exact) | `## Database conventions` `:1594` → `### Versioned migrations` `:1647` → `#### Adopting a table core already creates (extraction)` `:2044` |
| `lib/phoenix_kit_hello_world/migrations.ex` | exists |
| legal's extraction report | `phoenix_kit_legal/dev_docs/reports/2026-08-10-consent-logs-extraction.md` |
| billing owns `phoenix_kit_payment_provider_configs` | `phoenix_kit_billing/lib/phoenix_kit_billing/migrations.ex` |
| catalogue `pkc_schema` / entities `pkn_schema` / ecommerce `pke_schema` | markers found in each (built by interpolation from `@marker_prefix`, so a literal grep for `pkn_schema:1` misses it — it is there) |
| "Core never drops module tables conditionally" | core's drops (V173, V177) are `DROP TABLE IF EXISTS`, guarded on *existence*, never on module presence — the distinction the sentence draws is the right one |
| uninstall is a manual step in the module README | `phoenix_kit_hello_world/README.md:2077` — *"Real uninstalls are a human step"* |

## Findings

### IMPROVEMENT - MEDIUM — Phase 1 says `repair` "reverts the change"; it is additive-only and cannot

> **Phase 1 — first shape change.** Before releasing a module V2 that **alters**
> one of these tables […] otherwise `mix phoenix_kit.repair` **reverts the
> change** on every run.

`PhoenixKit.Migrations.Repair`'s own contract is narrower
(`lib/phoenix_kit/migrations/repair.ex:1-9`):

> Runtime, **additive-only** verify-and-repair […] `repair/1` […] actually
> applies **missing** objects and comment-policy writes

Additive-only means it creates what the manifest expects and finds absent. So:

* a module V2 that **drops or renames** an object the manifest still lists → repair
  re-creates it, and "reverts the change" describes the outcome fairly;
* a module V2 that **alters an object in place** (relaxes a `NOT NULL`, widens a
  type, changes a default) → repair has no mechanism to undo it.

The sentence names the altering case specifically, which is the one where the
claim does not hold. A reader who takes it literally will expect repair to
protect them from an in-place ALTER and be surprised either way — surprised it
did not revert, or surprised that drift is reported without being fixed.

Suggested rewording, keeping the operational point (you must still update the
manifest) while being accurate about the mechanism:

> …otherwise the manifest keeps expecting core's shape: `mix phoenix_kit.repair`
> is additive-only, so it re-creates anything your V2 *removed* on every run,
> and reports the rest as drift without fixing it.

### NITPICK — the `deprecated <date>` COMMENT convention has no referent

> Tables that a module has stopped using […] are marked with a
> `COMMENT ON TABLE … 'deprecated <date>: …'` by the host app

No such comment exists anywhere in the workspace — grep across `phoenix_kit` and
`phoenix_kit_ecommerce` finds none. "by the host app" may mean this is
prescriptive rather than descriptive, which is fine, but as written it reads
like an established practice a reader could go and look at. Either say it is a
convention being introduced here, or link the first instance once one exists.

### NITPICK — write the marker as `<ns>_schema:<N>`, not `<ns>_schema:1`

Phase 0 describes the marker as `<ns>_schema:1`. The version increments —
`phoenix_kit_billing` is already at `pkb_schema:2` — and the entities coordinator
writes it generically (`phoenix_kit_entities/lib/phoenix_kit_entities/migrations.ex:6`
uses `pkn_schema:<N>`). Since the surrounding sentence is specifically about the
module's *V1*, `:1` is not wrong there, but `<N>` matches the vocabulary the
implementations already use and avoids reading as a fixed literal.

## Not a finding, noted

`V135` is the baseline while the chain head is `V183`. Both are true and the
document is date-stamped in its filename, so this will not mislead today. If the
guide is expected to outlive the next squash, the baseline number is the line to
re-check first.
