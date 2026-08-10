# Release-readiness review — PhoenixKit 2.0 (squash), 2026-08-09

The maintainer is asking one question: **can this be published?** Not "is the
code good" — three rounds already covered that (GLM, an Opus agent with live
database access, and Kimi; every finding is fixed and the branch is
`BeamLabEU/phoenix_kit` PR **#689**). What is needed now is a go/no-go on
*publishing to Hex*, and the failure modes of a release are different from the
failure modes of a diff.

Your verdict must be one of: **GO**, **GO WITH CONDITIONS** (list them, ordered,
each with who must do it), or **NO-GO** (name the blocker). Say plainly which
facts you verified yourself and which you took from this brief.

## What is being released

The chain `V01`..`V134` is replaced by one generated baseline `V135`; deltas
`V136`..`V164` are unchanged; a database below `V135` is refused with an
actionable error naming the bridge release. `V164` additionally repairs a real
defect (`V56`/`V57` ran existence guards against still-queued DDL, leaving ~46
`*_uuid` columns nullable and ~67 of 70 foreign keys uncreated on every
installer-created database) and normalizes two indexes whose shape diverged
between `public` and named-schema installs.

Verification already on record for the exact commit in the PR (`bc3bae06`):
full scenario matrix S1–S22 with 0 FAIL and three documented SKIPs, a
public-path (mode A) equivalence oracle passing, 1919 tests passing, and
`mix phoenix_kit.release_check` green (`V135..V164` contiguous, `chain_hash`
matching all 30 shipped files). The core equivalence claim — baseline+deltas
produce byte-identical schema and seed data to the full pre-squash chain — is
what S1/S2 assert against tool-built references.

## The thing I believe is the actual blocker — verify or refute it

Core's own version is untouched at `1.7.235` (`mix.exs`, deliberately: version
bumps are maintainer-owned). If it is published as **2.0.0**, then every
sibling module package currently on Hex pins core as `~> 1.7.x`, i.e.
`>= 1.7.x and < 1.8.0`, which **2.0.0 cannot satisfy**. Measured today in this
workspace:

```
phoenix_kit_catalogue        ~> 1.7.189
phoenix_kit_crm             "~> 1.7 and >= 1.7.219"
phoenix_kit_document_creator ~> 1.7.189
phoenix_kit_ecommerce        ~> 1.7.231
phoenix_kit_emails           ~> 1.7.217
phoenix_kit_entities         ~> 1.7.214
phoenix_kit_hello_world      ~> 1.7.214
phoenix_kit_locations        ~> 1.7.189
phoenix_kit_manufacturing    ~> 1.7.231
phoenix_kit_projects         ~> 1.7.231
phoenix_kit_warehouse        ~> 1.7.214
```

Consequences to check: an application that depends on core `~> 2.0` **and** any
one of these modules gets an unsolvable dependency set. Confirm the resolver
semantics yourself, decide whether this is a hard blocker or merely a
coordination item, and say in what ORDER the packages must be published for
consumers never to see an unsolvable state. Also check whether a
`~> 1.7 or ~> 2.0` widening is even expressible for these packages and whether
anything in the modules' code would actually break against the squashed core
(they consume `PhoenixKit.Module`, `Routes.path/1`, the migration coordinator
contract).

## Everything else worth a release-gate opinion

1. **Is a major the right version at all?** What in this release is
   backwards-incompatible for a consumer who is already above the floor? The
   comments foreign key changes from `ON DELETE CASCADE` to `SET NULL` (a
   behavior change for anyone relying on user deletion removing comments), and
   below-floor databases stop migrating. Anything else you find.
2. **The hex package contents.** `mix.exs`'s `files:` whitelist is
   `~w(lib priv mix.exs README.md LICENSE CHANGELOG.md)`. Verify nothing needed
   ships missing and nothing private ships by accident — in particular that the
   30 migration modules and the generated manifest are included, and that
   `dev_docs/` (which contains internal review material) is excluded.
3. **The upgrade path for a third party**, `dev_docs/guides/2026-08-07-upgrading-to-2.0-guide.md`
   — but note that guide lives in `dev_docs/`, which is NOT in the hex package.
   Decide whether the release needs anything user-facing that a consumer can
   actually read after installing, and where it should live.
4. **What a consumer hits on the unhappy path.** Below the floor; a database
   whose version comment is missing or hand-edited; a run through PgBouncer in
   transaction-pooling mode; `V164` on a large table under traffic. Each of
   these has documented behavior — check the behavior matches the
   documentation, and say whether the failure is loud, safe and actionable.
5. **`mix prerelease`** (`deps.get --check-locked`, prod compile with warnings
   as errors, `quality.ci`, `deps.audit`, `hex.audit`, `docs`, `hex.build`,
   `release_check`) is running as this brief is written; read
   `/tmp/claude-1000/-www/7cd7b1b7-6ad0-4d0b-9c0c-631723f94572/scratchpad/prerelease.log`
   for its outcome and treat any failure there as a fact, not a rumour.
6. **Known-unproven, on the record** — a second PostgreSQL major (no container
   available), scenario `s16`'s body, and `s18` (a migration starting mid-repair,
   detected rather than prevented). Say whether any of these should gate a
   release or are acceptable as documented limitations.

## Rules

Read-only: do not edit files, do not publish anything, do not run migrations
against any database, do not push. The scenario harness may be run read-only if
you need to (see `dev_docs/squash/README.md`), but the shared PostgreSQL is at
its connection ceiling — check for headroom first and prefer reading recorded
results in `dev_docs/squash/` over re-running.

Be concrete and ordered. The output the maintainer needs is a decision plus a
checklist, not an essay.
