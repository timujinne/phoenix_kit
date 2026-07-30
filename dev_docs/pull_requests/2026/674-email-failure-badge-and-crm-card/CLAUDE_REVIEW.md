# PR #674 — Never render a failed email as sent, and surface a CRM contact on the user page

**Author:** Timujeen · **Merged:** 2026-07-30 (`cd4f9a5b`) · **Reviewed:** 2026-07-29

3 files, 2 commits — two unrelated changes:

1. **`email_activity_badges.ex`** — a new `status_only_badge/2` appends a red
   badge when `log.status` says the send failed but no timestamp or event backs
   it up, so the activity column can no longer show a plain blue "sent" badge for
   a log the detail page reports as failed.
2. **`user_details.ex` / `.html.heex`** — a guarded card linking the user to their
   CRM contact, loaded through the same optional-module shape as the connections
   stats.

**Verdict: both diagnoses are right and the reasoning in the comments is better
than most.** The activity badges genuinely do carry their whole meaning in
colour — the text is only ever a timestamp — so a status/timestamp mismatch really
does render a failure as a success, and the PR is correct that the writer is the
underlying bug but the component must not misreport in the meantime. The
`already_shown?` check even reasons explicitly about *not* comparing on badge
colour because a soft bounce is deliberately amber.

**What did not hold up is that same soft-bounce insight being discarded two lines
later, and a status whitelist that mirrors nothing real.** The list spells the
spam-complaint status `complained`, which no writer in the tree ever sets, and
omits `complaint`, which is the one `SqsProcessor` actually writes — so the fix
covers five statuses and leaves the sixth showing exactly the bug it was written
to remove, while a dead entry makes the list look complete. On the CRM side the
card reads and links cross-module data with no `crm` permission check, so a role
holding `users` but not `crm` sees a contact's name and then gets bounced to `/`
on clicking it.

All findings below are fixed.

---

## BUG - HIGH — the failure whitelist invents `complained` and omits the real `complaint`

`lib/phoenix_kit_web/components/core/email_activity_badges.ex:99`

```elixir
@failure_statuses ~w(failed bounced hard_bounced soft_bounced rejected complained)
```

`complained` is not a status anywhere in the tree. The canonical vocabulary is
`PhoenixKit.Modules.Emails.Log`'s changeset (`validate_inclusion(:status, …)` —
`queued sent delivered bounced hard_bounced soft_bounced opened clicked failed
rejected delayed complaint`) and core's own
`EmailStatusBadge.status_class/1`, which both spell it **`complaint`**. The only
writer agrees: `phoenix_kit_emails/lib/phoenix_kit/modules/emails/sqs_processor.ex:565`
sets `status: "complaint"`, and `Log.stats/1` counts
`CASE WHEN status = 'complaint'`.

So a spam-complaint log whose `complained_at` never got written still falls
through to the blue `badge-info` "sent" badge — the exact defect this PR exists to
fix, left in place for complaints, with a phantom entry standing in for coverage.
This is the failure mode the whitelist-vs-source-of-truth check is for: the list
was written from memory rather than read off the type it has to mirror.

**Fixed** — `complained` → `complaint`, with the comment naming the source of
truth so the next edit has somewhere to check against.

## BUG - MEDIUM — soft bounces are repainted red, contradicting the PR's own comment

`lib/phoenix_kit_web/components/core/email_activity_badges.ex:110`

```elixir
# Compare on event type, not badge colour: a soft bounce is deliberately
# amber, so a colour check would miss it and render a second badge.
…
[{"badge-error", log.status, log.status}]
```

The comment is right that a soft bounce is deliberately amber — `get_bounce_badge_class("soft_bounced")`
and `EmailStatusBadge.status_class("soft_bounced")` both return `badge-warning`,
because a soft bounce is retryable and not a terminal failure. The badge built two
lines below then hardcodes `badge-error` for every status in the list, so a
`soft_bounced` log with no `bounced_at` renders red in the list column and amber
on the detail page for the same log. The change swaps one kind of misreport for
another: the colour, which is the only thing carrying meaning here, now overstates
the failure.

Same shape in the text: `log.status` is emitted raw, so the badge reads
`hard_bounced` where every other surface reads "Hard Bounced" via
`EmailStatusBadge.format_status/1`.

**Fixed** — the status-only badge now takes both its class and its label from
`EmailStatusBadge`, which is promoted from two `defp`s to `@doc false` `def`s for
this. That also removes the second copy of the status vocabulary rather than
correcting it in place: there is now one status → colour/label map in core, so the
next status added can't be styled in one component and missed in the other.

## BUG - MEDIUM — the CRM card renders cross-module data with no `crm` permission check

`lib/phoenix_kit_web/live/users/user_details.ex:68` (as merged)

```elixir
crm_contact =
  if Code.ensure_loaded?(PhoenixKitCRM) and PhoenixKitCRM.enabled?() do
    PhoenixKitCRM.Contacts.get_by_user_uuid(user.uuid)
  end
```

The guard copies the connections-stats shape, but connections stats are about
*this* user and stay on this page; the CRM card renders another module's data and
links into `/admin/crm/contacts/:uuid`.

Reaching `/admin/users/:id` does not imply CRM access. Every admin route shares
one `live_session` whose only `on_mount` is `:phoenix_kit_ensure_admin`
(`integration.ex:1206`), which admits Owner, Admin **or any single permission
holder** via `Scope.can_access_admin_area?/1`, and then narrows per-view in
`enforce_admin_view_permission/2` (`auth.ex:1280`). So a role granted `users` but
not `crm` renders this card — reading a contact's name it has no grant for — and
is then redirected to `/` with a permission error the moment it clicks the link.
The card is both a small disclosure and a dead end for exactly the audience it
isn't meant for.

**Fixed** — extracted to `load_crm_contact/2`, which requires
`Scope.has_module_access?(scope, "crm")` before the module guard. That also skips
the query entirely for viewers who would never see the card.

## IMPROVEMENT - MEDIUM — `@crm_contact.name` renders an empty link when name is null

`lib/phoenix_kit_web/live/users/user_details.html.heex:378` (as merged)

`name` is `VARCHAR(255)` with no `NOT NULL` in `v138.ex:48`, and CRM ships
`Contact.display_name/1` (name → email → "Unnamed") precisely for that — every one
of its own call sites uses it (`contacts_live.ex:209`, `contact_show_live.ex:77`,
`list_members_live.ex:659`, …). The card is the one place that reads `.name`
directly, so a contact with a null name renders the card's only link as empty
text: present, clickable, invisible.

`Contact.changeset/2` does `validate_required([:name])`, so this needs a row that
did not come through the public changeset (the `v156` backfill, an import) — hence
IMPROVEMENT rather than BUG.

**Fixed** — a local `crm_contact_label/1` mirroring `display_name/1`'s fallback
chain, rather than calling into the optional module's schema from core.

## IMPROVEMENT - MEDIUM — two new gettext strings, never extracted

The card added `gettext("This user is linked to a CRM contact.")` (and my fix adds
`gettext("Unnamed contact")`), neither of which reached `default.pot`, so ru and
et — the two locales kept at 100% — had no entry at all. This is the same gap that
needed a follow-up commit after #673 (`3cf86a05`).

**Fixed** — the two msgids added to `default.pot` plus ru/et translations.
`"CRM"` needed nothing: it already exists as a msgid from `modules.ex:100` and is
translated in both.

Note for future sweeps: a plain `mix gettext.extract --merge` on this repo
reported **195 new / 12 removed / 53 re-worded (fuzzy)** per locale — the catalogs
had drifted far from the source, and running it as part of a small PR would have
buried the change. That drift was deliberately left out of this PR's scope and
then fixed in its own pass — see **Follow-up: catalog drift** below.

## NITPICK — the query lives in `mount/3`, so it runs twice

`load_crm_contact/2` is called from `mount/3`, which LiveView invokes for both the
dead render and the WebSocket connect. Deliberately left as-is: every other load
on this page (`get_user_with_roles`, `list_admin_notes`, `list_field_definitions`,
the connections stats) is already in `mount/3`, and moving one of them to
`handle_params/3` would be a page-wide refactor disguised as a review fix. The
permission gate at least removes the doubled query for viewers without CRM
access.

---

## Tests

`test/phoenix_kit_web/components/core/email_activity_badges_test.exs` (new) —
the component had none. Plain `ExUnit.Case`, no DB, matching the other core
component tests.

The whitelist bug is locked in by enumerating the canonical status list from
`Log`'s changeset and asserting the failing subset against it in both directions:
every failure status renders exactly one badge and never `badge-info`, and every
non-failure status renders none. `complaint` gets its own named test, so
re-introducing `complained` fails a test whose message says why. Colour parity
(`soft_bounced` amber, `hard_bounced`/`failed` red), the labels, and the
no-duplicate path (status + matching event → one badge, checked for all five
failure event shapes) are covered too.

One caveat: the no-duplicate cases render a timestamped badge, which calls
`Settings.get_setting("time_format", …)`. With no PostgreSQL that read burns its
4 s queue timeout before rescuing to the default, so the file takes ~20 s locally
and ~0 s wherever the suite has a DB. Left alone rather than mocked — `mix test`
is not this repo's gate, and CI runs with PostgreSQL.

## Gate

`mix precommit` (compile `--warnings-as-errors --all-warnings`,
`deps.unlock --check-unused`, `quality.ci` = format check + `credo --strict` +
dialyzer, `test.js`) — clean.

---

# Follow-up: catalog drift (1.7.222)

Ran as its own pass after the review, on the drift noted above. The headline is
that the drift was **not** cosmetic: gettext's fuzzy matching had been silently
carrying translations from one msgid onto a different one, and Elixir's Gettext
**compiles and serves fuzzy entries** (the flag is only a translator hint — see
`gettext.ex` moduledoc). So every wrong carryover was live in the ru and et UI.

## BUG - HIGH — fuzzy carryovers were serving wrong text in ru/et

The pattern: a short new msgid gets fuzzy-matched onto a similar-looking old one
and inherits its translation. Live examples, all flagged `fuzzy` and all rendering:

| msgid | ru served | et served | should be |
|---|---|---|---|
| `Approve` | "Апр" (April) | "Apr" | Подтвердить / Kinnita |
| `Port` | "Сортировать по" (Sort by) | "Sorteeri" | Порт / Port |
| `Email Unconfirmed` | "Email подтвержден" (**confirmed**) | "E-post kinnitatud" | не подтверждён / kinnitamata |
| `Full Access` | "Успешно" (Success) | "Õnnestus" | Полный доступ / Täielik juurdepääs |
| `unlimited` | "без названия" (untitled) | "pealkirjata" | без ограничений / piiramatu |
| `Large` | "Цель" (Target) | — | Большой |
| `Sign up` | "Войти" (Sign **in**) | "Logi sisse" | Зарегистрироваться / Registreeru |
| `Preview` | "Назад" (Back) | "Eelmine" (Previous) | Предпросмотр / Eelvaade |
| `Custom URLs` | "Пользовательские роли" (Custom **roles**) | "Kohandatud rollid" | Свои URL / Kohandatud URL-id |
| `Nord` / `Winter` / `Black` | "Нет" / "Введите" / "Назад" | "Ei" / "Sisesta" / "Tagasi" | theme names |
| `%{n}h ago`, `%{n}m ago` | both "…дней назад" (**days**) | both "…päeva tagasi" | ч / мин, t / min |
| `Approve sign-in` | "Вход через Apple" | "Apple sisselogimine" | Подтвердить вход / Kinnita sisselogimine |
| `Cannot delete send profile` | "Невозможно удалить последнего системного владельца" | "Viimast süsteemi omanikku ei saa kustutada" | about the send profile |

`Email Unconfirmed` rendering as "confirmed" and `Sign up` rendering as "Sign in"
are the two worst: both state the opposite of the truth on an auth surface.

Also wrong, and worth calling out separately: the xAI and OpenAI provider setup
instructions had inherited **Mistral's and DeepSeek's URLs**, so ru/et users were
told to fetch an xAI key from `console.mistral.ai` and an OpenAI key from
`platform.deepseek.com`.

## BUG - HIGH — `errors.po` had unresolvable interpolation bindings

In both ru and et, six `validate_length` messages carried `%{min}` / `%{max}`
while their msgid only ever supplies `%{count}`:

```
msgid "should be at least %{count} character(s)"
msgstr[0] "должно быть не менее %{min} символов"   # %{min} is never bound
```

Ecto passes `count`, so `%{min}` is a missing binding — not a wrong word, a
broken interpolation on every min/max length validation error in both locales.
Three more (`has an invalid entry`, `is/are still associated with this entry`)
were simply untranslated, and `should have %{count} item(s)` said "bytes".

## What was done

- `mix gettext.extract --merge` — the structural fix, applied to all 8 locales.
  195 msgids that existed in source but in no catalog, 12 dead entries removed.
- **ru and et taken to 0 untranslated / 0 fuzzy** across all three domains
  (`default`, `errors`, `phoenix_kit`) — 2182 + 24 + 7 entries each. That is 282
  ru / 281 et newly translated, plus 304 ru / 305 et fuzzy entries reviewed
  one at a time: ~136 per locale were genuinely invalidated by the reword and
  were rewritten, the rest were correct and only needed the flag cleared.
- Terminology was grounded in each catalog's existing non-fuzzy usage rather than
  invented (ru "бакет" not "хранилище" for bucket, since "Storage" is already
  "Хранилище"; et "dimensioon" 23× vs "mõõde" 4×, "teavitus" 15× vs "teatis" 5×).
- daisyUI theme names follow the **fr** precedent — the repo's only prior
  decision on them: translate the descriptive ones (`Winter` → Зима / Talv),
  keep genre and proper nouns (`Cyberpunk`, `Dracula`, `Lo-Fi`, `Nord`, `CMYK`).

## Verification

- **A full `extract --merge` is now a no-op** for every locale: `0 new, 0 removed,
  0 reworded (fuzzy)`, and byte-identical output on a second run. That is the
  actual definition of the drift being gone.
- **Placeholder audit across all 24 catalog files: 0 problems** — every `%{…}` in
  every msgstr (singular and each plural form) is bound by its msgid. This is the
  check that would have caught the `%{min}`/`%{max}` bug years ago; worth wiring
  into CI.
- `mix precommit` clean.

## Deliberately left alone

`de`, `es`, `it`, `pl`, `en` are structurally synced but remain stubs by design
(1960–2182 untranslated). `fr` was completed in a follow-up — see below.

---

# Follow-up 2: fr completed (1.7.223)

fr was at ~86% with 126 fuzzy. Same defect class as ru/et, confirmed live:

| msgid | fr served | should be |
|---|---|---|
| `Approve` | "avr." (April) | Approuver |
| `Sign out` | "S'inscrire" (Sign **up**) | Se déconnecter |
| `Email Unconfirmed` | "E-mail **confirmé**" | E-mail non confirmé |
| `Restore` | "Rétro" (the Retro theme) | Restaurer |
| `unlimited` | "sans titre" (untitled) | illimité |
| `Full Access` | "Succès" (Success) | Accès complet |
| `Port` | "Trier" (Sort) | Port |
| `Custom URLs` | "Rôles personnalisés" (Custom **roles**) | URL personnalisées |
| `Device` | "Service" | Appareil |
| `Create User` | "Créer un dossier" (Create **folder**) | Créer un utilisateur |
| `Sign in to %{project_title}` | "Nouveau sur %{project_title} ?" | Connexion à %{project_title} |
| `Integration added` | "Intégration **supprimée**" (removed) | Intégration ajoutée |
| `No unread notifications` | "Activer les notifications utilisateur" | Aucune notification non lue |
| `%{n}h ago`, `%{n}m ago` | both "il y a %{n} **jours**" | h / min |

`Sign out` → "S'inscrire" is the standout: the sign-out control read "Sign up".
The xAI setup steps had inherited Mistral's URLs here too.

**fr is now 0 untranslated / 0 fuzzy** across all three domains — 301 strings
translated and 126 fuzzy entries reviewed, 90 of them rewritten.

## BUG - MEDIUM — the audit missed placeholders that were *dropped*, not extra

The 1.7.222 audit only flagged msgstrs referencing a binding the msgid does not
supply (broken interpolation). fr exposed the mirror case: a carryover that drops
a placeholder the msgid *does* supply, silently losing the value.

```
msgid  "Requires %{module}"
msgstr "Obligatoire"          # module name gone, and it says "Required"
```

The audit now checks **both directions**, and correctly handles plural entries:
form 0 is compared against `msgid` and the rest against `msgid_plural`, because
English singulars routinely hardcode "1" and carry no `%{count}` (`1 session
revoked for %{email}`) — unioning both would false-positive on every such entry.

This found 5 more live instances, all in the otherwise-stub locales (`Requires
%{module}` in de/es/it/pl, `Active today at %{time}` in es), and all **worse than
being untranslated**: an empty msgstr falls back to correct English, whereas these
render "Required" with the module name silently missing. Fixed in all four.

Final: **0 extra, 0 dropped** across all 24 catalog files.

## Still open

`de`, `es`, `it`, `pl` were completed in a further follow-up — see below.

---

# Follow-up 3: de/es/it/pl completed — every locale now 100% (1.7.224)

The four remaining locales were stubs: ~2106 untranslated each (es ~1967, having
~139 entries already done), plus 40–97 fuzzy entries that *did* carry a
translation. Total ~8,500 strings across the four.

**All four are now 0 untranslated / 0 fuzzy** across `default` (2182), `errors`
(24) and `phoenix_kit` (7). With ru, et and fr that makes **every shipped locale
100% translated with no fuzzy flags anywhere.**

## How it was done safely

The volume (2146 msgids × 4 languages) made hand-editing the 28k-line catalogs a
non-option, so the edits went through a round-trip tool with three properties
worth recording:

- **A no-op apply is byte-identical.** Verified before every use — untouched
  blocks are never reflowed, so the diff only ever contains real changes.
- **Escaping round-trips.** The parser unescapes and the writer re-escapes, and
  `escape(unescape(x)) == x` is asserted on the one msgid containing a quote
  (`Allow "Keep me logged in" …`). Without this, that entry would have gained a
  double backslash.
- **Writes are filtered to each locale's work set** (untranslated ∪ fuzzy), so an
  existing good non-fuzzy translation is never clobbered. This is what kept es's
  139 pre-existing entries intact — visible in the apply counts, where es
  legitimately reports fewer writes than the other three on batches that
  overlapped its existing work.

Terminology was taken from each catalog's own pre-existing entries rather than
invented — e.g. pl already used "zasobnik" for *bucket* where de/es/it keep
"Bucket", and that split was preserved. daisyUI theme names follow the same fr
precedent as before: descriptive names translated (`Winter` → Invierno / Inverno /
Zima), genre and proper nouns kept (`Nord`, `Cyberpunk`, `Lo-Fi`, `CMYK`).

## `en` fuzzy flags cleared

`en` is untranslated **by design** — every msgstr is empty so Gettext falls back
to the msgid, which is already English. It carried 512 fuzzy flags on those empty
entries. They were inert (no msgstr to be wrong), but they made a fuzzy count
useless as a signal, so they were dropped without touching the empty msgstrs.

**"0 fuzzy anywhere in priv/gettext" is now a true, checkable invariant** — which
is the real win, because a non-zero fuzzy count from here on means a reword
actually happened and needs a human.

## Verification

- 7 locales × 3 domains: **0 untranslated, 0 fuzzy**. `en`: 0 fuzzy, untranslated
  by design.
- Bidirectional placeholder audit over all 24 files: **0 extra, 0 dropped**.
- `mix gettext.extract --merge`: all 24 files report `0 new, 0 removed, 0
  reworded`, and the tree is **byte-identical** afterwards.
- `mix precommit` clean.
