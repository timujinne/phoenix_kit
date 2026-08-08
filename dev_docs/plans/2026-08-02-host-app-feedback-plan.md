# Host-app feedback — verification and implementation plan

**Status:** reviewed and approved. Ready to implement.
**Baseline:** `phoenix_kit` 1.7.226 — every `file:line` reference below was
re-verified against this version on 2026-08-02.
**Companion repo:** `phoenix_kit_referrals` (one line, PR-W step 1).

## What this is

Eleven independent host-app teams reported ~43 issues while building on
phoenix_kit. Every claim was checked against source rather than accepted; the
results are below, grouped as **findings** (§C, what is actually true) and
**PRs** (§D, what to do about it). §G is the running order, §H proves nothing
was dropped.

## Delivery model

⚠️ **The `PR-x` labels are unit-of-work IDs, not pull requests.** Each is **one
commit**. There is **one pull request per repository** at the end, opened once
the whole set is in.

| Repo | What lands there |
|---|---|
| **`phoenix_kit`** (core) | the large majority of commits |
| **`phoenix_kit_referrals`** | one commit — PR-W step 1, the CSPRNG one-liner |
| **`phoenix_kit_legal`** | one commit — PR-B's half: stop shipping `PhoenixKitWeb.Controllers.ConsentConfigController` so core can own a stub that returns `204` when Legal is absent |

Commit messages start with `Add`/`Update`/`Fix`/`Remove` and carry no AI
attribution. Do not bump `@version`, edit `CHANGELOG.md`, tag, or publish —
releases are cut separately.

## Final verification protocol

When every commit is in, run **three sweeps at different context levels** before
opening the PRs. The point is that each level catches a different class of
defect, and the later ones must not be anchored by the plan:

1. **Plan-aware sweep.** Reviewers get this document and the diff, and hunt for
   defects *introduced by* implementing it — wrong anchors, half-applied
   changes, contradictions between commits, `Done when` criteria not actually met.
2. **Area-only sweep.** Reviewers are told only which areas moved (auth, settings
   cache, sitemap, components, storage docs) with **no plan and no diff**, and
   review those areas on their merits. Catches things the plan itself got wrong,
   which a plan-aware reviewer will tend to confirm rather than question.
3. **Blind sweep.** No context at all — plain "review this code". Fresh eyes on
   whatever they find, including code nobody in this triage looked at.

Do not collapse these into one pass. A reviewer holding the plan reads the diff
as *evidence for* the plan; that is exactly the bias sweeps 2 and 3 exist to
break. This triage already produced several fixes that were wrong on a premise
nobody had checked (see §B), and each was caught by re-checking rather than by
re-reading.

## How to use it

1. **§G** is the running order; **§H** maps every finding to a destination.
2. Each finding has a `### ` section (severity-ordered) carrying the evidence —
   `file:line`, what was measured, and what was ruled out. Read the finding
   before its PR; the PR assumes it.
3. Each PR states scope, shape, and **Done when** criteria.
4. **Re-verify anchors before editing.** They were true at 1.7.226; the tree
   moves.
5. **Quality gate:** `mix precommit` **unpiped**, exit code checked
   (`mix precommit > /tmp/pc.txt 2>&1; echo "EXIT=$?"`) — a pipeline reports the
   last command's status and turns a red gate green. Re-run after every rebase.
6. **Stop at the PR.** No `@version`, CHANGELOG, tag or `hex.publish`.

## Two things that shaped the outcome

**Seven reported "missing" features already existed.** `Storage.store_file/2`,
`Routes.path/2`'s `:locale` option, the not-installed-packages panel,
`Settings.get_project_title/0`, `referral_codes_required`, `mix phoenix_kit.update --yes`,
and `guides/custom-admin-pages.md` (481 lines, published on HexDocs). That is one
systemic discoverability problem, not seven documentation gaps — **PR-M4** is the
only item that targets the loop rather than its symptoms.

**Several first-instinct fixes were wrong, and the record of why is kept
deliberately.** Returning `{"enabled": false}` from the consent stub would have
force-granted every Google consent category (§B-II). A bare `ttl:` on the
settings cache would have broken every batch read (PR-F). Blocking OAuth at
account creation rested on two preconditions that turned out to be unreachable
(PR-Y). Those retractions are the most reusable part of this document: they stop
the next reader re-deriving an answer that was already tested and rejected.

---

## A. Corrections to the incoming report

**A1. `mix phoenix_kit.update --yes` ALREADY EXISTS** — `update.ex:166`
(`yes: :boolean`, `y:` alias); `:710-716` explicitly overrides the
non-interactive branch; documented at moduledoc `:47`, `--help` `:794`, and
`:853` ("For automated deployments, use the --yes flag").
Real residue: the hint at `:718-723` never mentions `-y`, and it returns `:ok`
→ **exit 0 with a pending migration**.

**A2. Stale test comment already fixed** at HEAD (`3fd9277d`). No action.

**A3. Wishlist #1 is "generalize", not "build"** — core already ships
`PhoenixKitHooks.PkDialogDraft` (`phoenix_kit.js:2613`): working reconnect-safe
draft capture via `phx:disconnected` + re-mount restore. Limits: **in-memory**
(not localStorage → survives socket reconnect, not page reload) and
**hardcoded to the calendar modal** (regex `/^event\[(.+)\]$/`, special-cased
`owner`/`owner_tz_entry`). Sole consumer: `phoenix_kit_calendar`.

**A4. Topp's "list not-installed modules in Admin → Modules" IS ALREADY BUILT** —
and shipped **2026-03-15** (`879cef62`, tagged in 1.7.77), long before their
1.7.214 baseline. `modules.html.heex:816-860` renders "Available Packages" cards
with a *Not installed* badge, Hex link, and an `Add to mix.exs` snippet — almost
exactly the mock-up they drew. The real defect is *why they never saw it*: see
T4. Do not build this feature; fix its failure mode.

**A6. `signed_in_path/1` hardcoded to `"/"` — ALREADY FIXED in 1.7.217.**
Reported as "private, hardcoded, no configuration… hosts have no way to say
send them to `/dashboard`". That was true; it isn't now.

- Current `auth.ex:2038`: `defp signed_in_path(_conn), do: Routes.post_auth_path()`
  — delegates to the #667 resolver, which reads the **`after_login_path`**
  setting (`routes.ex:98,127`), re-guards it as local + non-auth-page, and only
  then falls back to `"/"`.
- Their sharper sub-claim — *"it honours `user_return_to`, but nothing sets it
  during registration"* — is exactly what
  `session.ex:176 maybe_store_after_registration_path/1` now does: it reads the
  **`after_registration_path`** setting and stashes it into `:user_return_to`,
  with the same trim/local/auth-page guards, leaving an existing gate-stashed
  `return_to` alone.
- Both landed in commit `0f7b3db4` *"Fix registration sessions not persisting;
  add auth policy settings"* (PR #667), first tagged **v1.7.217**.
- Their citation `auth.ex:1873` vs the current `:2038` (~165 lines of drift) puts
  them on a **pre-1.7.217** tree — consistent with the 1.7.214 baseline stated in
  the Topp report.

Action: none in code. Tell the reporter to upgrade to ≥ 1.7.217 and use
`after_login_path` / `after_registration_path` on `/admin/settings/users`.

**A7. Stale reports are now a pattern worth fixing at the source.** Four of the
items triaged here were already-shipped work (A1 `--yes`, A2 test comment,
A4 not-installed-packages, A6 post-auth paths). Hosts are reporting in good
faith against pinned versions and burning review cycles on closed issues.
`mix phoenix_kit.update --status` already reports "available updates"
(`update.ex:785`), so the mechanism exists — what's missing is anything that
tells a host *what they'd gain*. Cheapest useful version: have `status`/`doctor`
print "you are N releases behind — see CHANGELOG for X…Y" when the installed
version trails Hex. Folded into **PR-M** as a docs/tooling note rather than its
own PR.

**A5. Reporters are multiple independent host teams, not one AI.** The
consent-config 404 (B2 / T3) is now reported **twice, independently** (Ratelia
and Topp). Treat corroborated items as higher confidence and higher priority.

---

## B. Corrections found during review

Fixes that were proposed, tested against the source, and rejected. Kept so the
reasoning is not re-derived.

**B-I. The "vendored JS only moves on `phoenix_kit.update`" premise is WRONG.**
`Mix.Tasks.Compile.PhoenixKitJsSources` is a **Mix compiler** that re-copies
`priv/static/assets/phoenix_kit.js` into the host on **every `mix compile`**.
Its own moduledoc: *"Vendoring it from a compiler makes it self-healing: it
comes back on the next `mix compile`, with zero dependency on
`phoenix_kit.update` ever having run again after install."*

Consequences:
- A **JS-side fix does reach hosts** on the next dep bump + recompile — for any
  host with the compiler in `mix.exs` (added by `phoenix_kit.install`).
  Only pre-compiler installs that never re-ran `update` stay frozen.
- **It also kills the panel's biggest objection.** Five of six reviewers said
  the prefix half of B2 needs a root-layout edit + `phoenix_kit.update`
  backfill. It doesn't: the compiler already runs `PhoenixKit.ModuleDiscovery`
  and can emit a tiny generated globals file (prefix + consent flag) alongside
  `phoenix_kit_modules.js` — zero-config, self-healing, no layout edit, no
  backfill gap.

**B-II. `{"enabled": false}` is a privacy landmine — do NOT ship it.**
Flagged by codex + kimi, and **confirmed in the source**. `phoenix_kit.js:752`:

```js
function resetGoogleConsentMode() {
  if (typeof window.dataLayer === "undefined") return;
  gtag("consent", "update", {
    "ad_storage": "granted", "analytics_storage": "granted",
    "ad_user_data": "granted", "ad_personalization": "granted", ... });
}
```

Today, no Legal module → 404 → `.catch` → **nothing happens**. With an
`{"enabled": false}` stub, every full page load would push
**consent-granted-for-everything** into `window.dataLayer` on any host running
GTM/GA with its own consent manager. That converts a log-noise fix into a
**GDPR regression that silently overrides a host CMP's denial**.

**204 No Content is the correct stub response.** `204` passes `response.ok`,
then `response.json()` rejects on the empty body → straight to `.catch` →
inert, exactly like today, for every already-vendored bundle. No JSON payload
can be made inert for old clients, because any parsed body hits the
`else → resetGoogleConsentMode()` branch.

**B-III. `PhoenixKit.Cache` already supports TTL; the settings cache doesn't
use it.** `:ttl` opt (`cache.ex:356/376`), enforced on read via `expires_at`
(`:441`, `:466`). `supervisor.ex:54` starts `{PhoenixKit.Cache, name: :settings,
sync_init: true, warmer: …}` with **no `:ttl`** → entries never expire. So the
cheapest fix for W4 is one line, and it bounds staleness in *every* topology.

**B-IV. Core already hard-depends on Postgres** (`mix.exs:67` `extra_applications`
includes `:postgrex`; `:81` `{:postgrex, "~> 0.22"}`). ZAI asked whether
LISTEN/NOTIFY would couple core to Postgres — it's already coupled, so that
objection dissolves.

**B-V. PR-8 fails CLOSED — verified, it is not a security bug.** codex asked
this first. `auth.ex:1302-1306`: unmapped view → `if
Scope.holds_all_enabled_permissions?(scope), do: {:cont}, else:
deny_admin_access(...)`. Diagnostics only. Rank accordingly.

---

## C. Confirmed findings

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| B2 | consent-config 404 per page load | CONFIRMED, two defects | `integration.ex:271` gates route on `Code.ensure_loaded?(Legal)`; `phoenix_kit.js:1350` fetches unconditionally on `DOMContentLoaded`. **Second defect:** `PHOENIX_KIT_PREFIX` is emitted only by core's own layouts, so on *host* pages the fetch guesses `/phoenix_kit` → custom-prefix hosts 404 **even with Legal installed** |
| F1 | unmapped admin LV → `Logger.debug` | CONFIRMED (fails closed) | `auth.ex:1297-1300` |
| F2 | `url_path` unset | CONFIRMED, narrower | auto-assigned at `auth.ex:833` via the `:handle_params` hook attached in `mount_phoenix_kit_current_user/2` (`:909`). Real gaps: `live_render` embeds (no handle_params) + host LVs bypassing the on_mount chain |
| F3 | custom permission keys imperative-only | CONFIRMED | `permissions.ex:185`, `:persistent_term`-backed |
| F4 | admin-tab story undocumented | CONFIRMED | dashboard README 1357 lines, 2 incidental `admin_tabs` mentions |
| F5 | `page_action` navigate-only | CONFIRMED | `layout_wrapper.ex:414` hardcodes `<.link navigate=…>` |
| C1 | kit clobbers process-global Gettext locale | CONFIRMED — **design settled, see PR-E** | six global `put_locale/1` sites: `:868`, `:899`, `:1042`, `:2137`, `:2168`, `:2215`. **Missed by the report:** `maybe_update_locale_from_params/2` (`:887-905`) re-fires the *default* locale globally on **every** `handle_params` once `current_locale_base != default_base` — so the host's workaround is load-bearing on hook ordering *and* on never touching that assign |
| C2 | auth pages don't follow host language | **WITHDRAWN BY REPORTER — docs gap, not a feature** — see L1 | et/ru ~95% translated (104/2026 empty msgstr); **de ~9%** (1836/2016 empty) |
| S1 | `Scope.authenticated?/1` no nil clause | CONFIRMED, broader | every other predicate has a catch-all (`owner?:291`, `can_access_admin_area?:327`, `superadmin?:475`, `can?:538`, …). Missing on `authenticated?/1:177` **and — unreported — `anonymous?/1:246`** |
| W2 | no PWA generator | CONFIRMED | no manifest/SW in `lib/` or `priv/` |
| W3 | `Storage.store_file/2` undiscoverable | CONFIRMED | exists `storage.ex:2436`, no host-facing guide |
| W4 | cache invalidation node-local | CONFIRMED (+3 corrections) | `cache.ex:219` `GenServer.cast`; 0 PubSub in `cache.ex`/`settings.ex`. **`Settings.Events.broadcast_setting_changed/2` (`events.ex:22`) has ZERO callers** while `live/settings.ex:158` already handles the message — dead API. See B-III/B-IV |
| W5 | `test/support` not shipped | CONFIRMED | `mix.exs:239` `files: ~w(lib priv mix.exs README.md LICENSE CHANGELOG.md)` |
| W6a | no iOS 16px input rule | CONFIRMED | zero input `font-size` rules in any shipped CSS |
| W6b | no locale-aware month helper | CONFIRMED, easy | `Utils.Date` = raw `Calendar.strftime`; **the `"Jan"`/`"Feb"` msgids + et/ru translations are already in core's catalog** (`default.pot:7086+`) as an extraction anchor for projects. `PhoenixKitProjects.L10n.short_month/1` is the impl to lift. Raw `%b` at `media_canvas_viewer.html.heex:335` |
| D1 | `/test-current-user` public, renders scope internals | CONFIRMED, reframed | see below |
| T1 | auth pages inherit host's phx.new layout → Phoenix branding | **CONFIRMED — reproduces in `phoenix_kit_parent`** | see below |
| T2 | auth wrapper hardcodes host chrome + uses `100vw` | CONFIRMED verbatim | `auth_page_wrapper.ex:69`, unchanged at 1.7.220 |
| T3 | consent-config 404 | CONFIRMED — **2nd independent report** | same as B2 |
| T4 | optional modules undiscoverable | **ALREADY BUILT — but network-gated** | see below |
| T5 | `rustler` must be declared in the host | CONFIRMED | `mix.exs:142` `{:mdex, "~> 0.13"}`, `:146` `{:rustler, ">= 0.0.0", optional: true}`. Optional deps aren't resolved for the host, so it must declare it. The code comment at `:143-145` already explains the source-build case — it just never reaches the install guide |
| T6 | two sources of truth for app name | **NOT A BUG — the reader already exists** | `PhoenixKit.Settings.get_project_title/0` (`settings.ex:264`) is exactly the documented single-source reader they asked for, with a defined precedence (DB setting → `config :phoenix_kit, :project_title` → default) and it's what the auth LVs already call (`login.ex:37`, `registration.ex:50`). Topp kept a parallel `Topp.Config.project_title/0` and the two drifted. **Fourth instance of the discovery pattern** — folded into PR-M docs, no code change |
| R1 | "Referral code is required" appears while typing in *other* fields | **CONFIRMED in both files** | see below |
| SEC1 | referral validation is an unthrottled brute-force + enumeration oracle | **CONFIRMED — +1 unreported finding, and fix (1) is weaker than claimed** | see below |
| M1 | magic-link request step ignores referral codes → unauth mail-send trigger | CONFIRMED | `magic_link_registration_request.ex:23,51` gate on `allow_registration` only; zero `referral` references in the file |
| M2 | referral code doesn't survive the magic-link round-trip | CONFIRMED | `magic_link_registration.ex:52` hardcodes `assign(:referral_code, nil)`; mount reads no referral param, and the token carries no referral payload |
| SEC2 | **OAuth signup bypasses invite-only entirely** | **CONFIRMED — full bypass** | `oauth.ex:235-246` `maybe_process_referral_code/2` is attribution-only: every branch returns `:ok` (no code → ok, invalid code → ok), and it runs *after* `find_or_create_user/3` has already created the account. `referral_codes_required` is never consulted on this path |
| M3 | `magic_link_registration_enabled` doesn't gate magic-link registration | **CONFIRMED — misleading security control** | see below |
| G1 | local buckets have no public-URL story | **HALF TRUE** | `providers/local.ex:156` `public_url/2` → `nil` ✓. But "no serving route exists" ✗ — a signed route is wired at `integration.ex:259` (`/file/:file_uuid/:variant/:token`, `FileController`) backed by `services/url_signer.ex` + `file_server.ex`. **Fifth discovery-pattern instance.** Caveat: that signer is already on core's own TODO list as weak (16-bit token, never expires, unauthenticated `/api/files/:uuid/info`) |
| G2 | `store_file/2` documents `user_uuid` as optional, validation requires it | CONFIRMED | docs `storage.ex:~2432` list it as a plain option; `store_file/2` uses `Keyword.get` (optional), but `file.ex:258-267 validate_system_managed_invariants/1` does `validate_required([:user_uuid])` for non-system-managed files. One-line docs fix |
| G3 | sitemap mounts under `url_prefix`, crawlers read domain root | CONFIRMED | `integration.ex:315` `scope unquote(url_prefix)` → `/phoenix_kit/sitemap.xml`. **No `robots.txt` route exists at all** |
| G4 | exclude-patterns setting replaces defaults AND can't hold them | **CONFIRMED — worse than reported** | see below |
| K1 | `button/1` has no `variant` → **collides with the host's own, so it goes unused** | CONFIRMED | `core/button.ex:16-18` takes only `type`/`class`/`rest`; `:27` hardcodes `"btn btn-primary phx-submit-loading:opacity-75"`. No variant, no `<.link>` rendering |
| K2 | no generic `badge` primitive | **PARTLY WRONG — six exist, but none is the primitive** | see below |
| K3 | `form_actions/1` can't do a `phx-click` cancel | CONFIRMED | `core/form_actions.ex:47` `attr :cancel_to, :string, required: true` — URL only, no event/slot option |
| K4 | `formatted_number/1` is integer-only | CONFIRMED | `number_formatter.ex:49,61` both guard `when is_integer(number)`; `:78` `format_number_value(number, _format), do: to_string(number)` — a float silently bypasses grouping entirely |
| K5 | no declarative way to hide a module's admin tabs | CONFIRMED | `Registry.unregister_tab/1` (`registry.ex:161`) is a `GenServer.call` mutating in-process state; the registry re-assembles from `AdminTabs.default_tabs/0` on init, so a supervisor restart resurrects the tabs |
| N1 | bell shows "View all" to users who can't open the inbox | **CONFIRMED — bell has zero permission awareness** | see below |
| U2 | admin theme not host-configurable; brand dies at `/admin` | **CONFIRMED — zero override path exists** | see below |
| U1 | `/dashboard`→`/admin` migration: no "customer" permission; coupling is wider than the route | **CONFIRMED — and it's a live boss-directed project, not a new ask** | see below |
| Q1 | `return_to` built with a stray trailing `?` | **CONFIRMED — exact one-line cause; "harmless" verified true** | see below |
| G6 | settings `:value` validated at 1000 chars but column is varchar(255) | **NEW — found while scoping G4; not in any report** | `setting.ex:187,196` `validate_length(:value, max: 1000)` vs `v03.ex:23` `add :value, :string` → varchar(255). Any 256–1000 char setting passes validation then dies with a Postgrex "value too long". Latent for every long setting, not just sitemap. Fixed by the same **V160** |
| G5 | asset/tile routes excluded only by `^/phoenix_kit` | CONFIRMED | exactly one occurrence of that pattern; no dedicated `/file`, `/tiles`, `/api/files` patterns |

> **Detail sections below are ordered by severity**, not by the order the
> reports arrived: security first, then incident-class, then correctness, then
> cosmetic, then the one open design question (U1).

### SEC1 — referral oracle (the one real security finding in this triage)

Every number in the report checks out:

| Claim | Verified |
|---|---|
| 5-char generated codes | `phoenix_kit_referrals.ex:91` `@code_length 5` |
| 32-char alphabet | `:90` `~c"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"` — 24 letters (no I/O) + 8 digits (no 0/1) = **exactly 32** |
| 32⁵ ≈ 33.5M = 25 bits | 33,554,432 = 2²⁵ exactly |
| custom codes may be 3 chars | `:157` `validate_length(:code, min: 3, max: 50)` → ~46k space, seconds to exhaust |
| four error strings enumerate | `registration.ex:289-306` — `"Invalid referral code"` vs `"…no longer active"` / `"…has expired"` / `"…reached its usage limit"`; the latter three **confirm the code exists** |
| unthrottled | no `RateLimiter` reference in `registration.ex` or `magic_link_registration.ex` |

**Refinement on "unthrottled":** core *does* rate-limit registration —
`RateLimiter.check_registration_rate_limit/2` exists (`rate_limiter.ex:264`) and
is wired at `auth.ex:445`, inside `Auth.register_user/2`. But the LV validates
the referral code **first** (`registration.ex:122`) and only reaches
`register_user` on `{:ok, _}`. **So a failing referral code never reaches the
limiter at all.** The limiter guards the consequential action and leaves the
cheap information leak in front of it completely open.

⚠️ **Therefore fix (1) is a UX fix, not a security fix.** The report presents
"validate on submit only" as resolving both issues in one change. It fully fixes
R1 — but against the oracle it buys almost nothing: `phx-submit` and
`phx-change` are both just websocket messages on an already-open socket, so an
attacker simply sends submits instead of changes at essentially the same rate.
Per the paragraph above, those submits still short-circuit before the limiter.
**Fix (3) — rate-limiting the referral check itself — is the actual security
fix, and it is not optional.**

**Unreported finding: referral codes are generated with a non-cryptographic
PRNG.** `phoenix_kit_referrals.ex:183`:

```elixir
for _ <- 1..@code_length, into: "", do: <<Enum.random(@code_alphabet)>>
```

`Enum.random/1` goes through Erlang's `:rand` — a fast PRNG seeded per process,
not designed to resist state recovery. Compare `registration.ex:311`, which
correctly uses `:crypto.strong_rand_bytes(16)` for a session id. For a value
that is the **sole gate on account creation** when `referral_codes_required` is
on, predictable generation is arguably worse than brute force: an attacker who
legitimately holds a couple of codes (they're handed out by design, and appear
in `?ref=CODE` links) may be able to derive further codes without guessing at
all. `generate_unique_code/1` inherits the same weakness. **One-line fix**, and
it should go in ahead of any of the tuning suggestions.

**Severity:** HIGH for invite-only deployments (`referral_codes_required` on —
this is the only thing standing between an attacker and account creation);
LOW-MEDIUM otherwise, where cracking a code only buys attribution/benefits.
Note this is the same Topp deployment shape that produced R1 and T4.
### L1–L2 — outcomes of the direct exchange with the Ratelia AI (2026-08-01)

**L1. C2 is withdrawn — do NOT build it.** The reporter retracted it after
finding the capability already exists: the kit ships a near-complete Estonian
catalog (`priv/gettext/et`, ~10.7k lines, 92 untranslated msgids) and
`Routes.path/2` already takes `:locale`. Their auth pages were English purely
because they linked without it. Their whole fix was one helper:

```elixir
def kit_path(path) do
  PhoenixKit.Utils.Routes.path(path, locale: Gettext.get_locale(RateliaWeb.Gettext))
end
```

Their words: *"item #2 is a documentation gap, not a feature request… I'd hate
for you to build something that already exists because my report implied it
didn't."* → folds into **PR-M** as one line: *host apps should pass `:locale` to
`Routes.path/2` when linking to kit pages*. **This reverses my own earlier
recommendation** that C2 was "the more valuable half" worth shipping first — it
was based on their initial report, which they have since corrected.

**Sixth instance of the discovery pattern** (with T4/F4/W3/T6/G1): the feature
existed, the host couldn't find it.

**L2. Prefixless primary URLs — observation right, diagnosis wrong.** They
reported that English also gets a prefix (`/phoenix_kit/en/…`, never prefixless)
and attributed it to `Config.default_locale()` being `"en-US"` making
`default_locale?("en")` false.

The observation is correct; the cause is not. `default_locale?/1`
(`routes.ex:276`) never consults `Config.default_locale/0` — it compares against
`get_default_language_base/0` (`:281`), which runs
`DialectMapper.extract_base/1` and normalises `"en-US"` → `"en"`. So that
comparison succeeds. The real cause is that **prefixless-primary is opt-in**:
`Languages.default_language_no_prefix?/0` (`languages.ex:558-560`) defaults to
**`false`**, so out of the box every language including the primary carries a
prefix.

So the doc line they asked for should say *"prefixless primary-language URLs are
opt-in via the `default_language_no_prefix` setting, which defaults to off"* —
**not** anything about `en-US`. → **PR-M**.

### M3 — a settings toggle that doesn't toggle anything

`magic_link_registration_enabled` has exactly five readers, and **neither
magic-link LiveView is among them**:

| Reader | What it does |
|---|---|
| `settings/settings.ex` | default `"true"` |
| `settings/setting.ex` | schema field |
| `live/settings/authorization.html.heex` | renders the admin toggle |
| `users/registration.ex` | assigns it |
| `users/registration.html.heex` | shows/hides the button |

`rg -c magic_link_registration_enabled` against
`magic_link_registration_request.ex` and `magic_link_registration.ex` returns
**zero**. Both gate on `allow_registration` instead
(`magic_link_registration_request.ex:23`, `:51`).

So switching it off **hides the button and leaves `/users/register/magic-link`
fully functional**. This is worse than a dead setting: it lives on the
**Authorization** settings page, so it reads as a security control, and an admin
who disables it will reasonably believe the route is closed. Anyone with the URL
walks straight in.

This is the same class as the demo-scaffolding naming problem (D1) — a control
whose name promises enforcement it never performs.
### G3/G4/G5 — one incident chain, and the setting is unrecoverable

These three aren't separate bugs; they're the sequence that published ~140 junk
URLs on a production host, with **no way back through the UI**.

1. **Sitemap mounts under the prefix** (`integration.ex:315`), so it serves at
   `/phoenix_kit/sitemap.xml`. Crawlers only read `/sitemap.xml` and
   `/robots.txt` at the domain root — and **core ships no `robots.txt` route at
   all**. So every public host must re-declare, and must know to use a scope
   with no alias or the controller resolves as `HostWeb.PhoenixKit.…`.
2. **Customising the exclude patterns silently replaces all 30 defaults.**
   Documented as intentional (`router_discovery.ex:200-211`, including a
   *"Saved lists are frozen"* warning) — but the doc warns about the
   *forward-compat* consequence (you won't get new defaults), not the immediate
   one (you just dropped every existing exclusion).
3. **Losing `^/phoenix_kit` publishes the asset routes** — G5. That single
   pattern is the only thing keeping `/phoenix_kit/tiles/:token/…`,
   `/phoenix_kit/file/:file_uuid/…` and `/phoenix_kit/api/files/…` out.
4. **Restoring the defaults is impossible.** Measured:

   | | |
   |---|---|
   | default list | **30 patterns, ~436 chars** as a JSON array |
   | `value` column | `v03.ex:23` `add :value, :string` → **varchar(255)** |
   | `value_json` column | `setting.ex:118` `field :value_json, :map` — **an array is not a map**, so `update_json_setting/2` rejects a list outright |

   Reporter's actual errors, from the production incident:

   ```
   value:      {"must provide either value or value_json", []}
   value_json: {"is invalid", [type: :map, validation: :cast]}
   ```

   The defaults **alone** are ~1.7× the column limit. There is no field on the
   settings row that can hold them, so once overridden the setting cannot be
   restored — let alone "defaults plus additions". That's the part that turned a
   misconfiguration into an incident.

**Note the inconsistency inside the same module:** the sibling setting
`sitemap_protected_pipelines` *extends* its defaults — `router_discovery.ex:218`
says so explicitly: *"Unlike exclude patterns, `sitemap_protected_pipelines`
only \*adds\* to this list — these defaults always apply."* Two adjacent settings,
opposite merge semantics, one of them documented as the safe one.

**Severity: HIGH** — highest non-security finding in this triage. It is an SEO
/ data-exposure incident (admin and auth URLs published to crawlers) with no
in-product recovery path.
### N1 — a link to a page the viewer will be bounced from

The reporter's principle is right and the code agrees with them everywhere
*except* here.

- **Destination is permission-gated.** `auth.ex:1430-1431` maps
  `Live.Notifications.Inbox` and `.Settings` → the `notifications` permission,
  enforced at mount by `enforce_admin_view_permission`.
- **The link is not.** `notifications_bell.ex:187-192` renders
  `navigate={Routes.path("/admin/notifications", …)}` unconditionally. Its own
  comment states the intent — *"Footer: always present so the full inbox is one
  click away, even when the recent list is empty"* — and "always present" is
  precisely the defect.
- **The bell can't gate it even if it wanted to.** Grepping
  `notifications_bell.ex` for `scope|has_module_access|can?|Permissions` returns
  **nothing**: the component never receives a scope. The render condition at the
  call site (`layout_wrapper.ex`) is `@socket && bell_user &&
  Notifications.enabled?()` — user presence and a module toggle, no permission.

**Contrast that proves it's an oversight, not a policy:** the sidebar already
does exactly the right thing — `registry.ex:743`
`Enum.filter(tabs, &Tab.permission_granted?(&1, scope))`. So a user without
`notifications` sees no Notifications tab in the sidebar, and then a "View all"
button in the header pointing at that same missing tab.

**Sweep: one occurrence.** `notifications_bell.ex:188` is the only unconditional
`Routes.path("/admin…")` link in shared chrome — the layouts don't hand-roll any
others; everything else routes through the permission-filtered tab registry.

**This is the third member of the "controls that don't control" family** (§E0),
and the mildest: `TestRequireAuthLive` promises auth it doesn't enforce, the
magic-link setting promises a gate it doesn't apply, and this promises a
destination it can't reach.

**Relevance to U1:** under options (A)/(B), *more* users hold the bell without
holding `notifications`, so the wrong-link population grows. Worth fixing before
the migration, not after.

### M1/M2 — invite-only is only half-enforced on the magic-link path

M1: the request step sends a registration email to any address a visitor types,
with no referral check, even when `referral_codes_required` is on. Account
creation is still blocked at completion, so it is **not an auth bypass** — the
reporter is right to say so. What it is: an unauthenticated mail-send trigger
attributable to your domain, and a bad invitee experience (they discover they
need a code only after clicking through from their inbox).

M2 compounds it: the code can't survive the trip even if collected. Mount
hardcodes `referral_code: nil` and reads nothing from URL or token, and the
`?ref=CODE` capture lives in **localStorage — per browser**. Request the link on
a laptop, open the mail on a phone, and the code is gone. A visitor who arrived
via a `?ref=` link may never have seen the code as text to re-type.

Fix shape: collect + validate the referral code at the **request** step, then
carry it through the token payload (preferred — tamper-proof and device
independent) or a `?referral_code=` param on the completion URL. Validating at
request also means the mail only goes out to someone holding a valid code, which
resolves M1 and M2 together.

⚠️ Note the interaction with **SEC1**: adding referral validation to the request
step creates a *second* unthrottled oracle unless the rate limiting from PR-W
step 2 covers it too. Do not land M1 before PR-W.
### T1 — auth pages ship Phoenix branding (reproduces in-house)

Resolution chain, all verified:
`layout_config.ex:46` (installer writes `{layouts_module, :app}`) →
`layout_wrapper.ex:968` `get_layout_config/0` → non-admin views take
`render_with_parent_layout` (`:172`) → `auth_page_wrapper.ex:62` renders inside
the host's `Layouts.app/1`.

**`phoenix_kit_parent` does this today.** `config/config.exs:21` sets
`layouts_module: PhoenixKitParentWeb.Layouts`, and that `app/1` still carries
generator output: logo (`layouts.ex:57`), `v{Application.spec(:phoenix, :vsn)}`
(`:58`), `phoenixframework.org` (`:102`), Phoenix GitHub (`:105`). So the login
page in the maintainer's own dev host renders Phoenix branding and three links off-product.

Two things the report didn't have:
- **An escape hatch already exists.** `config :phoenix_kit, layout: {Mod, :fun}`
  takes precedence over `layouts_module` (`layout_wrapper.ex:974-976`), so a host
  *can* point auth pages at a different layout today. It doesn't fix the default,
  and it isn't documented where anyone would find it.
- **Their "reads as dead scaffolding" claim is stronger than they argued.** The
  parent's `Layouts.app` **has** been customised (a bespoke publishing-aware
  language switcher, ~`:59`) and the Phoenix chrome still survived the edit.
  So it isn't just "nobody greps it" — it survives people actively editing the file.
### T2 — viewport math

`auth_page_wrapper.ex:69`, byte-identical at 1.7.220:
`min-h-[calc(100vh-4rem)]` (host header is exactly 4rem) · `-my-8` (host wraps in
`py-8`) · `w-[100vw]` + `-mx-[calc(50vw-50%)]` (full-bleed escape).

⚠️ **Hard constraint the reporter couldn't know:** the fix must **not** reach for
`scrollbar-gutter`. Core deleted every such override on 2026-07-12 and the
workspace rule is "never re-add `scrollbar-gutter` overrides in layouts,
PkDialog, or modules" (daisyUI investigation, closed). Their proposed shape —
`flex-1` inside a flex column, `width: 100%` instead of `100vw` — is correct and
compatible with that rule. It's the *same symptom class* as the daisyUI gutter
saga via a different mechanism, so it will look like a tempting place to
reintroduce the banned property.
### R1 — eager referral error (report is right; here's the corroboration)

`validate_referral_code/2` (`registration.ex:268`) returns
`{:error, "Referral code is required"}` whenever the code is required and blank,
and `handle_event("validate")` (`:216-231`) assigns that into
`:referral_code_error` on **every** `phx-change`. So the first keystroke in the
email field paints the referral input red and prints the message.

**The template proves the intent was otherwise** — `registration.html.heex:95-99`:

```heex
(@referral_code_error ||                            # branch 1 — UNGATED
   (@check_errors && @referral_codes_required &&    # branch 2 — gated on check_errors
      (is_nil(@referral_code) || @referral_code == ""))) && "input-error"
```

Branch 2 is the author's "don't nag before submit" gate — and it is
**unreachable for the empty case**, because branch 1 already fired. The message
itself (`:104-106`) is ungated too. That asymmetry is the tell: the gate was
written expecting `referral_code_error` *not* to be set eagerly.

`check_errors` semantics confirmed as "the user attempted submit": initialised
`false` at mount (`:81`), set `true` only on save paths (`:184`, `:192`), and
`assign_form/2` (`:258`) resets it **only when the changeset is valid** — so the
submit path's `assign(check_errors: true) |> assign_form(changeset)` is *not*
self-defeating. No second bug there.

**The sibling has the identical shape — confirmed.**
`magic_link_registration.ex:70-95` eagerly assigns the same error; its submit
path (`:145-151`) correctly pairs the error with `check_errors: true`. So in
both files the *submit* path is right and the *validate* path is the bug.

Diffing the two `validate_referral_code/2` + `validate_referral_code_value/1`
implementations (`registration.ex:268-300` vs
`magic_link_registration.ex:183-215`): **byte-identical logic** — the only
delta is that the magic-link copy dropped the four explanatory comments. Pure
copy-paste, no behavioural drift.

Two scoping facts worth carrying:
- **Blast radius is exactly two files.** `referral_code_error` appears nowhere
  else in `lib/`, and no other field is validated outside its changeset.
- **It only bites when `referral_codes_required` is true** — i.e. invite-only
  sites. That is precisely Topp's stated product requirement, so this and T4
  are the same customer walking into the same feature from two directions.

Minor: the input also carries `required={@referral_codes_required}`, so the
browser blocks an empty submit natively regardless. The eager server-side
message is pure additive noise.
### K1–K5 — component + host-integration gaps (NordSwitch)

**First: five of this report's items are not new.** 2.1, 2.2, 2.3, 2.5 and 3.1
are the same five as the friction list triaged at the start of this session —
same team, now with fuller evidence. They map to existing entries and need no new
tracking: **2.1→F1/PR-J, 2.2→F2/PR-N, 2.3→F3/PR-H, 2.5→F5/PR-I, 3.1→F4/PR-M.**
The added detail *strengthens* them (see K1 below for the sharpest example), it
doesn't change their scope.

**K1 is the one to act on, and the reason is not the missing variant.** A host
keeps its own `button/1` for non-primary cases, so importing the kit's raises
`function button/1 imported from both … call is ambiguous` — meaning the kit's
button **cannot be adopted at all**, not merely that it's limited. Their
observation that Phoenix 1.8's scaffold `button/1` is the *richer* one (variant +
renders as `<.link>` for `href`/`navigate`/`patch`) is the decisive argument:
until the kit's is a superset, adopting it is a downgrade. This is an adoption
blocker dressed as a feature request.

**K2 — their premise is wrong, the ask is still valid.** `badge.ex` has **six**
functions, not two: `role_badge`, `user_status_badge`, `code_status_badge`,
`category_badge`, `enabled_badge`, and `status_badge/1` (`:221`). The last is
close to what they want — it already takes `size` and `class` — but it is not a
primitive: `status_class/1` derives colour from a fixed status vocabulary
(falling back to `badge-ghost` at `:255`) and `status_label/1` derives the text
from the status string. So a "device model" chip renders ghost-coloured with a
mangled label. **The gap is a badge where the caller controls variant and content
independently**, with the six existing ones rebuilt on top — a narrower and more
defensible change than "there is no badge".

**K5 is worse than "reads as surgery".** `unregister_tab/1` mutates GenServer
state, and the registry rebuilds from `AdminTabs.default_tabs/0` on init — so
**any** supervisor restart silently resurrects the hidden tabs. A host that did
this at boot gets the module's UI back mid-flight with no signal. "I want this
module's data but not its UI" is a general need (they use
`phoenix_kit_locations` purely as a data layer), and config-driven
`:hidden_admin_tabs` honoured inside the registry's own init is the shape that
survives restarts.

**Worth recording what they said works** — this is the do-not-break list:
`:admin_dashboard_tabs` compiling routes into the kit's live_session with the
admin layout auto-applied; `url_prefix: ""` for root-level product URLs
(including the `"" → "/"` normalisation); fail-closed unmapped views ("the right
default; it just needs to be louder"); and `table_default`, the sortable DnD
suite, `empty_state`, `status_dot`, `stat_card`, `time_display`, `form_section`,
`table_row_menu` all adopted without friction. Their verdict on the migration
itself — "worked and took an afternoon" — is the counterweight to a 1200-line
defect list.

### T4 — the feature exists; the network kills it

`not_installed_packages/0` (`module_registry.ex:346`) →
`known_external_packages/0` (`:713`) → `PhoenixKit.KnownPackages.list()`, which
**fetches live from `https://hex.pm/api/packages`** (`known_packages.ex:47`,
`:166`) with `receive_timeout: 3000` (`:53`) across up to 20 pages (`:176`).

On failure with no usable cache: `handle_hex_failure/3` (`:126`) returns
`merge_extras([])` → `[]` by default, and `modules.html.heex:816` hides the whole
section when the list is empty. **There is no baked-in static catalog — Hex is
the only source.** It's also called synchronously in `mount/3`
(`modules.ex:35`), so a slow fetch blocks the admin page render.

So offline dev, a corporate proxy, CI, a slow link, or a hex.pm hiccup ⇒ the
entire discovery feature silently disappears — which is the exact symptom Topp
reported ("nothing indicates the feature exists"). The failure is logged
(`Logger.warning`) but invisible in the UI.

Separate small bug: the generated snippet hardcodes `"~> 0.1"`
(`modules.html.heex:857`) regardless of the package's real version, so it tells
hosts to pin a stale requirement (Topp's referrals is at `~> 0.4`).

**Bonus corroboration for PR-A:** this template calls
`Scope.authenticated?(@phoenix_kit_current_scope)` (`:22`, `:25`, `:28`) and
`Scope.anonymous?(...)` (`:29`) — the exact two functions missing nil clauses.
Safe here because the on_mount hook guarantees the assign, but core's own
generated template models the call pattern that raises in a host layout where it
doesn't. That's the Ratelia crash, shipped as an example.

---
### D1 — demo scaffolding, corrected framing

Reported as "a leftover whose two siblings correctly redirect". Accurate on the
facts, but the framing inverts the cause: **the three pages are a deliberate
demo of three different auth hooks**, and this one is public *by design*.
`router_integration.ex:415-428` emits:

| Route | on_mount hook | Behaviour |
|---|---|---|
| `/test-current-user` | `:phoenix_kit_mount_current_scope` | mounts scope, **gates nothing** — 200 for anonymous |
| `/test-redirect-if-auth` | `:phoenix_kit_redirect_if_authenticated_scope` | redirects when logged **in** |
| `/test-ensure-auth` | `:phoenix_kit_ensure_authenticated_scope` | redirects when logged **out** |

The siblings redirect because they demo the *gating* hooks. The template's own
badge reads `PhoenixKit Scope Mount: ALWAYS ACCESSIBLE`. So this isn't a broken
gate — it's scaffolding that works as designed and then never gets removed.

Three real defects behind it:

1. **Generated unconditionally, with no opt-out.** `lib/mix/tasks/phoenix_kit.install.ex:142` calls
   `DemoFiles.copy_test_demo_files/1` with no switch — install's `switches:`
   list (`:160-166`) has no `--demo`/`--skip-demo`. Every host gets three routes
   in a bare `scope "/"` at the app root, **outside the phoenix_kit prefix**.
2. **The completion notice sells them as a feature, not scaffolding**
   (`lib/mix/tasks/phoenix_kit.install.ex:499`: `• Test: /test-current-user, /test-ensure-auth`). Nothing
   anywhere says "remove before production."
3. **The name lies.** Module/file are `TestRequireAuthLive` /
   `test_require_auth_live.ex`, but the page uses the hook that does *not*
   require auth — its own moduledoc says "without requiring authentication".
   That's precisely how it survives a security skim: someone greps for auth
   demos, reads "RequireAuth", assumes it's gated.

**Severity: low, and the report is right to say so.** No cross-user leak — a
signed-in visitor sees only their *own* email/uuid (`test_require_auth_live.ex:31-34`).
Real costs are fingerprinting (advertises PhoenixKit + internal scope shape), an
unauthenticated LiveView mount + websocket at the app root, and launch hygiene.
### Q1 — empty-string truthiness in the return_to builder

Single cause, `auth.ex:2026` inside `path_with_return_to/2`:

```elixir
query = if uri.query, do: "?" <> uri.query, else: ""
target_path <> "?return_to=" <> URI.encode_www_form(path <> query)
```

`""` is truthy in Elixir, so a URI whose query is the empty string yields a bare
`"?"`. Confirmed by running it:

| page URL | `uri.query` | appended |
|---|---|---|
| `/dashboard/projects` | `nil` | `""` ✓ |
| `/dashboard/projects?` | `""` | **`"?"`** ✗ |
| `/dashboard/projects?a=1` | `"a=1"` | `"?a=1"` ✓ |

The `%URI{}` comes from `get_connect_info(socket, :uri)`, i.e. the browser's
`window.location.href`. It carries a bare `?` after a fieldless GET form submit,
a `push_patch` with empty params, or a hand-typed/link trailing `?` — and once
captured it can round-trip back into the URL, so it self-perpetuates.

**Fix:** `query = if uri.query in [nil, ""], do: "", else: "?" <> uri.query`.

**"Harmless" — verified, not assumed.** I checked the obvious way this could
bite: `Routes.auth_page?/1` (`routes.ex:158`) does
`String.split(["?", "#"], parts: 2) |> hd()` **before** comparing, so a trailing
`?` cannot sneak an auth page past the self-loop/login-loop guard. And
`local_path?/1` still accepts it. So it is genuinely cosmetic.

**Sweep: one occurrence.** `auth.ex:2026` is the only site with this shape. The
sibling query-builders all guard correctly — `oauth_buttons.ex:101` gates on
`is_binary/1` + `local_path?/1`, `qr_login.ex:108` on `query == []`,
`media_browser/embed.ex:175` on `qs == %{}`, `routes.ex:116` on `local_path?/1`,
and `pagination.ex:331` explicitly tests `query_string == ""`.
### U2 — the admin panel can't wear the host's brand

Every claim verified in `lib/phoenix_kit/theme_config.ex`:

| Claim | Verified |
|---|---|
| `default_theme/0` is a literal | `:303` — `def default_theme, do: "system"` |
| slider maps light/dark to phoenix themes | `:294-298` — `@slider_primary %{"system" => "system", "light" => "phoenix-light", "dark" => "phoenix-dark"}` |
| initial `<html>` theme hardcoded | `:12` — `@default_html_theme "phoenix-light"` |
| header hardcodes the label | `layout_wrapper.ex:382` — `{gettext("Admin Panel")}` |

**Stronger than reported: there is no override path at all.** `theme_config.ex`
contains **zero** `Application.get_env` / `Config.get` / `Settings.get` calls —
the whole module is compile-time module attributes. A host cannot influence the
admin theme by config, by setting, or by any documented seam. Their measurement
(`--color-primary` hue 262 vs their brand's 158) is the visible consequence.

**Why this is more than cosmetics — it is coupled to U1.** Their framing is the
important part: *"now that customer-facing sections are moving into this panel,
it stops being an operator-console detail and becomes the product's appearance."*
That is exactly right, and it makes U2's priority **dependent on the U1
decision**:

| If the maintainer picks… | U2 becomes |
|---|---|
| **(A)** baseline permission — customers enter `/admin` | **a blocker.** Customers would see phoenix-blue chrome and a header reading "Admin Panel" on the host's own product |
| **(B)** relax the entry gate — same outcome | **a blocker**, same reason |
| **(C)** keep `/dashboard` for customers | a normal polish item — operators can live with phoenix themes |

So U2 should not be scheduled until U1 is answered; under (A) or (B) it moves
into the same batch as the migration itself, not after it. The `"Admin Panel"`
label is the same story in miniature — fine for an operator console, wrong on a
customer-facing page.

**Shape when it happens** (their suggestion is right and matches an existing
precedent): accept `theme:` alongside the existing `layout:` config that
`LayoutWrapper.get_layout_config/0` already reads, plus a settings-backed
override; and let `@slider_primary`'s light/dark resolve to host theme names when
the host declares them, falling back to `phoenix-light`/`phoenix-dark`. Make the
header label configurable in the same change. Note the whole module is
compile-time today, so this is a real refactor (attributes → resolved
functions), not a one-liner — cost it accordingly.

### U1 — the dashboard→admin migration (design decision, not a bug)

**This is already the maintainer's own project** — `project_admin_unification_notifications.md`,
started 2026-07-22: deprecate `/phoenix_kit/dashboard`, unify on `/phoenix_kit/admin`
with permission-varied tabs. Topp is asking, from the outside, exactly the
question that project's notes list as an unsolved gap. Their timing point is
fair: they're about to add five more screens to the shell that's going away.

**Their coupling inventory is correct — all four confirmed:**

| Coupling | Verified |
|---|---|
| `PhoenixKitWeb.Layouts.dashboard` + `dashboard_assigns/1` | `layout_helpers.ex:84`, `@dashboard_layout_keys:21` |
| `{PhoenixKitWeb.Dashboard.ContextProvider, :default}` | `dashboard/context_provider.ex:1` |
| `user_dashboard_tabs` config key | `module.ex:154` callback, `tabs_initializer.ex:75`, `integration.ex:939` |
| `@admin_fallback_routes` is permission-scoped | `auth.ex:1206` |

The doctor notice (`doctor.ex:961-967`) does say "still works and needs no action
now" — so taking it at face value is right, and their read that a paths-only
guide would miss three of four couplings is correct.

**The blocker is real, and it is two gates deep — not one.** Their measured
302 for a `["User"]` account is reproducible from the source:

1. **Entry gate** — `Scope.can_access_admin_area?/1` (`scope.ex:319-325`) is
   `Admin role OR Owner role OR MapSet.size(perms) > 0`. A default User holds
   zero permissions ⇒ bounced before any tab is consulted.
2. **View gate** — `enforce_admin_view_permission` then requires
   `holds_all_enabled_permissions?/1` for unmapped views, which a bare user also
   fails.

**Half the machinery already exists**, which is worth telling them:
`Tab.permission_granted?(%Tab{permission: nil}, _)` → `true` and
`module_enabled?(%Tab{permission: nil})` → `true` (`tab.ex:581,607`), so a
universally-visible tab is already expressible. It just can't be *reached*,
because the entry gate fires first. So this is a gate problem, not a tab problem
— matching the project note's own framing ("don't rebuild the tab system; adapt
the gate + add a baseline tab").

**Their question 1 has no answer in core today.** There is no canonical
"ordinary customer" permission key. Hosts can register custom keys
(`Permissions.register_custom_key/2`) and `custom_admin_fallback_routes/0`
(`auth.ex:1259`) will honour a host tab's permission for landing — but each host
would be minting its own auth model, which is precisely the outcome they flag as
risky, and I agree.

**Their question 2 is the crux and only the maintainer can answer it:** is `/admin`
intended to be customer-visible? The permission system says yes; the URL says no.
Their branding point is sharp — a customer landing on `/admin/projects` is a
product decision, not a technical one.

Three shapes, for the maintainer to choose between (I am not picking one):

- **(A) Mint a canonical baseline key** (e.g. `"app"`), auto-granted to User,
  which also satisfies the entry gate. Best fit for the documented **role
  principle** (2026-07-23: "never hardcode a role for feature ACCESS; the 3
  default roles are conveniences") — it stays permission-keyed and role-agnostic.
- **(B) Relax the entry gate** to any authenticated user and let per-tab/per-view
  permissions do all the work. Simplest for hosts; largest semantic change; makes
  "/admin is customer-visible" official.
- **(C) Keep `/dashboard` for customer surfaces**, unify only admin-facing ones.
  Contradicts the deprecation notice already shipping in doctor.

**Answer to give Topp regardless of which is chosen:** don't build the five new
screens against `user_dashboard_tabs` + `Layouts.dashboard` + `ContextProvider`
yet — that's adding to the pile that has to move. Until the baseline-permission
decision lands, a host-owned route + host layout is the lower-migration-cost
place to put new customer screens.

**Their item 4 (doctor check naming coupled files) is good and cheap** — once
steps exist, extend `check_user_dashboard_deprecation/0` (which today returns a
generic `{:warn, …}`) to name the host's own `user_dashboard_tabs` entries and
any module importing `dashboard_assigns/1`. Folded into PR-M/PR-Q's doctor work.

## D. The PRs

Ordering merges the panel's rankings (they split on PR-1 vs PR-2 first; both are
cheap, so batch them) with the corrections above.

### Batch 1 — bugs, low risk

**PR-A — Scope nil-safety.** ⚠️ **Widened 2026-08-01** from "two predicates" to
"one documented invariant", after looking at the whole surface.

**The incoherence that decided it:** `user_uuid/1` (`:211`), `user_email/1`
(`:229`), `user_full_name/1` (`:379`) and `user_active?/1` (`:400`) all already
have explicit `%__MODULE__{user: nil}` clauses returning `nil`/`false`. So the
module answers *"who is the user?"* gracefully when there's a scope with no
user, and **crashes** when there's no scope. To a caller rendering a layout
those are the same situation — nobody is logged in. Answering one and raising on
the other isn't fail-fast, it's arbitrary, and it is what generates the next bug
report.

**The rule** (state it in the `Scope` moduledoc so new functions inherit it
without re-deriving the argument): *does `nil` have a semantically correct
answer, or would we be inventing one?*

| Function | nil answer | Verdict |
|---|---|---|
| `authenticated?/1` `:177` | no scope → not authenticated | **add** (`false` is correct, not a fallback) |
| `anonymous?/1` `:246` | no scope → anonymous | **add** — unreported, arguably worse: asking "is this an anon visitor?" is the natural thing to write on a public page |
| `user/1` `:194` | no scope → no user | **add** (matches its own `{user: nil}` semantics) |
| `user_uuid` / `user_email` / `user_full_name` / `user_active?` | ditto; already answered for nil-user | **add** — coherence |
| `to_map/1` `:420` | nothing to serialize | **LEAVE RAISING** |

`to_map/1` is the one place fail-fast is right: returning `%{}` or a map of nils
fabricates a shape that looks like real data, and it's a serialization/debug
helper — nobody calls it to decide what to render, so crashing surfaces the bug
where permissiveness buries it. (This is codex's warning against *mechanical*
nil clauses, applied where it actually bites rather than as a blanket rule.)

**Corroboration:** core's own generated demo template calls exactly the two
reported functions — `priv/templates/test_require_auth_live.ex:22-29` (`authenticated?`) and
`:29` (`anonymous?`). Safe there because the on_mount hook guarantees the assign,
but core ships sample code modelling the call pattern that raises in a host
layout. That is the Ratelia crash, shipped as an example.

**Done when:** seven nil clauses added; the invariant is documented in the
moduledoc; `to_map/1` still raises; a test asserts each nil-tolerant function
answers rather than raises; no existing caller changes behaviour.

**PR-B — consent-config 404.** Redesigned per B-I/B-II:
1. Always-present route; delegate to Legal when loaded, else **`204 No Content`**
   (never a JSON body — see B-II).
2. Emit `PHOENIX_KIT_PREFIX` + a consent flag from the **JS-sources compiler**
   into a generated globals file, so new bundles skip the request entirely and
   custom-prefix hosts stop guessing. No layout edit, no `update` backfill.
3. `cache-control: no-store` on the endpoint (unanimous panel point) — a cached
   "disabled" would outlive installing Legal.
4. Test against an **old vendored bundle**, not just the new one.
5. ⚠️ **BLOCKER found in final sweep — the stub collides with Legal.**
   `phoenix_kit_legal` defines **`PhoenixKitWeb.Controllers.ConsentConfigController`**
   (`phoenix_kit_legal/lib/phoenix_kit_legal/web/consent_config_controller.ex:1`) —
   the *same* module name a core stub would need, which is why the route at
   `integration.ex:271` references `Controllers.ConsentConfigController` under a
   compile-time `Code.ensure_loaded?` guard (`:270`). An always-present core stub
   under that name would clash. **Design must be:** ONE controller in core that
   delegates to Legal when loaded and returns `204` otherwise — and
   `phoenix_kit_legal` **stops shipping its own controller** (or renames it).
   **This makes PR-B a two-repo change**; §G2's repo footprint says core +
   referrals only, and must be updated. Scope the legal-package half explicitly.
6. The prefix-global half needs a **host-layout fixture** — the compiler emits the
   generated file, but nothing here verifies a host page that predates the
   compiler actually loads it.

**Done when:**
- With the Legal module absent, a request to `/api/consent-config` returns
  **204** and the router does **not** raise `NoRouteError`.
- A test pins that the response body is empty — `{"enabled": false}` must not
  reappear, because old vendored JS turns it into
  `resetGoogleConsentMode()` (see §B-II). This test is the guard on a real
  privacy regression; label it so nobody "simplifies" it away.
- With Legal present, the route still resolves to Legal's controller unchanged.
- The endpoint sets `cache-control: no-store`.

**PR-C + PR-G — `mix phoenix_kit.update` deploy honesty. ✅ BOTH APPROVED.**

**Correction to the incoming report:** it asked for a `--yes`/`--migrate` flag.
**That already exists** — `update.ex:166` (`yes: :boolean`, `y:` alias),
`:710-716` explicitly overrides the non-interactive branch, documented at
moduledoc `:47`, `--help` `:794`, and `:853` ("For automated deployments, use the
--yes flag"). Two real residues remain.

**PR-C — the hint never mentions the flag.** In a non-TTY shell (`:718-723`) it
prints only `mix ecto.migrate`. One string.

**PR-G — it returns `:ok`, so the task exits 0 with a migration pending.**
`ssh host "mix phoenix_kit.update"` succeeds while leaving new code against an
old schema — silent drift in exactly the environment where you least want it.
Fix: `Mix.raise/1` (non-zero exit, clean message, no stacktrace) naming both
escapes, which folds PR-C's text into the same message.

*the maintainer, 2026-08-02: ship both. The drift PR-G reveals is worse than a red
pipeline — the pipeline going red is how they find out.*

### Two review precautions checked and DROPPED
- ❌ **"Don't fire during install / `gen.*` flows."** Verified: nothing invokes
  `phoenix_kit.update` from `phoenix_kit.install` or any `gen.*` task — the only
  matches are filename patterns in `gen.migration.ex`. It runs standalone, so
  there is no install flow to guard.
- ❌ **"Split `--yes` from `--force`"** (codex: `--yes` conflates "answer prompts"
  with "override safety conditions"). `check_migration_conditions/0`
  (`:1086-1100`) checks exactly two things: an app name exists, and
  `System.get_env("CI") || !System.get_env("TERM")`. Interactivity is
  **environment detection, not a safety property**, so `-y` overriding it is
  correct and a separate `--force` would guard nothing.

**CHANGELOG must say plainly:** a deploy that was silently succeeding with
pending migrations will now fail. That is the intended effect.

**Done when:** non-interactive + pending migration + no `-y` → non-zero exit and
a message naming both `-y` and `mix ecto.migrate`; with `-y` the migration runs
and exits 0; nothing pending → exits 0 unchanged.

**PR-D — iOS input zoom. ⏸️ DEFERRED approved — document, do not implement.**
Record it in core's `AGENTS.md` `## TODOs` section (the existing home for
"workspace-tracked items not ready for inline `# TODO` in `lib/`", alongside the
component-coverage and signed-file-URL entries), stating explicitly that we are
holding off until it is a problem for the kit itself.

**The finding is real:** Mobile Safari zooms the viewport when a focused input's
font-size is under 16px, so any kit app using `text-sm` inputs gets a jarring
zoom on every field tap on iPhone. Verified: **zero** `font-size` rules target
inputs in any shipped core CSS — nothing guards against it today. Reported by a
real user as *"clicking the where field did a weird zoom in."*

**Why holding off is the right call, beyond priority:** neither scope cleanly
solves the reported instance.
- **Scoped to kit-owned forms** — the natural boundary, given how much of this
  triage has been about the kit reaching outside itself. But the reported zoom was
  on **Ratelia's own review form** ("the where field"), not a kit auth page, so
  scoping would not have fixed the case that prompted it.
- **Global** (`input:not([type=radio]):not([type=checkbox]), select, textarea`)
  — fixes it, but is core restyling host markup at ≤640px, including forms a host
  deliberately sized.

So the honest answer is to document the pattern so hosts can apply it, and
revisit if a **kit-owned** form surface hits it.

**Ready-to-use snippet for the TODO entry** (cover `select` and `textarea` too —
Safari zooms on all three, not just `input`):

```css
@media (max-width: 640px) {
  input:not([type="radio"]):not([type="checkbox"]), select, textarea {
    font-size: 16px;
  }
}
```

**Trigger to revisit:** a zoom report on a kit-owned form (auth pages, admin
forms, the core form components) rather than a host-authored one.

**PR-AA — ❌ RETIRED 2026-08-02, absorbed into PR-M2.** Both halves moved:
the `store_file/2` docs bug (`:user_uuid` listed as a plain option while
`file.ex:258-267` requires it for non-system files) and the "local `public_url/2`
returns nil; files are served via the signed route" explanation are now PR-M2's
content, together with the security caveat about the signer. Kept as a stub so
the G1/G2 → destination mapping in §H still resolves.

**PR-AC — split the notifications permission. ✅ SCOPE EXPANDED.**
Was "gate the bell's View-all link"; now "decide what the `notifications`
permission means", because gating the bell on today's rule would make it
*consistent with the wrong rule*.

`notifications.ex:658-659` states it: *"Base `notifications` permission gates the
**personal** pages (My Notifications + Notification Settings)."* Verified — all
three tabs (`:661`, `:678`, `:690`) carry `permission: "notifications"` and all
three are personal. So notifications are **delivered** to any user, **reading
your own** needs a grant, and the **bell has no check at all**
(`notifications_bell.ex` has zero `scope`/`Permissions` references). A user can
receive mail they are structurally unable to read. Meanwhile the sidebar hides
the tab (`registry.ex:743`) while the bell's unconditional "View all"
(`notifications_bell.ex:187-192`) points straight at it.

Gating the bell on `notifications` — the original PR-AC — makes all three agree
but turns a dead link into a **silent black hole**.

**The split:** reading your own mail is not an administrative capability.

| Surface | Gate |
|---|---|
| Bell + own recent list | authenticated (bell only renders in admin chrome) |
| `/admin/notifications` — own inbox | authenticated |
| `/admin/notifications/settings` — own prefs | authenticated |
| Any all-users / moderation view | **`notifications` permission** |

The dead link then disappears **without a check**. The permission is not made
vestigial — it regains its real job: the all-users moderation page was
deliberately removed and its context API survives for the rebuild
(`Notifications.admin_list/1` `:426`, `admin_stats/0` `:710`).

**Cost:** a user with no grant currently sees no tab; afterwards they see their
own inbox. That is a fix (they were already receiving those notifications) but
it is user-visible — CHANGELOG line. Hosts that withheld the grant to hide
notifications entirely should use the `notifications_enabled` kill switch.

**Coupling:** under U1 more users reach admin chrome without holding
`notifications`, so the affected population grows. Land before that.

**Done when:** a user with no grant sees the bell, their recent list, a working
"View all", their own inbox and settings; no personal page requires the
permission; sidebar and bell agree for every scope; `notifications_enabled:
false` still hides everything.

**PR-AD — component primitives. ✅ REVIEWED 2026-08-02 — scope RESTORED after a
false alarm of my own making.**

### The namespace-colonisation claim was WRONG — retracted
Mid-review An earlier draft the kit "puts ~95 unprefixed component names into every host
LiveView's namespace" and that four collide with the Phoenix scaffold
(`button`, `flash`, `header`, `input`, + `icon`), so the quality fix was a
`pk_`-prefix migration. **Checking who actually receives the import killed that:**

- `core_components()` is unquoted into four surfaces (`phoenix_kit_web.ex:43,61,
  72,86`), so the ~95 names reach anyone doing **`use PhoenixKitWeb, :live_view`**
  — i.e. **core itself and the ~20 feature modules**.
- A **host app's** LiveViews do `use MyAppWeb, :live_view`. They receive
  **nothing** from the kit automatically.
- So NordSwitch's collision was **voluntary**: they explicitly imported
  `Components.Core.Button` to use it, and it clashed with the scaffold button
  they already had. Ordinary Elixir, solved by `except:`/`alias`.
- And the actual recipients (core + modules) have **no competing `button/1`**, so
  a rename would impose ceremony on consumers with no collision — including
  turning **2,610** `<.icon>` call sites into `<.pk_icon>` for zero benefit.

Idiom agrees: `Phoenix.Component` exports `link`, `form`, `focus_wrap`
unprefixed; Elixir's answer to clashes is `import ... except:`. `pk_link` exists
because `link/1` clashes with something **in scope by default** — a different
situation. 

I over-extrapolated the panel's "generic-name bomb" point from *helpers leaking
through an internal import* (`c88c0d33`, real — `phoenix_kit_posts` could not
compile) to *components in a namespace hosts never receive*. Not the same problem.

### What ships
1. **Fix `button/1`'s real defect** (`core/button.ex`): `variant` must **REPLACE**
   the default colour, not append. Today `"btn btn-primary phx-submit-loading:opacity-75"`
   is hardcoded (`:27`) and `class="btn-ghost"` leaves `btn-primary` in place —
   daisyUI ordering decides the winner.
2. **Add link rendering** (`<.link>` when given `href`/`navigate`/`patch`) and
   extend `rest`'s include list (`:18`, today `~w(disabled form name value)`).
3. **Add `size`.** Core's own docs already promise it — `table_default.ex:43,49`
   show `<.button size="sm" navigate={~p"/users/…"}>`. Neither attr is declared,
   so `navigate` is **silently dropped**: copy that documented example and you get
   a dead control. (Doc example, not a live call site — grok correct, zai wrong.)
4. **Vocabulary = the kit's own, not the scaffold's.** The scaffold's `variant` is
   `values: ~w(primary)` — a knob that cannot vary. The kit already has a real set
   at `pk_link.ex:112`: `~w(primary secondary ghost link outline)`. Match that.
5. **Literal class map, never interpolation.** `defp variant_class("ghost"), do:
   "btn-ghost"` per variant — the repo's established pattern, and `stat_card.ex:50-57`
   documents the rationale verbatim: *"the values are a fixed list because Tailwind
   scans SOURCE for literal class names; an interpolated class is invisible to it."*
   Document `class="btn-error"` as the first-class escape hatch.
6. **`class` becomes `:any`, not `:string`** (scaffold parity) or list-classes fail
   attr validation.
7. **`badge/1` primitive** (`variant` × `size`, caller-supplied content), six
   existing badges rebuilt on top. `status_badge/1` (`:221`) cannot serve — it
   derives colour from a fixed status vocabulary and text from the status string.
   ⚠️ "output unchanged" is a claim to **prove with golden HTML asserts**, not
   assert: `category_badge` is a `<div>` and the others `<span>`, and
   `user_status_badge`/`code_status_badge` have no `class` attr today — do not add
   passthrough that alters output.
8. **`form_actions/1`**: relax `cancel_to` from `required: true` (`:47`) and accept
   `cancel_click` (+ `phx-target`) or a `:cancel` slot. Needs an explicit
   precedence among the three so you never render two Cancels or a dead one.
9. **`formatted_number/1`**: `:decimals` / `:fixed`. Both `:grouped` and `:short`
   guard `when is_integer(number)` (`:49`, `:61`) and `:78` falls through to
   `to_string/1`, so `1234.5` renders `"1234.5"` ungrouped today.
   ⚠️ If `:grouped` also starts grouping floats that is a **behaviour change** for
   existing float callers, not purely additive — flag it.

### Documented, not renamed
A host adopting the kit's button writes `import MyAppWeb.CoreComponents, except:
[button: 1]` (or deletes its own). **The superset does NOT remove the collision** —
both reviewers, independently: the ambiguity is name + import, and no change to
the kit's body resolves it. My earlier "make it a superset so the collision goes
away" was wrong. Document the one-line host step honestly.

**Scale, for expectations:** 9 `<.button>` call sites in core, 10 across modules —
against **413** raw `class="btn …"` in core alone. This is a correctness and
docs-accuracy fix, not an adoption unlock. (One of the nine is inside
`<.simple_form>`, so effective reach is wider than the literal count.)

**Done when:** `variant="ghost"` produces no `btn-primary`; `<.button navigate=…>`
renders a link and the `table_default` documented example works; `size` is
declared; every existing call site renders byte-identically except the documented
example, which starts working; golden tests pin all six badges; a float renders
grouped with fixed decimals.

**PR-AE — `:hidden_admin_tabs` config. ✅ APPROVED 2026-08-02 (see K5).** Honoured inside the registry's
`init`, so hiding survives a restart — that is the point, not the ergonomics.
`Registry.unregister_tab/1` (`registry.ex:161`) mutates GenServer state and the
registry rebuilds from `AdminTabs.default_tabs/0` on init, so **any** supervisor
restart silently resurrects the hidden tabs mid-flight with no signal.
"I want this module's data but not its UI" is a general need (NordSwitch uses
`phoenix_kit_locations` purely as a data layer).

**Done when:** a configured tab id is absent after a deliberate `Registry`
restart, where `unregister_tab/1` alone would have let it return.

**PR-W — 🔒 referral oracle** (see SEC1). **Security; top item.** Ordered by what
actually buys security, which is *not* the report's order:

1. **CSPRNG for code generation** — `Enum.random/1` → `:crypto.strong_rand_bytes`
   in `phoenix_kit_referrals.ex:183`. One line, no API change, biggest single
   win. Existing codes keep working (stored, not derived).
2. **Rate-limit the referral check** — the real fix. Key on IP (the LV already has
   `user_ip_address`, `registration.ex:88`) and reuse `RateLimiter`'s shape. Must
   sit on the *validation* path: a bad code short-circuits before
   `Auth.register_user`'s limiter (`auth.ex:445`), so a failing code never
   reaches it today.
3. **Collapse the four error strings to one** ("That code can't be used") —
   closes the enumeration oracle. Keep the distinct reasons in `Logger.debug`.
4. **Validate on submit only** — this is PR-V; it fixes the premature "Referral
   code is required" nag. Per SEC1 it is a **UX fix, not a security fix**:
   `phx-submit` and `phx-change` are both websocket messages at the same rate.
5. ~~**Raise `@code_length` and the custom-code minimum**~~ — ❌ **DROPPED
   (project decision).** Referral codes are attribution, not credentials;
   operators should be free to pick short/memorable codes. Technically sound too:
   the 25-bit space only mattered because the oracle was *unthrottled* — once
   step 2 lands, 33.5M keys at a few attempts/min/IP is already unbreakable.
   `@code_length 5` and `validate_length(:code, min: 3, max: 50)` stay as they are.

**Cross-repo footprint is now trivial:** the four error strings live in **core**
(`registration.ex` + `magic_link_registration.ex`), so steps 2, 3 and 4 are all
core-only. `phoenix_kit_referrals` gets **exactly one line** —
`phoenix_kit_referrals.ex:183`. State the merge order in the PR bodies; no shims.

**Residual risk accepted with the drop:** an operator running invite-only with a
3-char custom code has ~46k of space. Rate limiting is the control there, not
entropy. Worth one sentence in the referral admin UI, not a validation change.

**Done when:**
- `generate_random_code/0` draws from `:crypto.strong_rand_bytes`; a test asserts
  the alphabet and length are unchanged so existing codes stay valid.
- A test drives N+1 validations from one IP and asserts the N+1th is refused **on
  the validate path**, proving it never reaches `register_user`'s limiter.
- A test asserts non-existent / inactive / expired / limit-reached all return the
  **same** message, and the distinct reason still reaches `Logger.debug`.
- Blank-and-required produces **no** error during validate and **does** error on
  submit, in **both** `registration.ex` and `magic_link_registration.ex`.
- `mix precommit` green in both repos.

**PR-Y — 🔒 invite-only actually holds. ✅ DESIGN SETTLED.**
Enforcement is a **post-signup access gate**, NOT per-path creation blocking.
Accounts may be created by any means; an unsatisfied user is parked on an
"enter your referral code" screen.

### Why the gate — and a correction to the earlier draft
An earlier draft for creation-time blocking on the strength of a 2-AI panel. **Two of the
three objections did not survive checking their preconditions:**
- ❌ *"First OAuth signup becomes a confirmed Owner with no code."* True that
  `auth.ex:469` runs `ensure_first_user_is_owner/1` and `oauth.ex:192`
  auto-confirms — but `referral_codes_required` has **no default in core**; it is
  set via the referrals admin UI, which needs an admin, which needs a first user.
  Invite-only cannot be on before the first user exists. Unreachable.
- ❌ *"The gate enables email squatting."* `do_register_user/1` (`auth.ex:463-466`)
  already inserts with no `confirmed_at`, so password registration creates an
  unverified row for any address on **every** install today; OAuth and magic-link
  both require real mailbox/provider control. The gate returns invite-only
  installs to the exposure every normal install already has.
- ⚠️ *Oracle amplification* (minting accounts as fresh rate-limit buckets) is real
  but bounded by the rate limiting below, which ships anyway.

What remained were **requirements**, not objections.

### What ships
1. **The gate.** One predicate `access_satisfied?(scope)` folded into the TWO
   existing choke points — `confirmation_gate/2` (`auth.ex:1827-1838`) and the
   inline `email_confirmed?` checks in the 5 `on_mount` hooks + 2 auth plugs.
   **Not 11 new sites.** ⚠️ Key it on an **independent** flag, never
   `confirmed_at`: OAuth sets that (`oauth.ex:192`), so a gate keyed on it opens
   immediately.
2. **`/users/referral` parked screen** — it and log-out are the only routes an
   unsatisfied user can reach (mirror the `/users/confirm` allowlisting).
3. **Per-user state:** `custom_fields["referral_satisfied_at"]`. No migration —
   same pattern as `preferred_locale` and the notification-channel config.
4. **Rate limiting** on the OAuth callback and magic-link registration, keyed on
   `Plug.Conn.get_peer_data/1` (**not** `conn.remote_ip` — core's rule).
   ⚠️ **Corrected in final sweep:** the earlier claim that
   `check_magic_link_rate_limit/1` has "zero real callers" was **wrong** — the
   magic-link **login** path does throttle (`magic_link.ex:95`). What is actually
   unthrottled is **`MagicLinkRegistration.send_registration_link/1`**
   (`magic_link_registration.ex:28`, no limiter) and the **OAuth callback**. So
   the limit must be placed on `send_registration_link/1` specifically — not on
   "magic-link registration" generically — or dropping M1's request-step check
   leaves an unthrottled registration-mail path open.
5. **Hardening on the code screen** (inherits PR-W): submit-only not
   per-keystroke, ONE generic failure message, per-IP **and** per-account limits.
6. **Grandfathering — operator-controlled.** `referral_grandfather_existing`
   (**new, default `true`**): on flip-on, existing users are marked satisfied so
   nothing breaks; set `false` and every existing user hits the screen.
   `referral_required_enabled_at` recorded at flip-on so "existing" is evaluated
   once. 
7. **Exemption — permission-based, not role-based.** Anyone satisfying
   `Scope.holds_all_enabled_permissions?/1` never parks — the same predicate
   `enforce_admin_view_permission` uses; role-agnostic per the workspace
   principle, satisfied by Owner by construction. **Hard exemption regardless of
   the grandfather setting**, or `grandfather_existing: false` on an install
   whose codes are all used locks the operator out with no recovery.
8. **Org invitation satisfies the requirement.** A valid, email-scoped pending
   invitation marks the account satisfied. Both reviewers agreed; the caveat is
   that it makes org admins de-facto admission issuers — acceptable because
   invitations are email-bound. Without it the banner at
   `registration.html.heex:13-19` is a dead end under invite-only.
9. **Prune job** for accounts that never satisfy (mirror `PruneWorker`), so
   "registered" keeps meaning "admitted".

### Explicitly dropped
- ❌ **Creation-path blocking anywhere** — superseded by the gate.
- ❌ **Magic-link request-step validation.** Under the gate the account is created
  and parked regardless, so it only prevented wasted emails — which (4) handles.
  
- ❌ **A "re-verify all users" admin sweep.** (6) covers the flip-on case; a
  retroactive sweep is rarer. Add later if wanted.

**Done when:** with `referral_codes_required` on — a user created via OAuth,
magic-link or password lands on `/users/referral` and can reach nothing but
log-out; a valid code unlocks and stays unlocked; a user with full access never
parks; `grandfather_existing: true` leaves pre-existing users untouched and
`false` parks them; a valid org invitation satisfies without a code; the code
screen is submit-only, generic on failure, rate-limited per IP and per account.

**PR-X — 🔒 magic-link settings actually gate. ✅ APPROVED.** (see M3.) **Scope doubled after
review: the LOGIN half has the identical bug, and is the more serious one.**

| Setting | Read by today | Gates the route? |
|---|---|---|
| `magic_link_registration_enabled` | `registration.ex` + `.heex` (button), admin toggle | ❌ |
| `magic_link_login_enabled` | `login.ex:39` (button), `user_dashboard_nav.ex:504` (nav), admin toggle | ❌ |

`magic_link.ex` (the login LV) reads its setting **zero** times — `mount/3` only
calls `Auth.maybe_redirect_authenticated/1`. So `/users/magic-link` stays fully
functional with the setting off. Disabling passwordless login is a plausible
security-posture decision; the admin sees the button vanish and the route stays
open.

**Also gate the token-verify controller** (`magic_link_verify.ex`,
`GET /users/magic-link/:token`) — it reads neither setting, so in-flight links
keep working after both LVs are gated. **The project decision: gate it.** Turning
passwordless login off means "no more magic-link sign-ins", not "no new ones from
today"; tokens are short-lived so the blast radius is small.

Five call sites: 2 registration LVs, 1 login LV, 1 verify controller (branching
on which flow the token belongs to). The pattern already exists —
`allow_registration` — it just needs applying consistently.

**Done when:** with either setting off, its LV **and** its token route redirect
rather than render, asserted by tests. With both on, all four paths work.

**PR-AB — `return_to` trailing `?`. ✅ APPROVED.**
`auth.ex:2026`: `query = if uri.query, do: "?" <> uri.query, else: ""`. `""` is
truthy in Elixir, so a URI whose query is the empty string yields a bare `"?"`.
Verified by running it: `nil` → `""` ✓, `""` → **`"?"`** ✗, `"a=1"` → `"?a=1"` ✓.
The `%URI{}` comes from `get_connect_info(socket, :uri)` — the browser's
`window.location.href`, which carries a bare `?` after a fieldless GET submit, a
`push_patch` with empty params, or a typed trailing `?`; once captured it can
round-trip back into the URL and self-perpetuate.
**Fix:** `if uri.query in [nil, ""], do: "", else: "?" <> uri.query`.
**"Harmless" verified, not assumed:** `Routes.auth_page?/1` (`routes.ex:158`)
does `String.split(["?", "#"], parts: 2) |> hd()` **before** comparing, so a
trailing `?` cannot sneak an auth page past the self-loop guard; `local_path?/1`
still accepts it. Genuinely cosmetic.
**Sweep: one occurrence.** Every sibling query-builder guards correctly —
`oauth_buttons.ex:101` (`is_binary/1` + `local_path?/1`), `qr_login.ex:108`
(`query == []`), `media_browser/embed.ex:175` (`qs == %{}`), `routes.ex:116`
(`local_path?/1`), `pagination.ex:331` (explicit `query_string == ""`).
Good candidate to ride along with another `auth.ex` change.
**Done when:** a connect URI with `query: ""` produces a `return_to` with no
trailing `?`; well-formed URLs are unchanged.

**PR-Z — sitemap exclusions stop being a one-way door** (see G3/G4/G5).
Highest non-security item. Three parts.

**(a) Exclude patterns EXTEND the defaults**, matching the sibling
`sitemap_protected_pipelines` which already does (`router_discovery.ex:218`).
Pair with an explicit `:replace` escape hatch, since installs that saved a full
list would now get defaults re-added.

**(b) V160 — widen `phoenix_kit_settings.value` from `varchar(255)` to `text`.**
✅ Authorised a core migration. The read path already works —
`get_exclude_patterns/0` (`router_discovery.ex:373`) already JSON-decodes a
binary — so `value_json` was never needed; the only blocker is column width.
**G6, found while scoping:** `setting.ex:187,196` validate `:value` at
`max: 1000` while `v03.ex:23` created it as `varchar(255)`, so *any* setting
between 256 and 1000 chars passes the changeset then dies with a raw Postgrex
error. V160 fixes the whole class. V159 is released, so this opens a **new
V160**; must be prefix-safe, set `COMMENT ON TABLE phoenix_kit IS '160'` in
`up/1` and carry a correct `down/1`. Metadata-only in Postgres — no rewrite,
no long lock.

**(c) Root-mount the sitemap — narrowly. ✅ Decided 2026-08-01.** Three layers
answer these paths and core is **last**: `Plug.Static` runs in the endpoint
before the router (stock `static_paths/0` already lists `robots.txt`), then host
routes are declared before `phoenix_kit_routes()` (parent: host scopes at 20/66,
kit at **87**), then core. So root-mounting cannot hijack anything — but it is a
weak guarantee and nothing tells the host which layer won.
- **Root-mount `/sitemap.xml` (+ `sitemaps/`, `.xsl`, `assets/sitemap`) ONLY when
  `url_prefix != "/"`.** A root-installed host (NordSwitch runs `url_prefix: ""`,
  normalised at `integration.ex:134`) already serves it from the existing scope;
  a second route would define the same path twice. No new setting — routes are
  compile-time, `sitemap_enabled` is runtime and gates content.
- **Do NOT emit `robots.txt`** — host policy, and Plug.Static wins anyway.
  Document *add `Sitemap: https://…/sitemap.xml` to your robots.txt*.
- **Add a `mix phoenix_kit.doctor` check** reporting which layer serves
  `/sitemap.xml` and whether robots.txt references it. **This fixes the reported
  complaint** — the original failure was not knowing a re-declaration was needed.
- **Document the manual re-declaration**, including the no-alias scope gotcha
  (`scope "/" do` without an alias, or the controller resolves as
  `HostWeb.PhoenixKit.…`).

Also add explicit `/file`, `/tiles`, `/api/files` patterns to the defaults (G5)
so they never depend on `^/phoenix_kit` alone surviving.

**Done when:** a test saves and reloads the full 30-pattern default list
(~436 chars) byte-identically — it fails today and is what proves V160; a
256–1000 char value returns a changeset error, never a raw Postgrex error; with
the setting customised the built-in defaults still apply and the asset routes
stay excluded; V160's marker round-trips and the prefix-migration oracle passes.

**PR-Q — DELETE the demo scaffolding. ✅ approved.** Was "gate it behind
`--demo`"; digging showed the generator has no remaining purpose.

### Evidence it is vestigial
1. **Nothing references them but the installer** — `phoenix_kit_templates.ex`
   (template readers), `router_integration.ex:417-427` (route block),
   `install/demo_files.ex:43-45` (file copies). No tests, no other code.
2. **Zero documentation anywhere** — no guide, README or `dev_docs` mentions
   `/test-current-user` and friends. They are written into every host and never
   explained. The install notice (`lib/mix/tasks/phoenix_kit.install.ex:499`) lists them with no context.
3. **They date from `aea0c277` "Initial commit of version 1.0.0"** — original
   scaffolding from before the module system existed, not a considered addition.
4. **`mix phoenix_kit.update` never touches them** (zero `demo` references) —
   install-only, so they are frozen at whatever v1.0.0 emitted, never refreshed
   and never removed.
5. **`phoenix_kit_hello_world` already owns this job, properly** — its moduledoc:
   *"A minimal PhoenixKit plugin module — use this as a starting point for your
   own… demonstrates every required and commonly-used optional callback."*
   Installable, versioned, tested, documented.
6. **Real hosts have already deleted them.** Of four checked, only
   `phoenix_kit_parent` (the disposable dev host) still has the routes — `topp`,
   `farm_keeper_new` and `polymarket_bot` all stripped them by hand. Every real
   product removed them; that manual cleanup is exactly what the doctor check
   should prompt.

### What ships
- **Delete** `PhoenixKit.Install.DemoFiles`, the three `priv/templates/test_*_live.ex`,
  their three reader functions in `phoenix_kit_templates.ex`, the
  `generate_routes_code/1` demo block (`router_integration.ex:409-431`), and the
  `lib/mix/tasks/phoenix_kit.install.ex:142` call.
- **Drop them from the install completion notice** (`lib/mix/tasks/phoenix_kit.install.ex:499`).
- **KEEP the doctor check** — `check_demo_routes/0` in `mix phoenix_kit.doctor`,
  detecting the three modules/routes in a host and reporting "remove before
  production". This is the only piece with lasting value: it is the one part that
  reaches hosts that already have them, and deleting the generator does nothing
  for those.

### Why deletion beats a `--demo` flag
A flag keeps three undocumented, unmaintained, unversioned LiveViews alive for a
job `hello_world` does properly — and the evidence says nobody wants them. The
only thing lost is a post-install "is auth wired up?" smoke test, which
`phoenix_kit.doctor` covers more honestly; `/users/log-in` rendering is a better
signal than a page whose own badge reads `ALWAYS ACCESSIBLE`.

### Incidental
The deleted `test_require_auth_live.ex` called `Scope.authenticated?/1`
(`:22,25,28`) and `Scope.anonymous?/1` (`:29`) — the exact two functions PR-A
fixes. Core was shipping sample code modelling the call pattern that raises in a
host layout. Deleting it removes that bad example; PR-A still fixes the real bug.

**Done when:** a fresh install creates no `test_*_live.ex` and no demo routes;
the completion notice does not mention them; `mix phoenix_kit.doctor` reports
them on a host that still has them, with removal instructions.

**PR-R — auth pages stop rendering inside the host's `Layouts.app`.**
⚠️ **Corrected 2026-08-01 by a code-grounded panel (grok + zai).** My proposed
`auth_layout` config key is **withdrawn** — it rested on a false premise and an
impossible back-compat story.

### Two corrections to the earlier draft
**1. "The kit has its own brandable layout" was WRONG.**
`render_with_phoenix_kit_layout/1` (`layout_wrapper.ex:926-935`) emits only
`<.flash_group>` + `<.invitation_banners>` + `render_slot(@inner_block)`. It is
**not** a document layout — no `<html>`, head, assets or CSRF. Those come from
the **host's root layout** either way, because `Integration` never calls
`put_root_layout`. The branding (logo + title from settings) comes from
`auth_page_wrapper.ex:35-40`, which runs on **both** paths. So the change does
exactly one thing, and it should be described honestly: **stop wrapping auth
pages in the host's `:app`.**

**2. The back-compat story was self-contradictory.** Both reviewers, independently:
you cannot have *"auth defaults to the kit path"* **and** *"existing installs are
unaffected."* The absent-key default decides it, and `mix phoenix_kit.update`
**never writes layout config** (it's install-only, `Install.LayoutConfig`), so no
existing host would ever get the key written. If absent ⇒ kit path, every host
flips on a plain `mix deps.update`. Pick one. Both reviewers said: pick the
intentional, documented change — not a key pretending to be invisible.

### ✅ RESOLVED: the bypass is UNCONDITIONAL (panel-verified 2026-08-01)
The open question was conditional (bypass only when no layout configured) vs
unconditional. **Conditional is a provable no-op**, confirmed by both reviewers:

- `Install.LayoutConfig.detect_app_layouts/1` (`layout_config.ex:42-49`) resolves
  the host's Layouts module and writes `layouts_module:` + `phoenix_version_strategy: :modern`.
  The detector checks `FooWeb.Layouts` then `Foo.Layouts` — exactly what
  `mix phx.new` emits, so it succeeds for essentially every conventional host.
- `get_layout_config/0` then returns `{layouts_module, :app}` — **never nil**.
- And when it *is* nil, auth is **already** on the content-only path. So
  "bypass when nil" changes nothing for anyone, **including the reporting host**
  (verified: their config is `layouts_module: LangustWeb.Layouts`).

⚠️ **Correction to my phrasing:** `render_with_phoenix_kit_layout/1` is **not**
dead code. It is live for (a) core's own dev/test (core's config sets neither
key), (b) hosts where install detection failed — umbrella apps, renamed web
namespace, (c) the `apply_host_layout/3` `UndefinedFunctionError` rescue
(`:802-804`). It also has **zero test coverage**. "Dead for any host where
install detection succeeded" is the accurate claim.

**Precedent that makes this uncontroversial:** admin ALREADY does exactly this —
`render_admin_with_parent/1` is content-only whenever a layout is configured.
Auth is the outlier. This makes auth consistent with admin, not novel.

### The escape hatch — opt INTO chrome, default bypass
    config :phoenix_kit, auth_uses_host_layout: true   # restore host Layouts.app on auth

Both reviewers independently proposed this shape and both distinguished it from
the `auth_layout` key rejected earlier: **that one changed the default as a side
effect of adding a knob** (hence the self-contradictory back-compat story); here
the unset state simply *is* the new behaviour, and setting it is an explicit,
documented opt-back-in. Ship as a **breaking default change with a CHANGELOG
note — do not claim back-compat.**

### Does bypassing actually give a clean surface? Yes — for conventional hosts
Two layers, and `LayoutWrapper` controls only one:
- **Root** (document shell) is set by the **host's** router `put_root_layout`.
  Core's chrome-bearing root (`navbar` `:61`, `<main class="py-8">` `:177`,
  `max-w-7xl` `:178`) runs **only in core's standalone app**. It does **not**
  wrap host auth.
- **App** (chrome) is what gets bypassed. On a fresh `phx.new` host the logo /
  version / off-site links live in `app.html.heex`, and root is a bare shell.

⚠️ **Therefore "clean auth" must be asserted against a HOST-shaped fixture, not
core's own app** — core's dev/test app still has its own root chrome, so an
assertion written there would fail for the wrong reason.
Hosts that put nav in their *root* keep it and need the escape hatch.

### ✅ The design
**No new *layout* key** (one boolean opt-in only). Auth pages always take the content-only path; the existing
`layout: {Mod, :fun}` stays as the host's escape hatch for anyone who genuinely
wants their chrome on sign-in. Ship as a documented behaviour change with a
CHANGELOG line.

**Where to intercept — this is the load-bearing decision.** zai flagged that an
`auth_page?/1` predicate would have to enumerate every auth route (login,
register, reset, confirm, magic-link, QR, OAuth callbacks, locale-prefixed
variants) — miss one and it silently keeps the host layout, the same
"eleven sites" hazard core already warns about for confirmation gates.

**Use the component, not a route list.** Audited: **10 of 11 auth pages already
render through `auth_page_wrapper`** — the exception is `qr_login_confirm.html.heex`,
which calls raw `LayoutWrapper.app_layout`. So:
1. `AuthPageWrapper` takes the content-only path directly instead of delegating
   to `LayoutWrapper.app_layout`.
2. Move `qr_login_confirm` onto `AuthPageWrapper` (it should be there anyway —
   it is an auth page).

That converts "keep a route list in sync forever" into "auth pages use the auth
component", which is checkable and self-maintaining.

### Scope corrections
- ❌ **Admin is NOT affected** — zai claimed the Phoenix chrome survives on every
  admin page; it does not. `render_admin_with_parent/1` (`:835-845`) emits its
  own `<main>` + flash + slot and never calls the host's `:app`. (grok correct,
  zai wrong; verified.)
- ⚠️ **Residual Phoenix branding survives regardless.** The host's stock
  `root.html.heex` still carries `suffix=" · Phoenix Framework"`. Skipping `:app`
  does not remove it, so the bug only half-dies unless the installer/docs also
  address the root layout title. Worth a doc line.
- ⚠️ **Things auth loses with the host `:app`:** the theme toggle, and anything a
  host wired at app level rather than root — cookie-consent banner, analytics,
  CSP nonce, marketing header/footer. Mostly desirable for auth, but a host that
  put a consent banner in `:app` would lose it on login/register. Call it out in
  the CHANGELOG; the `layout:` escape hatch is the answer for them.
- 🔗 **Feeds PR-S.** `auth_page_wrapper.ex:69`'s `min-h-[calc(100vh-4rem)]` /
  `-my-8` hacks exist *because* of the host chrome wrap. Once auth stops nesting
  inside `:app`, those become vestigial — so PR-R and PR-S should land together
  and the CSS should be re-derived, not patched.

### ⚠️ Two unflagged breaks that must ship with it
1. **The auth background geometry is calibrated to the chrome being removed** —
   `auth_page_wrapper.ex:69`'s `calc(100vh-4rem)` / `-my-8` / full-bleed negative
   margins all assume the host-app parent. Bypass without fixing them and the
   background mis-sizes. This region is **already brittle**: commit `bcb93b39`
   is literally *"Fix auth page background breaking footer and page layout"*.
   **PR-S is not optional — it ships with PR-R or PR-R regresses.**
2. **Host app-layout globals stop reaching auth.** `render_with_phoenix_kit_layout/1`
   emits only flash + banners + slot — no `phoenix_kit_globals`, no asset links,
   no consent script. Core puts those in *root* (`root.html.heex:50-53`) and a
   host that copied that is fine; a host that put `phoenix_kit_globals`
   (CSRF/theme init) or a consent banner in their **app** layout loses it on
   auth only. Latent, host-dependent, invisible in core's own tests — needs a
   CHANGELOG callout.

**Done when:** a fresh `mix phoenix_kit.install` on a stock `phx.new` app shows
no Phoenix logo, version or off-site links on `/users/log-in` or `/users/register`;
`qr_login_confirm` renders through `AuthPageWrapper`; a host setting
`layout: {Mod, :fun}` still gets its own chrome on auth; admin rendering is
byte-identical.

**PR-S — auth wrapper viewport math. ✅ REVIEWED 2026-08-01; ships WITH PR-R.**

`auth_page_wrapper.ex:69` carries four hardcoded compensations:
`min-h-[calc(100vh-4rem)]` · `-my-8` · `w-[100vw]` · `-mx-[calc(50vw-50%)]`.

⚠️ **They are not arbitrary — they compensate for CORE's own root layout**
(grok, verified): `<nav class="navbar">` (`layouts/root.html.heex:61`) ≈ the
4rem, `<main class="py-8">` (`:177`) = the `-my-8`, `<div class="max-w-7xl
mx-auto px-4">` (`:178`) = what the full-bleed escapes. They are correct there
and break only when a host substitutes its own root. That kills my first
justification ("after PR-R the body is bare") — PR-R does not remove core's root
shell, only the host's `Layouts.app`.

### The panel's verdict on the proposed replacement
- ✅ **Width: `w-[100vw]` → `w-full`. Correct, unconditional, ships regardless of
  PR-R.** zai's mechanism is sharper than mine: the host root sets
  `[scrollbar-gutter:stable]` (`root.html.heex:5`), so the gutter is *always*
  reserved and `100vw` overflows by exactly the gutter width even with no
  scrollbar — the reported 8px (clientWidth 1265 vs scrollWidth 1273). `w-full`
  is a percentage of the containing block, gutter-excluded.
- ❌ **`min-h-screen` — BLOCKED by both reviewers.** It is `100vh`, a viewport
  unit: the same bug class. Nested in any padded ancestor the vertical scrollbar
  returns, and on mobile `100vh` is the *large* viewport so the card bottom sits
  behind the URL bar.
- ✅ **Delete `-my-8`** — also fixes a latent top-clip on short viewports.
- ✅ **Height: `min-h-full`** on the wrapper, with PR-R's render path owning a
  `min-h-dvh` ancestor. `min-h-full` is a percentage of the containing block, so
  it can never exceed it and never cause a scrollbar. If a host re-nests and the
  ancestor has no height it degrades to the card top-aligning — the right library
  failure mode; a forced scrollbar is not.
- ⛔ **Never `scrollbar-gutter`** — core deleted every such override 2026-07-12
  and the standing rule is never to re-add them. (The host's own root setting it
  is host-owned and out of scope.)
- Keep the injected `<style>` (`bg_style_tag`) and the flash group **inside the
  LiveView tree** — core already encodes that lesson for flash at
  `layout_wrapper.ex:920-925`.

**Why it ships with PR-R:** the compensations exist *because* of the chrome PR-R
removes, and that region is already brittle — commit `bcb93b39` is literally
*"Fix auth page background breaking footer and page layout."* Landing PR-R alone
regresses it.

**Done when:** on a host layout with a footer and non-default padding,
`/users/log-in` has **neither** scrollbar and `document.scrollWidth ==
clientWidth`; no `scrollbar-gutter` anywhere in core; the card still centres on a
short viewport and top-aligns rather than clipping when it overflows.

**PR-E — locale source becomes a setting. ✅ FINAL DESIGN, 2026-08-01.**
Reviewed by a code-grounded panel three times; this is the third and agreed
shape. grok + zai both: *"genuinely better"* than the resolver/fan-out design.
(gemini hit its quota; vibe timed out.)

### The reframe that shrank this
It is a **wrong-value** bug, not a wrong-mechanism bug. phoenix_kit is the app's
skeleton, so it *should* own locale distribution. Its only fault is deciding
wrong for hosts whose locale doesn't live in the URL. Make it resolve the right
value and the existing global write becomes benign — the host's backend, the
host's domain code, and all ~20 module backends read the correct locale through
the mechanism that already works.

**This deletes the entire previous design:** no `PhoenixKit.I18n` module, no
`gettext_backend/0` callback, no CI exhaustiveness test, no fan-out, no
per-backend shadowing invariant, no ownership flag, no out-of-tree version skew.

### The change
ONE setting governing where the kit reads the locale **when the URL carries no
locale segment**. Joins the existing `default_language_no_prefix` pattern
(`languages.ex:107`).

```
locale_source: :default (default, = today) | :session
```

- URL `/:locale` present → **always wins**. Admin pages unchanged; preserves the
  URL-authoritative fix at `auth.ex:1014-1022`.
- No URL locale → consult the configured source instead of jumping to the site
  default.

**Scope cut on panel advice — two proposed modes are dropped:**
- ❌ `:host_owned` — **broken by the process boundary** (zai). The host sets the
  locale in the HTTP request process; the LiveView mounts in a *different*
  process with a fresh dictionary. "Read what the host set, write nothing"
  leaves every LV at the app default and desyncs the module backends. It either
  collapses into `:session` or it doesn't work. No third option.
- ❌ `:user_preference` — **undefined for anonymous visitors**, who are the
  majority of Ratelia's public prefixless traffic. It would keep the bug for
  exactly the pages that motivated the work. (Also: it was deliberately dropped
  for routing at `auth.ex:2120-2132` over plug/LV desync.) Revisit only as an
  authed-only refinement.

### ⚠️ The implementation trap — flagged independently by both reviewers
**"Nothing else changes" is true about the mechanism and FALSE about the sites.**
The session read must be threaded through **all three** no-URL fallback paths:

| Site | What it is |
|---|---|
| `auth.ex:1023` | `mount_phoenix_kit_current_scope` — LV mount |
| `auth.ex:887` | `maybe_update_locale_from_params/2` — the `handle_params` hook |
| `auth.ex:2119` | the HTTP plug path |

Fix only the mount and **`:session` is cosmetic**: correct on first render, then
the first in-page `push_patch` snaps back to default. Both reviewers called this
the single most likely way the change ships and fixes nothing. It is also how
the `auth.ex:2120-2132` desync bug (HTTP renders German, LV snaps to English)
returns wearing a different hat.

### Sticky-locale: which bug returns, and which doesn't
zai's distinction, and it's the precise answer:
- **Self-stickiness** (`auth.ex:1014-1022` — the *kit* stashed a locale on a
  prefixed visit, then inherited it forever): does **NOT** return, because the
  key is host-authored and written only on an explicit user choice.
- **Plug/LV desync** (`auth.ex:2120-2132`): **does** return unless all three
  sites above are threaded. That is the whole risk.

### Host integration cost — larger than "just write a session key"
1. **LiveViews cannot write the session.** It needs a controller/plug
   `put_session/3` + redirect. A host switcher built as a LV `push_patch` writes
   nothing and `:session` reads `nil` forever.
2. **Login wipes it.** `renew_session/1` calls `clear_session()`
   (`auth.ex:232-237`) — its comment even says locale is deliberately not kept
   in session. The host must re-write the key post-login or the visitor reverts
   to English at sign-in.
3. **The kit's own switcher is URL-based** — `push_navigate` to a locale-prefixed
   URL (`auth.ex:799-809`). A prefixless host has no `/et/…` public route, so it
   must run its own switcher and suppress the kit's.
4. Session is a **connect-time snapshot** in LV, so a switch must navigate or
   reload — the kit's switcher already `push_navigate`s.

### Pin exactly one session key
`notifications_bell.ex:37` **already** reads `session["locale"]` for link
generation. So today a host writing that key gets Estonian *links* and English
*text* — a pre-existing half-honour. Pin one key, reconcile the bell, and
validate it (unknown value → fall through, never `nil → default` silently).

### Done when
- With `locale_source: :session` and a session locale set, a prefixless host page
  renders that locale **on mount, after a `push_patch`, and on the dead HTTP
  render** — the three-site test is the acceptance criterion.
- With `locale_source: :default` (unset), behaviour is byte-identical to today at
  all six write sites.
- A URL locale segment still wins over the session in both modes.
- Bell links and rendered text agree.

---

**PR-E2 — embedded LiveViews get a locale (independent, ship regardless).**
`assign_embedded_current_user/2` (`auth.ex:962-974`) assigns user + scope and
never touches locale. `live_render` children are separate processes
(`phoenix_component.ex:2173`), so they inherit nothing — every embedded module
LiveView renders in the site default today, regardless of the host's language.
Fix: read the pinned session key there, mirroring how `current_user_uuid` is
already threaded.

Precedent exists downstream: `PhoenixKitProjects.Web.Helpers.maybe_put_locale/1`
(`helpers.ex:370-375`) already does exactly this — and writes the **global** slot
too, so **core stopping is not sufficient**; that module re-clobbers a host on
every embed. It is the only module doing so (workspace sweep), but it means
PR-E is not core-only.

**Done when:** an embedded module LV rendered from a host page in Estonian
renders Estonian, and `phoenix_kit_projects` no longer needs its own helper.

**PR-F — settings cache staleness. ✅ REVIEWED 2026-08-02 — TTL only, PubSub dropped.**

### The approved-in-principle version would have caused an outage
An earlier draft "add `ttl:` — one line". **`get_settings_cached/2` (`settings.ex:382-394`)
does not fill on miss**: it calls `Cache.get_multiple/3` and maps the result, so a
key absent from the cache is simply absent from the returned map — only the
explicit `:__setting_does_not_exist__` sentinel maps to a default. Add a TTL and
after the first expiry wave, **OAuth credential helpers and the user-list date
formats silently read `nil`/defaults**. Compounding it, `put_multiple` stamps one
**shared `expires_at`**, so everything expires simultaneously.

**So bare `ttl:` is not a one-line fix; it is a one-line outage.**

### Two more corrections to the earlier draft
- **The LiveView handler is a NO-OP.** `live/settings.ex:158-160` is a catch-all
  `{:noreply, socket}` commented *"future-proof"*. My claim that the LV "already
  handles" `{:setting_changed, …}` was wrong — it subscribes and does nothing, so
  wiring the broadcast alone changes nothing user-visible.
- **The reported symptom is probably not a cache bug.** `get_project_title/0`
  (`:265`) calls **uncached** `get_setting/1` — DB every call. The stale title
  after a `mix run` script was most likely **LiveView assign staleness** (the
  layout freezes `@project_title` at mount). Corroboration that someone knew:
  `get_logo_uuid/0` is deliberately uncached *"so a logo change shows
  cluster-wide without a restart"* while `get_site_icon_uuid/0` is cache-backed.

### What ships
1. **PREREQUISITE — make the batch path safe.** Either give `get_settings_cached/2`
   a miss-fill (batch-query absent keys, `put_multiple` them), or re-warm on a
   timer via the existing `handle_info(:warm_cache, …)` (`cache.ex:640`).
   **TTL must not ship without one of these.**
2. **Then TTL** on the settings child (`supervisor.ex:52-56`). Suggested
   **`300_000` (5 min)**: settings are admin-rare writes, and it bounds the
   `mix run` / unclustered class without thrashing. The "hot path" worry was
   overstated — every `Cache.get` is already a `GenServer.call`, not bare ETS.
   Consider jittering `expires_at` to avoid the shared-expiry stampede.

### ❌ PubSub wiring DROPPED
`PubSub.Manager` is hardwired to **`Phoenix.PubSub.PG2`** (`pubsub/manager.ex:51`),
so it only reaches nodes joined by **distributed Erlang** — not multi-node
Fly/k8s/Heroku without clustering, and not `mix run`. Given a TTL floor it buys
near-instant propagation in exactly one topology, while adding a subscribe/warm
race (invalidate-then-warm can reinsert a pre-write snapshot), self-delivery, and
a second invalidation path. The dead `Events.broadcast_setting_changed/2` was
scoped for **multi-admin live UI**, not cache coherence — that is a separate
feature needing a real `handle_info`, not this. Reversible if wanted later.

### ❌ LISTEN/NOTIFY still out
Needs a dedicated non-pooled connection (PgBouncer transaction mode breaks it,
and core's doctor has a `check_pgbouncer`), NOTIFY fires on commit but the Ecto
sandbox never commits, and a lossy listener needs a full flush on reconnect.

**Done when:** a batch read after expiry returns real values, not `nil`/defaults
(the regression test that proves the prerequisite); a setting written by a
separate BEAM is visible to the web node within the TTL without a restart; no
`Cache.get` path regresses on a cache miss.

**PR-H — declarative custom permission keys. ✅ DECIDED 2026-08-02.**
`Permissions.register_custom_key/2` (`permissions.ex:185`) must run **after** boot
because the Admin auto-grant touches the DB, so every host needs a call at the end
of `Application.start/2` — while its admin *tabs* are declared declaratively in
config. Read `config :phoenix_kit, :custom_permission_keys` inside
`PhoenixKit.boot/1` (`phoenix_kit.ex:81`), which already does
`ModuleRegistry.rescan/0` + `run_all_legacy_migrations/0`, mirroring how
`:admin_dashboard_tabs` auto-registers via
`Registry.auto_register_custom_permission/1`.

**Bad keys RAISE at boot, failing app start.** Config is a deploy-time contract.
Contrast `Dashboard.Registry`, which *rescues* — correct there, because one bad
**tab** should not kill the whole dashboard; a hand-authored config list is
different. Logging-and-skipping hides the misconfiguration until a colleague
hits a 403, which is the very failure this PR exists to prevent.
(`register_custom_key/2` already raises on collision / invalid format /
max-keys — `permissions.ex:186-200`.)

**Two documented caveats:**
- **`boot/1` is opt-in** (its own moduledoc). A host that never calls it gets
  silent no-registration — the same footgun as today's imperative API, relocated.
  `install`/`update` wire it; state the dual requirement.
- **A key that already has a tab with `permission:` does not need config
  registration** — double-registering hits the override-warning path
  (`:246-249`). One source of truth per key; config is for **non-tab**,
  matrix-only keys.

Also document that boot-time config is not re-read at runtime — reboot to rescan.

**Done when:** a key declared only in config appears in the permission matrix
after boot; an invalid key fails app start with a clear message; a
tab-declared key is not double-registered.

**PR-I — `page_action` beyond `navigate:`. ✅ DECIDED 2026-08-02 — slot + map, with a documented limitation.**
`layout_wrapper.ex:96-99` declares `attr :page_action, :map`; the render at
`:412-423` hardcodes `<.link navigate={@page_action[:navigate]}>`. A page whose
primary action is a `phx-click` cannot use it and keeps its own header row.

**Shape: `slot :page_action` + keep the map as shorthand.** The codebase already
has this convention — `header.ex:15`, `modal.ex:93`, `simple_form.ex:29`,
`form_section.ex:88`, `user_dashboard_header.ex:49` all expose `slot :actions`,
while `layout_wrapper` has only `slot :inner_block` (`:113`). Growing the map
(`patch`, event, target, confirm, disabled, `JS`) would make it a junk drawer.
Render priority: non-empty slot → `render_slot`; else map → the existing chip.

⚠️ **The slot does NOT reach plugin LiveViews, and that limits the fix.**
`layouts/admin.html.heex:20` threads `page_action={assigns[:page_action]}` — an
**assign**; a slot cannot travel that way. So plugin LVs rendered through the
admin layout can still only use the map; the slot serves views calling
`LayoutWrapper.app_layout` directly. **The reporter's case ("+ Add device" on a
host admin page) is plugin-shaped, so the slot alone would not have fixed it.**
Document the split honestly rather than pretending slots flow through the layout;
threading a slot through `admin.html.heex` is more invasive than the problem
warrants. The map path also stays the LiveComponent-hostile one — `phx-target`
needs the slot.

**Constrain visually, not by API shape:** wrap slot content in the same chip
shell (`btn btn-xs btn-primary btn-circle shrink-0`) and document the contract as
*one compact control*; multi-action toolbars stay in-page.

**Done when:** the sole existing map caller (`user_details.html.heex:9-15`)
renders byte-identically; a direct `app_layout` caller can render a `phx-click`
action with `phx-target`; the docs state that plugin LVs get the map only.

**PR-J — unmapped admin views become visible. ✅ DECIDED 2026-08-02.**
`auth.ex:1298` emits ONE `Logger.debug`, then allows only
`Scope.holds_all_enabled_permissions?/1`. **Verified fail-closed — diagnostics,
not a security hole.** But a host ships an admin page that works for them (Owner)
and 403s for colleagues, with nothing at default log level.

**(a) Promote to a deduped `Logger.warning` on FIRST hit per view — for any role,
not just on deny**, so Owner-only testing still surfaces the misconfiguration
before a colleague hits the 403.

✅ **The "unbounded seen-set leak" worry An earlier draft was WRONG.**
`:persistent_term` keyed by **view module atom** is naturally bounded: it tracks
only the distinct unmapped LiveView modules that ever mount — small and finite —
and module atoms are already permanent in the BEAM. No cap needed. (Not the
process dictionary: that re-logs per LV process.)

**(b) `check_unmapped_admin_views/0` in `mix phoenix_kit.doctor`** — ~20 sibling
`check_*` functions already return `{:pass|:warn|:fail, msg}`.

⚠️ **The check would LIE as written.** `doctor.ex:79` sets
`update_mode: true` before `app.start`, and `supervisor.ex:16-17` uses that to
**skip `Dashboard.Registry`** — so the tab-driven view→permission cache is empty
under doctor, and mapped views would be reported unmapped. The check must start
the Registry (or flip the flag for its duration) or it is worse than useless.

⚠️ **And it has genuine false negatives.** The views that fail silently today are
typically host LVs that are neither in `:admin_dashboard_tabs` nor under a plugin
namespace — exactly what a config scan misses. So: **the runtime warning is the
primary signal; doctor is best-effort over the declared surface and must say so.**

**(c) Fix the stale moduledoc found in passing.** `auth.ex:25-26` still says
unmapped views *"allow Owner/Admin and deny custom roles"* — the code is now
role-agnostic `holds_all_enabled_permissions?/1`, which a named Admin with
revoked keys fails. It documents behaviour that was deliberately removed.

**Done when:** a first mount of an unmapped view logs one warning and no more;
the doctor check runs with the Registry live and does not flag tab-mapped views;
the moduledoc matches the code.

**PR-K — ship `PhoenixKit.Test` (portable subset only). ✅ DECIDED 2026-08-02.**
Panel split on mechanism; resolved in favour of shipping, because zai's own
answer concedes the decisive point.

### Mechanism: ship pure functions, do NOT generate, do NOT ship CaseTemplates
- **grok:** ship pure helpers in `lib/`. A generator freezes N copies that drift —
  and this workspace already has that disease (~20 modules with forked
  `DataCase`/`ConnCase`).
- **zai:** ship a `mix phoenix_kit.gen.test_support` generator (the
  `phx.gen.auth` precedent), because a shipped helper compiles in the *kit's*
  context and cannot adapt to the host's endpoint/repo.
- **Resolution:** zai's objection lands on a proposal grok did not make. Its own
  A4 concedes *"`log_in_user/2` only puts a session, so it's portable"*, and the
  fixtures call `Auth.register_user/1`, which uses the **configured** repo. The
  only non-portable parts are the `@endpoint` / `Test.Repo` CaseTemplate bits —
  which grok explicitly excludes. So: ship the portable subset,
  **`ConnCase`/`DataCase` and all Sandbox ownership stay host-owned.**

Adding `test/support` to `files:` is a non-starter (both): a dep's `test/support`
is never on the host's `elixirc_paths`, so the files would ship dead.

### API surface — explicit over convenient
`user_fixture/1` meaning "confirmed" is a **footgun** (both reviewers): confirm
state is invisible policy that flips auth behaviour, so a reader seeing
`user_fixture()` in a redirect-gate test cannot tell why it does not redirect.

| Function | Behaviour |
|---|---|
| `user_fixture/1` | **unconfirmed** — an honest mirror of `register_user/1` |
| `confirmed_user_fixture/1` | calls `admin_confirm_user/1` |
| `register_and_log_in_user/1` | the 90% convenience: confirmed + logged in |
| `log_in_user/2` | session only |
| `scope_for/1` | builds a real `%Scope{}` |

*"Is this user confirmed?" must be answerable by reading the test, not by
memorising a fixture default.*

### ✅ Settled: `confirmed_at == nil` is CORRECT, not a bug being papered over
kimi asked whether shipping a confirming fixture freezes a defect. It does not.
`magic_link_registration.ex:165` **explicitly documents** that
`registration_changeset` refuses to set `confirmed_at`; confirmation is a
separate transition with its own `admin_confirm_user/1`; and the redirect gate
exists precisely to handle registered-but-unconfirmed, so tests **must** be able
to produce that state. Flipping `register_user/1` to auto-confirm would itself be
the bug.

### Two things the helper must get right
1. **Set `:live_socket_id`.** Core's own `log_in_user/2` sets
   `"phoenix_kit_sessions:" <> Base.url_encode64(token)`; the hand-rolled host
   version in the report **omits it**, so LiveView disconnect-on-logout never
   fires. Hosts are not merely duplicating — they are duplicating *subtly wrong*,
   in a way only a session-invalidation test would catch. This is the strongest
   argument for shipping.
2. **Neutralise the rate limiter in `:test`** (zai). `register_user/1` calls
   `check_registration_rate_limit/2`, and the test adapter reports **one peer for
   every conn**, so mass-registering fixtures under `async: true` get
   `{:error, :rate_limit_exceeded}`. The kit's own `create_admin_user` would hit
   this too.

### Cost accepted
`lib/` makes this permanent, semver-bound, compiled-into-production API. Mitigate
by namespacing under `PhoenixKit.Test.*`, marking the moduledoc "ExUnit only",
and preferring opts over parallel names for future variants.

**Done when:** a host test can `register_and_log_in_user/1` and reach a gated
route; `user_fixture/1` produces a user the confirmation gate redirects;
`log_in_user/2` sets both `:user_token` and `:live_socket_id`; fixtures work
under `async: true` without tripping the limiter; no Sandbox code ships.

**PR-L — locale-aware month names. ✅ APPROVED.**
`PhoenixKit.Utils.Date` is raw `Calendar.strftime`, so `%b` yields English month
abbreviations regardless of the Gettext locale — live instance at
`media_canvas_viewer.html.heex:335`. Every localized consumer rebuilds its own
gettext'd month table.
**Cheap because the strings already exist:** core's catalog already carries the
`"Jan"`/`"Feb"`/… msgids (`priv/gettext/default.pot:7086+`) with et/ru
translations — they are there purely as an extraction anchor for
`phoenix_kit_projects` (`projects_gettext_manifest.ex:36-38`). So this is lifting
`PhoenixKitProjects.L10n.short_month/1` (`l10n.ex:112`) into
`PhoenixKit.Utils.Date`, not writing a translation table.
**Fix the raw `%b`** at `media_canvas_viewer.html.heex:335` in the same change;
modules can then drop their local copies.
**Done when:** a month abbreviation renders in the viewer's locale; the projects
copy can be deleted without behaviour change.

**PR-M — docs. ✅ DECIDED 2026-08-02 — split into four focused PRs, and the
headline item is NOT writing docs.**

### ⚠️ The biggest docs claim in this triage is FALSE
NordSwitch reported the host-app admin story is *"only discoverable by reading
`mix phoenix_kit.gen.admin.page`'s source."* **Not true** (grok, verified):
- `guides/custom-admin-pages.md` — **481 lines**, listed in `mix.exs:261` under
  `docs.extras`, i.e. **published on HexDocs**.
- `lib/phoenix_kit/dashboard/ADMIN_README.md` — also in `extras` (`:263`).

What is true is narrower: the *user dashboard* README (1357 lines) has 2
incidental `admin_tabs` mentions — but that is the wrong file, not the only doc.

**So this is the SEVENTH discovery-pattern instance** (with `Storage.store_file/2`,
`Routes.path/2 :locale`, the not-installed-packages panel,
`Settings.get_project_title/0`, `referral_codes_required`, and `--yes`). Seven
times a host reported something missing that was already built — and here,
already documented on HexDocs.

**That reframes the work: the problem is findability, not absence.**

### Four focused PRs, not one blob
zai's reasoning, adopted: an omnibus bundles unrelated review surfaces, cannot be
bisected, and reads as low-priority cleanup so it sits unmerged while the gaps
fester. Each also earns its own CHANGELOG line.

**PR-M1 — make the admin guide findable (cross-links, not new prose).**
Point at what already exists from the two places people actually look:
`mix phoenix_kit.gen.admin.page`'s `--help` + moduledoc (NordSwitch was reading
its *source*), and a link from `dashboard/README.md`, which owns the sibling
user-tab story. Do **not** duplicate the 481-line guide.

**PR-M2 — Storage: `store_file/2` + how to serve the file.**
Home: the `PhoenixKit.Storage` moduledoc (it is the public API surface) plus a
`dev_docs/guides/` entry. Must state the fact that made a host hand-roll uploads:
local `public_url/2` returns **`nil`** (`providers/local.ex:156`) and files are
served via the **signed route** `/file/:uuid/:variant/:token`
(`integration.ex:259`). Also fix `store_file/2`'s docs, which list `:user_uuid`
as a plain option while `file.ex:258-267` requires it for non-system files.
⚠️ **Document it as a constrained-scope feature with a prominent caveat, never as
a general "capability URL"** — core's own TODO already records the 16-bit token,
absent expiry, and unauthenticated `/api/files/:uuid/info`. A library documenting
a capability it knows is weak is the specific hazard; naming the limits defuses
it. Do not block the docs on fixing the signer, but link the TODO.

**PR-M3 — `Routes.path/2` `:locale`.** A `@doc` on `path/2` in `routes.ex` — the
opt *is* the contract, and that is where a reader looks. Cross-link the multilang
guide, since the symptom (English auth pages on a bilingual site) reads as an
i18n problem. This is the C2 withdrawal: the reporter retracted the feature
request after finding the option already existed.
**Fold PR-U here too** (host must declare `{:rustler, ">= 0.0.0", optional: true}`;
`MDEX_NATIVE_BUILD=1` for non-AVX CPUs) — the explanation already exists as a
comment at `mix.exs:143-145` and just needs to reach the install guide.

**PR-M4 — surface "what you'd gain" in `mix phoenix_kit.update --status`.**
⚠️ **Not a doc change — a delivery change**, and **the highest-value item here**
(zai, and I agree). `--status` already reports available updates
(`update.ex:785`); what is missing is anything telling a host what upgrading
buys. Render CHANGELOG highlights, or "you are N releases behind — see X…Y".
Every other item closes one gap once; this closes the **feedback loop** that
turns docs gaps into bug reports, every release. The evidence is this triage:
**four** items were already-shipped work reported as defects.

**Done when:** `gen.admin.page --help` links the published guide; the Storage
moduledoc states the `public_url` → `nil` + signed-route reality with its
limitations named; `path/2`'s doc shows the `:locale` opt; `--status` tells a
behind host what it would gain.

**PR-N — `url_path` fallback for embeds. ✅ APPROVED.**
The admin layout uses `assigns[:url_path]` for sidebar active-state. It **is**
auto-assigned — `auth.ex:833` inside `set_routing_info/3`, attached as a
`:handle_params` hook by `mount_phoenix_kit_current_user/2` (`:909-914`) — so any
*router-mounted* LV going through the kit's on_mount chain gets it free.
**The real gaps:** (a) `live_render`-embedded LVs, which have no `handle_params`
lifecycle, and (b) host LVs that render kit admin chrome without using the kit's
on_mount chain. Both render with no tab highlighted and no indication why.
**Fix:** default it from the tab's own `path` when the assign is absent.
Narrower than the report implied ("nothing tells a host page to set it"), but the
suggested remedy is right for the set it does affect.
**Done when:** an embedded admin LV highlights its own tab without the host
assigning `:url_path`; router-mounted LVs are unchanged.

**PR-T — surface the discovery failure. ✅ SHRUNK approved.**
Originally "ship a static fallback catalog + async fetch + version fix". Cut to
two items after checking the real costs; the rest was not worth it.

### What was dropped and why
- ❌ **Static bundled catalog.** Would mean maintaining a hardcoded package list
  inside core, re-releasing core to add a package, and carrying permanent drift —
  all to serve the offline case.  A link is
  always current because Hex maintains it, and nothing goes stale.
- ❌ **Async fetch off `mount/3`.** I overstated this. There is a 10-minute cache
  TTL (`known_packages.ex:51`), a 3-second timeout (`:53`), and a failed page
  returns `{:error, reason}` rather than paginating on (`:189-193`). Worst case
  is ~3s **once per 10 minutes**, only when hex.pm is unreachable. Async
  machinery is not justified.

### What ships
1. **Make the failure visible instead of hiding the section.** Today
   `handle_hex_failure/3` returns `merge_extras([])` → `[]`, and
   `modules.html.heex:816` hides "Available Packages" entirely when empty — so a
   network failure reads as "there are no packages". Render the section with a
   short note plus a link to the human equivalent of the search the code already
   runs (`@hex_search_url` + `?search=phoenix_kit_&sort=name`):
   *"Couldn't reach hex.pm. Browse PhoenixKit packages →"*
   → `https://hex.pm/packages?search=phoenix_kit_`
2. **Use the real version in the `Add to mix.exs` snippet.** The data is
   **already captured** — `known_packages.ex:244` sets
   `latest_version: pkg["latest_version"]` — and `modules.html.heex:857` ignores
   it, printing a hardcoded `{:#{pkg.package}, "~> 0.1"}`. So it tells hosts to
   pin a stale requirement while holding the correct version in the same struct
   (referrals is at `~> 0.4`). One line.

**Context:** this is no longer load-bearing for the invite-only story — that was
my misreading of the Topp report (they had found and installed referrals; the
problem was enforcement across auth paths, now PR-Y). The defect here is real but
independent, and this is the lowest-value item in the plan.

**Done when:** with hex.pm unreachable, the Modules page shows the section with
the note and a working link rather than hiding it; with hex.pm reachable, the
snippet shows the package's actual latest version.

**PR-U — document the `rustler` / `mdex` sharp edge. ✅ APPROVED.**
`mix.exs:142` `{:mdex, "~> 0.13"}`, `:146` `{:rustler, ">= 0.0.0", optional: true}`.
Optional deps are not resolved for the host, so a **source build of the NIF needs
the host to declare `{:rustler, ">= 0.0.0", optional: true}` itself**. CPUs
without AVX additionally need `MDEX_NATIVE_BUILD=1` and a ~10-minute Rust compile
on every fresh checkout. The explanation **already exists** as a code comment at
`mix.exs:143-145` — it simply never reaches the install guide or troubleshooting
docs. Pure docs; fold into PR-M.
**Out of scope, flag only:** making markdown/mdex a properly optional module so
hosts that never render markdown do not pay for it. That is a real architectural
question, not a docs fix.

**PR-O — generalize `PkDialogDraft`. ⏸️ NOT SCHEDULED 2026-08-02.** zai argues not to: one consumer, and
promoting an internal hook to public `DraftForm` is speculative semver surface.
If it happens, localStorage is **opt-in and off by default** — unanimous
privacy flag: drafts hold PII, persist across logout, and leak between users on
a shared device. Requires user+form-scoped keys, TTL, schema version, clear on
submit/logout, never password fields.

**PR-P — PWA generator. Out of the committed roadmap** (unanimous). The panel
inverted my risk read and they're right: a service worker lives in the *user's*
browser, can cache authenticated HTML/CSRF-bearing responses, and a versioning
mistake is **not server-side fixable**. If anything ships, emit manifest +
`/offline` only and make the SW opt-in.

---

## E0. The theme

Across three independent host teams, the highest-value findings are **not
features — they're the host-integration seam**:

| Seam | Finding | Symptom for the host |
|---|---|---|
| Layout | T1 | fresh install ships Phoenix branding on login |
| Viewport | T2 | two scrollbars on any non-default host layout |
| Locale | C1 | kit clobbers the host's process-global Gettext locale |
| Scope | S1 | kit predicate raises in a host layout |
| Client/server contract | B2/T3 | a 404 per page load, reported twice |
| Discovery | T4, F4, W3 | features exist but nobody can find them |

The pattern: **phoenix_kit is excellent when the host looks like the kit's
assumptions, and leaky when it doesn't.** Every one of these is the kit reaching
outward — into the host's layout, viewport, process dictionary, or Gettext
backend — and assuming a shape. Both Ratelia and Topp explicitly praised the
module system and the auth pages' *design*; the complaints are all about
coupling. That framing is worth stating up front to whoever implements this,
because it predicts where the next report comes from.

Discovery deserves its own line: **four separate items (T4, F4, W3, T6) are
"the feature exists and works, but nobody found it."** `Storage.store_file/2`,
admin tabs, the not-installed-packages panel, and
`Settings.get_project_title/0` are all built and all missed. That's a docs and
failure-mode problem, not an engineering one, and it's the cheapest value here.

A second, sharper pattern — **controls that don't control** (D1, M3, and
arguably W4's dead `broadcast_setting_changed/2`): a module named
`TestRequireAuthLive` that requires no auth; a setting on the *Authorization*
page that gates only a button; a broadcast API with no callers. Each one reads
as enforcement to whoever meets it next. These are worth fixing above equivalent
cosmetic work, because they actively mislead rather than merely omit.

## E. Cross-cutting gaps

1. **No semver / release policy.** PR-B, PR-E, PR-G are all observable behavior
   changes. PR-E and PR-G cannot both ride a patch release. Needs one
   collective versioning decision — The project decision.
2. **No server ↔ vendored-client compatibility matrix** (codex). Old bundles
   coexist with new server code; PR-B is where that already bites.
3. **C2 / German has no PR.** de is ~9% translated; after all 14 PRs a German
   host still gets broken auth pages. Either scope translation work or say
   out-of-scope explicitly.
4. **`auth.ex` is a contention hotspot** — PR-E (6 sites), PR-J (`:1298`),
   PR-N (`set_routing_info`) and PR-Y (the gate) all touch it. Land serially or
   eat a bad rebase.
5. **Regression tests that define success:** consent 404 (old + new bundle);
   `Scope` nil in a host layout; settings write from a separate BEAM; host
   locale surviving a kit mount + navigation; unmapped admin view denial.

## F. Open decisions

Everything else in this plan is settled. These are not.

**F1 — the customer permission (blocks U1 + U2).** Under the unified `/admin`,
what permission should a customer-facing section hold, and is `/admin` intended
to be customer-visible at all? The permission system says yes; the URL says no.
Three shapes are laid out in §U1:
(A) mint a baseline key auto-granted to User — best fit for the documented
role principle, since it stays permission-keyed and role-agnostic;
(B) relax the entry gate to any authenticated user;
(C) keep `/dashboard` for customer surfaces, contradicting the deprecation
notice already shipping in `phoenix_kit.doctor`.

⚠️ **This answer also sets U2's priority.** Under (A) or (B), customers reach
`/admin` and host-brandable admin theming stops being polish — the panel renders
phoenix-blue chrome and a header reading "Admin Panel" on the host's own product.
Under (C) it stays a normal polish item.

A host is actively blocked on this and has said they will build against whatever
is chosen and migrate their existing screens at the same time.

**F2 — release grouping.** PR-B (consent response), PR-E (locale source), PR-G
(non-zero exit) and PR-AC (notifications permission split) are all observable
behaviour changes. They cannot all ride one patch release. Needs one collective
semver decision at release time.

**F3 — German catalogue.** `de` is ~9% translated (1836/2016 msgids empty),
versus ~95% for `et`/`ru`. No PR covers it; after everything here lands, a German
host still gets largely untranslated auth pages. Either scope translation work or
record it as out of scope.

**F4 — optional markdown.** Making `mdex`/`rustler` a properly optional module,
so hosts that never render markdown do not pay the NIF cost, is a real
architectural question. PR-U documents the sharp edge; it does not scope this.

## G. Running order

If this ships in one batch, the defensible set is the corroborated,
low-design-risk bugs — no behaviour debates, no API surface:

**Security first (can ship alone, decoupled from everything else):**
**PR-W** (🔒 referral oracle — absorbs PR-V) · **PR-Y** (🔒 invite-only actually
holds — OAuth bypass; the original product requirement) · **PR-X** (🔒 magic-link
settings actually gate, incl. login + token verify).

**Then, highest non-security:** **PR-Z** (sitemap exclusions — incident-class,
no in-product recovery today).

**Then the rest:** **PR-A** (Scope nil) · **PR-B** (consent 204) ·
**PR-R** (auth pages leave the host's `Layouts.app` — unconditional) ·
**PR-S** (auth viewport math — ships WITH PR-R) ·
**PR-AC** (notifications permission split — needs the new enforcement path) · **PR-Q** (delete demo scaffolding +
doctor check) · **PR-C/PR-G** (`update` hint + non-zero exit) · **PR-T** (surface
discovery failure) · **PR-M2** (storage docs).

**Deferred, not in the cut:** PR-D (iOS zoom → core `AGENTS.md` TODOs),
PR-E/PR-E2 (locale — design settled, awaiting scheduling), PR-O (`DraftForm`),
PR-P (PWA).

## G2. Repo footprint — what actually gets touched

**Code changes land in two repos only:**

| Repo | PRs | Why |
|---|---|---|
| **`phoenix_kit`** (core) | everything except the below | all findings originate here |
| **`phoenix_kit_referrals`** | **PR-W** step 1 only | the CSPRNG one-liner (`:183`). Steps 2-4 are core; step 5 dropped |

`phoenix_kit_locations` appears in K5 only as the *motivating example* — the fix
(`:hidden_admin_tabs`) is in core's registry; locations itself is untouched.

**Downstream impact is a separate question, and one item is large:**

| PR | Consumers affected | Severity |
|---|---|---|
| **PR-E** (locale *source* setting — the global write STAYS) | ~~21 modules~~ **not affected**; superseded design — billing, bookings, catalogue, comments, crm, customer_support, document_creator, ecommerce, emails, legal, locations, manufacturing, newsletters, open_graph, posts, projects, publishing, referrals, staff, warehouse (+ parent) | ⚠️ **HIGH — see below** |
| **PR-Z / V160** | every host (core migration) | medium — additive column widening, no data change |
| **PR-AD** (`button/1` variant) | core call sites + any module using `<.button>` | low — additive, default variant preserves output |
| **PR-AE** (`:hidden_admin_tabs`) | any module contributing admin tabs | low — opt-in, hides nothing unless configured |
| **PR-B** (consent stub) | `phoenix_kit_legal` owns the real controller | low — stub must not shadow legal's route |

### ⚠️ Superseded — PR-E no longer drops the global write
An earlier PR-E deleted the six global `Gettext.put_locale/1` calls, which would
have un-localised ~20 module backends that document reliance on that slot. **That
design was rejected.** The final PR-E adds a `locale_source` setting governing
only where the kit *reads* the locale when the URL carries none; the global write
stays, so no module is affected and this is a core-only change. Do not implement
the ecosystem-wide rewrite this table originally described.


## H. Finding → destination map

Every finding has a home; nothing is silently dropped.

| Finding | Destination |
|---|---|
| SEC1 | **PR-W** 🔒 |
| M3 | **PR-X** 🔒 |
| R1 | PR-W step 4 (was PR-V) |
| SEC2, M1, M2 | **PR-Y** 🔒 (after PR-W) |
| G3, G4, G5 | **PR-Z** — highest non-security item |
| G6 | **PR-Z(b) / V160** — same migration |
| Q1 | **PR-AB** — one-line, no risk |
| K1, K2, K3, K4 | **PR-AD** — K1 is an adoption blocker |
| K5 | **PR-AE** |
| NordSwitch 2.1/2.2/2.3/2.5/3.1 | duplicates of **F1/F2/F3/F5/F4** — no new tracking |
| N1 | **PR-AC** — small; do before the U1 migration widens the affected population |
| U2 | **§F Q8 (dependent)** — schedule follows U1's answer; blocker under (A)/(B) |
| U1 | **§F Q8 — DESIGN DECISION for the maintainer**, blocks a host; feeds his own admin-unification project |
| G1, G2 | **PR-M2** (PR-AA retired into it) |
| S1 | PR-A |
| B2 / T3 | PR-B |
| T1 | PR-R |
| T2 | PR-S |
| T4 | PR-T |
| D1 | PR-Q |
| W6a | PR-D |
| W6b | PR-L |
| C1 | **PR-E** — design agreed (settings-based); embedded half is **PR-E2** |
| W4 | PR-F ← *needs The project decision* |
| A1 residue | PR-C (hint) + PR-G ← *needs The project decision* |
| F3 | PR-H |
| F5 | PR-I |
| F1 | PR-J |
| W5 | PR-K |
| F2 | PR-N |
| F4, W3, T6 | PR-M (docs) |
| T5 | PR-U (docs) |
| W1 | PR-O — **deferred**, one consumer |
| W2 | PR-P — **not scheduled**, service-worker blast radius |
| C2 (de ~9%) | **no PR** — needs a scope decision, see §E |
| A2 | already fixed at HEAD |
| A4 | already built (T4 covers the real defect) |
| A6 (`signed_in_path`) | already fixed in **1.7.217** — reporter needs an upgrade, no code change |
| A7 (stale-report loop) | PR-M note — surface "N releases behind" in `status`/`doctor` |

Held back for the maintainer's decisions: **PR-E** (locale — the big one), **PR-F** (cache
mechanism), **PR-G** (exit code). Dropped: **PR-P** (PWA), **PR-O**
(`DraftForm` generalisation).

⚠️ **`auth.ex` is heavily touched by the first cut** — PR-Y (the gate), PR-J
(`:1298`), PR-N (`set_routing_info`) and PR-E all edit it. Land them serially;
an earlier note claiming otherwise was wrong.
