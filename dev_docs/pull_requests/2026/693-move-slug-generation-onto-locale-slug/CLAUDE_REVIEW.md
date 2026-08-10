# PR #693 Review — Move slug generation onto `locale_slug`

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/693
**Author:** Max Don (mdon)
**Merged:** 2026-08-09 (`2562c3c9`, branch `mdon/main` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 4 files, +96 / −75. Replaces a hand-rolled Cyrillic table with the new `locale_slug` Hex package; adds one required runtime dependency.

---

## Verdict

**The change is right and the diagnosis behind it is right.** I did not take the
before/after claims on trust — I restored the pre-PR implementation verbatim and
ran both side by side over ~40 inputs. Every claim in the moduledoc checks out,
and the old code was worse than the PR says:

| Input | old (default opts) | old (`transliterate: true`) | new |
|---|---|---|---|
| `Größe Fußball` | `gr-e-fu-ball` | `gro-e-fu-ball` | `grosse-fussball` |
| `Café` | `caf` | `cafe` | `cafe` |
| `Ünïcödé Tëst` | `n-c-d-t-st` | `unicode-test` | `unicode-test` |
| `Кашпо` | `""` | `kashpo` | `kashpo` |
| `Ελληνικά` | `""` | `""` | `ellinika` |

Everything else in the matrix is byte-identical between old and new — custom
separators (`_`, `--`, `+`, `|`, `?`), whitespace collapsing, trimming,
`nil`/non-binary input, and the `ensure_unique/2` suffix walk, which the PR left
alone.

I also checked the things a delegation like this usually gets wrong:

| Question | Answer |
|---|---|
| Does `fallback: :empty` really keep output ASCII? | Yes — verified against path traversal, markup, emoji, zero-width, NUL bytes and CJK; all land in `[a-z0-9-]` |
| Does a bogus `:locale` raise? | No — `:strict` defaults false, `"not a tag"` / `42` / `""` all degrade to the neutral resolver |
| Does `max_length: nil` (always passed) confuse it? | No, `nil` is the library's own default |
| Is the new dep really dependency-free at consumer build time? | Yes — `yamerl` is `only: [:dev, :test], runtime: false`, and the generated tables are committed Elixir |
| Does `override: true` in `local_dep/2` break `mix hex.publish`? | No — the override only appears when `LOCALE_SLUG_PATH` is exported, so the published pin is a plain tuple |
| Is `separator: ""` a new crash? | No — `Regex.CompileError` in **both** old and new; pre-existing |

Three findings. One is a dependency pin that lets a third party change this
project's URLs; two are documentation that says the opposite of what the code
now does. All three are addressed here, and the behaviour I verified by hand is
now pinned by tests instead of living in this document.

**Verification caveat:** `test/phoenix_kit/utils/slug_test.exs` needs no
database, so unlike the previous two reviews **these tests actually ran** —
15 tests, 0 failures. `mix precommit` passes.

---

## IMPROVEMENT - HIGH — `~> 0.1` lets a dependency rewrite this project's URLs

**File:** `mix.exs`

```elixir
local_dep(:locale_slug, "~> 0.1"),
```

`~> 0.1` resolves to `>= 0.1.0 and < 1.0.0`, so `mix deps.update` will happily
take 0.2.0, 0.3.0 and so on. Two reasons that is the wrong pin here, and the
second is the one that matters:

1. `locale_slug` is at **0.1.0**. Below 1.0 there is no API-stability promise —
   the usual argument, and on its own it would only cost a compile error.
2. **The output is the contract.** This package's whole job is to decide what
   string a title becomes, and that string is persisted in URLs and compared for
   uniqueness. A minor release that revises a romanization table — precisely the
   kind of change a young transliteration library ships — silently changes the
   slug every host derives from the same title. That is a content change
   arriving as a dependency bump, with no CHANGELOG line in this repo and
   nothing in a diff to review.

The package's own docs make the risk concrete rather than theoretical: it
distinguishes `status: "verified"` tables (a human who reads the language signed
off) from machine audits, and advises preferring verified ones "for slugs you
persist". Tables getting promoted and corrected is the expected shape of 0.x
releases here.

This is also settled policy in this very file, twelve lines further down —
`leaf` carries a comment explaining why it is **not** `~> 0.3`:

> for a 0.x package where each minor is effectively a major it claimed a support
> window core cannot back

The same argument applies to `locale_slug`, with the extra weight that `leaf`
renders content while this one *names* it.

**Fixed:** pinned `~> 0.1.0` (`>= 0.1.0 and < 0.2.0`). Adopting a new minor now
requires a deliberate PhoenixKit release, which is where a slug-output change
belongs. `mix.lock` is unchanged — 0.1.0 satisfies both.

---

## IMPROVEMENT - MEDIUM — `transliterate/1` says "Contract preserved exactly" and lower-cases

**File:** `lib/phoenix_kit/utils/slug.ex`

> Contract preserved exactly: characters with no mapping pass through unchanged.

The sentence then justifies itself with a punctuation example, and **that example
is true** — I checked `ülo.kask` → `ulo.kask`, and spacing and repeated
underscores survive too, so `generate_username_from_email/1` is safe. But the
claim it is attached to is broader than the evidence, and case does not survive:

| Input | old | new |
|---|---|---|
| `MiXeD CaSe` | `MiXeD CaSe` | `mixed case` |
| `ÜLO KASK` | `ULO KASK` | `ulo kask` |
| `Кашпо` | `Кashpo` | `kashpo` |
| `Hello.World` | `Hello.World` | `hello.world` |

`LocaleSlug.transliterate/1` lower-cases before mapping. The old table had only
lowercase Cyrillic keys, so it left case alone and half-mapped uppercase input —
`"Кашпо"` came back `"Кashpo"`, which is a bug, not a contract. The new
behaviour is better. It is also a silent change to a **public** function, and
the docstring currently tells a reader the opposite.

Core is unaffected: its one caller (`user.ex:864`) does `String.downcase()`
immediately before. External packages calling `Slug.transliterate/1` on
mixed-case text will see the change.

**Fixed:** the docstring now claims only what holds (spacing and punctuation
survive; unromanizable scripts pass through in their own script) and has a
section stating the lower-casing outright. Pinned by tests for both halves.

---

## IMPROVEMENT - MEDIUM — "existing URLs are unaffected" is true of stored slugs only

**File:** `lib/phoenix_kit/utils/slug.ex`

> **Stored slugs are not rewritten** — only newly generated ones change. Existing
> URLs are unaffected.

Correct, and incomplete in the way that decides whether an upgrade is safe. A
caller that **re-derives** a slug from a title in order to *find* an existing row
— rather than reading the stored one — now derives a different string and misses.

The moduledoc frames the old breakage as a Cyrillic problem ("wherever a caller
forgot `transliterate: true`"), which reads as "if you don't have Cyrillic
content, nothing changes for you". The matrix says otherwise: under the old
default, `Café` slugged to `caf` and `Ünïcödé Tëst` to `n-c-d-t-st`. Any
English-language site with an accented product name or a French café is in scope.

Deriving is the wrong lookup key either way — this release is just when it stops
working quietly. That is worth one sentence in the place a maintainer will look.

**Fixed:** the moduledoc says which callers need checking and gives the accented
Latin examples. Pinned by a test that spells out the three concrete before/after
strings.

---

## Verified and left alone

- **`separator: ""` raises `Regex.CompileError`.** Both implementations do — the old one built `~r/#{Regex.escape("")}+/`, i.e. `~r/+/`. Pre-existing and unreachable from core. Noting it only because the exception now surfaces from inside a dependency, which makes it a harder trace than it was.
- **`local_dep/2`.** Correct as written: `System.get_env` at project-definition time, plain tuple when unset, `override: true` only on the path branch — so `mix hex.publish` sees no override (which Hex refuses). The comment warning against committing a hand-edited path tuple is the right thing to have written down.
- **`transliterate: true` accepted and ignored.** The right call for source compatibility, and the option is documented as ignored rather than quietly dropped.
- **`ensure_unique/2`.** Body untouched; only gained a docstring. Behaviour re-verified anyway (`post` → `post-2` with `post`/`post-1` taken; `""` never suffixed).
- **The rewritten test.** It inverts an existing assertion — `"a Cyrillic title still collapses to empty"` became `== "kashpo"` — and says in a comment that the old assertion was pinning the bug. That is exactly right, and the comment means nobody will "restore" it later.

---

## Changes in this pass

| File | Change |
|---|---|
| `mix.exs` | `locale_slug` pinned `~> 0.1.0` (was `~> 0.1`), with the reasoning inline |
| `lib/phoenix_kit/utils/slug.ex` | `transliterate/1` doc no longer claims exact preservation and documents the lower-casing; moduledoc covers re-derive callers and the accented-Latin change |
| `test/phoenix_kit/utils/slug_test.exs` | +4 tests: accented-Latin default change, ASCII-only output invariant, punctuation/spacing survival, lower-casing |

## Gate

`mix precommit` — format, `compile --warnings-as-errors`,
`deps.unlock --check-unused`, `credo --strict`, dialyzer, JS tests: **passing**.
`mix test test/phoenix_kit/utils/slug_test.exs` — **15 tests, 0 failures**
(this file needs no database, so it genuinely ran).
