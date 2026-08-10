defmodule PhoenixKit.Utils.Slug do
  @moduledoc """
  Helpers for generating consistent, URL-friendly slugs across PhoenixKit.

  The slug rule itself now lives in the [`locale_slug`](https://hex.pm/packages/locale_slug)
  package. This module keeps its existing public shape — `slugify/2`, `transliterate/1`,
  `ensure_unique/2` — so no caller changes, and delegates the hard part.

  ## Why it moved out

  The hand-rolled table here could not express a locale, and two bugs followed from
  that directly:

    * **`Größe Fußball` → `gro-e-fu-ball`.** NFD strips the umlaut and `ß` has no
      canonical decomposition at all, so the ASCII pass deleted it. German expands
      these (`oe`, `ss`) and Estonian folds them (`o`) — one table cannot do both, and
      this one was doing neither.
    * **A Cyrillic-only title produced an EMPTY slug** wherever a caller forgot
      `transliterate: true`. Callers read empty as "no slug yet" and regenerate
      forever; a CSV re-import of a Cyrillic catalogue inserted the whole feed again
      on every run.

  ## Transliteration is now the default

  `:transliterate` used to default to `false`, which is what made the empty-slug bug
  reachable. Blanks help nobody, so romanization is now always on and the option is
  accepted and ignored, for source compatibility.

  **Stored slugs are not rewritten** — only newly generated ones change. Existing URLs
  are unaffected.

  What that sentence does not cover, and what to check before upgrading: a caller that
  **re-derives** a slug from a title in order to find an existing row, rather than
  reading the stored one, now derives a different string. The old default mangled
  accented Latin as badly as it did Cyrillic — `Café` slugged to `caf`, `Ünïcödé Tëst`
  to `n-c-d-t-st` — so the change is not confined to scripts nobody used. Deriving is
  the wrong lookup key either way; this release is when it stops working quietly.

  ## Locale

  Pass `:locale` when the caller knows it; most do and were discarding it.

      Slug.slugify("Größe Fußball", locale: "de")   #=> "groesse-fussball"
      Slug.slugify("Töö õun", locale: "et")         #=> "too-oun"
      Slug.slugify("Цветокоррекция")                #=> "tsvetokorrektsiya"

  Without a locale the result is still correct, just not locale-tuned.
  """

  @doc """
  Converts the given `text` into a slug.

  Options:
    * `:separator` — character used between words (defaults to `"-"`)
    * `:locale` — BCP 47 tag (`"de"`, `"et"`); improves accuracy where known
    * `:max_length` — truncate, never mid-mapping
    * `:transliterate` — **ignored**; romanization is always on now. Accepted so the
      hundreds of existing `transliterate: true` call sites keep compiling.

  Returns an empty string when the input is blank or has no slug-able content.
  """
  @spec slugify(String.t() | nil, keyword()) :: String.t()
  def slugify(text, opts \\ [])

  def slugify(nil, _opts), do: ""

  def slugify(text, opts) when is_binary(text) do
    LocaleSlug.slugify(text,
      separator: Keyword.get(opts, :separator, "-"),
      locale: Keyword.get(opts, :locale),
      max_length: Keyword.get(opts, :max_length),
      # ASCII-or-nothing: PhoenixKit slugs land in paths that predate IRI support in
      # this codebase, so an unromanizable script should yield "" and let the caller's
      # uniqueness logic take over, rather than emitting native script into a URL that
      # other code assumes is ASCII.
      fallback: :empty
    )
  end

  def slugify(_text, _opts), do: ""

  @doc """
  Romanizes `text` and leaves everything else alone.

  Spacing and punctuation survive, which is the part callers depend on —
  `generate_username_from_email/1` calls this and then does
  `String.replace(".", "_")`, so folding punctuation into a separator here would turn
  `ülo.kask@` into `ulokask` instead of `ulo_kask`. Characters with no romanizer pass
  through in their own script (`"日本"` stays `"日本"`), so a caller that needs ASCII
  must still say so.

  Now covers Greek and the Latin letters that used to vanish, not just the
  Russian/Ukrainian Cyrillic this module hardcoded.

  ## One thing that did change: the result is lower-cased

  The old table only had lowercase Cyrillic keys, so it left case alone and mangled
  uppercase input — `"Кашпо"` came back `"Кashpo"`, half-romanized. This lower-cases
  first and maps the whole string, so `"MiXeD CaSe"` is now `"mixed case"` where it
  used to be returned untouched. Core's only caller downcases before calling anyway;
  a caller that needs the original casing has to keep its own copy.
  """
  @spec transliterate(String.t()) :: String.t()
  defdelegate transliterate(text), to: LocaleSlug

  @doc """
  Ensures the provided slug is unique by calling `exists_fun`.

  `exists_fun` should return truthy when the slug is already taken.

  This is where uniqueness belongs. Romanization is lossy in every language — Turkish
  `ılık` and `ilik` both romanize to `ilik`, and plain English `Café`/`Cafe` collide
  too — so slugs are not identifiers and the suffix here is the answer, not a better
  table.
  """
  @spec ensure_unique(String.t(), (String.t() -> boolean())) :: String.t()
  def ensure_unique("", _exists_fun), do: ""

  def ensure_unique(slug, exists_fun) when is_function(exists_fun, 1) do
    if exists_fun.(slug) do
      increment_slug(slug, 2, exists_fun)
    else
      slug
    end
  end

  defp increment_slug(base_slug, counter, exists_fun) do
    candidate = "#{base_slug}-#{counter}"

    if exists_fun.(candidate) do
      increment_slug(base_slug, counter + 1, exists_fun)
    else
      candidate
    end
  end
end
