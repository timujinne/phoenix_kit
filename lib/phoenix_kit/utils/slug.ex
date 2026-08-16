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

  ## Options

    * `:max_length` — the ceiling the *final* slug must respect, suffix included.

  Without it the suffix is simply appended, which overflows any cap the caller already
  applied: `slugify(title, max_length: 20)` returns 20 characters and `-2` makes 22.
  That silently defeats an SEO cap, and against a `varchar(n)` column Postgres raises
  rather than truncating. Given the option, the base is trimmed to make room —
  per candidate, since `-10` needs one more character than `-9` — and a trailing
  separator left by the trim is stripped so the result is never `foo--2`.
  """
  @spec ensure_unique(String.t(), (String.t() -> boolean()), keyword()) :: String.t()
  def ensure_unique(slug, exists_fun, opts \\ [])

  def ensure_unique("", _exists_fun, _opts), do: ""

  def ensure_unique(slug, exists_fun, opts) when is_function(exists_fun, 1) do
    if exists_fun.(slug) do
      increment_slug(slug, 2, exists_fun, Keyword.get(opts, :max_length))
    else
      slug
    end
  end

  defp increment_slug(base_slug, counter, exists_fun, limit) do
    suffix = "-#{counter}"
    candidate = trim_for(base_slug, suffix, limit) <> suffix

    if exists_fun.(candidate) do
      increment_slug(base_slug, counter + 1, exists_fun, limit)
    else
      candidate
    end
  end

  defp trim_for(base, _suffix, nil), do: base

  defp trim_for(base, suffix, limit) do
    keep = limit - String.length(suffix)

    if String.length(base) <= keep do
      base
    else
      base
      |> String.slice(0, Kernel.max(keep, 0))
      |> String.trim_trailing("-")
    end
  end

  @doc """
  Puts a generated, collision-free slug on `changeset`, derived from `source_field`.

  This is the changeset glue that was missing from core, and which 14 hand-rolled
  `maybe_generate_slug/1` copies across eight sibling packages each got a different
  subset of right.

  ## The four cases, and why "absent" is not "empty"

  The bug this exists to delete is reading `get_change(:slug)` and treating `nil` as
  "this record has no slug". It does not mean that — it means *this save did not carry
  one*, which is true of almost every save. `cast/3` drops a value equal to the data,
  so an edit form that faithfully re-sends the current slug produces no change at all.
  Under `get_change/2` that reads as "regenerate from the title", so renaming anything
  moved its live URL and nothing recorded the old one.

    * an explicit, non-blank slug always wins;
    * an explicitly blanked slug regenerates (the column is typically `NOT NULL`, so
      storing the blank is not an option);
    * **no slug in the changeset means unchanged** — generate only if the stored
      record has none;
    * a source that slugifies to `""` leaves the changeset alone rather than writing
      a blank that the next save would read as "no slug yet" and regenerate forever.

  ## Options

    * `:to` — the slug field. Defaults to `:slug`.
    * `:scope` — fields the uniqueness is *scoped by*, e.g. `[:user_uuid]` for a
      per-user slug backed by a composite index. Defaults to `[]` (global).
    * `:unique` — set `false` to skip the probe entirely. Defaults to `true`.
    * `:repo` — the repo to probe. Defaults to the configured PhoenixKit repo.
    * `:queryable` — override the probed source, e.g. to exclude soft-deleted rows:
      `queryable: from(p in Post, where: is_nil(p.deleted_at))`. Defaults to the
      changeset's own schema.
    * `:locale`, `:separator`, `:max_length` — forwarded to `slugify/2`.

  ## Uniqueness here is an allocator, not a guarantee

  The probe runs from inside the changeset, which is unusual but deliberate: it is
  what `Ecto.Changeset.unsafe_validate_unique/4` does, and the alternative — generate
  in the schema, uniquify in the context — splits one decision across two modules and
  is how the copies drifted in the first place.

  It stays advisory. A concurrent insert between the probe and the write still
  collides, so **every caller must also declare `unique_constraint/3` against an index
  that actually exists**. This function picks a free-looking suffix; the index is what
  makes it true.

  ## No repo configured is tolerated; a broken repo is not

  If no repo is configured at all, the uniqueness probe is skipped — the library is
  usable for pure changeset construction without a database. If a repo *is* configured
  and the query then fails, the error is allowed to raise. The predecessor in
  `phoenix_kit_posts` wrapped the whole probe in a bare `rescue _ -> slug`, which
  cannot tell those apart and answers a transient database fault by writing the
  unsuffixed slug — reintroducing exactly the duplicate the probe exists to prevent.

  ## Examples

      changeset |> Slug.put_slug(:title)
      changeset |> Slug.put_slug(:name, scope: [:user_uuid])
      changeset |> Slug.put_slug(:title, locale: "de", max_length: 60)
  """
  @spec put_slug(Ecto.Changeset.t(), atom(), keyword()) :: Ecto.Changeset.t()
  def put_slug(%Ecto.Changeset{} = changeset, source_field, opts \\ []) do
    to = Keyword.get(opts, :to, :slug)

    case Ecto.Changeset.fetch_change(changeset, to) do
      {:ok, slug} when is_binary(slug) and slug != "" ->
        changeset

      {:ok, _blank} ->
        changeset
        |> Ecto.Changeset.delete_change(to)
        |> generate(source_field, to, opts)

      :error ->
        if Map.get(changeset.data, to) in [nil, ""] do
          generate(changeset, source_field, to, opts)
        else
          changeset
        end
    end
  end

  defp generate(changeset, source_field, to, opts) do
    with value when is_binary(value) and value != "" <-
           Ecto.Changeset.get_field(changeset, source_field),
         slug when slug != "" <-
           slugify(value, Keyword.take(opts, [:separator, :locale, :max_length])) do
      Ecto.Changeset.put_change(changeset, to, unique(changeset, slug, to, opts))
    else
      _ -> changeset
    end
  end

  defp unique(changeset, slug, to, opts) do
    repo = Keyword.get_lazy(opts, :repo, fn -> PhoenixKit.Config.get(:repo, nil) end)

    if Keyword.get(opts, :unique, true) and repo do
      # `:max_length` is forwarded so the suffix respects the same ceiling the base
      # was cut to, rather than overflowing it by two characters.
      ensure_unique(slug, taken_fun(changeset, to, repo, opts),
        max_length: Keyword.get(opts, :max_length)
      )
    else
      slug
    end
  end

  defp taken_fun(changeset, to, repo, opts) do
    import Ecto.Query, only: [where: 3]

    schema = changeset.data.__struct__
    queryable = Keyword.get(opts, :queryable, schema)

    # Reflection, not an option: every PhoenixKit schema declares
    # `@primary_key {:uuid, UUIDv7, autogenerate: true}` today, but asking the caller
    # to restate it is one more thing 14 call sites can each get wrong.
    base =
      schema.__schema__(:primary_key)
      |> Enum.reduce(Ecto.Queryable.to_query(queryable), fn pk, query ->
        case Map.get(changeset.data, pk) do
          # An insert has nothing to exclude.
          nil -> query
          value -> where(query, [r], field(r, ^pk) != ^value)
        end
      end)
      |> scope_query(changeset, Keyword.get(opts, :scope, []))

    # Honours a schema prefix so a multi-tenant install probes its own rows rather
    # than "public"'s.
    prefix = changeset.data.__meta__.prefix

    fn candidate ->
      base
      |> where([r], field(r, ^to) == ^candidate)
      |> repo.exists?(prefix: prefix)
    end
  end

  defp scope_query(query, changeset, scope) do
    import Ecto.Query, only: [where: 3]

    Enum.reduce(scope, query, fn field_name, acc ->
      # NULL never equals NULL, so an unset scope has to be matched with IS NULL or
      # the probe silently reports every candidate free.
      case Ecto.Changeset.get_field(changeset, field_name) do
        nil -> where(acc, [r], is_nil(field(r, ^field_name)))
        value -> where(acc, [r], field(r, ^field_name) == ^value)
      end
    end)
  end
end
