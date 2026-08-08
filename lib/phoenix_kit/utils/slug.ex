defmodule PhoenixKit.Utils.Slug do
  @moduledoc """
  Helpers for generating consistent, URL-friendly slugs across PhoenixKit.

  Provides functions to slugify arbitrary text, enforce separator rules,
  and ensure uniqueness by delegating existence checks via callback.
  """

  # Lowercase Cyrillic -> Latin, Russian and Ukrainian. Applied before the
  # ASCII strip so a Cyrillic title yields a real slug: without it every
  # character is stripped and the slug comes back empty, which callers read
  # as "no slug yet" and regenerate forever (a CSV re-import of a Cyrillic
  # catalogue inserted the whole feed again on every run).
  @cyrillic_map %{
    "а" => "a",
    "б" => "b",
    "в" => "v",
    "г" => "g",
    "ґ" => "g",
    "д" => "d",
    "е" => "e",
    "ё" => "e",
    "є" => "ie",
    "ж" => "zh",
    "з" => "z",
    "и" => "i",
    "і" => "i",
    "ї" => "i",
    "й" => "i",
    "к" => "k",
    "л" => "l",
    "м" => "m",
    "н" => "n",
    "о" => "o",
    "п" => "p",
    "р" => "r",
    "с" => "s",
    "т" => "t",
    "у" => "u",
    "ф" => "f",
    "х" => "h",
    "ц" => "ts",
    "ч" => "ch",
    "ш" => "sh",
    "щ" => "shch",
    "ъ" => "",
    "ы" => "y",
    "ь" => "",
    "э" => "e",
    "ю" => "yu",
    "я" => "ya"
  }

  @doc """
  Converts the given `text` into a slug.

  Options:
    * `:separator` - character used between words (defaults to "-")
    * `:transliterate` - map Cyrillic to Latin and strip Latin diacritics
      before the ASCII pass (defaults to `false`)

  Returns an empty string when the input is blank or cannot be converted.
  """
  @spec slugify(String.t() | nil, keyword()) :: String.t()
  def slugify(text, opts \\ [])

  def slugify(nil, _opts), do: ""

  def slugify(text, opts) when is_binary(text) do
    separator = Keyword.get(opts, :separator, "-")
    escaped_separator = Regex.escape(separator)

    text
    |> String.downcase()
    |> maybe_transliterate(Keyword.get(opts, :transliterate, false))
    |> String.replace(~r/[^a-z0-9]+/u, separator)
    |> String.replace(~r/#{escaped_separator}+/, separator)
    |> String.trim(separator)
  end

  def slugify(_text, _opts), do: ""

  @doc """
  Maps lowercase Cyrillic characters to Latin and strips Latin diacritics.

  Anything outside those scripts is returned unchanged — the caller's slug
  pass still has to remove it.
  """
  @spec transliterate(String.t()) :: String.t()
  def transliterate(text) when is_binary(text) do
    text
    |> String.graphemes()
    |> Enum.map_join("", &Map.get(@cyrillic_map, &1, &1))
    |> String.normalize(:nfd)
    |> String.replace(~r/[\x{0300}-\x{036f}]/u, "")
  end

  defp maybe_transliterate(text, true), do: transliterate(text)
  defp maybe_transliterate(text, _), do: text

  @doc """
  Ensures the provided slug is unique by calling `exists_fun`.

  `exists_fun` should return truthy when the slug is already taken.
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
