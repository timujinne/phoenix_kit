defmodule PhoenixKit.Modules.Sitemap.DomainMode do
  @moduledoc """
  Multi-domain sitemap post-processing (one domain = one canonical language).

  Activated by a host-app provider:

      config :phoenix_kit, :sitemap_domains_provider, {MyAppWeb.SEO, :sitemap_domains}

  The provider returns `[%{host: "example.fr", language: "fr", primary: false}, ...]`.
  The result is VALIDATED here — exactly one `primary: true`, every host a
  distinct language (base-code level), well-formed hosts. Any violation
  deactivates domain mode (with a warning) rather than silently producing
  malformed URLs or dropping x-default.

  `rebuild_for_domains/2` regroups the entries the generator already
  collected across languages: for the domain of language L, every canonical
  group that HAS an L entry contributes one URL — L's own entry re-hosted on
  that domain with its locale prefix stripped (L is the default there) —
  carrying an alternates set computed ONCE per group (identical across all
  domain files by construction): each group language on its home URL, plus
  `x-default` for the primary domain's language when the group has it
  (omitted otherwise — never mislabel another language as x-default).

  Runs inside Oban jobs and unpiped controller requests: language resolution
  here never consults the request-scoped default-language override — the
  unprefixed-entry fallback reads the raw `is_default` flag, mirroring the
  generator's hardened `get_languages/0`.

  NB: the generator's `base_url` (Settings `site_url`) and the provider's
  primary host are independently-edited settings that must refer to the same
  site; rel-path extraction below is host-string-agnostic, so a mismatch
  yields consistent (if unexpected-host) URLs rather than corruption.
  """

  require Logger

  alias PhoenixKit.Modules.Languages
  alias PhoenixKit.Modules.Languages.DialectMapper
  alias PhoenixKit.Modules.Sitemap.UrlEntry

  @host_re ~r/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/
  @locale_prefix_re ~r/^\/([a-z]{2,3}(?:-[A-Za-z]{2,4})?)(?:\/|$)/

  @type domain :: %{host: String.t(), language: String.t(), primary: boolean()}

  @doc "Validated provider domains; [] (inactive) on any contract violation."
  @spec domains() :: [domain()]
  def domains do
    case Application.get_env(:phoenix_kit, :sitemap_domains_provider) do
      {mod, fun} -> mod |> apply(fun, []) |> validate()
      _ -> []
    end
  rescue
    error ->
      Logger.warning("[Sitemap] sitemap_domains_provider raised: #{Exception.message(error)}")
      []
  end

  @doc false
  @spec active?() :: boolean()
  def active?, do: domains() != []

  defp validate(list) when is_list(list) and list != [] do
    normalized =
      Enum.map(list, fn %{host: host, language: language} = d ->
        %{
          host: host |> to_string() |> String.downcase(),
          language: DialectMapper.extract_base(to_string(language)),
          primary: Map.get(d, :primary, false) == true
        }
      end)

    cond do
      Enum.any?(normalized, &(not Regex.match?(@host_re, &1.host))) ->
        warn_invalid("malformed host")

      Enum.count(normalized, & &1.primary) != 1 ->
        warn_invalid("exactly one primary domain required")

      normalized |> Enum.map(& &1.language) |> Enum.uniq() |> length() != length(normalized) ->
        warn_invalid("each host must map a distinct language")

      true ->
        normalized
    end
  rescue
    error ->
      Logger.warning("[Sitemap] invalid sitemap_domains_provider data: #{inspect(error)}")
      []
  end

  defp validate(_), do: []

  defp warn_invalid(reason) do
    Logger.warning("[Sitemap] domain mode disabled: #{reason}")
    []
  end

  @doc """
  Regroups collected entries into per-domain URL sets: `%{host => [UrlEntry.t()]}`.
  """
  @spec rebuild_for_domains([UrlEntry.t()], String.t()) :: %{String.t() => [UrlEntry.t()]}
  def rebuild_for_domains(entries, base_url) do
    case domains() do
      [] ->
        %{}

      domains ->
        default_lang = raw_default_language()
        enabled_bases = enabled_language_bases()
        host_by_lang = Map.new(domains, &{&1.language, &1.host})
        primary = Enum.find(domains, & &1.primary)

        groups =
          entries
          |> Enum.group_by(fn e -> e.canonical_path || {:loc, e.loc} end)
          |> Map.values()
          |> Enum.map(&group_by_language(&1, base_url, default_lang, enabled_bases))

        Map.new(domains, fn %{host: host, language: lang} ->
          {host, domain_entries(groups, lang, host_by_lang, primary, base_url)}
        end)
    end
  end

  defp group_by_language(members, base_url, default_lang, enabled_bases) do
    Map.new(members, fn e -> {entry_language(e, base_url, default_lang, enabled_bases), e} end)
  end

  defp domain_entries(groups, lang, host_by_lang, primary, base_url) do
    groups
    |> Enum.flat_map(fn by_lang ->
      case by_lang[lang] do
        nil ->
          []

        entry ->
          alternates = group_alternates(by_lang, host_by_lang, primary, base_url)

          [
            %{
              entry
              | loc: home_url(lang, entry, host_by_lang, primary, base_url),
                alternates: alternates
            }
          ]
      end
    end)
    |> Enum.sort_by(& &1.loc)
  end

  # Computed once per group and reused verbatim for every domain that carries
  # the group — the spec's "identical hreflang set on every duplicate".
  defp group_alternates(by_lang, host_by_lang, primary, base_url) do
    links =
      by_lang
      |> Enum.sort_by(fn {lang, _} -> lang end)
      |> Enum.map(fn {lang, entry} ->
        %{hreflang: lang, href: home_url(lang, entry, host_by_lang, primary, base_url)}
      end)

    case by_lang[primary.language] do
      nil ->
        links

      primary_entry ->
        links ++
          [
            %{
              hreflang: "x-default",
              href: home_url(primary.language, primary_entry, host_by_lang, primary, base_url)
            }
          ]
    end
  end

  defp home_url(lang, %UrlEntry{loc: loc}, host_by_lang, primary, base_url) do
    rel = String.replace_prefix(loc, String.trim_trailing(base_url, "/"), "")
    rel = if String.starts_with?(rel, "/"), do: rel, else: "/" <> rel

    case host_by_lang[lang] do
      nil -> "https://#{primary.host}#{rel}"
      host -> "https://#{host}#{strip_own_prefix(rel, lang)}"
    end
  end

  defp strip_own_prefix(rel, lang) do
    case String.split(rel, "/", parts: 3) do
      ["", ^lang] -> "/"
      ["", ^lang, rest] -> "/" <> rest
      _ -> rel
    end
  end

  # Language of an entry, from its loc's locale prefix — only when the
  # segment is a real enabled language (a "/api/..." first segment is not a
  # locale). Unprefixed entries (home, router-discovery) belong to the site
  # default. Reads the RAW is_default flag — never the request-scoped
  # override (Oban/unpiped safe).
  defp entry_language(%UrlEntry{loc: loc}, base_url, default_lang, enabled_bases) do
    rel = String.replace_prefix(loc, String.trim_trailing(base_url, "/"), "")

    with [_, code] <- Regex.run(@locale_prefix_re, rel),
         base = DialectMapper.extract_base(code),
         true <- base in enabled_bases do
      base
    else
      _ -> default_lang
    end
  end

  defp enabled_language_bases do
    if Languages.enabled?() do
      Languages.get_enabled_languages()
      |> Enum.map(&DialectMapper.extract_base(&1.code))
      |> MapSet.new()
    else
      MapSet.new()
    end
  rescue
    _ -> MapSet.new()
  end

  defp raw_default_language do
    if Languages.enabled?() do
      case Enum.find(Languages.get_languages(), & &1.is_default) do
        %{code: code} -> DialectMapper.extract_base(code)
        _ -> "en"
      end
    else
      "en"
    end
  rescue
    _ -> "en"
  end
end
