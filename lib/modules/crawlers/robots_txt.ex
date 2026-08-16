defmodule PhoenixKit.Modules.Crawlers.RobotsTxt do
  @moduledoc """
  Renders the complete `robots.txt` an operator should serve, from the
  Crawlers module's per-group toggles.

  PhoenixKit deliberately does **not** serve this file — `robots.txt` is host
  policy and `Plug.Static` answers before the router is consulted, so a
  generated route would be dead code on most installs and a silent override on
  the rest. What changed with the group toggles is how much there is to say:
  one `Sitemap:` line was dictation, a per-group policy is a file. So the
  settings page renders the whole thing for copy-paste, and this module is the
  pure builder behind it.

  ## Shape of the output

  robots.txt is default-allow, so only *blocked* groups produce stanzas — one
  `User-agent:` line per bot token, sharing a single `Disallow: /`. An
  explicit `User-agent: * / Disallow:` (empty = allow all) stanza leads the
  file so the operator's intent is visible rather than implied, and the
  `Sitemap:` line closes it.
  """

  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.Bots

  @doc """
  Build the robots.txt contents from the current settings.

  Options:

    * `:sitemap_url` — absolute URL for the `Sitemap:` line; omitted when nil.
  """
  @spec build(keyword()) :: String.t()
  def build(opts \\ []) do
    blocked = Enum.reject(Bots.group_keys(), &Crawlers.group_allowed?/1)
    build_for(blocked, opts)
  end

  @doc """
  Pure variant: build for an explicit list of blocked group keys. `build/1`
  reads the settings and delegates here; tests come in through this door.
  """
  @spec build_for([Bots.group()], keyword()) :: String.t()
  def build_for(blocked_group_keys, opts \\ []) do
    sitemap_url = Keyword.get(opts, :sitemap_url)

    sections =
      [allow_all_stanza()] ++
        Enum.map(blocked_group_keys, &blocked_stanza/1) ++
        sitemap_section(sitemap_url)

    sections
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

  defp allow_all_stanza do
    "# Default: everyone not listed below may crawl everything.\nUser-agent: *\nDisallow:\n"
  end

  defp blocked_stanza(group_key) do
    case Bots.group(group_key) do
      nil ->
        nil

      group ->
        agents = Enum.map_join(group.bots, "\n", &"User-agent: #{&1.token}")
        "# #{group.label}: blocked.\n#{agents}\nDisallow: /\n"
    end
  end

  defp sitemap_section(nil), do: []
  defp sitemap_section(url), do: ["Sitemap: #{url}\n"]
end
