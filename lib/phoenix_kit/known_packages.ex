defmodule PhoenixKit.KnownPackages do
  @moduledoc """
  Live catalog of known external PhoenixKit packages fetched from Hex.pm.

  Fetched on demand and cached in an ETS table for 10 minutes. On Hex
  failure, returns stale cached data when within the 24h max-stale-age
  cap, otherwise returns `extra_known_packages` config entries only.

  Cache uses an ETS named table (`:phoenix_kit_known_packages_cache`) with
  `read_concurrency: true` rather than `:persistent_term`, to avoid
  global-GC write amplification on multi-node cold deploys.

  ## Public API

    * `list/0` and `list/1` — return the catalog (cached).
    * `clear_cache/0` — wipes the cache (for tests).

  `list/1` accepts opts (intended for tests, not production):

    * `:ttl_ms` — cache TTL (default `:timer.minutes(10)`)
    * `:max_stale_age_ms` — how long stale data may be served on Hex
      failure (default `:timer.hours(24)`)
    * `:req_options` — pass-through to `Req.get/2`

  ## Operational signals

  Hex outages emit Logger entries at three levels — each maps to a
  distinct degradation state operators can alert on:

    * `:warning` "Hex fetch failed … serving stale data" — cache hit
      within `max_stale_age_ms`. Catalog still works; Hex briefly
      unavailable. Transient.
    * `:warning` "Hex fetch failed … no cached data" — Hex unreachable
      AND cache empty. Catalog shows config extras only. Visible
      degradation, but not a crisis (admin Modules page is the only
      consumer).
    * `:error` "Hex fetch failed … exceeds max stale age" — Hex
      unreachable for over `max_stale_age_ms`. Cached entries
      dropped, catalog falls back to config extras. The escalation
      level: page on this if it persists.
  """

  require Logger

  @table :phoenix_kit_known_packages_cache
  @cache_key :cache
  @status_key :status
  @hex_search_url "https://hex.pm/api/packages"
  @icon_marker_re ~r/\bhex_docs_icon_name:\s*([a-z0-9-]+)/
  @default_icon "hero-puzzle-piece"
  @skip_packages ["phoenix_kit"]
  @ttl_ms :timer.minutes(10)
  @max_stale_age_ms :timer.hours(24)
  @default_req_options [receive_timeout: 3000]
  @beamlab_org "BeamLabEU"

  @doc """
  Returns the list of known external PhoenixKit packages.

  Each entry is a map with keys: `key`, `module`, `package`,
  `hex_package`, `name`, `description`, `icon`, `hex_url`, `github_url`,
  `latest_version`, `source`.

  See module doc for `opts`.
  """
  @spec list(keyword()) :: [map()]
  def list(opts \\ []) do
    ensure_table()
    now = System.monotonic_time(:millisecond)
    ttl = Keyword.get(opts, :ttl_ms, @ttl_ms)

    case lookup() do
      {fetched_at, cached} when now - fetched_at < ttl ->
        cached

      _ ->
        fetch_and_cache(now, opts)
    end
  end

  @doc """
  Whether the last catalog read reached hex.pm.

  `:ok` — fresh data. `{:stale, age_minutes}` — hex.pm was unreachable but
  cached data is still being served. `:unavailable` — unreachable with nothing
  usable cached, so `list/1` returned config extras only.

  The UI needs this because "hex.pm is down" and "there are no packages" produce
  the same empty list, and showing the second when the first is true tells the
  operator something false.
  """
  @spec status() :: :ok | {:stale, non_neg_integer()} | :unavailable
  def status do
    case :ets.lookup(@table, @status_key) do
      [{@status_key, status}] -> status
      [] -> :ok
    end
  rescue
    ArgumentError -> :ok
  end

  @doc """
  The human equivalent of the search this module runs against the Hex API.

  Offered when hex.pm is unreachable: a link stays current because Hex
  maintains it, where a catalog bundled into core would need a core release to
  add a package and would drift permanently.
  """
  @spec browse_url() :: String.t()
  def browse_url, do: "https://hex.pm/packages?search=phoenix_kit_&sort=name"

  @doc "Clears the in-process cache. Intended for tests."
  @spec clear_cache() :: :ok
  def clear_cache do
    ensure_table()
    :ets.delete(@table, @cache_key)
    :ets.delete(@table, @status_key)
    :ok
  end

  # ---------------------------------------------------------------------------
  # Private — cache mechanics
  # ---------------------------------------------------------------------------

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])

      _ ->
        :ok
    end
  rescue
    # Race: another process called :ets.new/2 between our :ets.whereis/1
    # check and our :ets.new/2. The named table now exists; nothing
    # more to do.
    ArgumentError -> :ok
  end

  defp lookup do
    case :ets.lookup(@table, @cache_key) do
      [{@cache_key, fetched_at, list}] -> {fetched_at, list}
      [] -> nil
    end
  end

  defp fetch_and_cache(now, opts) do
    case fetch_from_hex(opts) do
      {:ok, hex_list} ->
        merged = merge_extras(hex_list)
        :ets.insert(@table, {@cache_key, now, merged})
        put_status(:ok)
        merged

      {:error, reason} ->
        handle_hex_failure(reason, now, opts)
    end
  end

  defp handle_hex_failure(reason, now, opts) do
    max_stale = Keyword.get(opts, :max_stale_age_ms, @max_stale_age_ms)

    case lookup() do
      {fetched_at, stale} when now - fetched_at <= max_stale ->
        age_minutes = div(now - fetched_at, :timer.minutes(1))

        Logger.warning(
          "PhoenixKit.KnownPackages: Hex fetch failed (#{inspect(reason)}) — " <>
            "serving stale data (age=#{age_minutes}m)"
        )

        put_status({:stale, age_minutes})
        stale

      {fetched_at, _stale} ->
        age_hours = div(now - fetched_at, :timer.hours(1))

        Logger.error(
          "PhoenixKit.KnownPackages: Hex fetch failed (#{inspect(reason)}) and " <>
            "cached data exceeds max stale age (#{age_hours}h) — returning extras only"
        )

        :ets.delete(@table, @cache_key)
        put_status(:unavailable)
        merge_extras([])

      nil ->
        Logger.warning(
          "PhoenixKit.KnownPackages: Hex fetch failed (#{inspect(reason)}) and " <>
            "no cached data — returning extras only"
        )

        put_status(:unavailable)
        merge_extras([])
    end
  end

  defp put_status(status) do
    :ets.insert(@table, {@status_key, status})
    :ok
  rescue
    ArgumentError -> :ok
  end

  # ---------------------------------------------------------------------------
  # Private — Hex fetch
  # ---------------------------------------------------------------------------

  defp fetch_from_hex(opts) do
    url = @hex_search_url <> "?search=phoenix_kit_&sort=name"
    req_options = Keyword.get(opts, :req_options, @default_req_options)
    fetch_hex_page(url, [], req_options, 1)
  end

  # `page_count` cap (`@max_pages`) bounds the recursion: a malformed
  # `Link` header (next URL pointing back to the same page, or hex
  # returning many more results than expected) can't loop forever.
  # 100 packages/page * 20 pages = 2000 packages — comfortable
  # headroom for the `phoenix_kit_*` namespace today.
  @max_pages 20

  defp fetch_hex_page(_url, acc, _opts, page) when page > @max_pages do
    Logger.warning(
      "PhoenixKit.KnownPackages: Hex pagination exceeded #{@max_pages} pages — " <>
        "stopping (returning #{length(acc)} entries collected so far)"
    )

    {:ok, acc}
  end

  defp fetch_hex_page(nil, acc, _opts, _page), do: {:ok, acc}

  defp fetch_hex_page(url, acc, req_options, page) do
    case Req.get(url, req_options) do
      {:ok, %{status: 200, body: packages, headers: headers}} when is_list(packages) ->
        valid = packages |> Enum.reject(&skip_package?/1) |> Enum.map(&shape_entry/1)
        next_url = parse_next_link(headers)
        fetch_hex_page(next_url, acc ++ valid, req_options, page + 1)

      {:ok, %{status: 200}} ->
        {:error, :malformed_response}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, e}
  end

  defp skip_package?(%{"name" => name}), do: name in @skip_packages
  defp skip_package?(_), do: false

  defp parse_next_link(headers) when is_map(headers) do
    link = headers |> Map.get("link", []) |> List.first()

    with binary when is_binary(binary) <- link,
         [_, url] <- Regex.run(~r/<([^>]+)>;\s*rel="next"/, binary) do
      url
    else
      _ -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # Private — entry shape (kept backward-compatible with the previous
  # hardcoded list: includes module/hex_package/github_url/latest_version)
  # ---------------------------------------------------------------------------

  defp shape_entry(pkg) do
    package = pkg["name"]
    key = String.replace_prefix(package, "phoenix_kit_", "")
    raw_description = get_in(pkg, ["meta", "description"]) || ""
    {stripped_description, icon} = parse_marker(raw_description)

    %{
      key: key,
      module: derive_module_atom(package),
      package: package,
      hex_package: package,
      name: humanize_key(key),
      description: stripped_description,
      icon: icon,
      hex_url: "https://hex.pm/packages/#{package}",
      github_url: github_url_for(pkg, package),
      latest_version: pkg["latest_version"],
      source: "hex"
    }
  end

  defp derive_module_atom(package) do
    package
    |> String.split("_")
    |> Enum.map_join("", &String.capitalize/1)
    |> then(&("Elixir." <> &1))
    |> String.to_atom()
  end

  defp github_url_for(pkg, package) do
    links = get_in(pkg, ["meta", "links"]) || %{}
    github = links["GitHub"] || links["Github"] || links["github"]

    if is_binary(github) and String.contains?(github, "github.com") do
      github
    else
      "https://github.com/#{@beamlab_org}/#{package}"
    end
  end

  defp humanize_key(key) do
    key |> String.split("_") |> Enum.map_join(" ", &String.capitalize/1)
  end

  defp parse_marker(description) do
    case Regex.run(@icon_marker_re, description) do
      [full_match, icon_name] ->
        stripped = description |> String.replace(full_match, "") |> String.trim()
        {stripped, icon_name}

      nil ->
        {String.trim(description), @default_icon}
    end
  end

  # ---------------------------------------------------------------------------
  # Private — config extras (parent-app-provided private/forked packages)
  # ---------------------------------------------------------------------------

  defp merge_extras(hex_list) do
    extras =
      :phoenix_kit
      |> Application.get_env(:extra_known_packages, [])
      |> Enum.map(&normalize_config_entry/1)

    # Config wins: concat config first, then hex; uniq_by keeps the first
    (extras ++ hex_list) |> Enum.uniq_by(& &1.package)
  end

  defp normalize_config_entry(entry) do
    package = Map.get(entry, :package)

    entry
    |> Map.put(:source, "config")
    |> Map.put_new(:hex_package, package)
    |> Map.put_new(:module, nil)
    |> Map.put_new(:github_url, nil)
    |> Map.put_new(:latest_version, nil)
  end
end
