defmodule PhoenixKit.Modules.Sitemap.Sources.RouterDiscovery do
  @moduledoc """
  Router Discovery source for sitemap generation.

  Automatically scans all GET routes from the parent application's router
  and includes them in the sitemap. Routes can be filtered using exclude
  patterns and include-only patterns.

  ## Settings

  - `sitemap_router_discovery_enabled` - Enable/disable auto-discovery (default: true)
  - `sitemap_router_discovery_exclude_patterns` - JSON array of regex patterns to exclude
  - `sitemap_router_discovery_include_only` - JSON array of regex patterns for whitelist mode
  - `sitemap_protected_pipelines` - JSON array of pipeline names that require authentication

  ## Pattern Syntax

  Exclude and include-only patterns are **regular expressions** (compiled with
  `Regex.compile/1`), not shell globs. A bare `"*"` is an invalid regex and is
  ignored with a logged warning — use `".*"` to match everything or `"^/prefix"`
  to match a path prefix. Invalid patterns never silently disable the source.

  ## Default Exclusions

  Custom exclude patterns **add to** the built-in defaults; they do not replace
  them. A host that saves one pattern of its own keeps every admin, auth and
  infrastructure exclusion, and picks up new defaults from later PhoenixKit
  versions. Saving `"!replace"` as the first entry opts into replacement.

  By default, the following patterns are excluded:
  - `^/admin` - Admin routes
  - `^/api` - API endpoints
  - `^/phoenix_kit` - PhoenixKit admin routes
  - `^/dev` - Development routes
  - `^/__` - Internal/technical routes (double-underscore convention, e.g.
    Publishing's internal dispatch scope)
  - `^/maintenance$` - PhoenixKit's reserved maintenance page route
  - `:[a-z_]+` - Routes with parameters
  - `\\*` - Wildcard routes

  Additionally, routes using authentication pipelines are automatically excluded:
  - `:phoenix_kit_require_authenticated` - Routes requiring user authentication
  - `:phoenix_kit_admin_only` - Routes requiring admin/owner role
  - `:authenticated` - Common name for authentication pipeline
  - `:require_authenticated` - Alternative authentication pipeline name
  - `:admin` - Common admin pipeline name
  - `:admin_only` - Alternative admin pipeline name

  Custom pipelines can be added via `sitemap_protected_pipelines` setting.

  LiveView routes using authentication `on_mount` hooks are also excluded:
  - `{PhoenixKitWeb.Users.Auth, :phoenix_kit_ensure_authenticated_scope}` - Ensures user is authenticated
  - `{PhoenixKitWeb.Users.Auth, :phoenix_kit_redirect_if_authenticated_scope}` - Redirects if already authenticated

  ## Examples

      # Enable auto-discovery (default)
      Settings.update_boolean_setting("sitemap_router_discovery_enabled", true)

      # Custom exclude patterns (added to the defaults)
      Settings.update_setting("sitemap_router_discovery_exclude_patterns",
        JSON.encode!(["^/private"]))

      # Replace the defaults entirely (rarely what you want — this is how an
      # authenticated URL ends up in a search index)
      Settings.update_setting("sitemap_router_discovery_exclude_patterns",
        JSON.encode!(["!replace", "^/private"]))

      # Whitelist mode - only include specific paths
      Settings.update_setting("sitemap_router_discovery_include_only",
        JSON.encode!(["^/products", "^/categories"]))

      # Custom protected pipelines (add to defaults)
      Settings.update_setting("sitemap_protected_pipelines",
        JSON.encode!(["my_auth_pipeline", "member_only"]))

  ## Sitemap Properties

  - Priority: 0.5 (default for discovered routes)
  - Change frequency: weekly
  - Category: "Routes"
  """

  @behaviour PhoenixKit.Modules.Sitemap.Sources.Source

  require Logger

  alias PhoenixKit.Modules.Sitemap.RouteResolver
  alias PhoenixKit.Modules.Sitemap.UrlEntry
  alias PhoenixKit.Settings

  # First entry of a saved exclude list to opt out of extending the defaults.
  # Not a regex — matched literally before compilation, so it can never be
  # confused with a real pattern.
  @replace_sentinel "!replace"

  @default_exclude_patterns [
    "^/admin",
    "^/api",
    "^/phoenix_kit",
    "^/dev",
    "^/test",
    "^/dashboard",
    # Internal/technical routes (double-underscore convention, e.g. Publishing's
    # "/__phoenix_kit_publishing_dispatch" catch-all dispatch scope) and
    # PhoenixKit's reserved maintenance page - neither is public content
    "^/__",
    "^/maintenance$",
    ":[a-z_]+",
    "\\*",
    # Auth pages - should not be indexed by search engines
    "/users/log-in",
    "/users/log-out",
    "/users/register",
    "/users/reset-password",
    "/users/confirm",
    "/users/referral",
    "/users/magic-link",
    "/users/settings",
    # QR device-handoff login: a public route with no auth pipeline and no
    # on_mount hook (the redirect-if-authenticated check lives in its mount/3),
    # so only this pattern keeps it out — and "/users/log-in" does not match it.
    "/users/qr-login",
    # Internal/functional pages - not for search engine indexing
    "/checkout",
    "/cart",
    "/newsletters/unsubscribe",
    "/health",
    "/ready",
    # Infrastructure. `/file`, `/tiles` and `/api/files` are storage-serving
    # routes; they are listed explicitly rather than left to `^/phoenix_kit`
    # and `^/api`, because a root-mounted install has no `/phoenix_kit` prefix
    # for the first two to hide behind.
    "/sitemap\\.",
    "/sitemaps/",
    "/assets/",
    "^/file/",
    "^/tiles/",
    "^/api/files",
    # Host apps that serve robots.txt from a controller (rather than
    # Plug.Static) expose it as a GET route — it is a directive file, not a page
    "^/robots\\.txt$",
    # Homepage is handled by Static source
    "^/$"
  ]

  # Default pipelines that require authentication - routes using these should not appear in sitemap
  # Can be extended via Settings: sitemap_protected_pipelines
  @default_protected_pipelines [
    :phoenix_kit_require_authenticated,
    :phoenix_kit_admin_only,
    :authenticated,
    :require_authenticated,
    :admin,
    :admin_only
  ]

  # Default on_mount hooks that require authentication (for LiveView routes)
  # Format: {Module, hook_name} - matches against on_mount id tuples
  @default_protected_on_mount_hooks [
    {PhoenixKitWeb.Users.Auth, :phoenix_kit_ensure_authenticated_scope},
    {PhoenixKitWeb.Users.Auth, :phoenix_kit_redirect_if_authenticated_scope}
  ]

  # Mapping of route prefixes to module enabled? checks
  # Routes with these prefixes are excluded from sitemap when the module is disabled
  @module_route_prefixes %{
    "/shop" => {PhoenixKitEcommerce, :enabled?},
    "/newsletters" => {PhoenixKit.Newsletters, :enabled?},
    "/publishing" => {PhoenixKit.Modules.Publishing, :enabled?},
    "/connections" => {PhoenixKit.Modules.Connections, :enabled?}
  }

  @impl true
  def source_name, do: :router_discovery

  @impl true
  def sitemap_filename, do: "sitemap-routes"

  @impl true
  def enabled? do
    Settings.get_boolean_setting("sitemap_router_discovery_enabled", true)
  end

  @impl true
  def collect(opts \\ []) do
    if enabled?() do
      do_collect(opts)
    else
      []
    end
  rescue
    error ->
      Logger.warning("RouterDiscovery source failed: #{inspect(error)}")
      []
  end

  ## Settings UI helpers

  @doc """
  Returns the subset of `patterns` that fail to compile as regexes.

  Mirrors the same `Regex.compile/1` check `compile_patterns/2` applies at
  collection time, so a pattern accepted here is guaranteed not to be
  silently dropped later. Used by the settings UI to reject invalid
  exclude/include-only patterns before saving, instead of persisting them
  and only discovering the problem in the logs.

  ## Examples

      iex> PhoenixKit.Modules.Sitemap.Sources.RouterDiscovery.invalid_patterns(["^/admin", "*"])
      ["*"]
  """
  @spec invalid_patterns([String.t()]) :: [String.t()]
  def invalid_patterns(patterns) when is_list(patterns) do
    Enum.filter(patterns, &match?({:error, _}, Regex.compile(&1)))
  end

  @doc """
  Returns the built-in default exclude patterns.

  Custom patterns saved in `sitemap_router_discovery_exclude_patterns` **add
  to** this list — matching how `sitemap_protected_pipelines` has always
  behaved. A saved list used to replace these outright, which made the setting
  a one-way door: adding a single pattern of your own silently un-excluded
  every admin, auth and infrastructure route, and later PhoenixKit versions
  could never ship a new default to that install.

  To genuinely replace the defaults, save the special entry `"!replace"` as the
  first pattern. That is deliberately awkward, because it is the option that
  can publish an authenticated URL to a search engine.
  """
  @spec default_exclude_patterns() :: [String.t()]
  def default_exclude_patterns, do: @default_exclude_patterns

  @doc """
  The sentinel that makes a saved exclude list replace the defaults instead of
  extending them.
  """
  @spec replace_defaults_sentinel() :: String.t()
  def replace_defaults_sentinel, do: @replace_sentinel

  @doc """
  Returns the built-in default protected pipelines.

  Unlike exclude patterns, `sitemap_protected_pipelines` only *adds* to this
  list — these defaults always apply. Exposed so the settings UI can show
  admins which pipelines are already protected without configuration.
  """
  @spec default_protected_pipelines() :: [atom()]
  def default_protected_pipelines, do: @default_protected_pipelines

  defp do_collect(opts) do
    base_url = Keyword.get(opts, :base_url)
    exclude_patterns = compile_patterns(effective_exclude_patterns(), "exclude")
    include_only = compile_include_only(get_include_only_patterns())

    RouteResolver.get_routes()
    |> Enum.filter(&valid_for_sitemap?(&1, exclude_patterns, include_only))
    |> Enum.map(&build_entry(&1, base_url))
    |> Enum.uniq_by(& &1.loc)
  end

  defp valid_for_sitemap?(route, exclude_patterns, include_only) do
    get_route?(route) and
      not excluded?(route.path, exclude_patterns) and
      included?(route.path, include_only) and
      not protected_by_route_info?(route) and
      not disabled_module_route?(route.path)
  end

  # Single route_info call checks both pipelines and on_mount hooks
  defp protected_by_route_info?(route) do
    case get_route_info(route.path) do
      nil ->
        false

      info ->
        has_protected_pipeline?(info) or has_protected_on_mount?(info)
    end
  end

  # Get route_info once per route (instead of twice)
  defp get_route_info(path) do
    case RouteResolver.get_router() do
      nil -> nil
      router -> Phoenix.Router.route_info(router, "GET", path, "localhost")
    end
  rescue
    _ -> nil
  end

  # Check if route_info has protected pipelines
  defp has_protected_pipeline?(%{pipe_through: pipelines}) when is_list(pipelines) do
    protected_pipelines = get_protected_pipelines()
    Enum.any?(protected_pipelines, &(&1 in pipelines))
  end

  defp has_protected_pipeline?(_), do: false

  # Check if route_info has protected on_mount hooks
  defp has_protected_on_mount?(%{
         phoenix_live_view: {_module, _action, _opts, %{extra: %{on_mount: hooks}}}
       })
       when is_list(hooks) do
    hook_ids = Enum.map(hooks, & &1.id)
    Enum.any?(@default_protected_on_mount_hooks, &(&1 in hook_ids))
  end

  defp has_protected_on_mount?(_), do: false

  defp get_protected_pipelines do
    custom_pipelines = get_custom_protected_pipelines()
    @default_protected_pipelines ++ custom_pipelines
  end

  defp get_custom_protected_pipelines do
    case Settings.get_setting("sitemap_protected_pipelines") do
      nil ->
        []

      json_string when is_binary(json_string) ->
        case JSON.decode(json_string) do
          {:ok, pipelines} when is_list(pipelines) ->
            Enum.map(pipelines, &safe_to_atom/1)

          _ ->
            []
        end

      pipelines when is_list(pipelines) ->
        Enum.map(pipelines, &safe_to_atom/1)

      _ ->
        []
    end
  end

  defp safe_to_atom(value) when is_atom(value), do: value
  defp safe_to_atom(value) when is_binary(value), do: String.to_atom(value)

  defp disabled_module_route?(path) do
    Enum.any?(@module_route_prefixes, fn {prefix, {mod, fun}} ->
      String.starts_with?(path, prefix) and not module_enabled?(mod, fun)
    end)
  end

  defp module_enabled?(mod, fun) do
    Code.ensure_loaded?(mod) and function_exported?(mod, fun, 0) and apply(mod, fun, [])
  rescue
    _ -> false
  end

  defp get_route?(route) do
    route.verb == :get
  end

  defp excluded?(path, regexes) do
    Enum.any?(regexes, &Regex.match?(&1, path))
  end

  # `:all` means no include-only patterns were configured → include everything.
  defp included?(_path, :all), do: true
  defp included?(path, {:whitelist, regexes}), do: Enum.any?(regexes, &Regex.match?(&1, path))

  # An unset/empty whitelist keeps the "include all" behavior; a configured
  # whitelist is compiled so an all-invalid list still excludes everything
  # (now with a logged warning) rather than silently flipping to include-all.
  defp compile_include_only([]), do: :all

  defp compile_include_only(patterns),
    do: {:whitelist, compile_patterns(patterns, "include_only")}

  # Compile raw pattern strings into `Regex` structs, logging and dropping any
  # that fail to compile. Patterns are regular expressions (not shell globs):
  # a bare "*" fails to compile and would otherwise be swallowed silently,
  # masking a misconfiguration (e.g. an include-only "*" would suppress the
  # entire source with no diagnostic trail).
  defp compile_patterns(patterns, context) do
    Enum.flat_map(patterns, fn pattern ->
      case Regex.compile(pattern) do
        {:ok, regex} ->
          [regex]

        {:error, reason} ->
          Logger.warning(
            "RouterDiscovery: ignoring invalid #{context} pattern #{inspect(pattern)} " <>
              "(#{inspect(reason)}). Patterns are regular expressions, not globs — " <>
              "use \".*\" to match everything or \"^/prefix\" for a path prefix."
          )

          []
      end
    end)
  end

  @doc """
  The exclude patterns actually in force: the built-in defaults plus whatever
  the host saved (or only the saved ones, behind the replace sentinel).

  Public so the settings UI and `mix phoenix_kit.doctor` can show the same
  answer collection uses, instead of each recomputing the merge.
  """
  @spec effective_exclude_patterns() :: [String.t()]
  def effective_exclude_patterns do
    "sitemap_router_discovery_exclude_patterns"
    |> Settings.get_setting()
    |> decode_patterns()
    |> merge_with_defaults()
  end

  defp decode_patterns(json_string) when is_binary(json_string) do
    case JSON.decode(json_string) do
      {:ok, patterns} when is_list(patterns) -> patterns
      _ -> []
    end
  end

  defp decode_patterns(patterns) when is_list(patterns), do: patterns
  defp decode_patterns(_), do: []

  # Saved patterns EXTEND the built-in defaults. Replacing them outright made
  # the setting a one-way door — adding one pattern of your own dropped every
  # admin and auth exclusion, and no later default could ever reach that
  # install. `"!replace"` as the first entry opts back into replacement for the
  # rare host that means it.
  defp merge_with_defaults([@replace_sentinel | patterns]), do: patterns

  defp merge_with_defaults(patterns),
    do: Enum.uniq(@default_exclude_patterns ++ patterns)

  defp get_include_only_patterns do
    case Settings.get_setting("sitemap_router_discovery_include_only") do
      nil ->
        []

      json_string when is_binary(json_string) ->
        case JSON.decode(json_string) do
          {:ok, patterns} when is_list(patterns) -> patterns
          _ -> []
        end

      patterns when is_list(patterns) ->
        patterns

      _ ->
        []
    end
  end

  defp build_entry(route, base_url) do
    url = build_url(route.path, base_url)
    title = extract_title(route)

    UrlEntry.new(%{
      loc: url,
      lastmod: module_lastmod(route),
      changefreq: "weekly",
      priority: 0.5,
      title: title,
      category: "Routes",
      source: :router_discovery
    })
  end

  # Approximate lastmod from the beam file modification time of the route's LiveView module.
  # Falls back to the plug module if no LiveView metadata is found.
  defp module_lastmod(route) do
    module = extract_liveview_module(route) || route.plug
    beam_file_mtime(module)
  rescue
    _ -> nil
  end

  defp extract_liveview_module(route) do
    case route.metadata do
      %{phoenix_live_view: {module, _, _, _}} when is_atom(module) -> module
      %{phoenix_live_view: {module, _, _}} when is_atom(module) -> module
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp beam_file_mtime(module) when is_atom(module) do
    case :code.which(module) do
      beam_path when is_list(beam_path) ->
        case File.stat(List.to_string(beam_path)) do
          {:ok, %{mtime: mtime}} ->
            NaiveDateTime.from_erl!(mtime) |> DateTime.from_naive!("Etc/UTC")

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  defp beam_file_mtime(_), do: nil

  defp build_url(path, nil) do
    base = Settings.get_setting("site_url", "")
    normalized_base = String.trim_trailing(base, "/")
    "#{normalized_base}#{path}"
  end

  defp build_url(path, base_url) when is_binary(base_url) do
    normalized_base = String.trim_trailing(base_url, "/")
    "#{normalized_base}#{path}"
  end

  defp extract_title(route) do
    # Try to extract meaningful title from plug module name
    plug_name =
      route.plug
      |> to_string()
      |> String.replace("Elixir.", "")
      |> String.split(".")
      |> List.last()

    # Convert CamelCase to Title Case
    plug_name
    |> String.replace(~r/([A-Z])/, " \\1")
    |> String.trim()
  end
end
