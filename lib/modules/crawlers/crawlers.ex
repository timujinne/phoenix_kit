defmodule PhoenixKit.Modules.Crawlers do
  @moduledoc """
  Crawlers module — who may read this site, and what we tell them.

  Renamed from `PhoenixKit.Modules.SEO` (V172 migrates the stored settings and
  permission rows): everything here is bot *policy* — indexing directives,
  per-bot-group access, crawler guidance — while actual SEO work (rank
  tracking) lives in the external `phoenix_kit_seo` package. The old name
  promised meta tags and Open Graph, which were never here (Open Graph is its
  own module).

  ## What it controls

    * A global `noindex, nofollow` robots directive — the staging-safety
      switch, injected into every layout head.
    * Per-group bot access toggles (`PhoenixKit.Modules.Crawlers.Bots`), which
      drive the generated `robots.txt` contents
      (`PhoenixKit.Modules.Crawlers.RobotsTxt`) and, optionally, best-effort
      application-level blocking (`PhoenixKitWeb.Plugs.CrawlerBlocker`).
    * `llms.txt` — a generated markdown summary served at `/llms.txt` telling
      AI assistants what this site is about.
    * Search-engine verification meta tags (Google Search Console, Bing).

  All access toggles default to **allowed** and enforcement defaults to
  **off**, so enabling the module changes nothing until the operator decides.
  """
  use PhoenixKit.Module

  alias PhoenixKit.Dashboard.Tab
  alias PhoenixKit.Modules.Crawlers.Bots
  alias PhoenixKit.Modules.Sitemap.Generator
  alias PhoenixKit.Settings

  @module_enabled_key "crawlers_module_enabled"
  @no_index_key "crawlers_no_index"
  @block_at_app_key "crawlers_block_at_app"
  @google_verification_key "crawlers_google_verification"
  @bing_verification_key "crawlers_bing_verification"
  @llms_txt_extra_key "crawlers_llms_extra"
  @module_name "crawlers"

  @doc """
  Indicates whether the Crawlers module is available in the admin.
  """
  def module_enabled? do
    Settings.get_boolean_setting(@module_enabled_key, false)
  end

  @doc """
  Enables the Crawlers module (exposes the settings page).
  """
  def enable_module do
    Settings.update_boolean_setting_with_module(@module_enabled_key, true, @module_name)
  end

  @doc """
  Disables the Crawlers module and clears any active directives.
  """
  def disable_module do
    case Settings.update_boolean_setting_with_module(@module_enabled_key, false, @module_name) do
      {:ok, _setting} = result ->
        # Ensure site becomes indexable once the module is disabled
        _ = update_no_index(false)
        result

      {:error, _changeset} = error ->
        error
    end
  end

  @doc """
  Returns true when the `noindex, nofollow` directive is active.
  """
  def no_index_enabled? do
    Settings.get_boolean_setting(@no_index_key, false)
  end

  @doc """
  Enables the global `noindex, nofollow` directive.
  """
  def enable_no_index do
    update_no_index(true)
  end

  @doc """
  Disables the global `noindex, nofollow` directive.
  """
  def disable_no_index do
    update_no_index(false)
  end

  @doc """
  Updates the directive to the provided boolean value.
  """
  def update_no_index(enabled?) when is_boolean(enabled?) do
    result = Settings.update_boolean_setting_with_module(@no_index_key, enabled?, @module_name)

    # The directive flips what the sitemap must advertise. Drop the cached
    # sitemap and regenerate so `/sitemap.xml` reflects the new state instead of
    # serving a stale file. Best-effort — never let it break the toggle.
    refresh_sitemap()

    result
  end

  # ── Bot group access ────────────────────────────────────────────────────────

  @doc """
  Whether a bot group is currently allowed. Unknown groups read as allowed —
  the registry is the allowlist of what can be *blocked*, and failing open
  matches the module's default-allow stance.
  """
  @spec group_allowed?(Bots.group() | String.t()) :: boolean()
  def group_allowed?(group_key) do
    Settings.get_boolean_setting(group_setting_key(group_key), true)
  end

  @doc """
  Allow or block a bot group.
  """
  @spec update_group_allowed(Bots.group() | String.t(), boolean()) ::
          {:ok, term()} | {:error, term()}
  def update_group_allowed(group_key, allowed?) when is_boolean(allowed?) do
    Settings.update_boolean_setting_with_module(
      group_setting_key(group_key),
      allowed?,
      @module_name
    )
  end

  @doc "The settings key holding a group's allow/block state."
  @spec group_setting_key(Bots.group() | String.t()) :: String.t()
  def group_setting_key(group_key), do: "crawlers_allow_#{group_key}"

  @doc "Keys of the groups currently blocked, in registry order."
  @spec blocked_groups() :: [Bots.group()]
  def blocked_groups do
    Enum.reject(Bots.group_keys(), &group_allowed?/1)
  end

  # ── Application-level blocking ──────────────────────────────────────────────

  @doc """
  Whether best-effort application-level blocking is on. Default off: robots.txt
  is the honest mechanism, and UA-matching is advisory-grade enforcement for
  bots that ignore it.
  """
  def block_at_app_enabled? do
    Settings.get_boolean_setting(@block_at_app_key, false)
  end

  @doc "Enable or disable application-level blocking of blocked groups' UAs."
  def update_block_at_app(enabled?) when is_boolean(enabled?) do
    Settings.update_boolean_setting_with_module(@block_at_app_key, enabled?, @module_name)
  end

  # ── Verification metas ──────────────────────────────────────────────────────

  @doc """
  Verification meta tags to inject into layout heads, as `{name, content}`
  tuples. Empty contents are dropped, so unset slots render nothing.
  """
  @spec verification_metas() :: [{String.t(), String.t()}]
  def verification_metas do
    [
      {"google-site-verification", Settings.get_setting(@google_verification_key, "")},
      {"msvalidate.01", Settings.get_setting(@bing_verification_key, "")}
    ]
    |> Enum.reject(fn {_name, content} -> content in [nil, ""] end)
  end

  @doc "Current Google Search Console verification content (raw setting)."
  def google_verification, do: Settings.get_setting(@google_verification_key, "")

  @doc "Current Bing (msvalidate.01) verification content (raw setting)."
  def bing_verification, do: Settings.get_setting(@bing_verification_key, "")

  @doc """
  Store the verification contents. Values are trimmed; pasting a full
  `<meta ...>` tag is a common slip, so the `content="..."` value is extracted
  from one rather than stored verbatim.
  """
  def update_verifications(google, bing) when is_binary(google) and is_binary(bing) do
    with {:ok, _} <-
           Settings.update_setting_with_module(
             @google_verification_key,
             normalize_verification(google),
             @module_name
           ),
         {:ok, _} <-
           Settings.update_setting_with_module(
             @bing_verification_key,
             normalize_verification(bing),
             @module_name
           ) do
      :ok
    end
  end

  defp normalize_verification(value) do
    value = String.trim(value)

    case Regex.run(~r/content=["']([^"']*)["']/, value) do
      [_, content] -> content
      nil -> value
    end
  end

  # ── llms.txt ────────────────────────────────────────────────────────────────

  @doc "Operator-provided extra markdown appended to the generated llms.txt."
  def llms_txt_extra, do: Settings.get_setting(@llms_txt_extra_key, "")

  @doc "Store the operator's extra llms.txt markdown."
  def update_llms_txt_extra(markdown) when is_binary(markdown) do
    Settings.update_setting_with_module(@llms_txt_extra_key, markdown, @module_name)
  end

  @impl PhoenixKit.Module
  @doc """
  Returns configuration metadata for dashboard cards and settings pages.
  """
  def get_config do
    %{
      module_enabled: module_enabled?(),
      no_index_enabled: no_index_enabled?(),
      blocked_groups: blocked_groups(),
      block_at_app: block_at_app_enabled?()
    }
  end

  # Invalidate + regenerate the sitemap after a noindex change. Wrapped so a
  # sitemap/Oban hiccup can never fail the settings write.
  defp refresh_sitemap do
    Generator.invalidate_and_regenerate()
    :ok
  rescue
    _ -> :ok
  end

  # ============================================================================
  # Module Behaviour Callbacks
  # ============================================================================

  @impl PhoenixKit.Module
  def module_key, do: "crawlers"

  @impl PhoenixKit.Module
  def module_name, do: "Crawlers"

  @impl PhoenixKit.Module
  def enabled?, do: module_enabled?()

  @impl PhoenixKit.Module
  def enable_system, do: enable_module()

  @impl PhoenixKit.Module
  def disable_system, do: disable_module()

  @impl PhoenixKit.Module
  def permission_metadata do
    %{
      key: "crawlers",
      label: "Crawlers",
      icon: "hero-bug-ant",
      description: "Indexing directives, bot access controls, and crawler guidance"
    }
  end

  @impl PhoenixKit.Module
  def settings_tabs do
    [
      Tab.new!(
        id: :admin_settings_crawlers,
        label: "Crawlers",
        icon: "hero-bug-ant",
        path: "crawlers",
        priority: 930,
        level: :admin,
        parent: :admin_settings,
        permission: "crawlers",
        gettext_backend: PhoenixKitWeb.Gettext
      )
    ]
  end
end
