defmodule PhoenixKitWeb.Components.Core.LanguageSwitcher do
  @moduledoc """
  Language switcher component for frontend and admin applications.

  Provides reusable language selection UI that pulls available languages
  from the unified Languages module. Three display variants are available:
  dropdown, button group, and inline.

  ## Continent Grouping

  When more than 7 languages are enabled (configurable via `continent_threshold`),
  the dropdown automatically shows a two-step interface: first pick a continent,
  then pick a language within it. Set `group_by_continent={false}` to always
  show a flat list regardless of language count.

  ## Examples

      # Basic dropdown — auto-groups by continent when >7 languages
      <.language_switcher_dropdown current_locale={@current_locale} />

      # Force flat list (no continent step)
      <.language_switcher_dropdown current_locale={@current_locale} group_by_continent={false} />

      # Custom threshold for continent grouping
      <.language_switcher_dropdown current_locale={@current_locale} continent_threshold={5} />

      # Show current language in trigger button
      <.language_switcher_dropdown current_locale={@current_locale} show_current={true} />

      # Button group (for mobile)
      <.language_switcher_buttons current_locale={@current_locale} />

      # Inline text links (for footers)
      <.language_switcher_inline current_locale={@current_locale} />
  """

  use Phoenix.Component

  alias Phoenix.LiveView.JS
  alias PhoenixKit.Config
  alias PhoenixKit.Modules.Languages
  alias PhoenixKit.Modules.Languages.DialectMapper
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.Utils.Values
  alias PhoenixKitWeb.Components.Core.Icon

  @default_locale Config.default_locale()

  @doc """
  Renders a dropdown language switcher.

  Displays a globe icon that opens a dropdown menu with available languages.
  Automatically fetches the configured languages (or defaults when unconfigured).
  Used in both frontend navigation bars and the admin panel header.

  When more than `continent_threshold` languages are enabled, shows a two-step
  continent → language navigation. Set `group_by_continent={false}` to disable.

  ## Examples

      <.language_switcher_dropdown current_locale={@current_locale} />

      <.language_switcher_dropdown
        current_locale={@current_locale}
        group_by_continent={false}
      />
  """
  attr(:current_locale, :string,
    default: nil,
    doc: "Current active language code (auto-detected if not provided)"
  )

  attr(:languages, :any,
    default: nil,
    doc: "List of language maps. If nil, fetches from Language Module"
  )

  attr(:show_flags, :boolean, default: true, doc: "Show language flags")
  attr(:show_names, :boolean, default: true, doc: "Show language names")
  attr(:show_native_names, :boolean, default: false, doc: "Show native language names")
  attr(:goto_home, :boolean, default: false, doc: "Redirect to home page on language switch")
  attr(:hide_current, :boolean, default: false, doc: "Hide currently selected language from list")
  attr(:class, :string, default: "", doc: "Additional CSS classes")

  attr(:current_path, :string,
    default: nil,
    doc: "Current path to preserve when switching languages"
  )

  attr(:scroll_threshold, :integer,
    default: 10,
    doc: "Number of languages after which to show scrollbar and search"
  )

  attr(:show_current, :boolean,
    default: false,
    doc: "Show current language (flag + name) in dropdown trigger instead of globe icon"
  )

  attr(:group_by_continent, :boolean,
    default: true,
    doc: "Enable continent grouping when language count exceeds continent_threshold"
  )

  attr(:continent_threshold, :integer,
    default: 7,
    doc: "Number of languages after which the continent grouping step is shown"
  )

  attr(:_language_update_key, :any,
    default: nil,
    doc: "Internal: forces re-render when languages change"
  )

  attr(:per_translation_urls, :list,
    default: nil,
    doc: """
    Optional list of per-translation URLs that override the locale-rewrite
    default. Each entry is `%{code: <display_code>, url: <full_url>}`.
    Both atom-keyed (`%{code: ..., url: ...}`) and string-keyed
    (`%{"code" => ..., "url" => ...}`) entries are accepted — useful
    when the list comes from JSON/JSONB rather than Elixir code.

    Useful when a feature module (e.g. `phoenix_kit_publishing`) has
    computed canonical URLs for each available translation that the
    simple locale-rewrite default can't reproduce — for example when
    a post has per-language URL slugs. Pass
    `assigns[:phoenix_kit_publishing_translations]` from the layout;
    the switcher resolves each language's `base_code` against the list
    (via `DialectMapper.extract_base/1`) and falls back to the
    locale-rewrite URL when no entry matches or the matched entry
    has a `nil` `url` (e.g. an unpublished draft).
    """
  )

  attr(:ai_translate, :map,
    default: nil,
    doc: """
    Optional opt-in for the AI-translate affordance. When present and
    `:enabled` is true, missing-language items show a sparkle button
    that fires the host LV's `phx-click` event (and a bulk
    "translate all missing" CTA renders below the list when ≥2 languages
    are missing).

    Shape:

        %{
          enabled: true,
          event: "translate_lang",        # phx-click target on host LV
          missing: ["es", "de"],          # base codes lacking a translation
          in_flight: ["es"]               # show spinner, click disabled
        }

    Only `:missing` and `:in_flight` drive rendering. A "completed"
    language is signalled simply by the host dropping its code from
    `:missing` — the sparkle then disappears on the next render. (There
    is no separate `:completed` checkmark state; pass nothing for it.)

    The component emits the host's event; the host owns enqueuing the
    actual translation worker and broadcasting the resulting `:missing` /
    `:in_flight` state back via PubSub. Set `:enabled` to `false` (or pass
    `nil`) to fall back to today's behavior with no AI UI — convenient for
    hosts that gate on `PhoenixKitAI.Translations.available?/0`.

    ## Bulk action dispatch

    The "Translate all missing" CTA fires the same event with
    `phx-value-lang="*"` as a sentinel. Host handlers branch on the
    value:

        def handle_event("translate_lang", %{"lang" => "*"}, socket) do
          # enqueue one job per *actionable* language (missing minus
          # in_flight) — matches the count shown on the bulk button
        end

        def handle_event("translate_lang", %{"lang" => lang}, socket) do
          # enqueue a single-language job
        end
    """
  )

  def language_switcher_dropdown(assigns) do
    assigns = prepare_dropdown_assigns(assigns)

    ~H"""
    <div class={["relative", @class]}>
      <details
        class="dropdown dropdown-end dropdown-bottom"
        id="language-switcher-dropdown"
        phx-hook="LanguageSwitcherPosition"
      >
        <summary class={[
          "btn btn-sm",
          if(@show_current, do: "gap-2", else: "btn-ghost btn-circle")
        ]}>
          <%= if @show_current do %>
            <span class="text-lg">{@current_language["flag"]}</span>
            <span class="font-medium">{@current_language["name"]}</span>
            <Icon.icon name="hero-chevron-down" class="w-4 h-4" />
          <% else %>
            <Icon.icon name="hero-globe-alt" class="w-5 h-5" />
          <% end %>
        </summary>
        <div
          class="dropdown-content w-56 rounded-box border border-base-200 bg-base-100 shadow-xl z-[60] mt-2"
          tabindex="0"
          phx-click-away={JS.remove_attribute("open", to: "#language-switcher-dropdown")}
        >
          <%= if @use_continents do %>
            <%!-- Continent-grouped two-step navigation using JS commands --%>

            <%!-- Step 1: Continent list --%>
            <ul id="ls-continents" class="p-2 list-none space-y-1 max-h-72 overflow-y-auto">
              <%= for {continent, langs} <- @continent_groups do %>
                <% continent_id = "ls-cont-" <> slug(continent) %>
                <li class="w-full">
                  <button
                    type="button"
                    phx-click={
                      JS.hide(to: "#ls-continents")
                      |> JS.show(to: "#ls-back")
                      |> JS.show(to: "##{continent_id}")
                    }
                    class="w-full flex items-center justify-between rounded-lg px-3 py-2 text-sm transition hover:bg-base-200 cursor-pointer"
                  >
                    <span class="font-medium text-base-content">{continent}</span>
                    <span class="badge badge-ghost badge-sm">{length(langs)}</span>
                  </button>
                </li>
              <% end %>
            </ul>

            <%!-- Back button (hidden initially) --%>
            <button
              id="ls-back"
              type="button"
              phx-click={
                JS.hide(to: "#ls-back")
                |> hide_all_continent_panels(@continent_groups)
                |> JS.show(to: "#ls-continents")
              }
              class="hidden flex items-center gap-2 px-3 py-2 text-sm font-medium text-primary hover:bg-base-200 border-b border-base-200 cursor-pointer"
            >
              <Icon.icon name="hero-arrow-left" class="w-4 h-4" />
              <span>All regions</span>
            </button>

            <%!-- Step 2: Language panels per continent (all hidden initially) --%>
            <%= for {continent, langs} <- @continent_groups do %>
              <% continent_id = "ls-cont-" <> slug(continent) %>
              <ul id={continent_id} class="hidden p-2 list-none space-y-1 max-h-64 overflow-y-auto">
                <%= if length(langs) > @continent_threshold do %>
                  <li class="pb-1">
                    <input
                      type="text"
                      placeholder="Search languages..."
                      class="input input-sm w-full"
                      id={"ls-search-" <> slug(continent)}
                      autocomplete="off"
                      oninput="
                        var t=this.value.toLowerCase().trim();
                        var ul=this.closest('ul');
                        var any=false;
                        ul.querySelectorAll('.language-item').forEach(function(i){
                          var n=i.dataset.name||'',v=i.dataset.native||'';
                          var m=!t||n.includes(t)||v.includes(t);
                          i.style.display=m?'':'none';
                          if(m)any=true;
                        });
                        var empty=ul.querySelector('.ls-no-results');
                        if(empty)empty.style.display=any?'none':'';
                      "
                    />
                  </li>
                <% end %>
                <%= for language <- langs do %>
                  <% url = resolve_url(language["base_code"], @current_path, @per_translation_urls) %>
                  <li
                    class="w-full language-item flex items-stretch"
                    data-name={String.downcase(language["name"] || "")}
                    data-native={String.downcase(language["native"] || "")}
                  >
                    <a
                      href={url}
                      phx-click="phoenix_kit_set_locale"
                      phx-value-locale={language["base_code"]}
                      phx-value-url={url}
                      class={[
                        "flex-1 flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition hover:bg-base-200",
                        if(language["base_code"] == @current_base, do: "bg-base-200", else: "")
                      ]}
                    >
                      <%= if @show_flags do %>
                        <span class="text-lg">{language["flag"]}</span>
                      <% end %>
                      <div class="flex-1">
                        <span class="font-medium text-base-content">{language["name"]}</span>
                      </div>
                      <%= if language["base_code"] == @current_base do %>
                        <span class="ml-auto">✓</span>
                      <% end %>
                    </a>
                    <.ai_translate_action
                      ai_translate={@ai_translate}
                      base_code={language["base_code"]}
                    />
                  </li>
                <% end %>
                <li class="ls-no-results px-3 py-2 text-sm text-base-content/50" style="display:none">
                  No languages found
                </li>
              </ul>
            <% end %>
          <% else %>
            <%!-- Flat language list (when <= threshold or continent grouping disabled) --%>
            <ul
              class={[
                "p-2 list-none space-y-1",
                @needs_scroll && "max-h-64 overflow-y-auto"
              ]}
              id="language-switcher-list"
            >
              <%= if @needs_scroll do %>
                <li class="pb-1">
                  <input
                    type="text"
                    placeholder="Search languages..."
                    class="input input-sm w-full"
                    id="language-search-input"
                    autocomplete="off"
                    oninput="
                      var t=this.value.toLowerCase().trim();
                      var ul=this.closest('ul');
                      var any=false;
                      ul.querySelectorAll('.language-item').forEach(function(i){
                        var n=i.dataset.name||'',v=i.dataset.native||'';
                        var m=!t||n.includes(t)||v.includes(t);
                        i.style.display=m?'':'none';
                        if(m)any=true;
                      });
                      var empty=ul.querySelector('.ls-no-results');
                      if(empty)empty.style.display=any?'none':'';
                    "
                  />
                </li>
              <% end %>
              <%= for language <- @languages do %>
                <% url = resolve_url(language["base_code"], @current_path, @per_translation_urls) %>
                <li
                  class="w-full language-item flex items-stretch"
                  data-name={String.downcase(language["name"] || "")}
                  data-native={String.downcase(language["native"] || "")}
                >
                  <a
                    href={url}
                    phx-click="phoenix_kit_set_locale"
                    phx-value-locale={language["base_code"]}
                    phx-value-url={url}
                    class={[
                      "flex-1 flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition hover:bg-base-200",
                      if(language["base_code"] == @current_base, do: "bg-base-200", else: "")
                    ]}
                  >
                    <%= if @show_flags do %>
                      <span class="text-lg">{language["flag"]}</span>
                    <% end %>
                    <%= if @show_names do %>
                      <div class="flex-1">
                        <span class="font-medium text-base-content">
                          <%= if @show_native_names && Map.get(language, "native") do %>
                            {language["native"]}
                          <% else %>
                            {language["name"]}
                          <% end %>
                        </span>
                      </div>
                    <% else %>
                      <div class="flex-1"></div>
                    <% end %>
                    <%= if language["base_code"] == @current_base do %>
                      <span class="ml-auto">✓</span>
                    <% end %>
                  </a>
                  <.ai_translate_action
                    ai_translate={@ai_translate}
                    base_code={language["base_code"]}
                  />
                </li>
              <% end %>
              <%= if @needs_scroll do %>
                <li class="ls-no-results px-3 py-2 text-sm text-base-content/50" style="display:none">
                  No languages found
                </li>
              <% end %>
            </ul>
          <% end %>
          <.ai_translate_bulk ai_translate={@ai_translate} />
        </div>
      </details>
    </div>
    """
  end

  # Per-language sparkle button rendered next to each `<a>` link.
  # Visible only when `ai_translate.enabled` is true AND the language
  # is in `ai_translate.missing`. Swaps to a spinner while the
  # corresponding language is in `ai_translate.in_flight`. Hosts that
  # complete a translation (and remove the code from `missing`) cause
  # the button to disappear naturally on the next render.
  attr(:ai_translate, :map, default: nil)
  attr(:base_code, :string, required: true)

  defp ai_translate_action(assigns) do
    ~H"""
    <%= if ai_translate_show?(@ai_translate, @base_code) do %>
      <%= cond do %>
        <% in_flight?(@ai_translate, @base_code) -> %>
          <span
            class="flex items-center justify-center px-3 text-base-content/60"
            aria-label="Translation in progress"
            title="Translation in progress"
          >
            <span class="loading loading-spinner loading-xs"></span>
          </span>
        <% true -> %>
          <button
            type="button"
            phx-click={event_name(@ai_translate)}
            phx-value-lang={@base_code}
            class="flex items-center justify-center px-3 text-base-content/50 hover:text-primary hover:bg-base-200 rounded-r-lg transition"
            aria-label="Translate this language with AI"
            title="Translate with AI"
          >
            <span aria-hidden="true">✨</span>
          </button>
      <% end %>
    <% end %>
    """
  end

  # Bulk "translate all missing" CTA rendered below the language list
  # when ≥2 languages are missing. Same `phx-click` event as the
  # per-language buttons; the host's handler distinguishes by the
  # absence of `phx-value-lang` (or its sentinel value).
  attr(:ai_translate, :map, default: nil)

  defp ai_translate_bulk(assigns) do
    ~H"""
    <%= if bulk_show?(@ai_translate) do %>
      <div class="border-t border-base-200 p-2">
        <button
          type="button"
          phx-click={event_name(@ai_translate)}
          phx-value-lang="*"
          class="w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-primary hover:bg-base-200 transition"
        >
          <span aria-hidden="true">✨</span>
          <span>Translate all missing ({length(actionable_missing(@ai_translate))})</span>
        </button>
      </div>
    <% end %>
    """
  end

  defp ai_translate_show?(nil, _base_code), do: false

  defp ai_translate_show?(cfg, base_code) when is_map(cfg) do
    enabled?(cfg) and event_name(cfg) != nil and base_code in missing_codes(cfg)
  end

  defp bulk_show?(nil), do: false

  defp bulk_show?(cfg) when is_map(cfg) do
    enabled?(cfg) and event_name(cfg) != nil and length(actionable_missing(cfg)) >= 2
  end

  defp enabled?(cfg), do: cfg[:enabled] == true or cfg["enabled"] == true

  # Non-empty event name. Without a host handler to dispatch to, the
  # affordance is dead UI — hide it. Whitespace-only event strings
  # count as empty.
  defp event_name(cfg), do: Values.presence(cfg[:event] || cfg["event"])

  defp in_flight?(cfg, base_code) do
    base_code in in_flight_codes(cfg)
  end

  defp in_flight_codes(cfg), do: cfg[:in_flight] || cfg["in_flight"] || []

  defp missing_codes(cfg) do
    cfg[:missing] || cfg["missing"] || []
  end

  # Languages still needing a translation **and** not already enqueued.
  # The bulk button uses this count so a single click doesn't redundantly
  # re-enqueue jobs the host already has in flight.
  defp actionable_missing(cfg) do
    missing_codes(cfg) -- in_flight_codes(cfg)
  end

  @doc """
  Renders a button group language switcher.

  Displays language buttons in a row. Good for mobile layouts and areas
  where space allows for multiple buttons. Automatically fetches the configured
  languages (or default top 12 if not configured).

  ## Examples

      <.language_switcher_buttons current_locale={@current_locale} />
  """
  attr(:current_locale, :string,
    default: nil,
    doc: "Current active language code (auto-detected if not provided)"
  )

  attr(:languages, :any,
    default: nil,
    doc: "List of language maps. If nil, fetches from Language Module"
  )

  attr(:show_flags, :boolean, default: true, doc: "Show language flags")
  attr(:show_names, :boolean, default: true, doc: "Show language names")
  attr(:goto_home, :boolean, default: false, doc: "Redirect to home page on language switch")
  attr(:hide_current, :boolean, default: false, doc: "Hide currently selected language from list")
  attr(:class, :string, default: "", doc: "Additional CSS classes")

  attr(:current_path, :string,
    default: nil,
    doc: "Current path to preserve when switching languages"
  )

  attr(:per_translation_urls, :list,
    default: nil,
    doc: "Optional per-translation URL overrides. See `language_switcher_dropdown/1` for details."
  )

  def language_switcher_buttons(assigns) do
    # Auto-detect current_locale if not explicitly provided
    # This might be a base code (en) or full dialect (en-US)
    locale =
      assigns.current_locale ||
        Process.get(:phoenix_kit_current_locale) ||
        Gettext.get_locale(PhoenixKitWeb.Gettext) ||
        @default_locale

    # Get enabled languages - these are full dialect codes with names
    # Ensure we always have a list, even if nil is returned
    languages_config = assigns.languages || Languages.get_display_languages() || []

    # Transform to include both base code (for URLs) and dialect (for preference)
    # Filter out any nil entries or entries with nil/empty base_code to prevent routing errors
    all_dialects =
      languages_config
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&is_map/1)
      |> Enum.map(fn lang ->
        dialect = lang.code
        base = DialectMapper.extract_base(dialect)
        flag = get_language_flag(dialect)

        %{
          "base_code" => base,
          "dialect" => dialect,
          "name" => lang.name || dialect || "Unknown",
          "flag" => flag
        }
      end)
      |> Enum.filter(fn lang ->
        base_code = lang["base_code"]
        is_binary(base_code) and base_code != ""
      end)
      |> Enum.sort_by(& &1["name"])

    # Extract base code from current locale for matching
    current_base = DialectMapper.extract_base(locale)

    # Filter out current dialect if hide_current is enabled
    filtered_languages =
      if assigns.hide_current do
        Enum.filter(all_dialects, &(&1["base_code"] != current_base))
      else
        all_dialects
      end

    assigns =
      assigns
      |> assign(:current_locale, locale)
      |> assign(:current_base, current_base)
      |> assign(:languages, filtered_languages)

    ~H"""
    <div class={["flex gap-2", @class]}>
      <%= for language <- @languages do %>
        <% url = resolve_url(language["base_code"], @current_path, @per_translation_urls) %>
        <a
          href={url}
          phx-click="phoenix_kit_set_locale"
          phx-value-locale={language["base_code"]}
          phx-value-url={url}
          class={[
            "btn btn-sm",
            if(language["base_code"] == @current_base,
              do: "btn-primary",
              else: "btn-outline"
            )
          ]}
        >
          <%= if @show_flags do %>
            <span>{language["flag"]}</span>
          <% end %>
          <%= if @show_names do %>
            <span>{language["base_code"] |> String.upcase()}</span>
          <% end %>
        </a>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders an inline language switcher.

  Displays languages as inline text links. Minimal design perfect for footers
  or compact navigation areas. Automatically fetches the configured languages
  (or default top 12 if not configured).

  ## Examples

      <.language_switcher_inline current_locale={@current_locale} />
  """
  attr(:current_locale, :string,
    default: nil,
    doc: "Current active language code (auto-detected if not provided)"
  )

  attr(:languages, :any,
    default: nil,
    doc: "List of language maps. If nil, fetches from Language Module"
  )

  attr(:show_flags, :boolean, default: true, doc: "Show language flags")
  attr(:show_names, :boolean, default: true, doc: "Show language names")
  attr(:goto_home, :boolean, default: false, doc: "Redirect to home page on language switch")
  attr(:hide_current, :boolean, default: false, doc: "Hide currently selected language from list")
  attr(:class, :string, default: "", doc: "Additional CSS classes")

  attr(:current_path, :string,
    default: nil,
    doc: "Current path to preserve when switching languages"
  )

  attr(:per_translation_urls, :list,
    default: nil,
    doc: "Optional per-translation URL overrides. See `language_switcher_dropdown/1` for details."
  )

  def language_switcher_inline(assigns) do
    # Auto-detect current_locale if not explicitly provided
    # This might be a base code (en) or full dialect (en-US)
    locale =
      assigns.current_locale ||
        Process.get(:phoenix_kit_current_locale) ||
        Gettext.get_locale(PhoenixKitWeb.Gettext) ||
        @default_locale

    # Get enabled languages - these are full dialect codes with names
    # Ensure we always have a list, even if nil is returned
    languages_config = assigns.languages || Languages.get_display_languages() || []

    # Transform to include both base code (for URLs) and dialect (for preference)
    # Filter out any nil entries or entries with nil/empty base_code to prevent routing errors
    all_dialects =
      languages_config
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&is_map/1)
      |> Enum.map(fn lang ->
        dialect = lang.code
        base = DialectMapper.extract_base(dialect)
        flag = get_language_flag(dialect)

        %{
          "base_code" => base,
          "dialect" => dialect,
          "name" => lang.name || dialect || "Unknown",
          "flag" => flag
        }
      end)
      |> Enum.filter(fn lang ->
        base_code = lang["base_code"]
        is_binary(base_code) and base_code != ""
      end)
      |> Enum.sort_by(& &1["name"])

    # Extract base code from current locale for matching
    current_base = DialectMapper.extract_base(locale)

    # Filter out current dialect if hide_current is enabled
    filtered_languages =
      if assigns.hide_current do
        Enum.filter(all_dialects, &(&1["base_code"] != current_base))
      else
        all_dialects
      end

    assigns =
      assigns
      |> assign(:current_locale, locale)
      |> assign(:current_base, current_base)
      |> assign(:languages, filtered_languages)

    ~H"""
    <div class={["flex gap-4 items-center", @class]}>
      <%= for {language, index} <- Enum.with_index(@languages) do %>
        <% url = resolve_url(language["base_code"], @current_path, @per_translation_urls) %>
        <div class="flex items-center gap-1">
          <%= if index > 0 do %>
            <span class="text-base-content/30">|</span>
          <% end %>
          <a
            href={url}
            phx-click="phoenix_kit_set_locale"
            phx-value-locale={language["base_code"]}
            phx-value-url={url}
            class={[
              "text-sm transition hover:text-primary",
              if(language["base_code"] == @current_base,
                do: "font-bold text-primary",
                else: "text-base-content"
              )
            ]}
          >
            <%= if @show_flags do %>
              <span class="mr-1">{language["flag"]}</span>
            <% end %>
            <%= if @show_names do %>
              {language["base_code"] |> String.upcase()}
            <% end %>
          </a>
        </div>
      <% end %>
    </div>
    """
  end

  # Chains JS.hide commands to hide all continent language panels
  defp hide_all_continent_panels(js, continent_groups) do
    Enum.reduce(continent_groups, js, fn {continent, _}, acc ->
      JS.hide(acc, to: "#ls-cont-#{slug(continent)}")
    end)
  end

  # Converts a continent name to a URL-safe slug for DOM IDs
  defp slug(nil), do: "unknown"

  defp slug(name) when is_binary(name) do
    name
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]+/, "-")
    |> String.trim("-")
  end

  defp slug(_), do: "unknown"

  # Prepares all assigns needed by the dropdown template.
  # Handles nil/invalid inputs gracefully — never crashes on bad data.
  defp prepare_dropdown_assigns(assigns) do
    locale =
      assigns.current_locale ||
        Process.get(:phoenix_kit_current_locale) ||
        Gettext.get_locale(PhoenixKitWeb.Gettext) ||
        @default_locale

    # Ensure locale is always a string
    locale = if is_binary(locale), do: locale, else: @default_locale

    languages_config =
      case assigns.languages do
        nil -> Languages.get_display_languages()
        list when is_list(list) -> list
        _ -> []
      end

    all_dialects = build_dialect_list(languages_config)

    filtered_languages =
      if assigns.hide_current do
        Enum.filter(all_dialects, &(&1["dialect"] != locale))
      else
        all_dialects
      end

    current_base = DialectMapper.extract_base(locale)

    current_language =
      Enum.find(all_dialects, &(&1["dialect"] == locale)) ||
        %{
          "base_code" => current_base,
          "dialect" => locale,
          "name" => String.upcase(locale),
          "native" => nil,
          "flag" => "🌐"
        }

    {use_continents, continent_groups} =
      maybe_build_continent_groups(assigns, filtered_languages)

    # When continent grouping is disabled but there are many languages,
    # use the continent_threshold to decide if search is needed (lower = more likely to show search)
    effective_scroll_threshold =
      if assigns.group_by_continent do
        assigns.scroll_threshold
      else
        min(assigns.scroll_threshold, assigns.continent_threshold)
      end

    needs_scroll = not use_continents and length(filtered_languages) > effective_scroll_threshold

    assigns
    |> assign(:current_locale, locale)
    |> assign(:current_base, current_base)
    |> assign(:languages, filtered_languages)
    |> assign(:current_language, current_language)
    |> assign(:needs_scroll, needs_scroll)
    |> assign(:use_continents, use_continents)
    |> assign(:continent_groups, continent_groups)
  end

  # Builds continent groups if grouping is enabled and threshold exceeded.
  # Returns {use_continents, groups} where groups is a list of {continent, dialect_maps}.
  # Falls back to flat list if grouping fails or produces no results.
  defp maybe_build_continent_groups(assigns, filtered_languages) do
    if assigns.group_by_continent and length(filtered_languages) > assigns.continent_threshold do
      # Count siblings globally before slicing by continent so dedup
      # decisions stay consistent across continent groups (a base
      # language with one dialect in Europe + another in North
      # America still gets the country qualifier in both groups).
      continent_groups_data = Languages.get_enabled_languages_by_continent()

      global_counts =
        continent_groups_data
        |> Enum.flat_map(fn {_continent, langs} -> langs end)
        |> Enum.uniq_by(&lang_code_for_counts/1)
        |> DialectMapper.group_dialects_by_base()

      groups =
        continent_groups_data
        |> Enum.map(fn {continent, langs} ->
          {continent, langs_to_dialect_maps(langs, global_counts)}
        end)
        |> Enum.reject(fn {_, langs} -> langs == [] end)

      if groups != [], do: {true, groups}, else: {false, []}
    else
      {false, []}
    end
  rescue
    _ -> {false, []}
  end

  defp lang_code_for_counts(lang) when is_struct(lang), do: lang.code
  defp lang_code_for_counts(lang) when is_map(lang), do: lang[:code] || lang["code"]
  defp lang_code_for_counts(_), do: nil

  # Transforms Language structs/maps from grouped continent data into
  # dialect maps. `counts` is the GLOBAL sibling count across all
  # enabled languages — never per-continent — so the dedup rule
  # behaves identically to the flat dropdown.
  defp langs_to_dialect_maps(langs, counts) do
    langs
    |> Enum.map(fn lang ->
      code = if is_struct(lang), do: lang.code, else: lang[:code]
      base = DialectMapper.extract_base(code)

      if is_binary(code) do
        %{
          "base_code" => base,
          "dialect" => code,
          "name" => display_name_for(lang, base, counts),
          "flag" => get_language_flag(code)
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(& &1["name"])
  end

  # Transforms language config into dialect maps for display.
  #
  # When only one dialect of a given base language is configured, the
  # displayed `name` strips the country qualifier and falls back to
  # the canonical base-language name (e.g. "English", "Estonian") —
  # the parenthetical implies a choice that doesn't exist when no
  # sibling dialect is enabled. Multiple dialects of the same base
  # language keep their full configured name so the user can tell
  # them apart.
  defp build_dialect_list(languages_config) do
    configured =
      languages_config
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&is_map/1)

    counts = DialectMapper.group_dialects_by_base(configured)

    configured
    |> Enum.map(fn lang ->
      dialect = lang.code
      base = DialectMapper.extract_base(dialect)

      %{
        "base_code" => base,
        "dialect" => dialect,
        "name" => display_name_for(lang, base, counts),
        "native" => get_native_name(dialect),
        "flag" => get_language_flag(dialect)
      }
    end)
    |> Enum.filter(fn lang ->
      base_code = lang["base_code"]
      is_binary(base_code) and base_code != ""
    end)
    |> Enum.sort_by(& &1["name"])
  end

  # Picks the displayed name for a single language entry: bare
  # language name (derived from the configured `:name` by stripping
  # the country qualifier) when this is the only dialect of its base,
  # full `:name` otherwise. Falls back to `String.upcase(base)` when
  # the entry has no name. Mirrors the pre-`d1c2d577` convention.
  #
  # `base` is always a binary at the call site
  # (`DialectMapper.extract_base/1` clauses cover `nil` / `""` / binary
  # and all return a binary), so the no-binary-base branch is
  # unreachable — keeping it would just confuse dialyzer.
  defp display_name_for(lang, base, counts) when is_binary(base) do
    full = get_in_lang(lang, :name) || get_in_lang(lang, "name")

    cond do
      Map.get(counts, base, 0) > 1 -> full || get_in_lang(lang, :code) || base
      is_binary(full) -> extract_base_language_name(full)
      true -> String.upcase(base)
    end
  end

  @doc """
  Strips the country / region qualifier from a configured language
  name. Used to render bare base-language labels when only one
  dialect of the base is enabled.

  Public because the admin top-bar dropdown
  (`PhoenixKitWeb.Components.AdminNav`) and the user dashboard nav
  (`PhoenixKitWeb.Components.UserDashboardNav`) both call into it via
  `dedupe_names/1` so all language menus share one rule.

  ## Examples

      iex> extract_base_language_name("Spanish (Mexico)")
      "Spanish"

      iex> extract_base_language_name("Chinese (Simplified)")
      "Chinese"

      iex> extract_base_language_name("Japanese")
      "Japanese"
  """
  def extract_base_language_name(full_name) when is_binary(full_name) do
    full_name
    |> String.split("(")
    |> List.first()
    |> String.trim()
  end

  @doc """
  Overrides each language entry's `:name` (or `"name"`) with the
  bare base-language label when only one dialect of that base is
  configured. Multi-dialect bases keep their full configured name so
  users can tell them apart.

  Accepts a list of language entries shaped as atom-keyed maps,
  string-keyed maps, or `%PhoenixKit.Modules.Languages.Language{}`
  structs. Returns the list in the same shape with the relevant
  `:name`/`"name"` key replaced.

  Used by the admin top-bar dropdown and the user dashboard nav to
  inherit the frontend switcher's dedup rule without duplicating the
  logic. Internal frontend-switcher code paths
  (`build_dialect_list/1`, `langs_to_dialect_maps/2`) compute names
  inline because they emit a new result map per entry; this helper
  is the entry point for callers that already have a list of entries
  and just need their names normalized.
  """
  def dedupe_names(languages) when is_list(languages) do
    counts = DialectMapper.group_dialects_by_base(languages)
    Enum.map(languages, &dedupe_one_name(&1, counts))
  end

  defp dedupe_one_name(lang, counts) do
    with code when is_binary(code) <- lang_code(lang),
         base <- DialectMapper.extract_base(code),
         true <- Map.get(counts, base, 0) <= 1 do
      full = get_in_lang(lang, :name) || get_in_lang(lang, "name")
      put_lang_name(lang, bare_name(full, base))
    else
      _ -> lang
    end
  end

  # `base` is always a binary at the call site (see
  # `display_name_for/3` for the same rationale), so we only need
  # two clauses.
  defp bare_name(full, _base) when is_binary(full), do: extract_base_language_name(full)
  defp bare_name(_full, base) when is_binary(base), do: String.upcase(base)

  defp lang_code(%{code: code}) when is_binary(code), do: code
  defp lang_code(%{"code" => code}) when is_binary(code), do: code
  defp lang_code(_), do: nil

  defp put_lang_name(lang, name) when is_struct(lang) do
    if Map.has_key?(lang, :name), do: %{lang | name: name}, else: lang
  end

  defp put_lang_name(lang, name) when is_map(lang) do
    cond do
      Map.has_key?(lang, :name) -> Map.put(lang, :name, name)
      Map.has_key?(lang, "name") -> Map.put(lang, "name", name)
      true -> Map.put(lang, :name, name)
    end
  end

  defp get_in_lang(lang, key) when is_struct(lang) and is_atom(key), do: Map.get(lang, key)
  defp get_in_lang(lang, key) when is_map(lang), do: Map.get(lang, key)
  defp get_in_lang(_, _), do: nil

  # Helper function to get language flag emoji
  defp get_language_flag(code) when is_binary(code) do
    case Languages.get_predefined_language(code) do
      %{flag: flag} -> flag
      nil -> "🌐"
    end
  end

  # Helper function to get native language name
  defp get_native_name(code) when is_binary(code) do
    case Languages.get_predefined_language(code) do
      %{native: native} -> native
      nil -> nil
    end
  end

  # Resolve a per-language URL — when the caller supplied `per_translation_urls`
  # (e.g. from `phoenix_kit_publishing`), prefer that explicit URL over the
  # locale-rewrite default. Falls back to `generate_base_code_url/2` when no
  # entry matches the requested base code.
  #
  # `per_translation_urls` arrives as a list of `%{code: <display_code>, url: ...}`
  # maps. We normalize each `code` to its base via `DialectMapper.extract_base/1`
  # so `"en-US"` and `"en"` both resolve cleanly when the consumer's switcher
  # iterates languages keyed by base code.
  defp resolve_url(base_code, current_path, nil),
    do: generate_base_code_url(base_code, current_path)

  defp resolve_url(base_code, current_path, []),
    do: generate_base_code_url(base_code, current_path)

  defp resolve_url(base_code, current_path, per_translation_urls)
       when is_list(per_translation_urls) and is_binary(base_code) do
    case Enum.find(per_translation_urls, fn entry ->
           entry_base_code(entry) == base_code
         end) do
      nil -> generate_base_code_url(base_code, current_path)
      entry -> entry_url(entry) || generate_base_code_url(base_code, current_path)
    end
  end

  defp resolve_url(base_code, current_path, _),
    do: generate_base_code_url(base_code, current_path)

  defp entry_base_code(%{code: code}) when is_binary(code), do: DialectMapper.extract_base(code)

  defp entry_base_code(%{"code" => code}) when is_binary(code),
    do: DialectMapper.extract_base(code)

  defp entry_base_code(_), do: nil

  defp entry_url(%{url: url}) when is_binary(url), do: url
  defp entry_url(%{"url" => url}) when is_binary(url), do: url
  defp entry_url(_), do: nil

  # Generate URL with ONLY base code - no dialect, no query params
  # This is the clean URL used in href attributes
  # Default language (from Languages module) gets clean URLs (no prefix),
  # other languages get locale prefix
  # Guard clauses for nil/empty base_code to prevent Phoenix.Param errors
  defp generate_base_code_url(nil, current_path), do: current_path || "/"
  defp generate_base_code_url("", current_path), do: current_path || "/"

  defp generate_base_code_url(base_code, current_path) do
    # Strip the URL prefix first (e.g., /phoenix_kit)
    url_prefix = PhoenixKit.Config.get_url_prefix()
    prefix_to_remove = if url_prefix == "/", do: "", else: url_prefix
    normalized = String.replace_prefix(current_path || "/", prefix_to_remove, "")

    # Ensure path starts with /
    normalized =
      if normalized == "" or not String.starts_with?(normalized, "/"), do: "/", else: normalized

    # Extract and strip the locale from the remaining path
    current_base = extract_locale_from_path(normalized)
    clean_path = strip_locale_from_path(normalized, current_base)

    # Admin paths use Routes.admin_path to keep locale in URL
    if String.contains?(clean_path, "/admin") do
      Routes.admin_path(clean_path, base_code)
    else
      Routes.path(clean_path, locale: base_code)
    end
  end

  # Extract the locale segment from a path (after prefix removal)
  # /en/admin => "en"
  # /en-US/admin => "en-US"
  defp extract_locale_from_path(path) do
    case String.split(path, "/", parts: 3) do
      ["", locale, _rest] ->
        if DialectMapper.valid_base_code?(locale), do: locale, else: nil

      ["", locale] ->
        if DialectMapper.valid_base_code?(locale), do: locale, else: nil

      _ ->
        nil
    end
  end

  # Strip locale prefix from path: /en/admin → /admin
  defp strip_locale_from_path(path, nil), do: path

  defp strip_locale_from_path(path, locale) do
    case String.split(path, "/", parts: 3) do
      ["", ^locale, rest] when is_binary(rest) -> "/#{rest}"
      ["", ^locale] -> "/"
      _ -> path
    end
  end
end
