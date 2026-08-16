defmodule PhoenixKitWeb.Components.Core.IntegrationPicker do
  @moduledoc """
  Reusable integration connection picker component.

  Displays integration connections as clickable cards in a modal or inline grid.
  Supports single and multi-select modes, search, and provider filtering.

  ## Examples

      <%-- Single select, one provider --%>
      <.integration_picker
        id="google-picker"
        connections={@all_connections}
        selected={[@selected_uuid]}
        provider="google"
        on_select="select_integration"
      />

      <%-- Multi-select, all providers, with search --%>
      <.integration_picker
        id="multi-picker"
        connections={@all_connections}
        selected={@selected_uuids}
        multiple={true}
        searchable={true}
        on_select="update_integrations"
      />

      <%-- Single select, all providers --%>
      <.integration_picker
        id="any-picker"
        connections={@all_connections}
        selected={[@selected_uuid]}
        on_select="pick_integration"
      />

  The parent LiveView is responsible for loading connections via
  `PhoenixKit.Integrations.list_connections/1` or building the list
  from `PhoenixKit.Integrations.Providers.all/0`.

  ## Events

  The component sends the `on_select` event with:
  - Single mode: `%{"uuid" => uuid, "action" => "select" | "deselect"}` —
    clicking an unselected card emits `"select"`; clicking the
    currently-selected card emits `"deselect"` so the parent can
    clear the binding.
  - Multi mode: `%{"uuid" => uuid, "action" => "add" | "remove"}` when toggled

  ## Search

  Search is handled client-side via the `IntegrationPickerSearch` JS hook.
  Cards are filtered by their `data-search-text` attribute (name, account, provider).
  No parent LiveView handler is needed — filtering is instant and local.
  """

  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.Icon, only: [icon: 1]
  import PhoenixKitWeb.Components.Core.TimeDisplay, only: [time_ago: 1]

  alias PhoenixKit.Integrations.Providers

  @doc """
  Renders an integration picker as a grid of cards.

  ## Attributes

  * `id` - Unique element ID (required)
  * `connections` - List of connection maps from `Integrations.list_connections/1`.
    Each map must have `:uuid`, `:name`, `:data` keys, and optionally `:provider`
    (a provider definition map with `:name`, `:icon`, `:key`).
  * `selected` - List of currently selected UUIDs (default: [])
  * `provider` - Filter to only show connections for this provider key (optional)
  * `multiple` - Allow multiple selection (default: false)
  * `searchable` - Show search input. Accepts `true` / `false` /
    `nil`. `nil` (the default) means auto-detect — the search input
    shows when there are more than 6 connections. Explicit `false`
    suppresses it even past the threshold; explicit `true` forces
    it even at small N. Typed `:any` in the attr definition because
    Phoenix's `:boolean` doesn't admit `nil`.
  * `compact` - Use compact card layout (default: false)
  * `on_select` - Event name sent to parent on selection (required)
  * `empty_url` - URL for "Add Integration" link shown when no connections exist (optional)
  * `class` - Additional CSS classes for the wrapper (optional)
  """
  attr :id, :string, required: true
  attr :connections, :list, required: true
  attr :selected, :list, default: []
  attr :provider, :string, default: nil
  attr :multiple, :boolean, default: false
  attr :searchable, :any, default: nil
  attr :compact, :boolean, default: false
  attr :on_select, :string, required: true
  attr :empty_url, :string, default: nil
  attr :class, :string, default: ""
  attr :search, :string, default: ""

  def integration_picker(assigns) do
    # Memoize provider_def per connection — search + render both need
    # it, so without the memo `Providers.get/1` runs twice per row on
    # every render (once in filter_by_search, once on the per-card
    # `provider_def={provider_def(conn)}` attr). The lookup is a Map.get
    # over `Providers.all/0` so the unit cost is small, but at the
    # picker's auto-search threshold (>6 connections) we're already
    # paying 14+ avoidable hits per keystroke.
    provider_defs = Map.new(assigns.connections, &{&1.uuid, provider_def(&1)})

    connections =
      assigns.connections
      |> filter_by_provider(assigns.provider)
      |> filter_by_search(assigns.search, provider_defs)

    show_search =
      case assigns.searchable do
        nil -> length(assigns.connections) > 6
        val -> val
      end

    selected = assigns.selected || []
    selected_set = MapSet.new(selected)
    existing_uuids = MapSet.new(Enum.map(connections, & &1.uuid))

    deleted_selections =
      Enum.filter(selected, fn uuid ->
        uuid && not MapSet.member?(existing_uuids, uuid)
      end)

    assigns =
      assigns
      |> assign(:filtered_connections, connections)
      |> assign(:deleted_selections, deleted_selections)
      |> assign(:show_search, show_search)
      |> assign(:selected_set, selected_set)
      |> assign(:provider_defs, provider_defs)

    ~H"""
    <div id={@id} class={["integration-picker", @class]}>
      <%!-- Search (client-side filtering via data attributes) --%>
      <div :if={@show_search} class="mb-3">
        <input
          type="text"
          placeholder={gettext("Search integrations...")}
          value={@search}
          phx-hook="IntegrationPickerSearch"
          id={"#{@id}-search"}
          data-picker-id={@id}
          class="input input-sm w-full"
        />
      </div>

      <%!-- Connection cards grid --%>
      <div
        :if={@filtered_connections != []}
        class={[
          "grid gap-2",
          if(@compact, do: "grid-cols-1", else: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3")
        ]}
      >
        <.connection_card
          :for={conn <- @filtered_connections}
          conn={conn}
          provider_def={Map.get(@provider_defs, conn.uuid)}
          selected={MapSet.member?(@selected_set, conn.uuid)}
          compact={@compact}
          on_select={@on_select}
          action={select_action(@multiple, conn.uuid, @selected_set)}
          show_provider_badge={is_nil(@provider)}
        />
      </div>

      <%!-- Deleted integration cards --%>
      <div
        :for={deleted_uuid <- @deleted_selections}
        class="card bg-error/5 border border-error/30 mt-2"
      >
        <div class={["card-body", if(@compact, do: "p-3", else: "p-4")]}>
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-error/10 flex items-center justify-center shrink-0">
              <.icon name="hero-exclamation-triangle" class="w-4 h-4 text-error" />
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <span class="font-medium text-error">{gettext("Integration deleted")}</span>
                <span class="badge badge-error badge-xs">{gettext("Missing")}</span>
              </div>
              <p class="text-xs text-base-content/50 truncate">
                {gettext("The selected integration no longer exists. Please choose a different one.")}
              </p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Empty state --%>
      <div
        :if={@filtered_connections == [] and @deleted_selections == []}
        class="text-center py-8 text-base-content/50"
      >
        <.icon name="hero-link" class="w-10 h-10 mx-auto mb-2 opacity-40" />
        <%= if @search != "" do %>
          <p class="text-sm">{gettext("No integrations match your search.")}</p>
        <% else %>
          <p class="text-sm">{gettext("No integrations configured.")}</p>
          <a
            :if={@empty_url}
            href={@empty_url}
            class="link link-primary text-sm"
          >
            {gettext("Add one in Settings → Integrations")}
          </a>
        <% end %>
      </div>
    </div>
    """
  end

  # Per-card render — extracted so the grid loop stays readable. The
  # provider definition (icon + display name) is auto-resolved from
  # `conn.data["provider"]` via the Providers registry, so callers
  # don't need to pre-attach it.
  attr :conn, :map, required: true
  attr :provider_def, :any, required: true
  attr :selected, :boolean, required: true
  attr :compact, :boolean, required: true
  attr :on_select, :string, required: true
  attr :action, :string, required: true
  attr :show_provider_badge, :boolean, default: true

  defp connection_card(assigns) do
    ~H"""
    <button
      type="button"
      phx-click={@on_select}
      phx-value-uuid={@conn.uuid}
      phx-value-action={@action}
      data-search-text={search_text(@conn, @provider_def)}
      class={
        [
          "card bg-base-100 border text-left transition-all cursor-pointer",
          "hover:shadow-md hover:border-primary/50",
          # Instant click feedback: `.phx-click-loading` is applied
          # automatically by LiveView to elements with `phx-click`
          # while the event is in flight. Dimming + disabling pointer
          # events bridges the perception gap between "click registered"
          # and "server-side state caught up" (which can take 100-500ms
          # while connected? + select_provider_connection round-trip).
          "phx-click-loading:opacity-60 phx-click-loading:pointer-events-none",
          if(@selected,
            do: "border-primary ring-2 ring-primary/20",
            else: "border-base-300"
          )
        ]
      }
    >
      <div class={["card-body", if(@compact, do: "p-3", else: "p-4")]}>
        <div class="flex items-center gap-3">
          <%!-- Provider icon --%>
          <span
            :if={@provider_def && @provider_def[:icon]}
            class="w-8 h-8 flex items-center justify-center bg-base-200 rounded-lg shrink-0"
          >
            <.icon name={@provider_def.icon} class="w-4 h-4" />
          </span>

          <div class="flex-1 min-w-0">
            <%!-- Connection name. Names are pure user-chosen labels
                 (post-V114): duplicates allowed, no privileged values,
                 the masked-credential subtitle below disambiguates
                 when two cards share a name. --%>
            <div class="flex items-center gap-2">
              <span class="font-medium truncate">
                {@conn.name}
              </span>
              <%!-- Provider badge — redundant when the picker is
                   filtering to a single provider (every card is the
                   same provider in that case). Shown only when the
                   picker is rendering mixed-provider connections,
                   which happens when the caller passes no `provider`
                   attr. --%>
              <span
                :if={@show_provider_badge && @provider_def && @provider_def[:name]}
                class="badge badge-ghost badge-xs shrink-0"
              >
                {@provider_def.name}
              </span>
            </div>

            <%!-- Subtitle: OAuth `external_account_id` (e.g.
                 "user@gmail.com") when present, otherwise a masked
                 credential tail (api_key / bot_token / access_key).
                 Empty when neither exists. --%>
            <p
              :if={connection_subtitle(@conn) not in [nil, ""]}
              class="text-xs text-base-content/60 truncate"
            >
              {connection_subtitle(@conn)}
            </p>

            <%!-- Age — "Created 3 days ago" using shared time_ago
                 hook so the value stays live without a server round
                 trip. Helps disambiguate same-named connections. --%>
            <p :if={@conn[:date_added]} class="text-xs text-base-content/40">
              {gettext("Created")} <.time_ago datetime={@conn.date_added} class="text-xs" />
            </p>
          </div>

          <%!-- Status + selection indicator --%>
          <div class="flex items-center gap-2 shrink-0">
            <%!-- In-flight spinner. Hidden by default; shown when
                 LiveView applies `.phx-click-loading` to this button
                 (the click handler's round-trip window). Hides the
                 status badge during loading so the spinner has a
                 clear visual home. --%>
            <span class="hidden phx-click-loading:inline-flex">
              <span class="loading loading-spinner loading-xs"></span>
            </span>

            <%!-- Status badge. Surfaces the row's actual `status`
                 (connected / configured / error / disconnected) with
                 a distinct label + colour for each, rather than
                 collapsing every non-`"connected"` state into a
                 single "Not connected". For error rows, the
                 validation message (e.g. "Invalid credentials")
                 hovers as the `title` attribute so the operator can
                 see WHY without clicking through. --%>
            <% {status_label, status_class} = status_badge(@conn.data) %>
            <span
              class={"badge badge-xs phx-click-loading:hidden" <> status_class}
              title={@conn.data["validation_status"]}
            >
              {status_label}
            </span>

            <%!-- Selection check. Always rendered so the row layout
                 doesn't reflow on pick/unpick; ghosted via low-contrast
                 colour when the card isn't selected, so it reads as
                 "selectable" rather than active. --%>
            <.icon
              name="hero-check-circle-solid"
              class={
                "w-5 h-5" <>
                  if(@selected, do: "text-primary", else: "text-base-content/20")
              }
            />
          </div>
        </div>
      </div>
    </button>
    """
  end

  # Maps the row's `status` field to a `{label, daisyUI-class}` pair
  # for the card's status badge. The four canonical statuses
  # (`connected`, `configured`, `error`, `disconnected`) get distinct
  # labels + colours so operators can tell at a glance whether the
  # row is healthy, untested, broken, or empty.
  defp status_badge(%{} = data) do
    case Map.get(data, "status") do
      "connected" -> {gettext("Connected"), "badge-success"}
      "error" -> {gettext("Auth failed"), "badge-error"}
      "configured" -> {gettext("Not tested"), "badge-warning"}
      "disconnected" -> {gettext("Not connected"), "badge-ghost"}
      _ -> {gettext("Not connected"), "badge-ghost"}
    end
  end

  defp filter_by_provider(connections, nil), do: connections

  defp filter_by_provider(connections, provider) do
    Enum.filter(connections, fn conn -> conn_provider_key(conn) == provider end)
  end

  defp conn_provider_key(conn), do: conn.data["provider"] || ""

  # Resolves the provider definition (icon + display name) for a
  # connection. Reads the bare provider string from JSONB and looks
  # it up in the registry. Returns `nil` when the provider isn't
  # registered (e.g. a custom provider contributed by a now-uninstalled
  # module).
  defp provider_def(conn) do
    case conn.data["provider"] do
      provider when is_binary(provider) and provider != "" -> Providers.get(provider)
      _ -> nil
    end
  end

  # Subtitle priority:
  # 1. OAuth account identifier (`external_account_id`) — already a
  #    human-readable string from the provider's userinfo endpoint.
  # 2. Masked credential tail — first 8 + ellipsis + last 4 of whichever
  #    credential field is present. Short keys (< 14 chars) fully mask
  #    so a 13-char key doesn't leak most of itself.
  # 3. Empty — show nothing, the card has just the name + age.
  defp connection_subtitle(conn) do
    case conn.data["external_account_id"] do
      account when is_binary(account) and account != "" ->
        account

      _ ->
        conn.data
        |> credential_value()
        |> mask_credential()
    end
  end

  defp credential_value(data) do
    Enum.find_value(~w(api_key bot_token access_key), fn key ->
      case data[key] do
        v when is_binary(v) and v != "" -> v
        _ -> nil
      end
    end)
  end

  defp mask_credential(nil), do: nil

  defp mask_credential(value) when is_binary(value) do
    if String.length(value) < 14 do
      "•••"
    else
      # `-4..-1//1` pins the step explicitly — Elixir 1.16+ warns on
      # negative-bound ranges without a step, and the warning becomes
      # an error in a future minor.
      String.slice(value, 0, 8) <> "…" <> String.slice(value, -4..-1//1)
    end
  end

  defp filter_by_search(connections, "", _provider_defs), do: connections
  defp filter_by_search(connections, nil, _provider_defs), do: connections

  defp filter_by_search(connections, search, provider_defs) do
    q = String.downcase(search)

    Enum.filter(connections, fn conn ->
      name = String.downcase(conn.name || "")
      account = String.downcase(conn.data["external_account_id"] || "")
      provider = String.downcase(conn.data["provider"] || "")

      provider_display =
        case Map.get(provider_defs, conn.uuid) do
          %{name: provider_name} when is_binary(provider_name) -> String.downcase(provider_name)
          _ -> ""
        end

      String.contains?(name, q) or String.contains?(account, q) or
        String.contains?(provider, q) or String.contains?(provider_display, q)
    end)
  end

  defp select_action(true, uuid, selected_set) do
    if MapSet.member?(selected_set, uuid), do: "remove", else: "add"
  end

  defp select_action(false, uuid, selected_set) do
    if MapSet.member?(selected_set, uuid), do: "deselect", else: "select"
  end

  defp search_text(conn, provider_def) do
    parts = [
      conn.name,
      conn.data["external_account_id"],
      conn.data["provider"],
      provider_def && provider_def[:name]
    ]

    parts |> Enum.reject(&is_nil/1) |> Enum.join(" ") |> String.downcase()
  end
end
