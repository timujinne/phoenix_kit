defmodule PhoenixKitWeb.Live.Integrations.MyIntegrations do
  @moduledoc """
  "My Integrations" — the current user's PERSONAL integration connections.

  Lists only connections owned by the logged-in user (API keys, SMTP, bot
  tokens — the self-owned-secret providers). Every context call is scoped to
  `owner: {:user, uuid}` where the uuid comes ONLY from the request scope,
  never from params — so a user can only ever see and act on their own
  connections. Gated by the independent `integrations` permission.

  Sibling of the system-wide page (`Live.Settings.Integrations`), which is
  gated separately by `integrations_system`. Both render with the same shared
  UI (`Components.Core.IntegrationsUI`) so the two stay visually consistent.
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.IntegrationsUI, only: [integration_status_badge: 1]

  # Imported per-LiveView rather than from `PhoenixKitWeb, :live_view`: a host
  # app that defines its own `row_link/1` would get an ambiguous import the
  # moment core wired this one in project-wide.
  import PhoenixKitWeb.Components.Core.RowLink, only: [row_link: 1]

  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Events
  alias PhoenixKit.Integrations.Providers
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes

  @impl true
  def mount(_params, _session, socket) do
    user_uuid = Scope.user_uuid(socket.assigns[:phoenix_kit_current_scope])

    if connected?(socket) and is_binary(user_uuid) do
      Events.subscribe(user_uuid)
    end

    {:ok,
     socket
     |> assign(:page_title, gettext("My Integrations"))
     |> assign(:project_title, Settings.get_project_title())
     |> assign(:url_path, Routes.path("/admin/settings/integrations"))
     |> assign(:user_uuid, user_uuid)
     |> assign(:validating, nil)
     |> load_connections()}
  end

  @impl true
  def handle_event("disconnect", %{"uuid" => uuid}, socket) do
    Integrations.disconnect(uuid, socket.assigns.user_uuid, owner: owner(socket))
    {:noreply, socket |> put_flash(:info, gettext("Disconnected")) |> load_connections()}
  end

  def handle_event("remove_connection", %{"uuid" => uuid}, socket) do
    case Integrations.remove_connection(uuid, socket.assigns.user_uuid, owner: owner(socket)) do
      :ok ->
        {:noreply,
         socket |> put_flash(:info, gettext("Connection removed")) |> load_connections()}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, gettext("Failed to remove connection"))}
    end
  end

  def handle_event("validate_connection", %{"uuid" => uuid}, socket) do
    send(self(), {:do_validate, uuid})
    {:noreply, assign(socket, :validating, uuid)}
  end

  @impl true
  def handle_info({:do_validate, uuid}, socket) do
    result =
      Integrations.validate_connection(uuid, socket.assigns.user_uuid, owner: owner(socket))

    Integrations.record_validation(uuid, result, owner: owner(socket))
    {:noreply, socket |> assign(:validating, nil) |> load_connections()}
  end

  # Live updates over this user's personal topic.
  def handle_info({event, _, _}, socket)
      when event in [
             :integration_setup_saved,
             :integration_connected,
             :integration_connection_added,
             :integration_connection_removed,
             :integration_validated
           ],
      do: {:noreply, load_connections(socket)}

  def handle_info({event, _}, socket)
      when event in [:integration_disconnected],
      do: {:noreply, load_connections(socket)}

  def handle_info({:integration_connection_renamed, _, _, _}, socket),
    do: {:noreply, load_connections(socket)}

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ── Internals ────────────────────────────────────────────────────────

  defp owner(socket), do: {:user, socket.assigns.user_uuid}

  defp load_connections(%{assigns: %{user_uuid: user_uuid}} = socket) when is_binary(user_uuid) do
    providers = Providers.for_scope(:personal)
    provider_keys = Enum.map(providers, & &1.key)
    providers_by_key = Map.new(providers, &{&1.key, &1})

    all_connections = Integrations.load_all_connections(provider_keys, owner: {:user, user_uuid})

    connections =
      Enum.flat_map(providers, fn provider ->
        Map.get(all_connections, provider.key, [])
        |> Enum.map(fn %{uuid: uuid, name: name, data: data} ->
          %{provider: providers_by_key[provider.key], uuid: uuid, name: name, data: data}
        end)
      end)

    assign(socket, :connections, connections)
  end

  defp load_connections(socket), do: assign(socket, :connections, [])

  @impl true
  def render(assigns) do
    ~H"""
    <PhoenixKitWeb.Components.LayoutWrapper.app_layout
      socket={@socket}
      flash={@flash}
      phoenix_kit_current_scope={assigns[:phoenix_kit_current_scope]}
      page_title={gettext("My Integrations")}
      page_subtitle={gettext("Your own service connections — only you can see these")}
      current_path={@url_path}
      project_title={@project_title}
      current_locale={assigns[:current_locale]}
    >
      <div class="px-4 py-6">
        <%!-- Connections table --%>
        <div :if={@connections != []}>
          <.table_default
            id="my-integrations-table"
            toggleable
            items={@connections}
            card_title={fn conn -> conn.provider.name end}
            card_fields={
              fn conn ->
                fields = [
                  %{
                    label: gettext("Status"),
                    value:
                      if(@validating == conn.uuid,
                        do: gettext("Testing..."),
                        else: elem(integration_status_badge(conn.data["status"]), 1)
                      )
                  }
                ]

                fields = fields ++ [%{label: gettext("Name"), value: conn.name}]

                if conn.data["external_account_id"],
                  do:
                    fields ++
                      [%{label: gettext("Account"), value: conn.data["external_account_id"]}],
                  else: fields
              end
            }
          >
            <:toolbar_title>
              <span class="text-sm text-base-content/60">
                {length(@connections)} {gettext("connections")}
              </span>
            </:toolbar_title>
            <:toolbar_actions>
              <.pk_link navigate="/admin/settings/integrations/new" class="btn btn-primary btn-sm">
                <.icon name="hero-plus" class="w-4 h-4" />
                {gettext("Add Integration")}
              </.pk_link>
            </:toolbar_actions>
            <:card_header :let={conn}>
              <div class="flex items-center gap-2">
                <.icon name={conn.provider.icon} class="w-5 h-5" />
                <span class="font-medium">{conn.provider.name}</span>
                <span class="badge badge-ghost badge-xs">{conn.name}</span>
              </div>
            </:card_header>

            <.table_default_header>
              <.table_default_row>
                <.table_default_header_cell>{gettext("Service")}</.table_default_header_cell>
                <.table_default_header_cell>{gettext("Name")}</.table_default_header_cell>
                <.table_default_header_cell>{gettext("Account")}</.table_default_header_cell>
                <.table_default_header_cell>{gettext("Status")}</.table_default_header_cell>
                <.table_default_header_cell>{gettext("Actions")}</.table_default_header_cell>
              </.table_default_row>
            </.table_default_header>

            <.table_default_body>
              <.table_default_row
                :for={conn <- @connections}
                class="relative transform-gpu cursor-pointer"
              >
                <.table_default_cell>
                  <.row_link
                    navigate={Routes.path("/admin/settings/integrations/#{conn.uuid}")}
                    label={conn.provider.name}
                  />
                  <div class="flex items-center gap-2">
                    <.icon name={conn.provider.icon} class="w-4 h-4 text-base-content/60" />
                    <span>{conn.provider.name}</span>
                  </div>
                </.table_default_cell>
                <.table_default_cell>
                  {conn.name}
                </.table_default_cell>
                <.table_default_cell>
                  <span :if={conn.data["external_account_id"]} class="text-sm">
                    {conn.data["external_account_id"]}
                  </span>
                  <span :if={!conn.data["external_account_id"]} class="text-base-content/30">—</span>
                </.table_default_cell>
                <.table_default_cell>
                  <%= if @validating == conn.uuid do %>
                    <span class="badge badge-sm badge-info gap-1">
                      <span class="loading loading-spinner loading-xs"></span>
                      {gettext("Testing...")}
                    </span>
                  <% else %>
                    <% {badge_class, badge_text} = integration_status_badge(conn.data["status"]) %>
                    <div>
                      <span class={"badge badge-sm #{badge_class}"}>{badge_text}</span>
                      <span
                        :if={conn.data["validation_status"] not in [nil, "", "ok"]}
                        class={[
                          "text-xs block mt-0.5",
                          if(conn.data["status"] == "error", do: "text-error", else: "text-warning")
                        ]}
                      >
                        {conn.data["validation_status"]}
                      </span>
                    </div>
                  <% end %>
                </.table_default_cell>
                <.table_default_cell class="relative z-10">
                  <.table_row_menu
                    id={"my-integration-menu-#{conn.uuid}"}
                    mode="auto"
                    label={gettext("Actions")}
                  >
                    <.table_row_menu_link
                      navigate={Routes.path("/admin/settings/integrations/#{conn.uuid}")}
                      icon="hero-pencil"
                      label={gettext("Configure")}
                    />
                    <.table_row_menu_button
                      :if={conn.data["status"] in ["connected", "configured", "error"]}
                      phx-click="validate_connection"
                      phx-value-uuid={conn.uuid}
                      icon="hero-signal"
                      label={gettext("Test Connection")}
                    />
                    <.table_row_menu_divider />
                    <.table_row_menu_button
                      phx-click="remove_connection"
                      phx-value-uuid={conn.uuid}
                      icon="hero-trash"
                      label={gettext("Remove")}
                      variant="error"
                      data-confirm={gettext("Remove this connection?")}
                    />
                  </.table_row_menu>
                </.table_default_cell>
              </.table_default_row>
            </.table_default_body>

            <:card_actions :let={conn}>
              <.table_row_menu
                id={"my-integration-card-menu-#{conn.uuid}"}
                mode="auto"
                label={gettext("Actions")}
              >
                <.table_row_menu_link
                  navigate={Routes.path("/admin/settings/integrations/#{conn.uuid}")}
                  icon="hero-pencil"
                  label={gettext("Configure")}
                />
                <.table_row_menu_button
                  :if={conn.data["status"] in ["connected", "configured", "error"]}
                  phx-click="validate_connection"
                  phx-value-uuid={conn.uuid}
                  icon="hero-signal"
                  label={gettext("Test Connection")}
                />
                <.table_row_menu_divider />
                <.table_row_menu_button
                  phx-click="remove_connection"
                  phx-value-uuid={conn.uuid}
                  icon="hero-trash"
                  label={gettext("Remove")}
                  variant="error"
                  data-confirm={gettext("Remove this connection?")}
                />
              </.table_row_menu>
            </:card_actions>
          </.table_default>
        </div>

        <%!-- Empty state --%>
        <div :if={@connections == []} class="text-center py-12">
          <.icon name="hero-link" class="h-16 w-16 mx-auto text-base-content/40 mb-4" />
          <h3 class="text-lg font-medium mb-2">{gettext("No personal integrations yet")}</h3>
          <p class="text-base-content/70 mb-4">
            {gettext("Connect your own API keys and services. Only you can see these.")}
          </p>
          <.pk_link navigate="/admin/settings/integrations/new" class="btn btn-primary btn-sm">
            <.icon name="hero-plus" class="w-4 h-4" />
            {gettext("Add Integration")}
          </.pk_link>
        </div>
      </div>
    </PhoenixKitWeb.Components.LayoutWrapper.app_layout>
    """
  end
end
