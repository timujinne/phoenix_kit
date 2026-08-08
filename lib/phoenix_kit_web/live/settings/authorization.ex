defmodule PhoenixKitWeb.Live.Settings.Authorization do
  @moduledoc """
  Authorization settings management LiveView for PhoenixKit.

  Manages login page branding and authentication methods including
  magic links and OAuth provider configuration.
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.Modules.Storage.URLSigner
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.OAuthConfig
  alias PhoenixKit.Utils.CssValue

  require Logger

  def mount(_params, _session, socket) do
    current_settings = Settings.list_all_settings()
    defaults = Settings.get_defaults()

    merged_settings = Map.merge(defaults, current_settings)
    changeset = Settings.change_settings(merged_settings)

    socket =
      socket
      |> assign(:page_title, "Authorization Settings")
      |> assign(:settings, merged_settings)
      |> assign(:saved_settings, merged_settings)
      |> assign(:changeset, changeset)
      |> assign(:saving, false)
      |> assign(
        :project_title,
        merged_settings["project_title"] || PhoenixKit.Config.get(:project_title, "PhoenixKit")
      )
      |> assign(:show_media_selector, false)
      |> assign(:media_selection_target, nil)

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  def handle_event("validate_settings", %{"settings" => settings_params}, socket) do
    changeset = Settings.validate_settings(settings_params)

    socket =
      socket
      |> assign(:settings, settings_params)
      |> assign(:changeset, changeset)

    {:noreply, socket}
  end

  def handle_event("save_settings", %{"settings" => settings_params}, socket) do
    socket = assign(socket, :saving, true)

    case validate_background_color(settings_params) do
      :ok ->
        do_save_settings(socket, settings_params)

      {:error, message} ->
        {:noreply, socket |> assign(:saving, false) |> put_flash(:error, message)}
    end
  end

  def handle_event("test_oauth", %{"provider" => provider}, socket) do
    provider_atom = String.to_existing_atom(provider)
    credentials = oauth_credentials_from_settings(provider_atom, socket.assigns.settings)

    case OAuthConfig.test_connection(provider_atom, credentials) do
      {:ok, message} ->
        {:noreply, put_flash(socket, :info, message)}

      {:error, message} ->
        {:noreply, put_flash(socket, :error, message)}
    end
  end

  def handle_event("reload_oauth_config", _params, socket) do
    OAuthConfig.configure_providers()
    {:noreply, put_flash(socket, :info, "OAuth configuration reloaded from database")}
  end

  def handle_event("open_media_selector", %{"target" => target}, socket) do
    {:noreply,
     socket
     |> assign(:show_media_selector, true)
     |> assign(:media_selection_target, String.to_existing_atom(target))}
  end

  def handle_event("clear_branding_image", %{"target" => target}, socket) do
    key =
      case target do
        "logo" -> "auth_logo_file_uuid"
        "background" -> "auth_background_image_file_uuid"
        "background_mobile" -> "auth_background_image_mobile_file_uuid"
      end

    settings = Map.put(socket.assigns.settings, key, "")
    {:noreply, assign(socket, :settings, settings)}
  end

  ## Media selector callbacks

  def handle_info({:media_selected, file_uuids}, socket) do
    file_uuid = List.first(file_uuids) || ""

    key =
      case socket.assigns.media_selection_target do
        :logo -> "auth_logo_file_uuid"
        :background -> "auth_background_image_file_uuid"
        :background_mobile -> "auth_background_image_mobile_file_uuid"
      end

    settings = Map.put(socket.assigns.settings, key, file_uuid)

    {:noreply,
     socket
     |> assign(:settings, settings)
     |> assign(:show_media_selector, false)
     |> assign(:media_selection_target, nil)}
  end

  def handle_info({:media_selector_closed}, socket) do
    {:noreply,
     socket
     |> assign(:show_media_selector, false)
     |> assign(:media_selection_target, nil)}
  end

  # Helper functions

  # The background colour lands in a `<style>` element on every public auth
  # page, so it is refused on write as well as sanitised on read
  # (`PhoenixKitWeb.Components.AuthPageWrapper`). Rejecting here is what tells
  # the operator their value was not stored; the read-side guard is what keeps
  # the page safe regardless of what is already in the table.
  defp validate_background_color(%{"auth_background_color" => value})
       when is_binary(value) and value != "" do
    if CssValue.color(value) == "" do
      {:error,
       "Background color must be a plain CSS color or gradient — " <>
         "for example #1e293b, rgb(30 41 59) or linear-gradient(135deg, #667eea, #764ba2)"}
    else
      :ok
    end
  end

  defp validate_background_color(_settings_params), do: :ok

  defp do_save_settings(socket, settings_params) do
    case Settings.update_settings(settings_params) do
      {:ok, updated_settings} ->
        OAuthConfig.configure_providers()

        changeset = Settings.change_settings(updated_settings)

        socket =
          socket
          |> assign(:settings, updated_settings)
          |> assign(:saved_settings, updated_settings)
          |> assign(:changeset, changeset)
          |> assign(:saving, false)
          |> put_flash(:info, "Authorization settings updated successfully")

        {:noreply, socket}

      {:error, errors} ->
        error_msg = format_error_message(errors)

        socket =
          socket
          |> assign(:saving, false)
          |> put_flash(:error, error_msg)

        {:noreply, socket}
    end
  end

  defp format_error_message(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Map.values()
    |> List.flatten()
    |> Enum.join(", ")
  end

  def signed_preview_url(file_uuid, variant) do
    URLSigner.signed_url(file_uuid, variant)
  end

  def get_oauth_callback_url(settings, provider) do
    site_url = settings["site_url"] || "https://example.com"
    url_prefix = PhoenixKit.Config.get_url_prefix()
    # "/" is the sentinel Config.get_url_prefix/0 returns for "no prefix"
    # (see compute_url_prefix/0) — treat it the same as "" here, matching
    # Routes.path/2 and UeberAuth.get_default_base_path/0.
    base_prefix = if url_prefix == "/", do: "", else: url_prefix

    "#{site_url}#{base_prefix}/users/auth/#{provider}/callback"
  end

  # Builds the credentials map OAuthConfig.test_connection/2 expects, from
  # the unsaved in-memory form state (`socket.assigns.settings`) rather than
  # the database — the "Test Credentials" button must validate what the
  # admin just typed, not the last-persisted values.
  defp oauth_credentials_from_settings(:google, settings) do
    %{
      client_id: settings["oauth_google_client_id"] || "",
      client_secret: settings["oauth_google_client_secret"] || ""
    }
  end

  defp oauth_credentials_from_settings(:github, settings) do
    %{
      client_id: settings["oauth_github_client_id"] || "",
      client_secret: settings["oauth_github_client_secret"] || ""
    }
  end

  defp oauth_credentials_from_settings(:facebook, settings) do
    %{
      app_id: settings["oauth_facebook_app_id"] || "",
      app_secret: settings["oauth_facebook_app_secret"] || ""
    }
  end

  @doc """
  Collapsible per-provider OAuth setup guide: the callback-URL box with a copy
  button, the provider-specific console steps (slot), and the reverse-proxy
  notice. One component instead of four hand-copied ~95-line blocks.
  """
  attr :callback_url, :string, required: true
  attr :copy_hint, :string, required: true, doc: "e.g. \"Copy this URL to Google Cloud Console\""
  slot :steps, required: true, doc: "provider-specific <li> instruction items"

  def oauth_setup_instructions(assigns) do
    ~H"""
    <div class="collapse collapse-arrow bg-base-200 mt-4">
      <input type="checkbox" class="peer" />
      <div class="collapse-title text-sm font-medium">
        {gettext("Setup Instructions")}
      </div>
      <div class="collapse-content text-sm space-y-4">
        <%!-- Callback URL --%>
        <div class="bg-base-100 border border-base-300 rounded-lg p-4">
          <div class="flex items-start gap-3">
            <.icon
              name="hero-information-circle"
              class="stroke-current shrink-0 h-5 w-5 text-info mt-0.5"
            />
            <div class="flex-1 min-w-0">
              <div class="text-sm font-semibold text-base-content mb-2">
                {gettext("Callback URL")}
              </div>
              <div class="flex items-center gap-2">
                <code class="flex-1 px-3 py-2 bg-base-200 text-base-content border border-base-300 rounded font-mono text-xs break-all">
                  {@callback_url}
                </code>
                <button
                  type="button"
                  class="btn btn-sm btn-square btn-outline"
                  onclick={"navigator.clipboard.writeText('#{@callback_url}')"}
                  title={gettext("Copy to clipboard")}
                >
                  <.icon name="hero-clipboard" class="h-4 w-4" />
                </button>
              </div>
              <div class="text-xs text-base-content/60 mt-2">{@copy_hint}</div>
            </div>
          </div>
        </div>

        <%!-- Provider-specific steps --%>
        <div class="space-y-3">
          <ol class="list-decimal list-inside space-y-2 text-base-content/80">
            {render_slot(@steps)}
          </ol>
        </div>

        <%!-- Reverse Proxy Notice --%>
        <div class="bg-base-200 border border-base-300 rounded-lg p-3 text-xs">
          <div class="flex items-start gap-2">
            <.icon name="hero-information-circle" class="h-4 w-4 text-info shrink-0 mt-0.5" />
            <div class="text-base-content/80">
              <strong class="text-base-content">
                {gettext("Reverse Proxy Users:")}
              </strong>
              {gettext("If behind nginx/apache, ensure")}
              <code class="px-1 py-0.5 bg-base-300 text-base-content rounded text-xs">
                X-Forwarded-Proto
              </code>
              {gettext("header is set to")}
              <code class="px-1 py-0.5 bg-base-300 text-base-content rounded text-xs">
                https
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
