defmodule PhoenixKitWeb.Live.Settings.EmailSending do
  @moduledoc """
  Core "Email Sending" admin settings page (`/admin/settings/email-sending`).

  Covers what core owns about outbound email: sender identity, which
  transport is actually in effect (static app-config mailer vs. a
  connected Integrations provider), the operator's choice of default send
  integration, and a test-send action. Send Profiles (per-account sender
  identity, rate limits, provider-specific options) live one level down
  at `/admin/settings/email-sending/profiles`.

  ## Path note

  This page is deliberately at `email-sending`, not `emails` — the
  optional `phoenix_kit_emails` module registers its own routable
  "Emails" settings tab at `/admin/settings/emails` (via its
  `settings_tabs/0`). The two pages coexist under different paths for
  now; a later change (Stage 1 task A5) will collapse them into one.

  ## Module-contributed sections

  Modules can extend this page without the core page knowing anything
  about them, via `PhoenixKit.Module.email_settings_sections/0` — see
  `PhoenixKit.ModuleRegistry.all_email_settings_sections/0`. Each
  section is a module-owned `Phoenix.LiveComponent`, rendered below the
  core sections, gated by its declared permission (or shown to any admin
  when the permission is `nil`).
  """

  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.Config
  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Providers
  alias PhoenixKit.Mailer
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes

  @default_integration_setting "default_email_integration_uuid"

  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, gettext("Email Sending"))
      |> assign(
        :page_subtitle,
        gettext(
          "Sender identity, transport, and the default integration used to deliver outbound email"
        )
      )
      |> assign(:project_title, Settings.get_project_title())
      |> assign(:current_path, get_current_path(socket.assigns.current_locale_base))
      |> assign_sender_identity()
      |> assign_transport_info()
      |> assign_email_integrations()
      |> assign_default_integration()
      |> assign_email_settings_sections()

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  def handle_event("save_sender_identity", %{"from_name" => name, "from_email" => email}, socket) do
    name = String.trim(name)
    email = String.trim(email)

    with {:ok, _} <- Settings.update_setting("from_name", name),
         {:ok, _} <- Settings.update_setting("from_email", email) do
      {:noreply,
       socket
       |> put_flash(:info, gettext("Sender identity updated"))
       |> assign_sender_identity()}
    else
      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, gettext("Could not save sender identity"))}
    end
  end

  def handle_event("select_default_integration", %{"integration_uuid" => uuid}, socket) do
    case Settings.update_setting(@default_integration_setting, uuid) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, gettext("Default send integration updated"))
         |> assign_default_integration()}

      {:error, _changeset} ->
        {:noreply,
         put_flash(socket, :error, gettext("Could not update default send integration"))}
    end
  end

  def handle_event("send_test_email", %{"recipient" => recipient}, socket) do
    case String.trim(recipient) do
      "" ->
        {:noreply, put_flash(socket, :error, gettext("Enter a recipient email address"))}

      recipient ->
        send_test_email(socket, recipient)
    end
  end

  defp send_test_email(socket, recipient) do
    email =
      Swoosh.Email.new()
      |> Swoosh.Email.to(recipient)
      |> Swoosh.Email.from({Mailer.get_from_name(), Mailer.get_from_email()})
      |> Swoosh.Email.subject(
        gettext("Test email from %{site}", site: socket.assigns.project_title)
      )
      |> Swoosh.Email.text_body(
        gettext("This is a test email sent from the Email Sending settings page.")
      )

    case Mailer.deliver_email(email) do
      {:ok, _result} ->
        {:noreply,
         put_flash(
           socket,
           :info,
           gettext("Test email sent to %{recipient}", recipient: recipient)
         )}

      {:error, {:incomplete_credentials, missing_fields}} ->
        {:noreply,
         put_flash(
           socket,
           :error,
           gettext(
             "Could not send test email: the send integration is missing required field(s): %{fields}",
             fields: Enum.map_join(missing_fields, ", ", &to_string/1)
           )
         )}

      {:error, reason} ->
        {:noreply,
         put_flash(
           socket,
           :error,
           gettext("Could not send test email: %{reason}", reason: inspect(reason))
         )}
    end
  end

  # ---------------------------------------------------------------------------
  # Private — assigns
  # ---------------------------------------------------------------------------

  defp assign_sender_identity(socket) do
    socket
    |> assign(:from_name, Settings.get_setting("from_name", ""))
    |> assign(:from_email, Settings.get_setting("from_email", ""))
    |> assign(:effective_from_name, Mailer.get_from_name())
    |> assign(:effective_from_email, Mailer.get_from_email())
  end

  defp assign_transport_info(socket) do
    mailer = Mailer.get_mailer()
    built_in? = mailer == PhoenixKit.Mailer

    config =
      if built_in?,
        do: Config.get(mailer, []),
        else: Config.get_parent_app_config(mailer, [])

    socket
    |> assign(:mailer_module, mailer)
    |> assign(:mailer_built_in?, built_in?)
    |> assign(:mailer_adapter, Keyword.get(config, :adapter))
  end

  # Single query for all email-capable providers' connections, mirroring
  # `PhoenixKitWeb.Live.Settings.Integrations.load_connections/1`.
  defp assign_email_integrations(socket) do
    providers = Providers.with_capability(:email_send)
    provider_keys = Enum.map(providers, & &1.key)
    providers_by_key = Map.new(providers, &{&1.key, &1})

    all_connections = Integrations.load_all_connections(provider_keys)

    connections =
      Enum.flat_map(providers, fn provider ->
        all_connections
        |> Map.get(provider.key, [])
        |> Enum.map(fn %{uuid: uuid, name: name, data: data} ->
          %{provider: providers_by_key[provider.key], uuid: uuid, name: name, data: data}
        end)
      end)

    assign(socket, :email_connections, connections)
  end

  defp assign_default_integration(socket) do
    assign(
      socket,
      :default_integration_uuid,
      Settings.get_setting(@default_integration_setting, "")
    )
  end

  defp assign_email_settings_sections(socket) do
    scope = socket.assigns[:phoenix_kit_current_scope]

    sections =
      ModuleRegistry.all_email_settings_sections()
      |> Enum.filter(&section_visible?(&1, scope))

    assign(socket, :email_settings_sections, sections)
  end

  defp section_visible?(%{permission: nil}, _scope), do: true

  defp section_visible?(%{permission: permission}, scope),
    do: Scope.has_module_access?(scope, permission)

  # ---------------------------------------------------------------------------
  # Private — template helpers
  # ---------------------------------------------------------------------------

  defp integration_status_badge("connected"), do: {"badge-success", gettext("Connected")}
  defp integration_status_badge("configured"), do: {"badge-warning", gettext("Not tested")}
  defp integration_status_badge("disconnected"), do: {"badge-ghost", gettext("Not connected")}
  defp integration_status_badge("error"), do: {"badge-error", gettext("Error")}
  defp integration_status_badge(_), do: {"badge-ghost", gettext("Not configured")}

  defp get_current_path(locale) do
    Routes.path("/admin/settings/email-sending", locale: locale)
  end
end
