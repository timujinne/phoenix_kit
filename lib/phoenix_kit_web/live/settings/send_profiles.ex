defmodule PhoenixKitWeb.Live.Settings.SendProfiles do
  @moduledoc """
  Send profiles list page — under the core Email Sending settings
  (`/admin/settings/email-sending/profiles`).

  Each send profile references an Integrations connection and carries
  per-account send parameters (sender identity, rate limits, provider
  "advanced" options). At most one profile may be the service-wide default.
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext

  # Imported per-LiveView rather than from `PhoenixKitWeb, :live_view`: a host
  # app that defines its own `row_link/1` would get an ambiguous import the
  # moment core wired this one in project-wide.
  import PhoenixKitWeb.Components.Core.RowLink, only: [row_link: 1]

  alias PhoenixKit.Email.SendProfiles
  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.Routes

  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, gettext("Send Profiles"))
      |> assign(
        :page_subtitle,
        gettext(
          "Service-wide default profile used by newsletter broadcasts. Transactional mail (auth, notifications) is routed by the Default Transactional Integration on the Email Sending page."
        )
      )
      |> assign(:page_section, gettext("Email Sending"))
      |> assign(:page_section_path, Routes.path("/admin/settings/email-sending"))
      |> assign(:project_title, Settings.get_project_title())
      |> assign(:current_path, get_current_path(socket.assigns.current_locale_base))
      |> assign(:send_profiles, [])

    {:ok, socket}
  end

  def handle_params(_params, _url, socket) do
    {:noreply, assign(socket, :send_profiles, SendProfiles.list_send_profiles())}
  end

  def handle_event("make_default", %{"uuid" => uuid}, socket) do
    send_profile = SendProfiles.get_send_profile!(uuid)

    case SendProfiles.set_default_send_profile(send_profile) do
      {:ok, _updated} ->
        {:noreply,
         socket
         |> put_flash(:info, gettext("Default send profile updated"))
         |> assign(:send_profiles, SendProfiles.list_send_profiles())}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, gettext("Could not set default send profile"))}
    end
  end

  def handle_event("delete_send_profile", %{"uuid" => uuid}, socket) do
    handle_delete(socket, uuid)
  end

  defp handle_delete(socket, uuid) do
    send_profile = SendProfiles.get_send_profile!(uuid)

    case SendProfiles.delete_send_profile(send_profile) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, gettext("Send profile deleted"))
         |> assign(:send_profiles, SendProfiles.list_send_profiles())}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, gettext("Cannot delete send profile"))}
    end
  end

  # Card-view field rows for `<.table_default toggleable>` — mirrors the
  # table columns (name/actions are handled by card_header/card_actions).
  defp send_profile_card_fields(send_profile) do
    [
      %{label: gettext("Provider"), value: send_profile.provider_kind},
      %{
        label: gettext("From"),
        value: send_profile.from_name || send_profile.from_email || "-"
      },
      %{
        label: gettext("Rate"),
        value:
          if(send_profile.rate_per_hour,
            do: gettext("%{count}/hr", count: send_profile.rate_per_hour),
            else: "-"
          )
      },
      %{
        label: gettext("Status"),
        value: enabled_badge(%{enabled: send_profile.enabled, size: :sm, class: ""})
      }
    ]
  end

  defp get_current_path(locale) do
    Routes.path("/admin/settings/email-sending/profiles", locale: locale)
  end
end
