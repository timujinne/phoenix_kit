defmodule PhoenixKitWeb.Live.Settings.ApiGuide do
  @moduledoc """
  Compatibility redirect for the retired `/admin/settings/api/guide` page.

  The guide is the "API guide" tab of Settings -> API (`/admin/settings/api?tab=guide`,
  `PhoenixKitWeb.Live.Settings.ApiGuidePanel`). This route stays registered, still gated
  by `api` (`PhoenixKitWeb.Users.Auth`'s view map), because the old path is out in the
  world: bookmarks and links. The locale of the old address is kept.

  Nothing is rendered: `push_navigate/2` from `mount/3` redirects before the first paint.
  """
  use PhoenixKitWeb, :live_view

  alias PhoenixKit.Utils.Routes

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     push_navigate(socket,
       to:
         Routes.path("/admin/settings/api?tab=guide",
           locale: socket.assigns[:current_locale_base]
         )
     )}
  end

  @impl Phoenix.LiveView
  def render(assigns), do: ~H""
end
