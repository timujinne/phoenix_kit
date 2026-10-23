defmodule PhoenixKitWeb.Live.Settings.ApiApprovals do
  @moduledoc """
  Compatibility redirect for the retired `/admin/settings/api/approvals` page.

  The approvals queue is a menu entry of its own at `/admin/approvals`
  (`PhoenixKitWeb.Live.Approvals`), shown while the site uses approvals. This route stays
  registered, still gated by `api`, because the old path is out in the world: bookmarks, and
  the link of notifications that were sent before the move. The `#approval-<uuid>` fragment
  of such a link is lost by the server-side redirect; the page then simply opens at the top.

  Nothing is rendered: `push_navigate/2` from `mount/3` redirects before the first paint.
  """
  use PhoenixKitWeb, :live_view

  alias PhoenixKit.Utils.Routes

  @impl true
  def mount(_params, _session, socket) do
    {:ok, push_navigate(socket, to: Routes.path("/admin/approvals"))}
  end

  @impl Phoenix.LiveView
  def render(assigns), do: ~H""
end
