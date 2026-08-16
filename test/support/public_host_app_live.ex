defmodule PhoenixKitWeb.Test.PublicHostAppLive do
  @moduledoc """
  Stand-in for a host app's own public LiveView: mounted at a real router
  path (routing features like `on_mount`'s `:handle_params` hooks require a
  non-nil `socket.router`, which `Phoenix.LiveViewTest.live_isolated/3`
  never provides) through `:phoenix_kit_mount_current_scope` — the on_mount
  a host app uses for current_user/locale support — but rendering with its
  own markup, never calling `LayoutWrapper.app_layout`.

  Routed only in `Mix.env() == :test` (see `PhoenixKitWeb.Router`); backs
  `test/phoenix_kit_web/users/auth_crawlers_no_index_test.exs`.
  """
  use Phoenix.LiveView

  on_mount {PhoenixKitWeb.Users.Auth, :phoenix_kit_mount_current_scope}

  @impl true
  def render(assigns) do
    ~H"""
    <div id="crawlers-no-index-probe" data-crawlers-no-index={inspect(assigns[:crawlers_no_index])}>
    </div>
    """
  end
end
