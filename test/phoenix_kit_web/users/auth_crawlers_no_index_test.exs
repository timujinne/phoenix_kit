defmodule PhoenixKitWeb.Users.AuthCrawlersNoIndexTest do
  @moduledoc """
  Regression test for `crawlers_no_index` not reaching a host application's own
  public LiveViews. `PhoenixKitWeb.Components.LayoutWrapper.app_layout_inner/1`
  is the only place that used to assign `:crawlers_no_index` — but it only wraps
  PhoenixKit's own admin/plugin views. A host app's public LiveView (its own
  layout, not routed through LayoutWrapper) never got the assign, so
  `root.html.heex`'s `<meta name="robots" content="noindex,nofollow">` never
  rendered for it even with the directive enabled (observed on Hydroforce's
  dev environment).

  `PhoenixKitWeb.Test.PublicHostAppLive` (test/support/public_host_app_live.ex)
  stands in for such a view: it mounts through PhoenixKit's
  `:phoenix_kit_mount_current_scope` on_mount (as a host app would, e.g. for
  current_user/locale support) but renders with its own markup, never calling
  `LayoutWrapper.app_layout`. It's routed at a real, test-only path (see
  `PhoenixKitWeb.Router`) rather than mounted via `live_isolated/3`, because
  the on_mount attaches a `:handle_params` hook that requires a non-nil
  `socket.router` — `live_isolated/3` never provides one and raises ("the
  view was not mounted at the router with the live/3 macro").

  Asserts against the actual disconnected/initial HTML response — the
  document a search engine crawler would see — rather than the raw
  `:crawlers_no_index` assign, so this exercises the real root-layout rendering
  path the reported bug was about, not just that the socket carries the
  assign.
  """

  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Modules.Crawlers

  @probe_path "/__test/crawlers-no-index-probe"

  setup do
    on_exit(fn -> Crawlers.update_no_index(false) end)
    :ok
  end

  test "a public host-app LiveView's initial render includes the noindex meta when the directive is enabled",
       %{conn: conn} do
    {:ok, _} = Crawlers.enable_no_index()

    html = conn |> get(@probe_path) |> html_response(200)

    assert html =~ ~s(<meta name="robots" content="noindex,nofollow">)
    assert html =~ ~s(<meta name="googlebot" content="noindex,nofollow">)
    assert html =~ ~s(data-crawlers-no-index="true")
  end

  test "a public host-app LiveView's initial render omits the noindex meta when the directive is disabled",
       %{conn: conn} do
    {:ok, _} = Crawlers.update_no_index(false)

    html = conn |> get(@probe_path) |> html_response(200)

    refute html =~ ~s(<meta name="robots" content="noindex,nofollow">)
    refute html =~ ~s(<meta name="googlebot" content="noindex,nofollow">)
    assert html =~ ~s(data-crawlers-no-index="false")
  end
end
