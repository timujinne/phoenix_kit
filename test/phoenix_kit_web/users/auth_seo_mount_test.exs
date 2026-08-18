defmodule PhoenixKitWeb.Users.AuthSEOMountTest do
  @moduledoc """
  Confirms `PhoenixKitWeb.Users.AuthSEO.seo_assigns/1` is actually wired into
  `mount/3` for the three stable, token-free auth LiveViews (registration,
  log-in, magic-link registration request) — `auth_seo_test.exs` covers the
  helper's own correctness, this covers that each LiveView calls it and
  assigns the result to the socket.

  There is nothing to see in the rendered HTML: `@canonical_url` /
  `@hreflang_links` are consumed by the HOST app's root layout (see the
  moduledoc on `AuthSEO`), which this library's own test endpoint does not
  render — same reasoning as `QrLoginConfirmTest` for reading state at the
  same layer the assign lands on, rather than through a render that was never
  going to show it. `:sys.get_state/1` on the LiveView pid is the documented
  house technique for reaching process state without a render or a sleep
  (see `AGENTS.md`'s test guidelines).
  """

  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKitWeb.Users.AuthSEO

  # Registration and log-in track an anonymous visitor session on connected
  # mount via `PhoenixKit.Admin.SimplePresence`. In a real host app that
  # GenServer is started by `PhoenixKit.Supervisor` (part of the host's own
  # supervision tree); this library's own test suite doesn't run inside one,
  # so any test that connects one of those two LiveViews has to start it —
  # mirrors `QrLoginConfirmTest`'s `start_supervised!(Keyfob.Store.ETS)` for
  # the same class of gap.
  setup do
    start_supervised!(PhoenixKit.Admin.SimplePresence)
    :ok
  end

  defp seo_assigns_of(view) do
    %{socket: socket} = :sys.get_state(view.pid)
    socket.assigns
  end

  describe "registration" do
    test "assigns canonical_url and hreflang_links matching AuthSEO", %{conn: conn} do
      expected = AuthSEO.seo_assigns("/users/register")

      {:ok, view, _html} = live(conn, "/phoenix_kit/users/register")

      assigns = seo_assigns_of(view)
      assert assigns.canonical_url == expected.canonical_url
      assert assigns.hreflang_links == expected.hreflang_links
    end
  end

  describe "log-in" do
    test "assigns canonical_url and hreflang_links matching AuthSEO", %{conn: conn} do
      expected = AuthSEO.seo_assigns("/users/log-in")

      {:ok, view, _html} = live(conn, "/phoenix_kit/users/log-in")

      assigns = seo_assigns_of(view)
      assert assigns.canonical_url == expected.canonical_url
      assert assigns.hreflang_links == expected.hreflang_links
    end
  end

  describe "magic-link registration request" do
    test "assigns canonical_url and hreflang_links matching AuthSEO", %{conn: conn} do
      expected = AuthSEO.seo_assigns("/users/register/magic-link")

      {:ok, view, _html} = live(conn, "/phoenix_kit/users/register/magic-link")

      assigns = seo_assigns_of(view)
      assert assigns.canonical_url == expected.canonical_url
      assert assigns.hreflang_links == expected.hreflang_links
    end
  end
end
