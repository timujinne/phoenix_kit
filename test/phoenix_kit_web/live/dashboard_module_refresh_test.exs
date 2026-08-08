defmodule PhoenixKitWeb.Live.DashboardModuleRefreshTest do
  @moduledoc """
  The module-refresh subscription belongs to the GATE, not to this page.

  `:phoenix_kit_ensure_admin` subscribes an admin mount to module
  enable/disable events so the sidebar re-renders the moment an Owner toggles a
  module, and it assigns `:phoenix_kit_current_module_key` as part of the
  per-view permission enforcement. `/admin` mounts through that hook like every
  other admin page, so `PhoenixKitWeb.Live.Dashboard` must not do either job
  itself.

  An earlier revision moved the `/admin` route onto the authenticated
  live_session, which took the hook away, and restored the subscription from
  `Dashboard.mount/3` via a public `Auth.attach_module_refresh_hook/1`. The
  route is back where it belongs and that second mechanism is gone; these tests
  are what notices if it comes back — two mechanisms for one subscription is
  how a socket ends up subscribed twice, or an "idempotent" guard ends up load
  bearing.

  Who the gate subscribes is decided by `Scope.can_access_admin_area?/1` in the
  hook, so a visitor admitted only by the landing exemption — holding no
  permissions, shown no navigation — never joins the topic. That branch needs a
  user row to reach; the pure decision it hangs off is pinned DB-free in
  `test/phoenix_kit_web/users/auth_test.exs`.

  DB-free: both scopes here are denied the statistics, so `assign_overview/3`
  runs no aggregate. The Client scope is the interesting one — it can reach the
  admin area (it holds two permissions) without holding everything.
  """
  use ExUnit.Case, async: false

  alias Phoenix.LiveView.Lifecycle
  alias Phoenix.LiveView.Socket
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKitWeb.Live.Dashboard

  defp scope(roles, permissions) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000c1", email: "mod@example.com"},
      authenticated?: true,
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  # Disconnected: `connected?/1` is false, so `assign_overview/3` neither
  # subscribes nor tracks presence.
  defp socket(scope) do
    %Socket{
      assigns: %{__changed__: %{}, phoenix_kit_current_scope: scope},
      private: %{connect_params: %{}, lifecycle: %Lifecycle{}}
    }
  end

  defp hook_names(socket), do: Enum.map(socket.private.lifecycle.handle_info, & &1.id)

  describe "Dashboard.mount/3 does not duplicate what the admin hook already did" do
    test "it attaches no module-refresh hook of its own" do
      for s <- [scope(["Client"], ["client_portal", "notifications"]), scope(["User"], [])] do
        {:ok, socket} = Dashboard.mount(%{}, %{}, socket(s))

        refute socket.assigns[:phoenix_kit_module_hook_attached?]
        refute :phoenix_kit_module_refresh in hook_names(socket)
      end
    end

    test "it does not set the current-module key" do
      # On the landing, `admin_gate_decision/2` answers `:landing` and the hook
      # skips `enforce_admin_view_permission/2` — which is what assigns this
      # key. Its only reader, `handle_scope_refresh/2`, uses it to push a user
      # off a page whose module permission they just lost, and that must never
      # happen on the guaranteed landing. The page must not reinstate it.
      for s <- [scope(["Client"], ["client_portal"]), scope(["User"], [])] do
        {:ok, socket} = Dashboard.mount(%{}, %{}, socket(s))
        refute Map.has_key?(socket.assigns, :phoenix_kit_current_module_key)
      end
    end

    test "the page still records whether the visitor may see operator content" do
      # The one admin-shaped decision the page does make for itself, and the
      # one the welcome-only rendering hangs off.
      client = scope(["Client"], ["client_portal", "notifications"])
      assert Scope.can_access_admin_area?(client)
      {:ok, socket} = Dashboard.mount(%{}, %{}, socket(client))
      assert socket.assigns.can_access_admin_area?

      plain = scope(["User"], [])
      refute Scope.can_access_admin_area?(plain)
      {:ok, socket} = Dashboard.mount(%{}, %{}, socket(plain))
      refute socket.assigns.can_access_admin_area?
    end
  end
end
