defmodule PhoenixKitWeb.ReferralGateRouteTest do
  @moduledoc """
  `/users/referral` is where every authentication gate parks an unadmitted
  account, so it is the one page such an account MUST be able to reach.

  If it ever moved into a gated `live_session`, the gate would redirect it to
  itself and a parked user would have no way out but log-out — a lockout that
  no other test would notice, because every gated page behaves correctly right
  up until you look at this one.
  """
  use PhoenixKitWeb.ConnCase, async: true

  # Suffix-matched: the real path carries the host's mount prefix and an
  # optional locale segment.
  defp routes_ending_in(suffix) do
    Enum.filter(
      PhoenixKitWeb.Router.__routes__(),
      &(&1.verb == :get and String.ends_with?(&1.path, suffix))
    )
  end

  defp on_mount_ids(route) do
    case get_in(route.metadata, [:phoenix_live_view]) do
      {_view, _action, _opts, %{extra: %{on_mount: hooks}}} -> Enum.map(hooks, & &1.id)
      _ -> []
    end
  end

  test "is routed on the ungated auth surface, not behind an account gate" do
    routes = routes_ending_in("/users/referral")

    assert routes != [], "/users/referral is not routed at all"

    on_mounts = routes |> Enum.flat_map(&on_mount_ids/1) |> Enum.uniq()

    # The permissive mount hook assigns the scope without gating on it. Any
    # `ensure_*` hook here would mean the parked user is redirected away from
    # the only page that can unblock them.
    refute Enum.any?(on_mounts, fn
             {_mod, hook} -> hook |> to_string() |> String.contains?("ensure_")
             _ -> false
           end),
           "the referral gate page is behind an ensure_* hook: #{inspect(on_mounts)}"
  end

  test "/users/confirm is on the same ungated surface, for the same reason" do
    # The sibling parked page. Pinning both together says the property belongs
    # to the surface rather than to one route.
    routes = routes_ending_in("/users/confirm")

    assert routes != []

    refute Enum.any?(routes, fn route ->
             Enum.any?(on_mount_ids(route), fn
               {_mod, hook} -> hook |> to_string() |> String.contains?("ensure_")
               _ -> false
             end)
           end)
  end
end
