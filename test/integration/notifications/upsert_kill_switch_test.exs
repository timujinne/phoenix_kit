defmodule PhoenixKit.Integration.Notifications.UpsertKillSwitchTest do
  @moduledoc """
  `upsert_inapp/3` honors the `notifications_enabled` kill switch.

  It didn't: the function is built on `create_inapp/2`, whose documented
  kill-switch bypass is justified only for the DigestWorker ("the digest
  already decided to post") — but `upsert_inapp/3` is a host-facing entry
  point, so "off" quietly did not apply to the newest creation path.

  `async: false` because the switch is a global setting; the sandbox rolls
  the write back, and `enabled?/0` reads uncached, so no cache priming or
  cleanup is needed (same pattern as `FanOutTest`).
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Notifications
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth

  defp create_user do
    {:ok, user} =
      Auth.register_user(%{
        email: "notif_kill_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    user
  end

  test "upsert_inapp is a no-op while notifications are disabled" do
    user = create_user()
    Settings.update_boolean_setting("notifications_enabled", false)

    assert {:ok, :skipped} =
             Notifications.upsert_inapp(user.uuid, "k", %{text: "should not exist"})

    assert {[], 0} = Notifications.list_for_user(user.uuid)
  end

  test "and works again the moment they are re-enabled" do
    user = create_user()
    Settings.update_boolean_setting("notifications_enabled", true)

    assert {:ok, %Notifications.Notification{}} =
             Notifications.upsert_inapp(user.uuid, "k", %{text: "posted"})
  end
end
