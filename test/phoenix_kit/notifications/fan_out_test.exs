defmodule PhoenixKit.Notifications.FanOutTest do
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.Notifications
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth

  defp user do
    {:ok, u} =
      Auth.register_user(%{
        email: "fanout-#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    u
  end

  defp committed_entry(actor_uuid) do
    # A CORE-registered action: type resolution needs the owning module's
    # notification_types in the registry, and only core's own are present
    # in this suite.
    {:ok, entry} =
      PhoenixKit.Activity.log(%{
        action: "comment.replied",
        module: "comments",
        actor_uuid: actor_uuid,
        resource_type: "project",
        resource_uuid: Ecto.UUID.generate(),
        metadata: %{"title" => "Standup"}
      })

    entry
  end

  test "fans one committed entry out per recipient, skipping the actor, no extra feed rows" do
    Settings.update_boolean_setting("notifications_enabled", true)

    actor = user()
    [a, b] = [user(), user()]
    entry = committed_entry(actor.uuid)

    before_entries = PhoenixKit.RepoHelper.repo().aggregate(Entry, :count)

    results =
      Notifications.fan_out_from_activity(entry, [a.uuid, b.uuid, actor.uuid, a.uuid])

    # Deduped recipients: a, b, actor → actor self-skips.
    assert length(results) == 3
    assert Enum.count(results, &match?({:ok, %Notifications.Notification{}}, &1)) == 2
    assert {:ok, :skipped} in results

    # The feed kept exactly the one canonical entry.
    assert PhoenixKit.RepoHelper.repo().aggregate(Entry, :count) == before_entries
  end

  test "recipients' prefs are honored per user" do
    Settings.update_boolean_setting("notifications_enabled", true)

    muted = user()

    {:ok, muted} =
      Auth.update_user_custom_fields(muted, %{
        "notification_preferences" => %{"comments" => false}
      })

    open = user()
    entry = committed_entry(user().uuid)

    results = Notifications.fan_out_from_activity(entry, [muted.uuid, open.uuid])
    assert [{:ok, :skipped}, {:ok, %Notifications.Notification{}}] = results
  end
end
