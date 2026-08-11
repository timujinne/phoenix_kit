defmodule PhoenixKit.Integration.Notifications.OrderingTest do
  @moduledoc """
  Unseen first, then newest first within each group.

  Newest-first alone interleaves the two: reading a notification leaves it
  where it was, so anything still outstanding ends up scattered among things
  already dealt with. On an inbox of any size that means scrolling the whole
  list to find what was missed — the one question a notification centre exists
  to answer at a glance.

  Ordering is a promise the UI makes, so it is pinned against the database
  rather than against a sort function: this is what a host embedding the bell
  actually gets.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Activity
  alias PhoenixKit.Notifications
  alias PhoenixKit.Users.Auth

  defp create_user do
    {:ok, user} =
      Auth.register_user(%{
        email: "notif_order_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    user
  end

  # One notification for `target`, labelled so order is readable in a failure.
  # The actor differs from the target so the activity hook fans it out.
  defp notify(target, actor, label) do
    Activity.log(%{
      action: "demo.notification",
      module: "demo",
      mode: "manual",
      actor_uuid: actor.uuid,
      resource_type: "demo",
      target_uuid: target.uuid,
      metadata: %{"notification_text" => label}
    })

    # `inserted_at` has second granularity in this schema, so several created
    # inside one second would tie and leave the newest-first half of the order
    # unprovable. Waiting is the honest way to get distinct timestamps.
    Process.sleep(1_100)

    {rows, _} = Notifications.list_for_user(target.uuid)
    Enum.find(rows, &(text(&1) == label))
  end

  defp text(notification), do: get_in(notification.activity.metadata, ["notification_text"])

  defp labels(target) do
    {rows, _} = Notifications.list_for_user(target.uuid)
    Enum.map(rows, &text/1)
  end

  defp bell_labels(target, limit) do
    target.uuid |> Notifications.recent_for_user(limit) |> Enum.map(&text/1)
  end

  describe "list_for_user/2" do
    @tag timeout: 120_000
    test "an unseen older notification outranks a seen newer one" do
      target = create_user()
      actor = create_user()

      notify(target, actor, "old")
      newer = notify(target, actor, "new")

      # Newest first while both are unseen.
      assert labels(target) == ["new", "old"]

      # Reading the newer one sends it below the older one still outstanding —
      # the whole point. Before this, "new" stayed on top and "old" sat under
      # something already handled.
      {:ok, _} = Notifications.mark_seen(target.uuid, newer.uuid)

      assert labels(target) == ["old", "new"]
    end

    @tag timeout: 120_000
    test "newest first still holds within each group" do
      target = create_user()
      actor = create_user()

      notify(target, actor, "a")
      notify(target, actor, "b")
      c = notify(target, actor, "c")
      d = notify(target, actor, "d")

      # The two NEWEST are the ones read. Marking the two oldest instead would
      # leave both orderings agreeing on d, c, b, a, and prove nothing.
      {:ok, _} = Notifications.mark_seen(target.uuid, c.uuid)
      {:ok, _} = Notifications.mark_seen(target.uuid, d.uuid)

      # Unseen b, a (newest first) — then seen d, c (newest first). Plain
      # newest-first would say d, c, b, a.
      assert labels(target) == ["b", "a", "d", "c"]
    end

    @tag timeout: 120_000
    test "all seen falls back to plain newest first" do
      target = create_user()
      actor = create_user()

      first = notify(target, actor, "first")
      second = notify(target, actor, "second")

      {:ok, _} = Notifications.mark_seen(target.uuid, first.uuid)
      {:ok, _} = Notifications.mark_seen(target.uuid, second.uuid)

      assert labels(target) == ["second", "first"]
    end
  end

  describe "recent_for_user/2" do
    @tag timeout: 120_000
    test "an unread notification is not pushed off the end by a read one" do
      # The dropdown shows a handful, so this is worse here than in the full
      # list: with plain newest-first the badge counts something the bell
      # cannot show, because a notification already read took its place.
      target = create_user()
      actor = create_user()

      notify(target, actor, "unread")
      read = notify(target, actor, "read")

      {:ok, _} = Notifications.mark_seen(target.uuid, read.uuid)

      assert bell_labels(target, 1) == ["unread"]
      assert Notifications.count_unread(target.uuid) == 1
    end
  end
end
