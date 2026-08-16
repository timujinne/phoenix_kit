defmodule PhoenixKitWeb.Live.Notifications.InboxGroupingTest do
  @moduledoc """
  The inbox's day sections against the unseen-first order.

  `Notifications.list_for_user/2` returns unseen first and only then
  newest-first, so the day sequence restarts at the seen block. The grouping
  used to chunk on the day alone, which emitted the same header twice — one
  "Today" for the unread run and another for the read one, with a week of
  history in between. Pinned here because the duplicate is invisible until an
  inbox holds both read and unread rows spanning more than one day, which no
  other test sets up.
  """
  use PhoenixKitWeb.ConnCase, async: true

  import Ecto.Query

  alias PhoenixKit.Activity
  alias PhoenixKit.Notifications
  alias PhoenixKit.Notifications.Notification
  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.Routes

  @inbox_path Routes.path("/admin/notifications")

  defp create_user do
    {:ok, user} =
      Auth.register_user(%{
        email: "inbox_group_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    user
  end

  # One notification for `target`, aged `days_ago` and optionally already read.
  # `inserted_at` is written directly: the fan-out stamps "now", and the bug
  # only shows up once rows straddle a day boundary.
  defp notify(target, actor, label, days_ago, seen?) do
    Activity.log(%{
      action: "demo.notification",
      module: "demo",
      mode: "manual",
      actor_uuid: actor.uuid,
      resource_type: "demo",
      target_uuid: target.uuid,
      metadata: %{"notification_text" => label}
    })

    {rows, _} = Notifications.list_for_user(target.uuid)

    notification =
      Enum.find(rows, &(get_in(&1.activity.metadata, ["notification_text"]) == label))

    if seen?, do: {:ok, _} = Notifications.mark_seen(target.uuid, notification.uuid)

    backdate(notification.uuid, days_ago)
    notification
  end

  defp backdate(uuid, days_ago) do
    at = DateTime.utc_now() |> DateTime.add(-days_ago, :day) |> DateTime.truncate(:second)

    RepoHelper.repo().update_all(
      from(n in Notification, where: n.uuid == ^uuid),
      set: [inserted_at: at]
    )
  end

  # The section headers, in render order.
  defp headers(html) do
    html
    |> Floki.parse_document!()
    |> Floki.find("h2.uppercase")
    |> Enum.map(&(&1 |> Floki.text() |> String.trim()))
  end

  test "read and unread rows spanning two days never repeat a section header", %{conn: conn} do
    {admin, _token} = create_admin_user()
    actor = create_user()

    # Both days present on both sides of the seen split — the minimum shape
    # that makes a day-only chunk repeat itself.
    notify(admin, actor, "unread today", 0, false)
    notify(admin, actor, "unread older", 3, false)
    notify(admin, actor, "read today", 0, true)
    notify(admin, actor, "read older", 3, true)

    conn = log_in_user(conn, admin)
    {:ok, _view, html} = live(conn, @inbox_path)

    headers = headers(html)

    assert length(headers) == 4
    assert headers == Enum.uniq(headers)

    # The unread run leads, and says so — an inbox opened to answer "what did
    # I miss" should not make the reader infer it from row tint alone.
    assert [first, second | _] = headers
    assert first =~ "Unread"
    assert second =~ "Unread"
  end
end
