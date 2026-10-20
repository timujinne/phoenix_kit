defmodule PhoenixKit.API.ApprovalsNotifierTest do
  @moduledoc """
  The "approval waiting" notice: to those who may decide, at most one per key
  per ten minutes, coalesced into one unread notification.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiFlowHarness

  alias PhoenixKit.API.Approvals.Notifier
  alias PhoenixKit.API.Canonical
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Notifications
  alias PhoenixKit.Test.ApiHarness

  @tool "flowkit.delete_items"

  setup do
    setup_flow()
    %{agent: agent(), owner: KeyTestSupport.owner_user()}
  end

  defp later(time, seconds), do: DateTime.add(time, seconds, :second)
  defp unread(user), do: Notifications.count_unread(user.uuid)
  defp notified_at(row), do: Repo.get!(Confirmation, row.uuid).notified_at

  test "the Owner and the creator of the key are told", %{agent: agent, owner: owner} do
    owner_before = unread(owner)
    agent_before = unread(agent.owner)

    {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

    assert unread(owner) == owner_before + 1
    assert unread(agent.owner) == agent_before + 1
    assert %DateTime{} = notified_at(row)
  end

  test "someone who may not decide is not told", %{agent: agent} do
    {stranger, _role} = ApiHarness.user_with(["settings", "dashboard"])
    before = unread(stranger)

    {:ok, _row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

    assert unread(stranger) == before
  end

  test "a second approval of the same key within ten minutes sends nothing", %{
    agent: agent,
    owner: owner
  } do
    t0 = DateTime.utc_now()
    {:ok, _first, :created} = queue(agent, @tool, %{"ids" => ["a"]}, now: t0)
    after_first = unread(owner)

    {:ok, second, :created} = queue(agent, @tool, %{"ids" => ["b"]}, now: later(t0, 300))

    assert unread(owner) == after_first
    assert notified_at(second) == nil
  end

  test "after ten minutes the unread notice is refreshed, not repeated", %{
    agent: agent,
    owner: owner
  } do
    t0 = DateTime.utc_now()
    {:ok, _first, :created} = queue(agent, @tool, %{"ids" => ["a"]}, now: t0)
    {:ok, _second, :created} = queue(agent, @tool, %{"ids" => ["b"]}, now: later(t0, 60))
    after_two = unread(owner)

    {:ok, third, :created} = queue(agent, @tool, %{"ids" => ["c"]}, now: later(t0, 601))

    assert unread(owner) == after_two
    assert %DateTime{} = notified_at(third)

    [latest | _] = Notifications.recent_for_user(owner.uuid, 5)
    assert latest.metadata["notification_text"] =~ "3"
    assert latest.metadata["notification_link"] =~ "/admin/approvals#approval-#{third.uuid}"
    refute latest.metadata["notification_link"] =~ "/settings/"
  end

  test "another key is told about separately", %{agent: agent, owner: owner} do
    t0 = DateTime.utc_now()
    {:ok, _first, :created} = queue(agent, @tool, %{"ids" => ["a"]}, now: t0)
    after_first = unread(owner)

    {:ok, other, :created} = queue(agent(), @tool, %{"ids" => ["a"]}, now: later(t0, 5))

    assert unread(owner) == after_first + 1
    assert %DateTime{} = notified_at(other)
  end

  test "with notifications switched off an approval is still queued, and nobody is told", %{
    agent: agent,
    owner: owner
  } do
    KeyTestSupport.put_setting("notifications_enabled", "false")
    owner_before = unread(owner)
    agent_before = unread(agent.owner)

    assert {:ok, _row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

    assert unread(owner) == owner_before
    assert unread(agent.owner) == agent_before
  end

  test "the notice links to the card of the approval that triggered it", %{
    agent: agent,
    owner: owner
  } do
    {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

    [latest | _] = Notifications.recent_for_user(owner.uuid, 5)
    link = latest.metadata["notification_link"]

    assert String.ends_with?(link, "/admin/approvals#approval-#{row.uuid}")
  end

  describe "notify_requested/2 never raises" do
    import ExUnit.CaptureLog

    test "a failure is logged by its kind, without the values, and answers :ok", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      broken = %{row | actor_key_uuid: "sentinel-not-a-uuid-4471"}

      log = capture_log(fn -> assert Notifier.notify_requested(broken) == :ok end)

      assert log =~ "approval notice failed"
      assert log =~ "Ecto.Query.CastError"
      refute log =~ "sentinel-not-a-uuid-4471"
    end

    test "a row of an unknown key is not a failure", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      ghost = %{row | actor_key_uuid: UUIDv7.generate()}

      log = capture_log(fn -> assert Notifier.notify_requested(ghost) == :ok end)

      refute log =~ "approval notice failed"
    end
  end

  describe "the text" do
    defp pending!(agent, id, expires_at) do
      %Confirmation{}
      |> Confirmation.changeset(%{
        kind: "approval",
        tool: @tool,
        input_hash: Canonical.hash(@tool, %{"ids" => [id]}),
        fingerprint: String.duplicate("f", 64),
        input: %{"ids" => [id]},
        actor_key_uuid: agent.key.uuid,
        preview: %{},
        status: "pending",
        expires_at: expires_at
      })
      |> Repo.insert!()
    end

    defp latest_text(user) do
      [latest | _] = Notifications.recent_for_user(user.uuid, 1)
      latest.metadata["notification_text"]
    end

    test "one waiting operation is named in the singular, with the key", %{
      agent: agent,
      owner: owner
    } do
      row = pending!(agent, "a", DateTime.add(DateTime.utc_now(), 3600, :second))

      assert Notifier.notify_requested(row) == :ok

      assert latest_text(owner) ==
               ~s(1 operation of the API key "agent" is waiting for your approval.)
    end

    test "several are counted in the plural", %{agent: agent, owner: owner} do
      soon = DateTime.add(DateTime.utc_now(), 3600, :second)
      row = pending!(agent, "a", soon)
      pending!(agent, "b", soon)

      assert Notifier.notify_requested(row) == :ok

      assert latest_text(owner) ==
               ~s(2 operations of the API key "agent" are waiting for your approval.)
    end

    test "a pending approval whose time has passed is not waiting", %{
      agent: agent,
      owner: owner
    } do
      now = DateTime.utc_now()
      pending!(agent, "old", DateTime.add(now, -60, :second))
      row = pending!(agent, "new", DateTime.add(now, 3600, :second))

      assert Notifier.notify_requested(row, now) == :ok

      assert latest_text(owner) ==
               ~s(1 operation of the API key "agent" is waiting for your approval.)
    end
  end
end
