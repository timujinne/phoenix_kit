defmodule PhoenixKit.API.ApprovalsRequestTest do
  @moduledoc """
  `PhoenixKit.API.Approvals`: queueing a dangerous call (dedupe, cap, expiry, size),
  what an agent may read back, the views of the queue, and who may decide.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiFlowHarness

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Canonical
  alias PhoenixKit.API.Confirm
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.PubSub.Manager, as: PubSub
  alias PhoenixKit.Test.ApiFlowStore
  alias PhoenixKit.Test.ApiFlowTools
  alias PhoenixKit.Test.ApiHarness
  alias PhoenixKit.Users.Permissions

  @tool "flowkit.delete_items"

  setup do
    setup_flow()
    %{agent: agent()}
  end

  defp later(time, seconds), do: DateTime.add(time, seconds, :second)
  defp row!(row), do: Repo.get!(Confirmation, row.uuid)

  # The SQL of every query `fun` runs in this process.
  defp queries_of(fun) do
    test_pid = self()
    handler = "approvals-queries-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:phoenix_kit, :test, :repo, :query],
      fn _event, _measurements, %{query: query}, _config ->
        if self() == test_pid, do: send(test_pid, {:query, query})
      end,
      nil
    )

    try do
      fun.()
    after
      :telemetry.detach(handler)
    end

    drain_queries([])
  end

  defp drain_queries(acc) do
    receive do
      {:query, query} -> drain_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "request/2" do
    test "stores a pending approval with the arguments, the preview and the request context", %{
      agent: agent
    } do
      t0 = DateTime.utc_now()
      assert {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a", "b"]}, now: t0)

      stored = row!(row)
      assert stored.kind == "approval"
      assert stored.status == "pending"
      assert stored.tool == @tool
      assert stored.actor_key_uuid == agent.key.uuid
      assert stored.input == %{"ids" => ["a", "b"]}
      assert stored.input_hash == Canonical.hash(@tool, %{"ids" => ["a", "b"]})
      assert stored.preview["totals"] == %{"delete" => 2}
      assert stored.context["base_url"] == "https://shop.example"
      assert stored.context["request_id"] == "req-test"
      assert DateTime.diff(stored.expires_at, t0) in (72 * 3600 - 2)..(72 * 3600 + 2)
    end

    test "the lifetime is a setting", %{agent: agent} do
      KeyTestSupport.put_setting("api_approval_ttl_hours", "2")
      t0 = DateTime.utc_now()
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]}, now: t0)

      assert DateTime.diff(row.expires_at, t0) in 7198..7202
    end

    test "writes a permanent api.approval_requested entry for the key's owner", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      assert [entry] =
               Repo.all(
                 from(e in Entry,
                   where: e.action == "api.approval_requested" and e.resource_uuid == ^row.uuid
                 )
               )

      assert entry.module == "api"
      assert entry.permanent
      assert entry.actor_uuid == agent.owner.uuid
      assert entry.metadata["tool"] == @tool
      assert entry.metadata["key_prefix"] == agent.key.prefix
    end

    test "a repeat after the touched values changed closes the old approval and makes a new one",
         %{agent: agent} do
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      ApiFlowStore.put("a", 999)

      assert {:ok, second, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      assert second.uuid != first.uuid
      assert row!(first).status == "expired"
      assert row!(first).input == nil
      assert row!(second).status == "pending"
      assert row!(second).fingerprint != first.fingerprint

      # Asked again with nothing changed, it is the new one that comes back.
      assert {:ok, again, :existing} = queue(agent, @tool, %{"ids" => ["a"]})
      assert again.uuid == second.uuid
    end

    test "an identical pending request returns the existing approval", %{agent: agent} do
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a", "b"]})
      {:ok, again, :existing} = queue(agent, @tool, %{"ids" => ["a", "b"]})

      assert again.uuid == first.uuid

      assert Repo.aggregate(
               from(c in Confirmation, where: c.actor_key_uuid == ^agent.key.uuid),
               :count
             ) == 1
    end

    test "other arguments or another tool are another approval", %{agent: agent} do
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, second, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      {:ok, third, :created} = queue(agent, "flowkit.progress_write", %{})

      assert Enum.uniq([first.uuid, second.uuid, third.uuid]) |> length() == 3
    end

    test "the tool is part of the identity of a pending request", %{agent: agent} do
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      # The same key and the same hash under another tool name: only the tool differs.
      args = %{
        actor: agent.actor,
        tool: "flowkit.progress_write",
        input: %{"ids" => ["a"]},
        input_hash: first.input_hash,
        preview: %{},
        fingerprint: first.fingerprint,
        context: %{}
      }

      assert {:ok, second, :created} = Approvals.request(args)
      refute second.uuid == first.uuid
    end

    test "the same request from another key is another approval", %{agent: agent} do
      other = agent()

      {:ok, mine, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, theirs, :created} = queue(other, @tool, %{"ids" => ["a"]})

      refute mine.uuid == theirs.uuid
    end

    test "a key holds at most api_approval_pending_max pending approvals", %{agent: agent} do
      KeyTestSupport.put_setting("api_approval_pending_max", "2")

      assert {:ok, _, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      assert {:ok, _, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      assert {:error, :pending_cap} = queue(agent, @tool, %{"ids" => ["c"]})

      # An identical request is not a new approval: never capped.
      assert {:ok, _, :existing} = queue(agent, @tool, %{"ids" => ["a"]})

      # Another key has its own allowance.
      assert {:ok, _, :created} = queue(agent(), @tool, %{"ids" => ["c"]})
    end

    test "a decided approval frees a place under the cap", %{agent: agent} do
      KeyTestSupport.put_setting("api_approval_pending_max", "1")
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      assert {:error, :pending_cap} = queue(agent, @tool, %{"ids" => ["b"]})

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^first.uuid),
        set: [status: "rejected"]
      )

      assert {:ok, _, :created} = queue(agent, @tool, %{"ids" => ["b"]})
    end

    test "a pending approval whose time has passed counts for nothing and is expired", %{
      agent: agent
    } do
      t0 = DateTime.utc_now()
      {:ok, old, :created} = queue(agent, @tool, %{"ids" => ["a"]}, now: t0)

      assert {:ok, fresh, :created} =
               queue(agent, @tool, %{"ids" => ["a"]}, now: later(t0, 73 * 3600))

      refute fresh.uuid == old.uuid
      expired = row!(old)
      assert expired.status == "expired"
      assert expired.input == nil
    end

    test "an input over 1 MB is refused and stores nothing", %{agent: agent} do
      big = %{"ids" => [String.duplicate("a", 1_048_577)]}

      assert {:error, :input_too_large} = queue(agent, @tool, big)

      assert Repo.aggregate(
               from(c in Confirmation, where: c.actor_key_uuid == ^agent.key.uuid),
               :count
             ) == 0
    end

    test "a row the table would refuse is an error, not a raise, and stores nothing", %{
      agent: agent
    } do
      tool = "flowkit." <> String.duplicate("a", 125)

      args = %{
        actor: agent.actor,
        tool: tool,
        input: %{"ids" => ["a"]},
        input_hash: Canonical.hash(tool, %{"ids" => ["a"]}),
        preview: %{},
        fingerprint: "fp",
        context: %{}
      }

      assert {:error, %Ecto.Changeset{errors: errors}} = Approvals.request(args)
      assert Keyword.has_key?(errors, :tool)

      assert Repo.aggregate(
               from(c in Confirmation, where: c.actor_key_uuid == ^agent.key.uuid),
               :count
             ) == 0
    end

    test "an input of exactly 1 MB is stored", %{agent: agent} do
      pad = 1_048_576 - byte_size(JSON.encode!(%{"ids" => [""]}))
      input = %{"ids" => [String.duplicate("a", pad)]}
      assert byte_size(JSON.encode!(input)) == 1_048_576

      assert {:ok, _, :created} = queue(agent, @tool, input)
    end

    test "announces the change on the approvals topic", %{agent: agent} do
      PubSub.subscribe("phoenix_kit:api:approvals")

      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      uuid = row.uuid
      assert_receive {:api_approval_changed, ^uuid}
    end
  end

  describe "get_for_key/2" do
    test "an agent reads its own approval", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      assert %Confirmation{uuid: uuid} = Approvals.get_for_key(row.uuid, agent.key.uuid)
      assert uuid == row.uuid
    end

    test "another key, an unknown id, a malformed id and a confirmation code read as nothing", %{
      agent: agent
    } do
      other = agent()
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      {:ok, issued} =
        Confirm.issue_token(
          agent.actor,
          @tool,
          String.duplicate("1", 64),
          %{},
          String.duplicate("f", 64)
        )

      assert Approvals.get_for_key(row.uuid, other.key.uuid) == nil
      assert Approvals.get_for_key(UUIDv7.generate(), agent.key.uuid) == nil
      assert Approvals.get_for_key("not-a-uuid", agent.key.uuid) == nil
      assert Approvals.get_for_key(issued.row.uuid, agent.key.uuid) == nil
      assert Approvals.get_for_key(nil, agent.key.uuid) == nil
    end

    test "a pending approval past its time reads as expired", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
        set: [expires_at: past]
      )

      assert %Confirmation{status: "expired"} = Approvals.get_for_key(row.uuid, agent.key.uuid)
    end
  end

  describe "status_view/1" do
    test "a pending approval shows its preview and the time left, never its input", %{
      agent: agent
    } do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a", "b"]})

      view = Approvals.status_view(row!(row))

      assert view["approval_id"] == row.uuid
      assert view["status"] == "pending"
      assert view["tool"] == @tool
      assert view["preview"]["totals"] == %{"delete" => 2}
      assert view["expires_in_seconds"] > 0
      assert is_binary(view["expires_at"])
      refute Map.has_key?(view, "input")
      refute Map.has_key?(view, "result")
    end

    test "an executed approval shows its result", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
        set: [status: "executed", result: %{"deleted" => 1}]
      )

      view = Approvals.status_view(row!(row))

      assert view["status"] == "executed"
      assert view["result"] == %{"deleted" => 1}
      refute Map.has_key?(view, "expires_in_seconds")
    end

    test "a decided approval shows when it was decided", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      decided_at = DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
        set: [status: "rejected", decided_at: decided_at]
      )

      view = Approvals.status_view(row!(row))
      assert view["decided_at"] == DateTime.to_iso8601(decided_at)

      {:ok, pending, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      refute Map.has_key?(Approvals.status_view(row!(pending)), "decided_at")
    end

    test "a failed or stale approval shows its error and the partial results", %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      error = %{"code" => "forbidden", "detail" => "The key no longer holds x."}

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
        set: [status: "failed", result: %{"error" => error, "partial" => %{"done" => 1}}]
      )

      view = Approvals.status_view(row!(row))
      assert view["status"] == "failed"
      assert view["error"] == error
      assert view["partial"] == %{"done" => 1}

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
        set: [status: "stale", result: %{"error" => %{"code" => "stale"}}]
      )

      assert %{"status" => "stale", "error" => %{"code" => "stale"}} =
               Approvals.status_view(row!(row))
    end
  end

  describe "who may decide" do
    setup %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      %{row: row!(row)}
    end

    test "an Owner may", %{row: row} do
      owner = KeyTestSupport.owner_user()
      assert Approvals.may_decide?(KeyTestSupport.scope_of(owner), row)
    end

    test "the creator of the key may, while they hold the tool's permission", %{
      row: row,
      agent: agent
    } do
      assert Approvals.may_decide?(agent.scope, row)

      assert :ok = Permissions.revoke_permission(agent.role.uuid, "settings")
      refute Approvals.may_decide?(KeyTestSupport.scope_of(agent.owner), row)
    end

    test "another holder of api may not, even with the tool's permission", %{row: row} do
      {other, _role} = ApiHarness.user_with(["settings", "dashboard"])
      refute Approvals.may_decide?(KeyTestSupport.scope_of(other), row)
    end

    test "a person without api may not, even the creator of the key", %{row: row, agent: agent} do
      assert :ok = Permissions.revoke_permission(agent.role.uuid, "api")
      refute Approvals.may_decide?(KeyTestSupport.scope_of(agent.owner), row)

      stranger = KeyTestSupport.register_user!()
      refute Approvals.may_decide?(KeyTestSupport.scope_of(stranger), row)
    end

    test "a code row is not an approval", %{agent: agent} do
      {:ok, issued} =
        Confirm.issue_token(
          agent.actor,
          @tool,
          String.duplicate("1", 64),
          %{},
          String.duplicate("f", 64)
        )

      refute Approvals.may_decide?(agent.scope, issued.row)
    end
  end

  describe "deciders/1" do
    setup %{agent: agent} do
      {:ok, row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      %{row: row!(row), owner: KeyTestSupport.owner_user()}
    end

    defp decider_ids(row), do: row |> Approvals.deciders() |> Enum.map(& &1.uuid)

    test "the Owner and the creator of the key", %{row: row, agent: agent, owner: owner} do
      ids = decider_ids(row)

      assert owner.uuid in ids
      assert agent.owner.uuid in ids
    end

    test "an inactive Owner is not one", %{row: row, owner: owner} do
      Repo.update_all(from(u in PhoenixKit.Users.Auth.User, where: u.uuid == ^owner.uuid),
        set: [is_active: false]
      )

      refute owner.uuid in decider_ids(row)
    end

    test "a creator who lost the tool's permission is not one", %{
      row: row,
      agent: agent,
      owner: owner
    } do
      assert :ok = Permissions.revoke_permission(agent.role.uuid, "settings")

      ids = decider_ids(row)
      refute agent.owner.uuid in ids
      assert owner.uuid in ids
    end

    test "a creator who lost api is not one", %{row: row, agent: agent, owner: owner} do
      assert :ok = Permissions.revoke_permission(agent.role.uuid, "api")

      ids = decider_ids(row)
      refute agent.owner.uuid in ids
      assert owner.uuid in ids
    end

    test "an Owner who also created the key is listed once", %{owner: owner} do
      {key, _token} = ApiHarness.issue_key(owner, scopes(), %{name: "own"})
      {:ok, actor} = Confirm.live_actor(key.uuid)
      mine = %{actor: actor, scope: KeyTestSupport.scope_of(owner)}

      {:ok, row, :created} = queue(mine, @tool, %{"ids" => ["own"]})
      ids = decider_ids(row)

      assert owner.uuid in ids
      assert ids == Enum.uniq(ids)
    end

    test "a code row has no deciders", %{agent: agent} do
      {:ok, issued} =
        Confirm.issue_token(
          agent.actor,
          @tool,
          String.duplicate("1", 64),
          %{},
          String.duplicate("f", 64)
        )

      assert Approvals.deciders(issued.row) == []
    end
  end

  describe "the views" do
    test "an Owner sees every pending approval, the creator only those of their keys", %{
      agent: agent
    } do
      other = agent()
      {:ok, mine, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, theirs, :created} = queue(other, @tool, %{"ids" => ["b"]})

      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())

      owner_ids = owner_scope |> Approvals.list_pending() |> Enum.map(& &1.approval.uuid)
      assert mine.uuid in owner_ids
      assert theirs.uuid in owner_ids

      assert [%{approval: %{uuid: uuid}, key: key}] = Approvals.list_pending(agent.scope)
      assert uuid == mine.uuid
      assert key.uuid == agent.key.uuid

      assert Approvals.pending_count(agent.scope) == 1
    end

    test "decided and expired approvals are not pending", %{agent: agent} do
      {:ok, rejected, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, expired, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      {:ok, waiting, :created} = queue(agent, @tool, %{"ids" => ["c"]})
      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^rejected.uuid),
        set: [status: "rejected"]
      )

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^expired.uuid),
        set: [expires_at: past]
      )

      assert [%{approval: %{uuid: uuid}}] = Approvals.list_pending(agent.scope)
      assert uuid == waiting.uuid
    end

    test "list_recent/2 shows decided approvals, newest change first, within the limit", %{
      agent: agent
    } do
      for {id, status} <- [{"a", "executed"}, {"b", "rejected"}, {"c", "failed"}] do
        {:ok, row, :created} = queue(agent, @tool, %{"ids" => [id]})

        Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
          set: [status: status]
        )
      end

      {:ok, _pending, :created} = queue(agent, @tool, %{"ids" => ["d"]})

      assert length(Approvals.list_recent(agent.scope, 10)) == 3
      assert length(Approvals.list_recent(agent.scope, 2)) == 2
      assert Enum.all?(Approvals.list_recent(agent.scope, 10), &(&1.approval.status != "pending"))
    end

    test "list_recent/2 filters by key in SQL: many newer decisions of other keys do not hide mine",
         %{agent: agent} do
      {:ok, mine, :created} = queue(agent, @tool, %{"ids" => ["mine"]})
      hour_ago = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^mine.uuid),
        set: [status: "executed", updated_at: hour_ago]
      )

      other = agent()

      for n <- 1..12 do
        {:ok, row, :created} = queue(other, @tool, %{"ids" => ["other-#{n}"]})

        Repo.update_all(from(c in Confirmation, where: c.uuid == ^row.uuid),
          set: [status: "rejected"]
        )
      end

      assert [%{approval: %{uuid: uuid}}] = Approvals.list_recent(agent.scope, 1)
      assert uuid == mine.uuid

      assert length(
               Approvals.list_recent(KeyTestSupport.scope_of(KeyTestSupport.owner_user()), 20)
             ) >= 13
    end

    test "list_pending/2 is oldest first", %{agent: agent} do
      {:ok, first, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, second, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^first.uuid),
        set: [inserted_at: DateTime.add(now, -10, :second)]
      )

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^second.uuid),
        set: [inserted_at: DateTime.add(now, -60, :second)]
      )

      assert [second.uuid, first.uuid] ==
               agent.scope |> Approvals.list_pending() |> Enum.map(& &1.approval.uuid)
    end

    test "list_recent/2 is newest change first", %{agent: agent} do
      {:ok, older, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, newer, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^older.uuid),
        set: [status: "executed", updated_at: DateTime.add(now, -600, :second)]
      )

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^newer.uuid),
        set: [status: "failed", updated_at: DateTime.add(now, -5, :second)]
      )

      assert [newer.uuid, older.uuid] ==
               agent.scope |> Approvals.list_recent(10) |> Enum.map(& &1.approval.uuid)
    end

    test "the lists leave the arguments in the database", %{agent: agent} do
      {:ok, pending, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, decided, :created} = queue(agent, @tool, %{"ids" => ["b"]})

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^decided.uuid),
        set: [status: "executed"]
      )

      assert row!(pending).input == %{"ids" => ["a"]}
      assert [%{approval: shown}] = Approvals.list_pending(agent.scope)
      assert shown.uuid == pending.uuid
      assert shown.input == nil
      assert shown.tool == @tool
      assert shown.preview["totals"] == %{"delete" => 1}

      assert [%{approval: recent}] = Approvals.list_recent(agent.scope, 10)
      assert recent.uuid == decided.uuid
      assert recent.input == nil
    end

    test "pending_count/1 counts what the person may decide, for an Owner too", %{agent: agent} do
      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())
      before = Approvals.pending_count(owner_scope)

      {:ok, _first, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      {:ok, second, :created} = queue(agent, @tool, %{"ids" => ["b"]})
      {:ok, third, :created} = queue(agent(), @tool, %{"ids" => ["c"]})
      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^second.uuid),
        set: [expires_at: past]
      )

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^third.uuid),
        set: [status: "rejected"]
      )

      assert Approvals.pending_count(agent.scope) == 1
      assert Approvals.pending_count(owner_scope) == before + 1

      assert Approvals.pending_count(KeyTestSupport.scope_of(KeyTestSupport.register_user!())) ==
               0
    end

    test "pending_count/1 equals the length of list_pending/2 for every kind of viewer", %{
      agent: agent
    } do
      other = agent()
      for id <- ["a", "b", "c"], do: {:ok, _, :created} = queue(agent, @tool, %{"ids" => [id]})
      for id <- ["d", "e"], do: {:ok, _, :created} = queue(other, @tool, %{"ids" => [id]})
      {holder, _role} = ApiHarness.user_with(["api", "settings", "dashboard"])

      viewers = fn ->
        [
          KeyTestSupport.scope_of(KeyTestSupport.owner_user()),
          KeyTestSupport.scope_of(agent.owner),
          KeyTestSupport.scope_of(other.owner),
          KeyTestSupport.scope_of(holder),
          KeyTestSupport.scope_of(KeyTestSupport.register_user!())
        ]
      end

      counts = fn -> for scope <- viewers.(), do: Approvals.pending_count(scope) end

      listed = fn ->
        for scope <- viewers.(), do: scope |> Approvals.list_pending() |> length()
      end

      assert counts.() == listed.()
      assert [_owner, 3, 2, 0, 0] = counts.()

      assert :ok = Permissions.revoke_permission(agent.role.uuid, "settings")
      assert counts.() == listed.()
      assert [_owner, 0, 2, 0, 0] = counts.()

      ApiFlowTools.set_enabled(false)
      assert counts.() == listed.()
      assert [_owner, 0, 0, 0, 0] = counts.()
    end

    test "pending_count/1 for a non-Owner reads no preview or result", %{agent: agent} do
      {:ok, _row, :created} = queue(agent, @tool, %{"ids" => ["a"]})

      queries = queries_of(fn -> assert Approvals.pending_count(agent.scope) == 1 end)

      assert queries != []
      assert Enum.any?(queries, &(&1 =~ "phoenix_kit_api_confirmations"))
      refute Enum.any?(queries, &(&1 =~ ~s("preview") or &1 =~ ~s("result")))
    end

    test "a creator who lost the tool's permission sees none of its approvals", %{agent: agent} do
      for id <- ["a", "b", "c"], do: {:ok, _, :created} = queue(agent, @tool, %{"ids" => [id]})
      {:ok, done, :created} = queue(agent, @tool, %{"ids" => ["d"]})

      Repo.update_all(from(c in Confirmation, where: c.uuid == ^done.uuid),
        set: [status: "executed"]
      )

      assert length(Approvals.list_pending(agent.scope)) == 3
      assert length(Approvals.list_recent(agent.scope, 10)) == 1

      assert :ok = Permissions.revoke_permission(agent.role.uuid, "settings")
      scope = KeyTestSupport.scope_of(agent.owner)

      assert Approvals.list_pending(scope) == []
      assert Approvals.list_recent(scope, 10) == []
      assert Approvals.pending_count(scope) == 0
    end

    test "a person who may not decide sees nothing", %{agent: agent} do
      {:ok, _row, :created} = queue(agent, @tool, %{"ids" => ["a"]})
      stranger = KeyTestSupport.register_user!()

      assert Approvals.list_pending(KeyTestSupport.scope_of(stranger)) == []
      assert Approvals.list_recent(KeyTestSupport.scope_of(stranger), 10) == []
    end
  end
end
