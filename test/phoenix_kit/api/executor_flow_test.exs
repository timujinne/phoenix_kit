defmodule PhoenixKit.API.ExecutorFlowTest do
  @moduledoc """
  The first half of the dangerous-operation flow in the executor: the control fields
  (shapes, the header, what the handler sees), dry runs, and idempotency (replay,
  reuse, in-progress, takeover, release, credentials). Plug level, real keys, the
  `flowkit` test tools.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.Test.ApiFlowHarness
  import PhoenixKit.Test.ApiHarness, only: [api_conn: 3, json: 1]
  import Plug.Conn

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Canonical
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Flow
  alias PhoenixKit.API.Idempotency
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.Test.ApiFlowStore
  alias PhoenixKit.Test.ApiHarness
  alias PhoenixKit.Users.Permissions

  @touch "flowkit.touch_item"
  @misbehave "flowkit.misbehave"

  setup do
    setup_flow()
    agent = agent(requires_approval: false)
    %{agent: agent, token: agent.token}
  end

  defp idem,
    do:
      "idem-key-" <>
        String.pad_leading(Integer.to_string(System.unique_integer([:positive])), 12, "0")

  defp authed(audience, opts) do
    :post |> api_conn("/", opts) |> Auth.call(Auth.init(audience: audience))
  end

  defp call(token, tool, input, opts \\ []),
    do: Executor.call(authed(:admin, Keyword.put(opts, :token, token)), :admin, tool, input)

  defp public_call(tool, input), do: Executor.call(authed(:public, []), :public, tool, input)

  defp record_count(key), do: Repo.aggregate(from(r in Record, where: r.key == ^key), :count)
  defp error_paths(conn), do: Enum.map(json(conn)["context"]["errors"], & &1["path"])

  describe "the control fields" do
    test "a read tool refuses each of them", %{token: token} do
      for field <- ["dry_run", "confirm_token", "idempotency_key"] do
        conn = call(token, "flowkit.read_items", %{field => "0123456789abcdef"})

        assert conn.status == 422, field
        assert Enum.any?(error_paths(conn), &(&1 =~ field))
        refute_received {:flow, "flowkit.read_items", _, _}
      end
    end

    test "dry_run must be a boolean: the string \"false\" is a 422, never a real run", %{
      token: token
    } do
      for value <- ["false", "true", 0, 1] do
        conn = call(token, @touch, %{"name" => "x", "dry_run" => value})
        assert conn.status == 422, inspect(value)
      end

      assert ApiFlowStore.calls() == 0
      refute_received {:flow, @touch, _, _}
    end

    test "an idempotency key of 15 or 129 characters, or with a space, is a 422", %{token: token} do
      for key <- [
            String.duplicate("a", 15),
            String.duplicate("a", 129),
            "has a space in it 0123456789"
          ] do
        conn = call(token, @touch, %{"name" => "x", "idempotency_key" => key})

        assert conn.status == 422, key
        assert "idempotency_key" in error_paths(conn)
      end

      refute_received {:flow, @touch, _, _}
    end

    test "an unknown field is still refused", %{token: token} do
      assert 422 == call(token, @touch, %{"name" => "x", "bogus" => 1}).status
    end

    test "the handler never sees the control fields", %{token: token} do
      conn =
        call(token, @touch, %{
          "name" => "x",
          "idempotency_key" => idem(),
          "confirm_token" => "ct_whatever"
        })

      assert conn.status == 200
      assert_received {:flow, @touch, input, %{dry_run?: false}}
      assert input == %{"name" => "x"}
    end

    test "discovery lists them on write tools only, and closes every schema", %{token: token} do
      conn = Executor.list(authed(:admin, token: token), :admin)
      tools = Map.new(json(conn)["tools"], &{&1["name"], &1})

      write = tools[@touch]["input_schema"]

      assert %{"dry_run" => %{"type" => "boolean"}, "confirm_token" => _, "idempotency_key" => _} =
               write["properties"]

      assert write["additionalProperties"] == false

      read = tools["flowkit.read_items"]["input_schema"]
      refute Map.has_key?(read["properties"], "dry_run")
      assert read["additionalProperties"] == false
    end
  end

  describe "dry_run" do
    test "answers the preview and writes nothing", %{token: token} do
      conn = call(token, @touch, %{"name" => "x", "dry_run" => true})

      assert conn.status == 200

      assert %{
               "executed" => false,
               "dry_run" => true,
               "preview" => %{"rows" => [%{"ref" => "x"}]}
             } = json(conn)

      assert ApiFlowStore.calls() == 0
      assert_received {:flow, @touch, %{"name" => "x"}, %{dry_run?: true}}
      refute_received {:flow, @touch, _, %{dry_run?: false}}
    end

    test "creates no code and no approval", %{token: token} do
      call(token, @touch, %{"name" => "x", "dry_run" => true})

      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "a dry run is logged as a preview", %{token: token, agent: agent} do
      call(token, @touch, %{"name" => "x", "dry_run" => true})

      assert [entry] =
               Repo.all(
                 from(e in Entry,
                   where: e.action == "api.request" and e.resource_uuid == ^agent.key.uuid
                 )
               )

      assert entry.metadata["outcome"] == "preview"
    end

    test "a handler that ignores the dry run is a 500, and the log says what is wrong", %{
      token: token
    } do
      log =
        capture_log(fn ->
          conn = call(token, @misbehave, %{"mode" => "write", "dry_run" => true})
          assert conn.status == 500
          assert json(conn)["code"] == "internal_error"
        end)

      assert log =~ "dry run"
    end

    test "an error the handler answers to a dry run is answered as that error", %{token: token} do
      conn = call(token, @misbehave, %{"mode" => "dry_error", "dry_run" => true})

      assert conn.status == 422
      assert json(conn)["code"] == "insufficient_stock"
    end

    test "a dry run answered with an error whose message is not UTF-8 is a 500", %{token: token} do
      {conn, log} =
        with_log(fn ->
          call(token, @misbehave, %{"mode" => "dry_bad_message", "dry_run" => true})
        end)

      assert conn.status == 500
      assert json(conn)["code"] == "internal_error"
      assert log =~ "not valid UTF-8"
      refute log =~ "secret-detail"
    end

    test "a throw or an exit during a dry run is a 500 and the log keeps only its kind", %{
      token: token
    } do
      for {mode, kind} <- [{"dry_throw", "throw"}, {"dry_exit", "exit"}] do
        {conn, log} =
          with_log(fn -> call(token, @misbehave, %{"mode" => mode, "dry_run" => true}) end)

        assert conn.status == 500, mode
        assert json(conn)["code"] == "internal_error"
        assert log =~ "#{kind}: a tuple of size 2", mode
        refute log =~ "secret-detail", mode
        refute conn.resp_body =~ "secret-detail", mode
      end
    end

    test "a dry run answered in the wrong shape is a 500 and the log keeps only the shape", %{
      token: token
    } do
      {conn, log} =
        with_log(fn ->
          call(token, @misbehave, %{"mode" => "dry_wrong_shape", "dry_run" => true})
        end)

      assert conn.status == 500
      assert log =~ "answered a dry run with a tuple of size 2 tagged :ok"
      refute log =~ "secret-detail"
    end

    test "a preview JSON cannot hold is a 500 problem document, not an exception", %{
      token: token
    } do
      for mode <- ["dry_tuple", "dry_struct", "dry_binary"] do
        {conn, log} =
          with_log(fn -> call(token, @misbehave, %{"mode" => mode, "dry_run" => true}) end)

        assert conn.status == 500, mode
        assert json(conn)["code"] == "internal_error"
        refute log =~ "secret-detail", mode
        refute conn.resp_body =~ "secret-detail", mode
      end
    end

    test "a handler that raises during a dry run is a 500 with no detail", %{token: token} do
      {conn, log} =
        with_log(fn -> call(token, @misbehave, %{"mode" => "raise", "dry_run" => true}) end)

      assert conn.status == 500
      refute conn.resp_body =~ "secret-detail"
      refute log =~ "secret-detail"
      assert log =~ "RuntimeError"
    end
  end

  describe "the handler context" do
    test "a request and an approved operation hand the handler the same keys", %{token: token} do
      call(token, @touch, %{"name" => "x"})
      assert_received {:flow, @touch, _input, ctx}

      assert Enum.sort(Map.keys(ctx)) == Enum.sort(Executor.context_keys())
      assert ctx.approved_by_uuid == nil
      assert ctx.confirmation_uuid == nil
      assert ctx.dry_run? == false
      assert ctx.progress.(%{"done" => 1}) == :ok
    end
  end

  describe "Executor.context/2" do
    test "merges overrides over the request's context and keeps only context keys", %{
      token: token
    } do
      conn = authed(:admin, token: token)

      state = %{
        conn: conn,
        actor: conn.assigns[:phoenix_kit_api_actor],
        scopes: [],
        audience: :admin,
        dry_run?: false,
        confirmation: nil
      }

      ctx = Executor.context(state, approved_by_uuid: "approver", not_a_context_key: 1)

      assert ctx.approved_by_uuid == "approver"
      assert Enum.sort(Map.keys(ctx)) == Enum.sort(Executor.context_keys())
    end
  end

  describe "idempotency" do
    test "the same key and request return the first answer, with no second write", %{token: token} do
      key = idem()

      first = call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      second = call(token, @touch, %{"name" => "x", "idempotency_key" => key})

      assert first.status == 200 and second.status == 200
      assert json(first) == %{"touched" => "x", "call" => 1}
      assert second.resp_body == first.resp_body
      assert get_resp_header(first, "idempotent-replayed") == []
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert ApiFlowStore.calls() == 1

      assert_received {:flow, @touch, _, %{dry_run?: false}}
      refute_received {:flow, @touch, _, %{dry_run?: false}}
    end

    test "the key may come as the Idempotency-Key header", %{token: token} do
      key = idem()
      opts = [headers: [{"idempotency-key", key}]]

      first = call(token, @touch, %{"name" => "x"}, opts)
      second = call(token, @touch, %{"name" => "x"}, opts)
      same_in_body = call(token, @touch, %{"name" => "x", "idempotency_key" => key}, opts)

      assert second.resp_body == first.resp_body
      assert same_in_body.resp_body == first.resp_body
      assert ApiFlowStore.calls() == 1

      differs = call(token, @touch, %{"name" => "x", "idempotency_key" => idem()}, opts)
      assert differs.status == 422
      assert "idempotency_key" in error_paths(differs)
    end

    test "the Idempotency-Key header sent twice is a 422, even with the same value", %{
      token: token
    } do
      key = idem()
      conn = authed(:admin, token: token)

      conn = %{
        conn
        | req_headers: conn.req_headers ++ [{"idempotency-key", key}, {"idempotency-key", key}]
      }

      conn = Executor.call(conn, :admin, @touch, %{"name" => "x"})

      assert conn.status == 422
      assert "idempotency_key" in error_paths(conn)
      assert ApiFlowStore.calls() == 0
      refute_received {:flow, @touch, _, _}
      assert record_count(key) == 0
    end

    test "a read tool ignores the header", %{token: token} do
      conn = call(token, "flowkit.read_items", %{}, headers: [{"idempotency-key", "short"}])
      assert conn.status == 200
    end

    test "the same key with other arguments is 409 idempotency_key_reused", %{token: token} do
      key = idem()
      call(token, @touch, %{"name" => "x", "idempotency_key" => key})

      conn = call(token, @touch, %{"name" => "y", "idempotency_key" => key})

      assert conn.status == 409
      assert json(conn)["code"] == "idempotency_key_reused"
      assert ApiFlowStore.calls() == 1
    end

    test "the same arguments written in another order are the same request", %{token: token} do
      key = idem()
      first = ~s({"idempotency_key": "#{key}", "changes": [{"id": "a", "value": 101}]})
      second = ~s({"changes": [{"value": 101, "id": "a"}], "idempotency_key": "#{key}"})

      call(token, "flowkit.set_values", JSON.decode!(first))
      again = call(token, "flowkit.set_values", JSON.decode!(second))

      assert again.status == 200
      assert get_resp_header(again, "idempotent-replayed") == ["true"]
    end

    test "another key of the same user is another scope", %{token: token, agent: agent} do
      key = idem()
      {_second_key, second_token} = ApiHarness.issue_key(agent.owner, scopes(), %{name: "second"})

      call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      conn = call(second_token, @touch, %{"name" => "x", "idempotency_key" => key})

      assert conn.status == 200
      assert get_resp_header(conn, "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 2
    end

    test "a request that is still running is 409 idempotency_in_progress", %{
      token: token,
      agent: agent
    } do
      key = idem()

      {:claimed, _claim} =
        Idempotency.claim(agent.key.uuid, key, Canonical.hash(@touch, %{"name" => "x"}))

      conn = call(token, @touch, %{"name" => "x", "idempotency_key" => key})

      assert conn.status == 409
      assert json(conn)["code"] == "idempotency_in_progress"
      assert ApiFlowStore.calls() == 0
    end

    test "a claim whose lease has run out is taken over", %{token: token, agent: agent} do
      key = idem()
      long_ago = DateTime.add(DateTime.utc_now(), -600, :second)

      {:claimed, _claim} =
        Idempotency.claim(agent.key.uuid, key, Canonical.hash(@touch, %{"name" => "x"}), long_ago)

      first = call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      second = call(token, @touch, %{"name" => "x", "idempotency_key" => key})

      assert first.status == 200
      assert second.resp_body == first.resp_body
      assert ApiFlowStore.calls() == 1
    end

    test "a write that failed does not keep the key", %{token: token} do
      key = idem()

      for _ <- 1..2 do
        conn = call(token, @misbehave, %{"mode" => "fail", "idempotency_key" => key})
        assert conn.status == 422
        assert json(conn)["code"] == "insufficient_stock"
      end

      assert record_count(key) == 0
    end

    test "a crash does not keep the key", %{token: token} do
      key = idem()

      {conn, _log} =
        with_log(fn ->
          call(token, @misbehave, %{"mode" => "raise", "idempotency_key" => key})
        end)

      assert conn.status == 500
      assert record_count(key) == 0
    end

    test "an answer that carries a credential is never stored", %{token: token} do
      key = idem()

      first = call(token, @misbehave, %{"mode" => "leak", "idempotency_key" => key})
      second = call(token, @misbehave, %{"mode" => "leak", "idempotency_key" => key})

      assert first.status == 200 and second.status == 200
      refute json(first)["session_token"] == json(second)["session_token"]
      assert get_resp_header(second, "idempotent-replayed") == []
      assert record_count(key) == 0
    end

    test "an answer that carries a credential the tool declares is never stored", %{token: token} do
      key = idem()

      first = call(token, @misbehave, %{"mode" => "leak_link", "idempotency_key" => key})
      second = call(token, @misbehave, %{"mode" => "leak_link", "idempotency_key" => key})

      assert first.status == 200 and second.status == 200
      refute json(first)["link"] == json(second)["link"]
      assert get_resp_header(second, "idempotent-replayed") == []
      assert record_count(key) == 0
    end

    test "a dry run never claims the key, so the real call may use it", %{token: token} do
      key = idem()

      call(token, @touch, %{"name" => "x", "dry_run" => true, "idempotency_key" => key})
      assert record_count(key) == 0

      conn = call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      assert conn.status == 200
      assert record_count(key) == 1
    end

    test "a dry run is answered even while the real call holds the key", %{
      token: token,
      agent: agent
    } do
      key = idem()

      {:claimed, _claim} =
        Idempotency.claim(agent.key.uuid, key, Canonical.hash(@touch, %{"name" => "x"}))

      conn = call(token, @touch, %{"name" => "x", "dry_run" => true, "idempotency_key" => key})

      assert conn.status == 200
      assert %{"dry_run" => true, "executed" => false} = json(conn)
      assert get_resp_header(conn, "idempotent-replayed") == []
    end

    test "rights are checked before a replay: a lost permission is a 403", %{
      token: token,
      agent: agent
    } do
      key = idem()
      call(token, @touch, %{"name" => "x", "idempotency_key" => key})

      assert :ok = Permissions.revoke_permission(agent.role.uuid, "settings")

      conn = call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      assert conn.status == 403
    end

    test "a replay is not a write: it adds no api.request entry", %{token: token, agent: agent} do
      key = idem()

      count = fn ->
        Repo.aggregate(
          from(e in Entry,
            where: e.action == "api.request" and e.resource_uuid == ^agent.key.uuid
          ),
          :count
        )
      end

      call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      assert count.() == 1

      call(token, @touch, %{"name" => "x", "idempotency_key" => key})
      assert count.() == 1
    end

    test "a store or a release that fails is logged, never raised, and the answer goes out" do
      # A claim with no uuid makes the query raise, as a failing database would.
      broken = %{uuid: nil, locked_at: DateTime.utc_now()}

      log =
        capture_log(fn ->
          assert :ok = Flow.finish(%{claim: broken, store?: true, body: ~s({"ok":true})})
          assert :ok = Flow.finish(%{claim: broken, store?: true, body: ~s({"pk_token":"x"})})
          assert :ok = Flow.finish(%{claim: broken, store?: false, body: ~s({"ok":true})})
          assert :ok = Flow.release(%{claim: broken})
        end)

      assert log =~ "Idempotency-Key claim"
      assert log =~ "ArgumentError"
    end

    test "a public write with a client token and a key is replayed per client token" do
      key = idem()
      body = %{"text" => "hi", "session_token" => "session-one", "idempotency_key" => key}

      first = public_call("flowkit.public_write", body)
      second = public_call("flowkit.public_write", body)

      other_session =
        public_call("flowkit.public_write", %{body | "session_token" => "session-two"})

      assert second.resp_body == first.resp_body
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert get_resp_header(other_session, "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 2
    end

    test "a public tool that cannot replay refuses the idempotency_key field and ignores the header" do
      key = idem()

      refused = public_call("flowkit.mint_session", %{"idempotency_key" => key})
      assert refused.status == 422
      assert error_paths(refused) == ["idempotency_key"]
      refute_received {:flow, "flowkit.mint_session", _, _}

      conn = authed(:public, headers: [{"idempotency-key", key}])
      first = Executor.call(conn, :public, "flowkit.mint_session", %{})
      second = Executor.call(conn, :public, "flowkit.mint_session", %{})

      assert first.status == 200 and second.status == 200
      refute first.resp_body == second.resp_body
      assert get_resp_header(second, "idempotent-replayed") == []
      assert record_count(key) == 0
    end

    test "a tool that cannot replay still takes dry_run" do
      conn = public_call("flowkit.mint_session", %{"dry_run" => true})

      assert conn.status == 200
      assert %{"executed" => false, "dry_run" => true} = json(conn)
    end

    test "a tool that declares no client token but has a cart_token property is still replayed per token (legacy)" do
      key = idem()
      body = %{"text" => "hi", "cart_token" => "legacy-one", "idempotency_key" => key}

      first = public_call("flowkit.legacy_write", body)
      second = public_call("flowkit.legacy_write", body)
      other = public_call("flowkit.legacy_write", %{body | "cart_token" => "legacy-two"})

      assert second.resp_body == first.resp_body
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert get_resp_header(other, "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 2
    end

    test "a public write without a client token has no idempotency" do
      key = idem()
      body = %{"text" => "hi", "idempotency_key" => key}

      first = public_call("flowkit.public_write", body)
      second = public_call("flowkit.public_write", body)

      assert first.status == 200 and second.status == 200
      assert get_resp_header(second, "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 2
      assert record_count(key) == 0
    end
  end
end
