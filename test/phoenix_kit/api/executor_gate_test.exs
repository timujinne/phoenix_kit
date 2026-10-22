defmodule PhoenixKit.API.ExecutorGateTest do
  @moduledoc """
  The dangerous-operation gate in the executor: when a call is dangerous, the preview
  and the one-time code, the approval queue, and every way a code is
  refused. Plug level, real keys, the `flowkit` test tools.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import Plug.Conn, only: [get_resp_header: 2]
  import PhoenixKit.Test.ApiFlowHarness
  import PhoenixKit.Test.ApiHarness, only: [api_conn: 3, json: 1, put_setting: 2]

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Flow
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Test.ApiFlowStore

  @delete "flowkit.delete_items"
  @all_items %{"a" => 100, "b" => 200, "c" => 300}

  setup do
    setup_flow()
    plain = agent(requires_approval: false)
    %{plain: plain, token: plain.token, gated: agent(requires_approval: true)}
  end

  defp authed(audience, opts),
    do: :post |> api_conn("/", opts) |> Auth.call(Auth.init(audience: audience))

  defp call(token, tool, input, opts \\ []),
    do: Executor.call(authed(:admin, Keyword.put(opts, :token, token)), :admin, tool, input)

  defp public_call(tool, input), do: Executor.call(authed(:public, []), :public, tool, input)

  defp code_of(conn), do: json(conn)["confirm_token"]
  defp rows(kind), do: Repo.all(from(c in Confirmation, where: c.kind == ^kind))
  defp real_run_messages, do: flush_real_runs([])

  defp flush_real_runs(acc) do
    receive do
      {:flow, _tool, _input, %{dry_run?: false}} = message -> flush_real_runs([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "the confirmation code: the preview, then the code" do
    test "asking again for the same call while its code is live returns that code, not another row",
         %{token: token} do
      first = call(token, @delete, %{"ids" => ["a"]})
      again = call(token, @delete, %{"ids" => ["a"]})
      other = call(token, @delete, %{"ids" => ["b"]})

      assert code_of(again) == code_of(first)
      refute code_of(other) == code_of(first)
      assert length(rows("token")) == 2
    end

    test "the first call changes nothing and returns the preview and a code", %{
      token: token,
      plain: plain
    } do
      conn = call(token, @delete, %{"ids" => ["a", "b"]})

      assert conn.status == 200

      assert %{
               "executed" => false,
               "status" => "confirmation_required",
               "preview" => %{"totals" => %{"delete" => 2}, "rows" => [_, _]},
               "confirm_token" => "ct_" <> _,
               "expires_in_seconds" => 120,
               "expires_at" => expires_at
             } = json(conn)

      assert {:ok, _, _} = DateTime.from_iso8601(expires_at)
      assert ApiFlowStore.items() == @all_items
      assert real_run_messages() == []

      assert [row] = rows("token")
      assert row.status == "unused"
      assert row.tool == @delete
      assert row.actor_key_uuid == plain.key.uuid
      assert row.preview == json(conn)["preview"]

      assert [entry] =
               Repo.all(
                 from(e in Entry,
                   where: e.action == "api.request" and e.resource_uuid == ^plain.key.uuid
                 )
               )

      assert entry.metadata["outcome"] == "confirmation_required"
    end

    test "repeating the call with the code runs it, once", %{token: token} do
      input = %{"ids" => ["a", "b"]}
      code = token |> call(@delete, input) |> code_of()

      done = call(token, @delete, Map.put(input, "confirm_token", code))

      assert done.status == 200
      assert json(done) == %{"deleted" => 2}
      assert ApiFlowStore.items() == %{"c" => 300}
      assert [{:flow, @delete, ^input, ctx}] = real_run_messages()
      assert ctx.confirmation_uuid == hd(rows("token")).uuid
      assert hd(rows("token")).status == "used"

      again = call(token, @delete, Map.put(input, "confirm_token", code))

      assert again.status == 409

      assert %{
               "code" => "confirm_token_invalid",
               "context" => %{"reason" => "used", "preview" => preview}
             } = json(again)

      assert is_map(preview)
      assert real_run_messages() == []
    end

    test "the order of the arguments does not matter", %{token: token} do
      first = %{"changes" => [%{"id" => "a", "value" => 200}]}
      code = token |> call("flowkit.set_values", first) |> code_of()

      reordered = %{"confirm_token" => code, "changes" => [%{"value" => 200, "id" => "a"}]}

      assert call(token, "flowkit.set_values", reordered).status == 200
      assert ApiFlowStore.items()["a"] == 200
    end

    test "other arguments are 409 with a fresh preview, and the code is not spent", %{
      token: token
    } do
      code = token |> call(@delete, %{"ids" => ["a", "b"]}) |> code_of()

      wrong = call(token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert wrong.status == 409

      assert %{
               "context" => %{
                 "reason" => "other_arguments",
                 "preview" => %{"totals" => %{"delete" => 1}}
               }
             } = json(wrong)

      assert ApiFlowStore.items() == @all_items

      assert call(token, @delete, %{"ids" => ["a", "b"], "confirm_token" => code}).status == 200
    end

    test "another key may not use the code", %{token: token} do
      other = agent(requires_approval: false)
      code = token |> call(@delete, %{"ids" => ["a"]}) |> code_of()

      conn = call(other.token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert conn.status == 409
      assert json(conn)["context"]["reason"] == "invalid"
      assert ApiFlowStore.items() == @all_items
    end

    test "an expired code is refused", %{token: token} do
      code = token |> call(@delete, %{"ids" => ["a"]}) |> code_of()
      past = DateTime.utc_now() |> DateTime.add(-5, :second) |> DateTime.truncate(:second)
      Repo.update_all(Confirmation, set: [expires_at: past])

      conn = call(token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert conn.status == 409
      assert json(conn)["context"]["reason"] == "expired"
      assert ApiFlowStore.items() == @all_items
    end

    test "a code issued before the tool's module was switched off is refused, and works again once it is back on",
         %{token: token} do
      input = %{"ids" => ["a"]}
      code = token |> call(@delete, input) |> code_of()

      put_setting("api_disabled_modules", "api_flow_tools")
      conn = call(token, @delete, Map.put(input, "confirm_token", code))

      assert conn.status == 404
      assert json(conn)["code"] == "not_found"
      assert ApiFlowStore.items() == @all_items
      assert real_run_messages() == []
      assert hd(rows("token")).status == "unused"

      put_setting("api_disabled_modules", "")
      assert call(token, @delete, Map.put(input, "confirm_token", code)).status == 200
      assert ApiFlowStore.items() == Map.delete(@all_items, "a")
    end

    test "values that changed since the preview: 409 with the new values, nothing written", %{
      token: token
    } do
      input = %{"ids" => ["a"]}
      code = token |> call(@delete, input) |> code_of()
      ApiFlowStore.put("a", 999)

      conn = call(token, @delete, Map.put(input, "confirm_token", code))

      assert conn.status == 409

      assert %{
               "context" => %{"reason" => "changed", "preview" => %{"rows" => [%{"from" => 999}]}}
             } = json(conn)

      assert ApiFlowStore.items() == Map.put(@all_items, "a", 999)
      assert real_run_messages() == []
      assert hd(rows("token")).status == "unused"
    end

    test "a code nobody issued is 409 with a fresh preview", %{token: token} do
      conn = call(token, @delete, %{"ids" => ["a"], "confirm_token" => "nonsense"})

      assert conn.status == 409

      assert %{
               "context" => %{"reason" => "invalid", "preview" => %{"totals" => %{"delete" => 1}}}
             } = json(conn)

      assert rows("token") == []
    end

    test "simultaneous confirmations run the operation once", %{token: token} do
      {:ok, _} = PhoenixKit.Settings.update_setting("api_confirm_batch_over", "1")
      input = %{"items" => [%{}, %{}]}
      code = token |> call("flowkit.batch_touch", input) |> code_of()

      statuses =
        1..6
        |> Task.async_stream(
          fn _ ->
            call(token, "flowkit.batch_touch", Map.put(input, "confirm_token", code)).status
          end,
          max_concurrency: 6,
          timeout: :infinity
        )
        |> Enum.map(fn {:ok, status} -> status end)

      assert Enum.count(statuses, &(&1 == 200)) == 1
      assert Enum.count(statuses, &(&1 == 409)) == 5
      assert ApiFlowStore.calls() == 1
    end

    test "a failure after the code was claimed keeps the code spent", %{token: token} do
      input = %{"fail" => true}
      code = token |> call("flowkit.progress_write", input) |> code_of()

      failed = call(token, "flowkit.progress_write", Map.put(input, "confirm_token", code))
      assert failed.status == 422
      assert json(failed)["code"] == "insufficient_stock"

      again = call(token, "flowkit.progress_write", Map.put(input, "confirm_token", code))
      assert again.status == 409
      assert json(again)["context"]["reason"] == "used"
    end

    test "dry_run on a dangerous call is a preview with no code", %{token: token} do
      conn = call(token, @delete, %{"ids" => ["a"], "dry_run" => true})

      assert conn.status == 200
      assert %{"executed" => false, "dry_run" => true, "preview" => _} = json(conn)
      refute Map.has_key?(json(conn), "confirm_token")
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "dry_run with a live code previews and does not spend the code", %{token: token} do
      input = %{"ids" => ["a", "b"]}
      code = token |> call(@delete, input) |> code_of()

      dry =
        call(token, @delete, input |> Map.put("confirm_token", code) |> Map.put("dry_run", true))

      assert dry.status == 200
      assert %{"executed" => false, "dry_run" => true, "preview" => _} = json(dry)
      assert [%{status: "unused"}] = rows("token")
      assert ApiFlowStore.items() == @all_items
      assert real_run_messages() == []

      done = call(token, @delete, Map.put(input, "confirm_token", code))

      assert done.status == 200
      assert json(done) == %{"deleted" => 2}
      assert ApiFlowStore.items() == %{"c" => 300}
      assert [%{status: "used"}] = rows("token")
    end

    test "a code sent with a call that is not dangerous is ignored", %{token: token} do
      conn = call(token, "flowkit.touch_item", %{"name" => "x", "confirm_token" => "ct_whatever"})

      assert conn.status == 200
      assert ApiFlowStore.calls() == 1
    end
  end

  describe "what is dangerous" do
    test "exactly api_confirm_batch_over rows is not, one more is", %{token: token} do
      fifty = call(token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 50)})
      assert fifty.status == 200
      assert json(fifty) == %{"count" => 50}

      fifty_one = call(token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 51)})
      assert json(fifty_one)["status"] == "confirmation_required"
      assert ApiFlowStore.calls() == 1
    end

    test "the threshold is a setting", %{token: token} do
      put_setting("api_confirm_batch_over", 10)

      ten = call(token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 10)})
      assert ten.status == 200
      assert json(ten) == %{"count" => 10}

      assert json(call(token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 11)}))[
               "status"
             ] == "confirmation_required"
    end

    test "a price that moves more than 30 percent is, 30 percent is not, a first value is not", %{
      token: token
    } do
      ok = call(token, "flowkit.set_values", %{"changes" => [%{"id" => "a", "value" => 130}]})
      assert ok.status == 200
      assert ApiFlowStore.items()["a"] == 130

      big = call(token, "flowkit.set_values", %{"changes" => [%{"id" => "b", "value" => 261}]})
      assert json(big)["status"] == "confirmation_required"
      assert ApiFlowStore.items()["b"] == 200

      first =
        call(token, "flowkit.set_values", %{"changes" => [%{"id" => "new", "value" => 5000}]})

      assert first.status == 200
      assert ApiFlowStore.items()["new"] == 5000
    end

    test "a batch over the threshold is dangerous on a tool that also has a danger check", %{
      token: token
    } do
      first_values = fn count ->
        %{"changes" => for(n <- 1..count, do: %{"id" => "new-#{n}", "value" => 10})}
      end

      fifty = call(token, "flowkit.set_values", first_values.(50))
      assert fifty.status == 200
      assert json(fifty) == %{"updated" => 50, "effects" => [%{"code" => "reindex_queued"}]}

      fifty_one = call(token, "flowkit.set_values", first_values.(51))
      assert json(fifty_one)["status"] == "confirmation_required"
      assert ApiFlowStore.items()["new-51"] == nil
    end

    test "a danger check that raises counts as dangerous", %{token: token} do
      log =
        capture_log(fn ->
          conn = call(token, "flowkit.misbehave", %{"mode" => "danger_raises"})
          assert json(conn)["status"] == "confirmation_required"
        end)

      assert log =~ "the danger check of flowkit.misbehave failed"
      assert real_run_messages() == []
    end

    test "a danger check that fails never puts a request value in the log", %{token: token} do
      for mode <- ~w(danger_raises_input danger_key_error danger_throws danger_exits) do
        sentinel = "sentinel-#{mode}-#{System.unique_integer([:positive])}"

        log =
          capture_log(fn ->
            conn = call(token, "flowkit.misbehave", %{"mode" => mode, "note" => sentinel})
            assert json(conn)["status"] == "confirmation_required", mode
          end)

        assert log =~ "the danger check of flowkit.misbehave failed", mode
        refute log =~ sentinel, mode
      end

      assert real_run_messages() == []
    end

    test "a danger check that answers something but true or false counts as dangerous", %{
      token: token
    } do
      for mode <- ~w(danger_returns_yes danger_returns_nil) do
        log =
          capture_log(fn ->
            conn = call(token, "flowkit.misbehave", %{"mode" => mode})
            assert json(conn)["status"] == "confirmation_required", mode
          end)

        assert log =~ "instead of true or false", mode
      end

      assert real_run_messages() == []
    end

    test "the danger check is called with a context that says dry_run", %{token: token} do
      conn = call(token, "flowkit.misbehave", %{"mode" => "danger_dry_run"})

      assert json(conn)["status"] == "confirmation_required"
      assert real_run_messages() == []
    end

    test "a read tool is never dangerous, however long its list", %{token: token} do
      assert call(token, "flowkit.read_items", %{}).status == 200

      conn = call(token, "flowkit.read_many", %{"ids" => for(n <- 1..60, do: "id-#{n}")})

      assert conn.status == 200
      assert json(conn) == %{"count" => 60}
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    # `Tool.validate/1` refuses these at build time (see tool_danger_test.exs), but a
    # hand-written struct skips it, and the gate must not read "I do not understand this"
    # as "safe" (a bad declaration fails closed).
    defp bare_state(danger) do
      tool = %PhoenixKit.API.Tool{
        name: "flowkit.typo",
        audience: :public,
        handler: {__MODULE__, :noop},
        annotations: %{read_only: false, destructive: false, idempotent: false, open_world: false},
        danger: danger
      }

      %{
        tool: tool,
        audience: :public,
        actor: %PhoenixKit.API.Actor{kind: :anonymous, client_token_hash: nil},
        input: %{},
        rows: 0,
        control: %{},
        dry_run?: false
      }
    end

    test "a danger declaration nobody understands counts as dangerous" do
      # Dangerous public calls without a client token stop at the 422 of `confirm_flow/1`:
      # reaching it proves the gate took the call for dangerous.
      for bad <- [
            :allways,
            "always",
            true,
            {PhoenixKit.API.Tool},
            {nil, :check},
            {PhoenixKit.Test.ApiFlowTools, nil},
            {"m", "f"},
            [:always]
          ] do
        log =
          capture_log(fn ->
            assert {:error, :validation_failed, _detail, _context, _state} =
                     Flow.gate(bare_state(bad)),
                   inspect(bad)
          end)

        assert log =~ "which is not understood", inspect(bad)
      end
    end

    test "no declaration and a short input is not dangerous" do
      state = bare_state(nil)
      assert {:ok, ^state} = Flow.gate(state)
    end

    test "a public write is never dangerous because of its length" do
      put_setting("api_confirm_batch_over", 1)

      conn = public_call("flowkit.public_write", %{"text" => "x", "lines" => [%{}, %{}, %{}]})

      assert conn.status == 200
      assert ApiFlowStore.calls() == 1
    end
  end

  describe "a public tool: the code is bound to the client token" do
    test "the client that got the code may use it, another may not" do
      ApiFlowStore.put("session:session-1", ["line"])
      first = public_call("flowkit.clear_session", %{"session_token" => "session-1"})

      assert %{"status" => "confirmation_required", "confirm_token" => code} = json(first)
      assert [row] = rows("token")
      assert row.actor_key_uuid == nil

      assert row.client_token_hash ==
               :crypto.hash(:sha256, "session-1") |> Base.url_encode64(padding: false)

      other =
        public_call("flowkit.clear_session", %{
          "session_token" => "session-2",
          "confirm_token" => code
        })

      assert other.status == 409

      done =
        public_call("flowkit.clear_session", %{
          "session_token" => "session-1",
          "confirm_token" => code
        })

      assert done.status == 200
      assert json(done) == %{"cleared" => true}
      refute Map.has_key?(ApiFlowStore.items(), "session:session-1")
    end

    test "a dangerous public tool that cannot replay still asks for the code and takes it once" do
      ApiFlowStore.put("session:session-1", ["line"])
      args = %{"session_token" => "session-1"}

      keyed =
        public_call(
          "flowkit.drop_session",
          Map.put(args, "idempotency_key", String.duplicate("k", 20))
        )

      assert keyed.status == 422
      assert rows("token") == []

      first = public_call("flowkit.drop_session", args)
      assert %{"status" => "confirmation_required", "confirm_token" => code} = json(first)
      assert Map.has_key?(ApiFlowStore.items(), "session:session-1")

      done = public_call("flowkit.drop_session", Map.put(args, "confirm_token", code))
      assert done.status == 200
      assert json(done) == %{"cleared" => true}
      refute Map.has_key?(ApiFlowStore.items(), "session:session-1")

      again = public_call("flowkit.drop_session", Map.put(args, "confirm_token", code))
      assert again.status == 409
    end

    test "a dangerous public call without a client token is a 422" do
      conn = public_call("flowkit.clear_session", %{})

      assert conn.status == 422
      assert json(conn)["detail"] == "A client token is required for this operation."
      assert Enum.any?(json(conn)["context"]["errors"], &(&1["path"] == "session_token"))
      assert rows("token") == []
    end
  end

  describe "a public tool that declares no client token but has a cart_token property (legacy)" do
    test "its code is bound to the cart_token, and another token may not use it" do
      ApiFlowStore.put("legacy:token-1", ["line"])
      first = public_call("flowkit.legacy_clear", %{"cart_token" => "token-1"})

      assert %{"status" => "confirmation_required", "confirm_token" => code} = json(first)
      assert [row] = rows("token")

      assert row.client_token_hash ==
               :crypto.hash(:sha256, "token-1") |> Base.url_encode64(padding: false)

      other =
        public_call("flowkit.legacy_clear", %{"cart_token" => "token-2", "confirm_token" => code})

      assert other.status == 409

      done =
        public_call("flowkit.legacy_clear", %{"cart_token" => "token-1", "confirm_token" => code})

      assert done.status == 200
      refute Map.has_key?(ApiFlowStore.items(), "legacy:token-1")
    end

    test "a dangerous call without the token is a 422 that names cart_token" do
      conn = public_call("flowkit.legacy_clear", %{})

      assert conn.status == 422
      assert json(conn)["detail"] == "A client token is required for this operation."
      assert Enum.any?(json(conn)["context"]["errors"], &(&1["path"] == "cart_token"))
      assert rows("token") == []
    end
  end

  describe "a NUL character in the input" do
    # Neither a confirmation code nor an approval can keep it (it is not storable in jsonb),
    # so the call is a 422 before anything is claimed or written, on every path.
    defp nul_value, do: "x" <> <<0>> <> "tail-#{System.unique_integer([:positive])}"

    test "code: 422, no raise, no row, and the value is not logged", %{token: token} do
      sentinel = nul_value()

      log =
        capture_log(fn ->
          conn = call(token, @delete, %{"ids" => ["a", sentinel]})

          assert conn.status == 422
          assert json(conn)["code"] == "validation_failed"
          assert [%{"path" => "ids[1]"}] = json(conn)["context"]["errors"]
          refute conn.resp_body =~ "tail-"
        end)

      refute log =~ "tail-"
      assert Repo.aggregate(Confirmation, :count) == 0
      assert ApiFlowStore.items() == @all_items
    end

    test "approval: 422, no raise, no approval", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => [nul_value()]})

      assert conn.status == 422
      assert json(conn)["code"] == "validation_failed"
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "a public tool: 422 for a client token with a NUL" do
      conn = public_call("flowkit.clear_session", %{"session_token" => nul_value()})

      assert conn.status == 422
      assert [%{"path" => "session_token"}] = json(conn)["context"]["errors"]
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "a dry run is refused too, and a call that is not dangerous", %{token: token} do
      assert call(token, @delete, %{"ids" => [nul_value()], "dry_run" => true}).status == 422
      assert call(token, "flowkit.touch_item", %{"name" => nul_value()}).status == 422
      assert ApiFlowStore.calls() == 0
    end

    test "a NUL in a nested value or in a key is found, and the refusal releases the claim", %{
      token: token
    } do
      key = "retry-key-0123456789"
      bad = %{"items" => [%{nul_value() => 2}]}

      for _attempt <- 1..2 do
        conn = call(token, "flowkit.batch_touch", bad, headers: [{"idempotency-key", key}])

        assert conn.status == 422

        assert [%{"path" => "items[0]", "message" => "has a key with a NUL character"}] =
                 json(conn)["context"]["errors"]
      end

      assert Repo.aggregate(PhoenixKit.API.Idempotency.Record, :count) == 0

      nested = %{"items" => [%{"deep" => [%{"name" => nul_value()}]}]}
      conn = call(token, "flowkit.batch_touch", nested)

      assert conn.status == 422
      assert [%{"path" => "items[0].deep[0].name"}] = json(conn)["context"]["errors"]
    end

    test "a read tool is not looked at", %{token: token} do
      assert call(token, "flowkit.read_many", %{"ids" => [nul_value()]}).status == 200
    end
  end

  describe "the host's request context hook" do
    defmodule CountingHook do
      @moduledoc false
      def resolve(_conn) do
        send(self(), :request_context_resolved)
        %{}
      end
    end

    setup do
      Application.put_env(:phoenix_kit, :api_request_context, {CountingHook, :resolve})
      on_exit(fn -> Application.delete_env(:phoenix_kit, :api_request_context) end)
    end

    defp resolutions(count \\ 0) do
      receive do
        :request_context_resolved -> resolutions(count + 1)
      after
        0 -> count
      end
    end

    test "is asked once per call, however many times the flow builds a context", %{
      token: token,
      gated: gated
    } do
      # The preview call: the danger check, the dry run and the issue of a code.
      moves = %{"changes" => [%{"id" => "a", "value" => 200}]}
      first = call(token, "flowkit.set_values", moves)
      assert code_of(first)
      assert resolutions() == 1

      # The confirming call: the danger check, a fresh dry run and the real run.
      confirmed =
        call(token, "flowkit.set_values", Map.put(moves, "confirm_token", code_of(first)))

      assert confirmed.status == 200
      assert resolutions() == 1

      # Approval: the dry run and the snapshot kept with the approval.
      assert call(gated.token, @delete, %{"ids" => ["a"]}).status == 200
      assert resolutions() == 1

      # A dry run, and an ordinary call.
      assert call(token, @delete, %{"ids" => ["a"], "dry_run" => true}).status == 200
      assert resolutions() == 1
      assert call(token, "flowkit.touch_item", %{"name" => "x"}).status == 200
      assert resolutions() == 1
    end
  end

  describe "a fingerprint the store cannot hold" do
    @misbehave "flowkit.misbehave"

    test "code: 64 characters is issued, 65 or a non-UTF-8 text is a 500 with no row", %{
      token: token
    } do
      conn = call(token, @misbehave, %{"mode" => "fingerprint_64"})
      assert conn.status == 200
      assert is_binary(code_of(conn))
      assert [%{fingerprint: fingerprint}] = rows("token")
      assert byte_size(fingerprint) == 64

      for mode <- ["fingerprint_65", "fingerprint_not_utf8"] do
        {conn, log} = with_log(fn -> call(token, @misbehave, %{"mode" => mode}) end)

        assert conn.status == 500, mode
        assert json(conn)["code"] == "internal_error"
        assert log =~ "fingerprint", mode
      end

      assert length(rows("token")) == 1
    end

    test "approval: 64 characters is queued, 65 or a non-UTF-8 text is a 500 with no row", %{
      gated: gated
    } do
      conn = call(gated.token, @misbehave, %{"mode" => "fingerprint_64"})
      assert conn.status == 200
      assert json(conn)["status"] == "pending_approval"

      for mode <- ["fingerprint_65", "fingerprint_not_utf8"] do
        {conn, log} = with_log(fn -> call(gated.token, @misbehave, %{"mode" => mode}) end)

        assert conn.status == 500, mode
        assert json(conn)["code"] == "internal_error"
        assert log =~ "fingerprint", mode
      end

      assert length(rows("approval")) == 1
    end

    test "the claim of an Idempotency-Key is given up", %{token: token} do
      key = "fingerprint-key-0123456789"
      input = %{"mode" => "fingerprint_65"}

      log =
        capture_log(fn ->
          for _attempt <- 1..2 do
            conn = call(token, @misbehave, input, headers: [{"idempotency-key", key}])
            assert conn.status == 500
          end
        end)

      assert log =~ "fingerprint"
      assert Repo.aggregate(PhoenixKit.API.Idempotency.Record, :count) == 0
    end

    test "the row refuses a fingerprint over 64 characters instead of raising" do
      changeset =
        Confirmation.changeset(%Confirmation{}, %{
          kind: "token",
          tool: "flowkit.delete_items",
          input_hash: "h",
          fingerprint: String.duplicate("f", 65),
          client_token_hash: "c",
          status: "unused",
          expires_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })

      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :fingerprint)
    end
  end

  describe "a key that requires approval" do
    test "a dangerous call is queued, not run, and no code is issued", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => ["a", "b"]})

      assert conn.status == 200

      assert %{
               "executed" => false,
               "status" => "pending_approval",
               "approval_id" => approval_id,
               "preview" => %{"totals" => %{"delete" => 2}},
               "expires_in_seconds" => seconds
             } = json(conn)

      assert seconds > 0
      refute Map.has_key?(json(conn), "confirm_token")
      assert ApiFlowStore.items() == @all_items
      assert real_run_messages() == []
      assert rows("token") == []

      assert [row] = rows("approval")
      assert row.uuid == approval_id
      assert row.status == "pending"
      assert row.input == %{"ids" => ["a", "b"]}
      request_id = conn.assigns.phoenix_kit_api_request_id
      assert is_binary(request_id)

      assert row.context == %{
               "language" => PhoenixKit.Utils.Multilang.primary_language(),
               "currency" => nil,
               "hosts" => ["www.example.com"],
               "base_url" => "http://www.example.com",
               "request_id" => request_id
             }

      assert [entry] =
               Repo.all(
                 from(e in Entry,
                   where: e.action == "api.request" and e.resource_uuid == ^gated.key.uuid
                 )
               )

      assert entry.metadata["outcome"] == "pending_approval"
    end

    test "an identical request returns the same approval", %{gated: gated} do
      first = call(gated.token, @delete, %{"ids" => ["a"]})
      second = call(gated.token, @delete, %{"ids" => ["a"]})

      assert json(first)["approval_id"] == json(second)["approval_id"]
      assert length(rows("approval")) == 1
    end

    test "a held answer asked for again carries the replay header, a new approval does not", %{
      gated: gated
    } do
      first = call(gated.token, @delete, %{"ids" => ["a"]})
      same = call(gated.token, @delete, %{"ids" => ["a"]})

      key = "idem-key-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")
      keyed = call(gated.token, @delete, %{"ids" => ["a"], "idempotency_key" => key})
      keyed_again = call(gated.token, @delete, %{"ids" => ["a"], "idempotency_key" => key})

      other = call(gated.token, @delete, %{"ids" => ["b"]})

      assert get_resp_header(first, "idempotent-replayed") == []
      assert get_resp_header(same, "idempotent-replayed") == ["true"]
      assert get_resp_header(keyed, "idempotent-replayed") == ["true"]
      assert get_resp_header(keyed_again, "idempotent-replayed") == ["true"]
      assert json(keyed_again)["approval_id"] == json(first)["approval_id"]
      assert get_resp_header(other, "idempotent-replayed") == []

      assert same.status == 200
      assert %{"executed" => false, "status" => "pending_approval"} = json(same)
    end

    test "the cap of pending approvals is a 429", %{gated: gated} do
      put_setting("api_approval_pending_max", 1)

      assert call(gated.token, @delete, %{"ids" => ["a"]}).status == 200

      capped = call(gated.token, @delete, %{"ids" => ["b"]})
      assert capped.status == 429
      assert json(capped)["code"] == "rate_limited"
      assert get_resp_header(capped, "retry-after") == ["300"]

      assert call(gated.token, @delete, %{"ids" => ["a"]}).status == 200
    end

    test "an input over 1 MB is a 413", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => [String.duplicate("a", 1_048_577)]})

      assert conn.status == 413
      assert json(conn)["code"] == "payload_too_large"
      assert rows("approval") == []
    end

    test "a code is never accepted from such a key", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => ["a"], "confirm_token" => "ct_whatever"})

      assert conn.status == 409
      assert json(conn)["context"]["reason"] == "approval_required"
      assert rows("approval") == []
    end

    test "dry_run is a preview with no approval", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => ["a"], "dry_run" => true})

      assert conn.status == 200
      assert %{"dry_run" => true} = json(conn)
      assert rows("approval") == []
    end

    test "a pending_approval answer is not stored under an Idempotency-Key", %{gated: gated} do
      key = "idem-key-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")
      input = %{"ids" => ["a"], "idempotency_key" => key}

      first = call(gated.token, @delete, input)

      assert first.status == 200
      assert %{"status" => "pending_approval", "approval_id" => first_id} = json(first)
      assert Repo.aggregate(Record, :count) == 0

      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())
      assert {:ok, _row} = Approvals.reject(first_id, owner_scope)

      second = call(gated.token, @delete, input)

      assert second.status == 200
      assert get_resp_header(second, "idempotent-replayed") == []
      assert %{"status" => "pending_approval", "approval_id" => second_id} = json(second)
      refute second_id == first_id
      assert Repo.aggregate(Record, :count) == 0
    end

    test "a write that is not dangerous is queued too, not run", %{gated: gated} do
      conn = call(gated.token, "flowkit.touch_item", %{"name" => "x"})

      assert conn.status == 200

      assert %{
               "executed" => false,
               "status" => "pending_approval",
               "approval_id" => approval_id,
               "preview" => %{"rows" => [%{"ref" => "x", "action" => "touch"}]}
             } = json(conn)

      refute Map.has_key?(json(conn), "confirm_token")
      assert ApiFlowStore.calls() == 0
      assert real_run_messages() == []
      assert rows("token") == []

      assert [%{uuid: ^approval_id, status: "pending", input: %{"name" => "x"}}] =
               rows("approval")
    end

    test "a write whose danger check says no is queued as well", %{gated: gated} do
      conn =
        call(gated.token, "flowkit.set_values", %{"changes" => [%{"id" => "a", "value" => 110}]})

      assert conn.status == 200
      assert %{"status" => "pending_approval"} = json(conn)
      assert ApiFlowStore.items() == @all_items
      assert [%{status: "pending"}] = rows("approval")
    end

    test "approving a write that is not dangerous runs it once", %{gated: gated} do
      conn = call(gated.token, "flowkit.touch_item", %{"name" => "x"})
      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())

      assert {:ok, %{status: "executed", result: %{"touched" => "x", "call" => 1}}} =
               Approvals.approve(json(conn)["approval_id"], owner_scope)

      assert ApiFlowStore.calls() == 1
    end

    test "the same write from a key without the flag runs at once", %{token: token} do
      conn = call(token, "flowkit.touch_item", %{"name" => "x"})

      assert conn.status == 200
      assert %{"touched" => "x", "call" => 1} = json(conn)
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "a code sent with a write that is not dangerous is refused, nothing is run", %{
      gated: gated
    } do
      conn = call(gated.token, "flowkit.touch_item", %{"name" => "x", "confirm_token" => "ct_x"})

      assert conn.status == 409
      assert json(conn)["context"]["reason"] == "approval_required"
      assert ApiFlowStore.calls() == 0
      assert rows("approval") == []
    end

    test "dry_run of a write that is not dangerous is a preview with no approval", %{
      gated: gated
    } do
      conn = call(gated.token, "flowkit.touch_item", %{"name" => "x", "dry_run" => true})

      assert conn.status == 200
      assert %{"executed" => false, "dry_run" => true, "preview" => _} = json(conn)
      assert ApiFlowStore.calls() == 0
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "a read runs at once", %{gated: gated} do
      conn = call(gated.token, "flowkit.read_items", %{})

      assert conn.status == 200
      assert json(conn) == %{"items" => @all_items}
      assert Repo.aggregate(Confirmation, :count) == 0
    end

    test "approving it later runs the operation as the key's owner", %{gated: gated} do
      conn = call(gated.token, @delete, %{"ids" => ["a"]})
      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())

      assert {:ok, %{status: "executed"}} =
               Approvals.approve(json(conn)["approval_id"], owner_scope)

      assert ApiFlowStore.items() == Map.delete(@all_items, "a")
    end
  end
end
