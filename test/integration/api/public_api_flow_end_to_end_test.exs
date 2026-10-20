defmodule PhoenixKit.API.PublicApiFlowEndToEndTest do
  @moduledoc """
  The dangerous-operation flow through the real endpoint, router and database: nothing
  is called as a function except the Owner's decision on an approval. One `describe` per
  property of the flow that must hold.

  Requests carry an `X-Forwarded-For` address of their own (believed because the test
  peer is loopback), so no test shares a rate-limit bucket with another.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Test.ApiFlowHarness
  alias PhoenixKit.Test.ApiFlowStore
  alias PhoenixKit.Test.ApiHarness
  alias PhoenixKit.Utils.Routes

  @delete "flowkit.delete_items"
  @all_items %{"a" => 100, "b" => 200, "c" => 300}

  setup %{conn: conn} do
    ApiFlowHarness.setup_flow()

    %{
      conn: conn,
      plain: ApiFlowHarness.agent(requires_approval: false),
      gated: ApiFlowHarness.agent(requires_approval: true)
    }
  end

  # --- requests ---------------------------------------------------------

  defp api_path(tool), do: Routes.path("/api/admin/v1/" <> tool)

  defp from_ip(conn, ip \\ KeyTestSupport.unique_ip()),
    do: put_req_header(conn, "x-forwarded-for", ip)

  defp bearer(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp with_headers(conn, headers),
    do: Enum.reduce(headers, conn, fn {name, value}, acc -> put_req_header(acc, name, value) end)

  defp post_json(conn, path, body) do
    conn |> put_req_header("content-type", "application/json") |> post(path, body)
  end

  defp call_tool(conn, token, tool, body, headers \\ []) do
    conn
    |> from_ip()
    |> bearer(token)
    |> with_headers(headers)
    |> post_json(api_path(tool), JSON.encode!(body))
  end

  # The body exactly as written, for the test of key order.
  defp call_raw(conn, token, tool, raw) do
    conn |> from_ip() |> bearer(token) |> post_json(api_path(tool), raw)
  end

  defp json(conn), do: JSON.decode!(conn.resp_body)
  defp code_of(conn), do: json(conn)["confirm_token"]

  defp idem,
    do:
      "e2e-key-" <>
        String.pad_leading(Integer.to_string(System.unique_integer([:positive])), 12, "0")

  defp reason(conn), do: json(conn)["context"]["reason"]

  # Phoenix logs at :debug and `config/test.exs` sets the primary level to :warning: raise it
  # for real or a `refute log =~ x` passes without having looked at anything.
  defp capture_debug_log(fun) do
    original = Logger.level()
    Logger.configure(level: :debug)

    try do
      with_log([level: :debug], fun)
    after
      Logger.configure(level: original)
    end
  end

  describe "a confirmation code is spent exactly once" do
    test "preview, confirm and replay are 200, 200 and 409", %{conn: conn, plain: plain} do
      first = call_tool(conn, plain.token, @delete, %{"ids" => ["a"]})
      assert first.status == 200

      assert %{"executed" => false, "status" => "confirmation_required", "confirm_token" => code} =
               json(first)

      assert ApiFlowStore.items() == @all_items

      second = call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})
      assert second.status == 200
      assert json(second) == %{"deleted" => 1}
      refute Map.has_key?(ApiFlowStore.items(), "a")

      replay = call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})
      assert replay.status == 409
      assert ["application/problem+json" <> _] = get_resp_header(replay, "content-type")
      assert %{"code" => "confirm_token_invalid"} = json(replay)
      assert reason(replay) == "used"
    end

    test "six simultaneous confirmations run the operation once", %{conn: conn, plain: plain} do
      KeyTestSupport.put_setting("api_confirm_batch_over", 1)
      body = %{"items" => [%{}, %{}]}
      code = conn |> call_tool(plain.token, "flowkit.batch_touch", body) |> code_of()

      statuses =
        1..6
        |> Task.async_stream(
          fn _ ->
            build_conn()
            |> call_tool(plain.token, "flowkit.batch_touch", Map.put(body, "confirm_token", code))
            |> Map.fetch!(:status)
          end,
          max_concurrency: 6,
          timeout: :infinity
        )
        |> Enum.map(fn {:ok, status} -> status end)

      assert Enum.sort(statuses) == [200, 409, 409, 409, 409, 409]
      assert ApiFlowStore.calls() == 1
    end

    test "another key may not use the code", %{conn: conn, plain: plain} do
      other = ApiFlowHarness.agent(requires_approval: false)
      code = conn |> call_tool(plain.token, @delete, %{"ids" => ["a"]}) |> code_of()

      refused = call_tool(conn, other.token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert refused.status == 409
      assert reason(refused) == "invalid"
      assert ApiFlowStore.items() == @all_items
    end
  end

  describe "a code is bound to the values it previewed" do
    test "values that changed since the preview: 409 with the new values, nothing written", %{
      conn: conn,
      plain: plain
    } do
      code = conn |> call_tool(plain.token, @delete, %{"ids" => ["a"]}) |> code_of()
      ApiFlowStore.put("a", 999)

      refused = call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert refused.status == 409
      assert reason(refused) == "changed"
      assert [%{"from" => 999}] = json(refused)["context"]["preview"]["rows"]
      assert ApiFlowStore.items()["a"] == 999
    end

    test "other arguments and an expired code are refused with a fresh preview", %{
      conn: conn,
      plain: plain
    } do
      code = conn |> call_tool(plain.token, @delete, %{"ids" => ["a", "b"]}) |> code_of()

      other = call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})
      assert other.status == 409 and reason(other) == "other_arguments"
      assert json(other)["context"]["preview"]["totals"] == %{"delete" => 1}

      past = DateTime.utc_now() |> DateTime.add(-5, :second) |> DateTime.truncate(:second)
      Repo.update_all(Confirmation, set: [expires_at: past])

      expired =
        call_tool(conn, plain.token, @delete, %{"ids" => ["a", "b"], "confirm_token" => code})

      assert expired.status == 409 and reason(expired) == "expired"
      assert ApiFlowStore.items() == @all_items
    end

    test "the same arguments in another key order are the same arguments", %{
      conn: conn,
      plain: plain
    } do
      first =
        call_raw(
          conn,
          plain.token,
          "flowkit.set_values",
          ~s({"changes":[{"id":"a","value":200}]})
        )

      code = code_of(first)

      done =
        call_raw(
          conn,
          plain.token,
          "flowkit.set_values",
          ~s({"confirm_token":"#{code}","changes":[{"value":200,"id":"a"}]})
        )

      assert done.status == 200
      assert ApiFlowStore.items()["a"] == 200
    end
  end

  describe "a retried write is applied once and no credential is stored" do
    test "the Idempotency-Key header replays the first answer", %{conn: conn, plain: plain} do
      headers = [{"idempotency-key", idem()}]

      first = call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "x"}, headers)
      second = call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "x"}, headers)

      assert first.status == 200 and second.status == 200
      assert second.resp_body == first.resp_body
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert ApiFlowStore.calls() == 1
    end

    test "the same key for another request is 409 idempotency_key_reused", %{
      conn: conn,
      plain: plain
    } do
      headers = [{"idempotency-key", idem()}]
      call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "x"}, headers)

      refused = call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "y"}, headers)

      assert refused.status == 409
      assert json(refused)["code"] == "idempotency_key_reused"
      assert ApiFlowStore.calls() == 1
    end

    test "a confirming call may reuse the key of its preview", %{conn: conn, plain: plain} do
      key = idem()
      headers = [{"idempotency-key", key}]

      preview = call_tool(conn, plain.token, @delete, %{"ids" => ["a"]}, headers)
      assert json(preview)["status"] == "confirmation_required"
      assert Repo.aggregate(from(r in Record, where: r.key == ^key), :count) == 0

      done =
        call_tool(
          conn,
          plain.token,
          @delete,
          %{"ids" => ["a"], "confirm_token" => code_of(preview)},
          headers
        )

      assert done.status == 200

      again =
        call_tool(
          conn,
          plain.token,
          @delete,
          %{"ids" => ["a"], "confirm_token" => code_of(preview)},
          headers
        )

      assert again.status == 200
      assert again.resp_body == done.resp_body
      assert get_resp_header(again, "idempotent-replayed") == ["true"]
    end

    test "a confirming call that is refused gives the key back", %{conn: conn, plain: plain} do
      key = idem()
      headers = [{"idempotency-key", key}]

      code = conn |> call_tool(plain.token, @delete, %{"ids" => ["a"]}, headers) |> code_of()
      ApiFlowStore.put("a", 999)

      refused =
        call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code}, headers)

      assert refused.status == 409
      assert reason(refused) == "changed"
      assert Repo.aggregate(from(r in Record, where: r.key == ^key), :count) == 0

      # The refusal gave the claim up (`Flow.release/1`). If it kept the claim, this call
      # would be answered `409 idempotency_in_progress` instead of a new preview.
      again = call_tool(conn, plain.token, @delete, %{"ids" => ["a"]}, headers)
      assert again.status == 200
      assert json(again)["status"] == "confirmation_required"
      assert ApiFlowStore.items()["a"] == 999
    end

    test "an answer that carries a credential is never stored", %{conn: conn, plain: plain} do
      headers = [{"idempotency-key", idem()}]

      first = call_tool(conn, plain.token, "flowkit.misbehave", %{"mode" => "leak"}, headers)
      second = call_tool(conn, plain.token, "flowkit.misbehave", %{"mode" => "leak"}, headers)

      refute json(first)["session_token"] == json(second)["session_token"]
      assert get_resp_header(second, "idempotent-replayed") == []
      assert Repo.aggregate(Record, :count) == 0
    end

    test "the code and the secret of the API key appear in no log line, the idempotency key in no request-parameter line",
         %{conn: conn, plain: plain} do
      original = Application.fetch_env(:phoenix, :filter_parameters)

      Application.put_env(
        :phoenix,
        :filter_parameters,
        ~w(password token secret api_key idempotency_key)
      )

      on_exit(fn ->
        case original do
          {:ok, value} -> Application.put_env(:phoenix, :filter_parameters, value)
          :error -> Application.delete_env(:phoenix, :filter_parameters)
        end
      end)

      [_pk, _prefix, secret] = String.split(plain.token, "_", parts: 3)
      key = idem()

      {code, log} =
        capture_debug_log(fn ->
          first =
            call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "idempotency_key" => key})

          code = code_of(first)

          call_tool(conn, plain.token, @delete, %{
            "ids" => ["a"],
            "idempotency_key" => key,
            "confirm_token" => code
          })

          code
        end)

      # Not vacuous: the endpoint's own request lines were captured.
      assert log =~ "Sent 200"
      refute log =~ code
      refute log =~ plain.token
      refute log =~ secret

      # The idempotency key is not a secret and `PhoenixKit.Test.Repo` logs its queries
      # with their parameters at :debug (the claim row carries the key), so the whole log
      # may name it. What the filter list promises is the request-parameter lines of the
      # endpoint (the `Parameters:` line of `Phoenix.Logger`).
      parameter_lines = log |> String.split("\n") |> Enum.filter(&(&1 =~ "Parameters:"))
      assert parameter_lines != []
      refute Enum.any?(parameter_lines, &(&1 =~ key))
    end
  end

  describe "an approval re-checks the world at decision time" do
    defp owner_scope, do: KeyTestSupport.scope_of(KeyTestSupport.owner_user())

    test "queued, followed, approved by the Owner, executed", %{conn: conn, gated: gated} do
      queued = call_tool(conn, gated.token, @delete, %{"ids" => ["a"]})
      assert queued.status == 200

      assert %{"executed" => false, "status" => "pending_approval", "approval_id" => id} =
               json(queued)

      assert ApiFlowStore.items() == @all_items

      pending = call_tool(conn, gated.token, "system.get_approval", %{"approval_id" => id})

      assert %{"status" => "pending", "preview" => %{"totals" => %{"delete" => 1}}} =
               json(pending)

      assert {:ok, %{status: "executed"}} = Approvals.approve(id, owner_scope())
      refute Map.has_key?(ApiFlowStore.items(), "a")

      done = call_tool(conn, gated.token, "system.get_approval", %{"approval_id" => id})
      assert %{"status" => "executed", "result" => %{"deleted" => 1}} = json(done)
    end

    test "another key reads nothing of it", %{conn: conn, gated: gated, plain: plain} do
      %{"approval_id" => id} =
        conn |> call_tool(gated.token, @delete, %{"ids" => ["a"]}) |> json()

      assert call_tool(conn, plain.token, "system.get_approval", %{"approval_id" => id}).status ==
               404
    end

    test "a key revoked before the decision: failed, nothing written", %{conn: conn, gated: gated} do
      %{"approval_id" => id} =
        conn |> call_tool(gated.token, @delete, %{"ids" => ["a"]}) |> json()

      {:ok, _} = Keys.revoke(Keys.get_key(gated.key.uuid), nil)

      assert {:ok, %{status: "failed"}} = Approvals.approve(id, owner_scope())
      assert ApiFlowStore.items() == @all_items
    end

    test "values that changed before the decision: stale, nothing written", %{
      conn: conn,
      gated: gated
    } do
      %{"approval_id" => id} =
        conn |> call_tool(gated.token, @delete, %{"ids" => ["a"]}) |> json()

      ApiFlowStore.put("a", 999)

      assert {:ok, %{status: "stale"}} = Approvals.approve(id, owner_scope())
      assert ApiFlowStore.items()["a"] == 999
    end

    test "an identical request returns the same approval, and a rejected one never runs", %{
      conn: conn,
      gated: gated
    } do
      first = call_tool(conn, gated.token, @delete, %{"ids" => ["a"]})
      second = call_tool(conn, gated.token, @delete, %{"ids" => ["a"]})
      id = json(first)["approval_id"]

      assert json(second)["approval_id"] == id
      assert {:ok, %{status: "rejected"}} = Approvals.reject(id, owner_scope())
      assert {:error, :not_pending} = Approvals.approve(id, owner_scope())
      assert ApiFlowStore.items() == @all_items
    end
  end

  describe "the edges of the control fields and the threshold" do
    test "a string dry_run is a 422 problem and nothing runs", %{conn: conn, plain: plain} do
      for value <- ["false", "true"] do
        refused =
          call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "x", "dry_run" => value})

        assert refused.status == 422
        assert json(refused)["code"] == "validation_failed"
      end

      assert ApiFlowStore.calls() == 0
    end

    test "control fields on a read tool are a 422", %{conn: conn, plain: plain} do
      for field <- ["dry_run", "confirm_token", "idempotency_key"] do
        assert call_tool(conn, plain.token, "flowkit.read_items", %{field => "0123456789abcdef"}).status ==
                 422
      end
    end

    test "an idempotency key of 15 characters is a 422, as a field and as a header", %{
      conn: conn,
      plain: plain
    } do
      short = String.duplicate("a", 15)

      assert call_tool(conn, plain.token, "flowkit.touch_item", %{
               "name" => "x",
               "idempotency_key" => short
             }).status == 422

      assert call_tool(conn, plain.token, "flowkit.touch_item", %{"name" => "x"}, [
               {"idempotency-key", short}
             ]).status == 422

      assert ApiFlowStore.calls() == 0
    end

    test "50 rows run, 51 need a code", %{conn: conn, plain: plain} do
      fifty =
        call_tool(conn, plain.token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 50)})

      assert fifty.status == 200 and json(fifty) == %{"count" => 50}

      fifty_one =
        call_tool(conn, plain.token, "flowkit.batch_touch", %{"items" => List.duplicate(%{}, 51)})

      assert json(fifty_one)["status"] == "confirmation_required"
      assert ApiFlowStore.calls() == 1
    end

    test "a dry run writes nothing and creates no code", %{conn: conn, plain: plain} do
      dry = call_tool(conn, plain.token, @delete, %{"ids" => ["a"], "dry_run" => true})

      assert dry.status == 200
      assert %{"executed" => false, "dry_run" => true} = json(dry)
      assert Repo.aggregate(Confirmation, :count) == 0
      assert ApiFlowStore.items() == @all_items
    end

    test "with the admin API off every one of these paths is a 404 and no table is touched", %{
      conn: conn,
      plain: plain
    } do
      ApiHarness.switch(:admin, false)

      for tool <- [@delete, "flowkit.touch_item", "system.get_approval"] do
        off = call_tool(conn, plain.token, tool, %{"ids" => ["a"]}, [{"idempotency-key", idem()}])

        assert off.status == 404
        assert json(off)["code"] == "not_found"
      end

      assert Repo.aggregate(Record, :count) == 0
      assert Repo.aggregate(Confirmation, :count) == 0
    end
  end
end
