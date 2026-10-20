defmodule PhoenixKit.API.CombinedMcpFlowTest do
  @moduledoc """
  The MCP transport and the dangerous-operation flow together, through the
  real endpoint, router, body guard and database: every check is an HTTP
  request against `PhoenixKitWeb.Endpoint`.

  Neither the MCP tests nor the flow tests can see the seam between the two:
  the MCP plug must hand the control fields (`dry_run`, `confirm_token`,
  `idempotency_key`) to the executor as tool arguments, a preview, a prompt
  for a confirmation code and a pending approval are ordinary results (never
  `isError`), and the schemas the clients are shown must list the control
  fields and cover those answers.

  Each request gets an `X-Forwarded-For` address of its own, so no test
  shares a public rate-limit bucket with another.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import Ecto.Query
  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [put_setting: 2, wait_for_window_room: 0]

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.OutputShape
  alias PhoenixKit.API.Registry
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Test.ApiFlowHarness
  alias PhoenixKit.Test.ApiFlowStore
  alias PhoenixKit.Test.ApiHarness
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Utils.Routes

  @delete "flowkit_delete_items"
  @all_items %{"a" => 100, "b" => 200, "c" => 300}
  @control ["dry_run", "confirm_token", "idempotency_key"]
  @version "2025-06-18"

  defmodule CountingTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_combined_counting_tools"
    def module_name, do: "Combined counting tools"
    def enabled?, do: true

    # Every walk of the registry calls this once; the test reads the count.
    def api_tools do
      send(:persistent_term.get({__MODULE__, :observer}), :walked)

      [
        Tool.new!(
          name: "counting.public_write",
          audience: :public,
          description: "Counting.",
          handler: {__MODULE__, :write},
          annotations: %{
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false
          }
        )
      ]
    end

    def write(_input, %{dry_run?: true}), do: {:preview, %{"totals" => %{"writes" => 1}}, "fp"}
    def write(_input, _ctx), do: {:ok, %{"written" => true}}
  end

  defmodule SessionTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_combined_session_tools"
    def module_name, do: "Combined session tools"
    def enabled?, do: true

    # Two public tools that are always dangerous; only the second lists `session_token` in
    # `required`.
    def api_tools do
      [
        tool("sessiontools.drop_session", []),
        tool("sessiontools.drop_session_required", ["session_token"])
      ]
    end

    defp tool(name, required) do
      Tool.new!(
        name: name,
        audience: :public,
        client_token: "session_token",
        description: "Drops a session.",
        input_schema: %{
          "type" => "object",
          "required" => required,
          "properties" => %{"session_token" => %{"type" => "string"}},
          "additionalProperties" => false
        },
        handler: {__MODULE__, :drop},
        danger: :always,
        annotations: %{read_only: false, destructive: true, idempotent: false, open_world: false}
      )
    end

    def drop(_input, %{dry_run?: true}), do: {:preview, %{"totals" => %{"drop" => 1}}, "fp"}
    def drop(_input, _ctx), do: {:ok, %{"dropped" => true}}
  end

  setup %{conn: conn} do
    ApiFlowHarness.setup_flow()

    %{
      conn: conn,
      plain: ApiFlowHarness.agent(requires_approval: false),
      gated: ApiFlowHarness.agent(requires_approval: true)
    }
  end

  # --- requests -------------------------------------------------------------

  defp maybe_bearer(conn, nil), do: conn
  defp maybe_bearer(conn, token), do: ApiHarness.bearer(conn, token)

  defp rpc(conn, path, body, opts) do
    conn
    |> ApiHarness.with_client_ip(Keyword.get_lazy(opts, :ip, &KeyTestSupport.unique_ip/0))
    |> maybe_bearer(opts[:token])
    |> put_req_header("content-type", "application/json")
    |> put_req_header("accept", "application/json")
    |> put_req_header("mcp-protocol-version", Keyword.get(opts, :version, @version))
    |> post(Routes.path(path), JSON.encode!(body))
  end

  defp message(method, params),
    do: %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}

  defp mcp_call(conn, path, token, tool, arguments, opts) do
    rpc(
      conn,
      path,
      message("tools/call", %{"name" => tool, "arguments" => arguments}),
      [token: token] ++ opts
    )
  end

  defp admin_call(conn, token, tool, arguments, opts \\ []),
    do: mcp_call(conn, "/mcp/admin", token, tool, arguments, opts)

  defp tools_list(conn, path, token) do
    conn
    |> rpc(path, message("tools/list", %{}), token: token)
    |> json()
    |> get_in(["result", "tools"])
    |> Map.new(&{&1["name"], &1})
  end

  defp rest_call(conn, token, tool, body, headers \\ []) do
    conn
    |> ApiHarness.with_client_ip()
    |> maybe_bearer(token)
    |> then(fn conn ->
      Enum.reduce(headers, conn, fn {k, v}, acc -> put_req_header(acc, k, v) end)
    end)
    |> put_req_header("content-type", "application/json")
    |> post(Routes.path("/api/admin/v1/" <> tool), JSON.encode!(body))
  end

  defp json(conn), do: JSON.decode!(conn.resp_body)
  defp result(conn), do: Map.fetch!(json(conn), "result")
  defp structured(conn), do: conn |> result() |> Map.fetch!("structuredContent")
  defp text(result), do: result["content"] |> hd() |> Map.fetch!("text")
  defp dotted(mcp_name), do: String.replace(mcp_name, "_", ".", global: false)

  defp shop_call(conn, tool, arguments, opts \\ []),
    do: mcp_call(conn, "/mcp/public", nil, tool, arguments, opts)

  defp idem,
    do: "idem-key-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")

  defp claims(key), do: Repo.aggregate(from(r in Record, where: r.key == ^key), :count)

  defp spent_codes, do: Repo.aggregate(from(c in Confirmation, where: c.status == "used"), :count)

  # The `api.request` entries of a key, oldest first: {tool, outcome, code}.
  defp audits(key_uuid) do
    from(e in Entry,
      where: e.action == "api.request" and e.resource_uuid == ^key_uuid,
      order_by: [asc: e.inserted_at, asc: e.uuid]
    )
    |> Repo.all()
    |> Enum.map(&{&1.metadata["tool"], &1.metadata["outcome"], &1.metadata["code"]})
  end

  # --- (a) a dangerous tool asks for a code ------------------------------------

  describe "a dangerous tool over MCP" do
    test "without a code it answers confirmation_required as a normal result and executes nothing",
         %{conn: conn, plain: plain} do
      answer = admin_call(conn, plain.token, @delete, %{"ids" => ["a"]})

      assert answer.status == 200
      result = result(answer)
      assert result["isError"] == false

      assert %{
               "executed" => false,
               "status" => "confirmation_required",
               "confirm_token" => code,
               "expires_at" => _,
               "expires_in_seconds" => seconds,
               "preview" => %{"totals" => %{"delete" => 1}}
             } = result["structuredContent"]

      assert is_binary(code) and is_integer(seconds)
      assert JSON.decode!(text(result)) == result["structuredContent"]
      assert ApiFlowStore.items() == @all_items
    end

    test "with the code, sent as an argument, it executes once", %{conn: conn, plain: plain} do
      code = conn |> admin_call(plain.token, @delete, %{"ids" => ["a"]}) |> structured()
      code = code["confirm_token"]

      done = admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      assert done.status == 200
      assert result(done)["isError"] == false
      assert structured(done) == %{"deleted" => 1}
      refute Map.has_key?(ApiFlowStore.items(), "a")

      again = admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})
      assert result(again)["isError"] == true
      assert text(result(again)) =~ "[confirm_token_invalid]"
    end

    test "a code for other arguments is an error result and executes nothing", %{
      conn: conn,
      plain: plain
    } do
      code = conn |> admin_call(plain.token, @delete, %{"ids" => ["a"]}) |> structured()

      refused =
        admin_call(conn, plain.token, @delete, %{
          "ids" => ["a", "b"],
          "confirm_token" => code["confirm_token"]
        })

      assert result(refused)["isError"] == true
      assert text(result(refused)) =~ "[confirm_token_invalid]"
      assert ApiFlowStore.items() == @all_items
    end

    test "a code issued over MCP is redeemed over REST", %{conn: conn, plain: plain} do
      code = conn |> admin_call(plain.token, @delete, %{"ids" => ["c"]}) |> structured()

      done =
        rest_call(conn, plain.token, "flowkit.delete_items", %{
          "ids" => ["c"],
          "confirm_token" => code["confirm_token"]
        })

      assert done.status == 200
      assert json(done) == %{"deleted" => 1}
      refute Map.has_key?(ApiFlowStore.items(), "c")
    end

    test "a client of the older revision gets the prompt as text, still not an error", %{
      conn: conn,
      plain: plain
    } do
      answer = admin_call(conn, plain.token, @delete, %{"ids" => ["a"]}, version: "2025-03-26")

      result = result(answer)
      assert result["isError"] == false
      refute Map.has_key?(result, "structuredContent")
      assert %{"status" => "confirmation_required"} = JSON.decode!(text(result))
    end
  end

  # --- (b) a key that needs approval --------------------------------------------

  describe "a key that requires approval" do
    test "gets pending_approval over MCP as a normal result", %{conn: conn, gated: gated} do
      answer = admin_call(conn, gated.token, @delete, %{"ids" => ["a"]})

      assert answer.status == 200
      result = result(answer)
      assert result["isError"] == false

      assert %{
               "executed" => false,
               "status" => "pending_approval",
               "approval_id" => approval_id,
               "preview" => %{"totals" => %{"delete" => 1}}
             } = result["structuredContent"]

      assert is_binary(approval_id)
      refute Map.has_key?(result["structuredContent"], "confirm_token")
      assert ApiFlowStore.items() == @all_items
    end

    test "marks the held answer of an operation that already waits as a replay, with or without a key",
         %{conn: conn, gated: gated} do
      first = admin_call(conn, gated.token, @delete, %{"ids" => ["a"]})
      same = admin_call(conn, gated.token, @delete, %{"ids" => ["a"]})

      keyed =
        admin_call(conn, gated.token, @delete, %{"ids" => ["a"], "idempotency_key" => idem()})

      other = admin_call(conn, gated.token, @delete, %{"ids" => ["b"]})

      assert get_resp_header(first, "idempotent-replayed") == []

      for again <- [same, keyed] do
        assert again.status == 200
        assert result(again)["isError"] == false
        assert structured(again)["approval_id"] == structured(first)["approval_id"]
        assert get_resp_header(again, "idempotent-replayed") == ["true"]
      end

      refute structured(other)["approval_id"] == structured(first)["approval_id"]
      assert get_resp_header(other, "idempotent-replayed") == []

      assert audits(gated.key.uuid) ==
               List.duplicate({"flowkit.delete_items", "pending_approval", nil}, 4)
    end

    test "changed values replace a held approval across REST and MCP without a replay header",
         %{conn: conn, gated: gated} do
      input = %{"ids" => ["a"], "idempotency_key" => idem()}
      first = rest_call(conn, gated.token, "flowkit.delete_items", input)
      assert first.status == 200
      assert %{"approval_id" => first_id} = json(first)

      ApiFlowStore.put("a", 999)
      changed = admin_call(conn, gated.token, @delete, input)
      assert changed.status == 200

      assert %{
               "executed" => false,
               "status" => "pending_approval",
               "approval_id" => changed_id,
               "preview" => %{"rows" => [%{"from" => 999}]}
             } = structured(changed)

      refute changed_id == first_id
      assert get_resp_header(changed, "idempotent-replayed") == []
      assert Repo.get!(Confirmation, first_id).status == "expired"

      again = rest_call(conn, gated.token, "flowkit.delete_items", input)
      assert again.status == 200
      assert json(again)["approval_id"] == changed_id
      assert get_resp_header(again, "idempotent-replayed") == ["true"]
      assert ApiFlowStore.items() == Map.put(@all_items, "a", 999)
    end

    test "gets pending_approval over REST, and the same operation is one approval on both",
         %{conn: conn, gated: gated} do
      rest = rest_call(conn, gated.token, "flowkit.delete_items", %{"ids" => ["a"]})

      assert rest.status == 200

      assert %{"executed" => false, "status" => "pending_approval", "approval_id" => id} =
               json(rest)

      assert ApiFlowStore.items() == @all_items

      mcp = conn |> admin_call(gated.token, @delete, %{"ids" => ["a"]}) |> structured()
      assert mcp["approval_id"] == id
    end

    test "can follow the approval with system_get_approval over MCP until the Owner decides", %{
      conn: conn,
      gated: gated
    } do
      %{"approval_id" => id} =
        conn |> admin_call(gated.token, @delete, %{"ids" => ["a"]}) |> structured()

      pending = admin_call(conn, gated.token, "system_get_approval", %{"approval_id" => id})
      assert result(pending)["isError"] == false
      assert %{"status" => "pending"} = structured(pending)

      owner_scope = KeyTestSupport.scope_of(KeyTestSupport.owner_user())
      assert {:ok, %{status: "executed"}} = Approvals.approve(id, owner_scope)
      refute Map.has_key?(ApiFlowStore.items(), "a")

      done = admin_call(conn, gated.token, "system_get_approval", %{"approval_id" => id})
      assert %{"status" => "executed", "result" => %{"deleted" => 1}} = structured(done)
    end

    test "an ordinary key with a code in hand is not asked for approval", %{
      conn: conn,
      plain: plain
    } do
      answer = admin_call(conn, plain.token, @delete, %{"ids" => ["a"]})
      assert structured(answer)["status"] == "confirmation_required"
    end
  end

  # --- (c) dry run -----------------------------------------------------------------

  describe "dry_run over MCP" do
    test "returns the preview, creates no code and no approval, and writes nothing", %{
      conn: conn,
      plain: plain,
      gated: gated
    } do
      for agent <- [plain, gated] do
        answer = admin_call(conn, agent.token, @delete, %{"ids" => ["a"], "dry_run" => true})

        assert result(answer)["isError"] == false

        assert structured(answer) == %{
                 "executed" => false,
                 "dry_run" => true,
                 "preview" => %{
                   "rows" => [%{"ref" => "a", "action" => "delete", "from" => 100}],
                   "totals" => %{"delete" => 1}
                 }
               }
      end

      assert ApiFlowStore.items() == @all_items
    end

    test "on a tool that needs no confirmation it is a preview too, not the write", %{
      conn: conn,
      plain: plain
    } do
      answer =
        admin_call(conn, plain.token, "flowkit_touch_item", %{"name" => "x", "dry_run" => true})

      assert %{"executed" => false, "dry_run" => true, "preview" => _} = structured(answer)
      assert ApiFlowStore.calls() == 0
    end

    test "a read tool has no control fields: the argument is a validation error", %{
      conn: conn,
      plain: plain
    } do
      answer = admin_call(conn, plain.token, "flowkit_read_items", %{"dry_run" => true})

      assert result(answer)["isError"] == true
      assert text(result(answer)) =~ "[validation_failed]"
    end
  end

  # --- (d) what the clients are told -------------------------------------------------

  describe "tools/list and openapi.json" do
    test "tools/list shows the control fields on write tools only, as the validator enforces them",
         %{conn: conn, plain: plain} do
      tools = tools_list(conn, "/mcp/admin", plain.token)

      for name <- ["flowkit_delete_items", "flowkit_touch_item", "flowkit_set_values"] do
        properties = tools[name]["inputSchema"]["properties"]
        assert Enum.all?(@control, &Map.has_key?(properties, &1)), "#{name} lacks a control field"
        assert tools[name]["inputSchema"]["additionalProperties"] == false
      end

      for name <- ["flowkit_read_items", "flowkit_read_many"] do
        properties = tools[name]["inputSchema"]["properties"]
        assert Enum.all?(@control, &(not Map.has_key?(properties, &1)))
      end

      for {name, descriptor} <- tools, String.starts_with?(name, "flowkit_") do
        {:ok, tool} = Registry.find(dotted(name), :admin)
        assert descriptor["inputSchema"] == Map.put(Executor.input_schema(tool), "type", "object")
      end

      key = tools["flowkit_touch_item"]["inputSchema"]["properties"]["idempotency_key"]
      assert %{"type" => "string", "minLength" => 16, "maxLength" => 128} = key
    end

    test "the public tools/list leaves idempotency_key off a tool that cannot replay", %{
      conn: conn
    } do
      tools = tools_list(conn, "/mcp/public", nil)

      properties = tools["flowkit_mint_session"]["inputSchema"]["properties"]
      assert Map.keys(properties) |> Enum.sort() == ["confirm_token", "dry_run"]

      refused = shop_call(conn, "flowkit_mint_session", %{"idempotency_key" => idem()})
      assert result(refused)["isError"] == true
      assert text(result(refused)) =~ "[validation_failed] "
    end

    test "the public tools/list shows them on public write tools", %{conn: conn} do
      tools = tools_list(conn, "/mcp/public", nil)

      properties = tools["flowkit_public_write"]["inputSchema"]["properties"]
      assert Enum.all?(@control, &Map.has_key?(properties, &1))

      assert Enum.all?(
               @control,
               &(not Map.has_key?(tools["testkit_public_echo"]["inputSchema"]["properties"], &1))
             )
    end

    test "the OpenAPI documents show them in the request body of write tools only", %{
      conn: conn,
      plain: plain
    } do
      admin =
        conn
        |> ApiHarness.with_client_ip()
        |> ApiHarness.bearer(plain.token)
        |> get(Routes.path("/api/admin/v1/openapi.json"))
        |> json()

      body = fn document, path ->
        get_in(document, [
          "paths",
          path,
          "post",
          "requestBody",
          "content",
          "application/json",
          "schema"
        ])
      end

      for tool <- ["flowkit.delete_items", "flowkit.touch_item"] do
        assert Enum.all?(@control, &Map.has_key?(body.(admin, "/" <> tool)["properties"], &1))
      end

      assert Enum.all?(
               @control,
               &(not Map.has_key?(body.(admin, "/flowkit.read_items")["properties"], &1))
             )

      {:ok, tool} = Registry.find("flowkit.delete_items", :admin)

      assert body.(admin, "/flowkit.delete_items") ==
               Map.put_new(Executor.input_schema(tool), "type", "object")

      public =
        conn
        |> ApiHarness.with_client_ip()
        |> get(Routes.path("/api/public/v1/openapi.json"))
        |> json()

      assert Enum.all?(
               @control,
               &Map.has_key?(body.(public, "/flowkit.public_write")["properties"], &1)
             )
    end

    test "REST discovery shows the same output schema as MCP, for a write and a read tool", %{
      conn: conn,
      plain: plain
    } do
      mcp = tools_list(conn, "/mcp/admin", plain.token)

      rest =
        conn
        |> ApiHarness.with_client_ip()
        |> ApiHarness.bearer(plain.token)
        |> get(Routes.path("/api/admin/v1"))
        |> json()
        |> Map.fetch!("tools")
        |> Map.new(&{&1["name"], &1})

      assert %{"anyOf" => [_success, _preview]} = rest["flowkit.delete_items"]["output_schema"]

      for name <- ["flowkit.delete_items", "flowkit.touch_item", "flowkit.read_items"] do
        assert rest[name]["output_schema"] == mcp[String.replace(name, ".", "_")]["outputSchema"]
      end
    end

    test "the output schema of a write tool covers every answer the flow gives", %{
      conn: conn,
      plain: plain,
      gated: gated
    } do
      tools = tools_list(conn, "/mcp/admin", plain.token)
      assert %{"anyOf" => [success, preview], "type" => "object"} = tools[@delete]["outputSchema"]
      assert success == %{"type" => "object"}
      assert preview == OutputShape.preview_shape()
      refute Map.has_key?(tools["flowkit_read_items"]["outputSchema"], "anyOf")

      answers = [
        conn
        |> admin_call(plain.token, @delete, %{"ids" => ["a"], "dry_run" => true})
        |> structured(),
        conn |> admin_call(plain.token, @delete, %{"ids" => ["a"]}) |> structured(),
        conn |> admin_call(gated.token, @delete, %{"ids" => ["a"]}) |> structured()
      ]

      assert Enum.map(answers, & &1["status"]) == [
               nil,
               "confirmation_required",
               "pending_approval"
             ]

      for answer <- answers, do: assert_conforms(answer, preview)

      # The shape is not vacuous: an answer it was not written for does not conform.
      assert_raise ExUnit.AssertionError, fn ->
        assert_conforms(Map.put(hd(answers), "invented", 1), preview)
      end
    end
  end

  # The subset of JSON Schema the preview shape uses: required, properties (types and
  # enums). An unknown property is a mismatch only when the shape would forbid it, and it
  # does not, so the test also demands that every property the flow answers is DECLARED.
  defp assert_conforms(answer, shape) do
    for key <- shape["required"], do: assert(Map.has_key?(answer, key), "missing #{key}")

    for {key, value} <- answer do
      spec = shape["properties"][key]
      assert spec, "the shape does not declare #{inspect(key)}"
      assert type_ok?(spec["type"], value), "#{key} is not a #{spec["type"]}"

      if spec["enum"],
        do: assert(value in spec["enum"], "#{key} is not one of #{inspect(spec["enum"])}")
    end
  end

  defp type_ok?("object", value), do: is_map(value)
  defp type_ok?("string", value), do: is_binary(value)
  defp type_ok?("integer", value), do: is_integer(value)
  defp type_ok?("boolean", value), do: is_boolean(value)

  # --- (e) the limiter and idempotency --------------------------------------------------

  describe "the public rate limit comes before the registry walk" do
    setup do
      wait_for_window_room()
      :ok = ModuleRegistry.register(CountingTools)
      :persistent_term.put({CountingTools, :observer}, self())

      on_exit(fn ->
        ModuleRegistry.unregister(CountingTools)
        :persistent_term.erase({CountingTools, :observer})
      end)

      :ok
    end

    test "an over-limit call that carries the control fields walks the registry zero times", %{
      conn: conn
    } do
      put_setting("api_public_ip_rate_per_min", 1)
      ip = KeyTestSupport.unique_ip()

      first =
        mcp_call(conn, "/mcp/public", nil, "counting_public_write", %{"dry_run" => true}, ip: ip)

      assert first.status == 200
      assert %{"dry_run" => true} = structured(first)
      assert_received :walked
      flush_walks()

      for arguments <- [
            %{"dry_run" => true},
            %{"confirm_token" => "some-code"},
            %{"idempotency_key" => "0123456789abcdef"},
            %{}
          ],
          name <- ["counting_public_write", "counting.public_write", "no_such_tool"] do
        refused = mcp_call(conn, "/mcp/public", nil, name, arguments, ip: ip)
        assert refused.status == 429
        assert %{"code" => "rate_limited"} = json(refused)
      end

      refute_received :walked
    end

    test "an unknown tool within the limit is a -32602 error, control fields or not", %{
      conn: conn
    } do
      ip = KeyTestSupport.unique_ip()
      answer = mcp_call(conn, "/mcp/public", nil, "no_such_tool", %{"dry_run" => true}, ip: ip)

      assert answer.status == 200
      refute Map.has_key?(json(answer), "result")

      assert %{"code" => -32_602, "message" => "Unknown tool: no_such_tool"} =
               json(answer)["error"]
    end
  end

  describe "idempotency_key as an MCP argument" do
    setup do
      wait_for_window_room()
      :ok
    end

    test "replays the first answer and does not run the tool again", %{conn: conn, plain: plain} do
      key = "mcp-idem-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")
      arguments = %{"name" => "x", "idempotency_key" => key}

      first = admin_call(conn, plain.token, "flowkit_touch_item", arguments)
      assert result(first)["isError"] == false
      assert get_resp_header(first, "idempotent-replayed") == []
      assert %{"touched" => "x", "call" => call} = structured(first)

      second = admin_call(conn, plain.token, "flowkit_touch_item", arguments)
      assert result(second)["isError"] == false
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert structured(second) == %{"touched" => "x", "call" => call}
      assert ApiFlowStore.calls() == 1
    end

    test "the same key with other arguments is refused as an error result", %{
      conn: conn,
      plain: plain
    } do
      key = "mcp-idem-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")

      assert admin_call(conn, plain.token, "flowkit_touch_item", %{
               "name" => "x",
               "idempotency_key" => key
             }).status == 200

      other =
        admin_call(conn, plain.token, "flowkit_touch_item", %{
          "name" => "y",
          "idempotency_key" => key
        })

      assert result(other)["isError"] == true
      assert text(result(other)) =~ "[idempotency_key_reused]"
      assert ApiFlowStore.calls() == 1
    end

    test "a key that is too short is a validation error before anything runs", %{
      conn: conn,
      plain: plain
    } do
      answer =
        admin_call(conn, plain.token, "flowkit_touch_item", %{
          "name" => "x",
          "idempotency_key" => "short"
        })

      assert result(answer)["isError"] == true
      assert text(result(answer)) =~ "[validation_failed]"
      assert ApiFlowStore.calls() == 0
    end

    test "a key used first over REST replays over MCP", %{conn: conn, plain: plain} do
      key = "rest-idem-" <> String.pad_leading("#{System.unique_integer([:positive])}", 12, "0")

      rest =
        rest_call(conn, plain.token, "flowkit.touch_item", %{"name" => "x"}, [
          {"idempotency-key", key}
        ])

      assert rest.status == 200
      %{"call" => call} = json(rest)

      replay =
        admin_call(conn, plain.token, "flowkit_touch_item", %{
          "name" => "x",
          "idempotency_key" => key
        })

      assert get_resp_header(replay, "idempotent-replayed") == ["true"]
      assert structured(replay) == %{"touched" => "x", "call" => call}
      assert ApiFlowStore.calls() == 1
    end
  end

  # --- (f) the idempotency header is REST's, the argument is MCP's ---------------------------

  describe "the Idempotency-Key header" do
    setup do
      wait_for_window_room()
      :ok
    end

    test "is ignored over MCP: the same header on two calls does not replay", %{
      conn: conn,
      plain: plain
    } do
      key = idem()

      call = fn ->
        conn
        |> put_req_header("idempotency-key", key)
        |> admin_call(plain.token, "flowkit_touch_item", %{"name" => "h"})
      end

      first = call.()
      second = call.()

      assert result(first)["isError"] == false
      assert result(second)["isError"] == false
      assert get_resp_header(second, "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 2
      assert claims(key) == 0
    end

    test "is not validated over MCP either: a malformed one or one that differs from the argument is not an error",
         %{conn: conn, plain: plain} do
      malformed =
        conn
        |> put_req_header("idempotency-key", "short")
        |> admin_call(plain.token, "flowkit_touch_item", %{"name" => "a"})

      assert result(malformed)["isError"] == false

      header_key = idem()
      argument_key = idem()

      differing =
        conn
        |> put_req_header("idempotency-key", header_key)
        |> admin_call(plain.token, "flowkit_touch_item", %{
          "name" => "b",
          "idempotency_key" => argument_key
        })

      assert result(differing)["isError"] == false
      assert claims(header_key) == 0
      assert claims(argument_key) == 1
    end

    test "is honoured over REST: two calls replay, and a header that differs from the field is a 422",
         %{conn: conn, plain: plain} do
      headers = [{"idempotency-key", idem()}]

      first = rest_call(conn, plain.token, "flowkit.touch_item", %{"name" => "h"}, headers)
      second = rest_call(conn, plain.token, "flowkit.touch_item", %{"name" => "h"}, headers)

      assert get_resp_header(first, "idempotent-replayed") == []
      assert get_resp_header(second, "idempotent-replayed") == ["true"]
      assert json(second) == json(first)
      assert ApiFlowStore.calls() == 1

      differing =
        rest_call(
          conn,
          plain.token,
          "flowkit.touch_item",
          %{"name" => "h", "idempotency_key" => idem()},
          headers
        )

      assert differing.status == 422
    end
  end

  # --- (g) the audit trail ------------------------------------------------------------------

  describe "the audit trail of write calls over MCP" do
    test "has one entry per call with the outcome of that call, and none for a replay or a read",
         %{conn: conn, plain: plain, gated: gated} do
      admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "dry_run" => true})
      prompt = admin_call(conn, plain.token, @delete, %{"ids" => ["a"]})
      code = structured(prompt)["confirm_token"]
      admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})
      admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "confirm_token" => code})

      admin_call(conn, plain.token, "flowkit_touch_item", %{
        "name" => "x",
        "idempotency_key" => "short"
      })

      admin_call(conn, gated.token, @delete, %{"ids" => ["b"]})

      key = idem()

      admin_call(conn, plain.token, "flowkit_touch_item", %{
        "name" => "r",
        "idempotency_key" => key
      })

      admin_call(conn, plain.token, "flowkit_touch_item", %{
        "name" => "r",
        "idempotency_key" => key
      })

      admin_call(conn, plain.token, "flowkit_read_items", %{})

      assert audits(plain.key.uuid) == [
               {"flowkit.delete_items", "preview", nil},
               {"flowkit.delete_items", "confirmation_required", nil},
               {"flowkit.delete_items", "ok", nil},
               {"flowkit.delete_items", "error", "confirm_token_invalid"},
               {"flowkit.touch_item", "error", "validation_failed"},
               {"flowkit.touch_item", "ok", nil}
             ]

      assert audits(gated.key.uuid) == [{"flowkit.delete_items", "pending_approval", nil}]
    end

    test "has no second entry when the same operation runs over REST after its prompt over MCP",
         %{conn: conn, plain: plain} do
      code = conn |> admin_call(plain.token, @delete, %{"ids" => ["c"]}) |> structured()

      rest_call(conn, plain.token, "flowkit.delete_items", %{
        "ids" => ["c"],
        "confirm_token" => code["confirm_token"]
      })

      assert audits(plain.key.uuid) == [
               {"flowkit.delete_items", "confirmation_required", nil},
               {"flowkit.delete_items", "ok", nil}
             ]
    end
  end

  # --- (h) the idempotency claim ------------------------------------------------------------

  describe "the idempotency claim of an MCP call" do
    setup do
      wait_for_window_room()
      :ok
    end

    test "is given up after a write that fails and after one that raises, so a retry runs again",
         %{conn: conn, plain: plain} do
      log =
        capture_log(fn ->
          for mode <- ["fail", "raise"] do
            key = idem()
            arguments = %{"mode" => mode, "idempotency_key" => key}

            first = admin_call(conn, plain.token, "flowkit_misbehave", arguments)
            retry = admin_call(conn, plain.token, "flowkit_misbehave", arguments)

            assert result(first)["isError"] == true
            assert text(result(retry)) == text(result(first))
            refute text(result(retry)) =~ "idempotency_in_progress"
            assert claims(key) == 0
          end
        end)

      assert log =~ "tool flowkit.misbehave failed"
    end

    test "is not kept by a prompt, a pending approval, a dry run, a validation error or a refusal",
         %{conn: conn, plain: plain, gated: gated} do
      prompt_key = idem()

      prompt =
        admin_call(conn, plain.token, @delete, %{"ids" => ["a"], "idempotency_key" => prompt_key})

      assert structured(prompt)["status"] == "confirmation_required"
      assert claims(prompt_key) == 0

      pending_key = idem()
      arguments = %{"ids" => ["a"], "idempotency_key" => pending_key}
      pending = admin_call(conn, gated.token, @delete, arguments)
      again = admin_call(conn, gated.token, @delete, arguments)
      assert structured(again)["approval_id"] == structured(pending)["approval_id"]
      assert get_resp_header(pending, "idempotent-replayed") == []
      assert get_resp_header(again, "idempotent-replayed") == ["true"]
      assert claims(pending_key) == 0

      dry_key = idem()

      dry =
        admin_call(conn, plain.token, "flowkit_touch_item", %{
          "name" => "q",
          "dry_run" => true,
          "idempotency_key" => dry_key
        })

      assert structured(dry)["dry_run"] == true
      assert claims(dry_key) == 0

      refused_key = idem()

      invalid =
        admin_call(conn, plain.token, "flowkit_touch_item", %{
          "nope" => 1,
          "idempotency_key" => refused_key
        })

      assert result(invalid)["isError"] == true

      {owner, _role} = ApiHarness.user_with(["dashboard"])

      {_key, read_only} =
        ApiHarness.issue_key(owner, ["flowkit.items:read"], %{
          name: "read only",
          requires_approval: false
        })

      forbidden =
        admin_call(conn, read_only, "flowkit_touch_item", %{
          "name" => "z",
          "idempotency_key" => refused_key
        })

      assert text(result(forbidden)) =~ "[forbidden]"
      assert claims(refused_key) == 0
    end
  end

  # --- (i) codes -------------------------------------------------------------------------------

  describe "confirmation codes over MCP" do
    test "a dry run with a code in hand does not spend it", %{conn: conn, plain: plain} do
      code = conn |> admin_call(plain.token, @delete, %{"ids" => ["a"]}) |> structured()

      dry =
        admin_call(conn, plain.token, @delete, %{
          "ids" => ["a"],
          "dry_run" => true,
          "confirm_token" => code["confirm_token"]
        })

      assert structured(dry)["dry_run"] == true
      assert spent_codes() == 0
    end

    test "a call that is no longer dangerous runs and leaves the code unspent", %{
      conn: conn,
      plain: plain
    } do
      ApiFlowStore.put("v", 100)
      big = %{"changes" => [%{"id" => "v", "value" => 200}]}

      prompt = admin_call(conn, plain.token, "flowkit_set_values", big)
      code = structured(prompt)["confirm_token"]

      ApiFlowStore.put("v", 190)

      done =
        admin_call(conn, plain.token, "flowkit_set_values", Map.put(big, "confirm_token", code))

      assert structured(done)["updated"] == 1
      assert spent_codes() == 0
    end
  end

  # --- (j) the public endpoint ---------------------------------------------------------------

  describe "a dangerous public tool over MCP" do
    test "needs a client token to ask for a code, and the code is bound to that client token", %{
      conn: conn
    } do
      without = shop_call(conn, "flowkit_clear_session", %{"confirm_token" => "x.y"})
      assert text(result(without)) =~ "[validation_failed]"

      asked = shop_call(conn, "flowkit_clear_session", %{"session_token" => "session-aaaa"})
      assert %{"status" => "confirmation_required", "confirm_token" => code} = structured(asked)

      other_session =
        shop_call(conn, "flowkit_clear_session", %{
          "session_token" => "session-bbbb",
          "confirm_token" => code
        })

      assert text(result(other_session)) =~ "[confirm_token_invalid]"

      done =
        shop_call(conn, "flowkit_clear_session", %{
          "session_token" => "session-aaaa",
          "confirm_token" => code
        })

      assert structured(done) == %{"cleared" => true}
      assert Repo.aggregate(from(c in Confirmation, where: c.kind == "approval"), :count) == 0
    end

    test "cannot reach an admin tool, under either name", %{conn: conn} do
      for name <- [
            "flowkit_delete_items",
            "flowkit.delete_items",
            "system_get_approval",
            "system_get_identity"
          ] do
        answer = shop_call(conn, name, %{"ids" => ["a"]})
        assert %{"code" => -32_602} = json(answer)["error"], name
      end
    end

    test "ignores an idempotency key without a client token and keeps one answer per client token with it",
         %{conn: conn} do
      key = idem()
      shop_call(conn, "flowkit_public_write", %{"text" => "x", "idempotency_key" => key})
      shop_call(conn, "flowkit_public_write", %{"text" => "x", "idempotency_key" => key})
      assert ApiFlowStore.calls() == 2

      key = idem()

      call = fn session ->
        shop_call(conn, "flowkit_public_write", %{
          "text" => "x",
          "session_token" => session,
          "idempotency_key" => key
        })
      end

      assert get_resp_header(call.("c1"), "idempotent-replayed") == []
      assert get_resp_header(call.("c1"), "idempotent-replayed") == ["true"]
      assert get_resp_header(call.("c2"), "idempotent-replayed") == []
      assert ApiFlowStore.calls() == 4
    end
  end

  describe "a dangerous public tool whose schema does not require session_token" do
    setup do
      :ok = ModuleRegistry.register(SessionTools)
      on_exit(fn -> ModuleRegistry.unregister(SessionTools) end)
      :ok
    end

    test "answers a dry run without a client token and refuses the real call", %{conn: conn} do
      dry = shop_call(conn, "sessiontools_drop_session", %{"dry_run" => true})
      assert %{"executed" => false, "dry_run" => true} = structured(dry)

      real = shop_call(conn, "sessiontools_drop_session", %{})
      assert result(real)["isError"] == true
      assert text(result(real)) =~ "[validation_failed]"
    end

    test "refuses both when the schema requires it", %{conn: conn} do
      for arguments <- [%{"dry_run" => true}, %{}] do
        answer = shop_call(conn, "sessiontools_drop_session_required", arguments)
        assert result(answer)["isError"] == true
        assert text(result(answer)) =~ "[validation_failed]"
      end
    end
  end

  defp flush_walks do
    receive do
      :walked -> flush_walks()
    after
      0 -> :ok
    end
  end
end
