defmodule PhoenixKit.API.ExecutorSeamTest do
  @moduledoc """
  `PhoenixKit.API.Executor.execute/4`, `visible/2` and `input_schema/1`: the
  transport-neutral half of the executor that MCP and OpenAPI use. Plug level,
  real keys, real database, the fake module `PhoenixKit.Test.ApiTools`.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.ControlFields
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Registry
  alias PhoenixKit.Test.ApiTools

  @read "testkit.items:read"
  @write "testkit.items:write"

  setup do
    setup_api()
    {owner, _role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{owner: owner, key: key, token: token}
  end

  defp authed(token, opts \\ []) do
    :post
    |> api_conn("/", Keyword.put(opts, :token, token))
    |> Auth.call(Auth.init(audience: :admin))
  end

  defp header?(headers, wanted),
    do: Enum.any?(headers, fn {name, _value} -> String.downcase(name) == wanted end)

  defp audit_entries(key) do
    Repo.all(
      from(e in Entry,
        where: e.action == "api.request" and e.resource_uuid == ^key.uuid,
        order_by: e.inserted_at
      )
    )
  end

  describe "execute/4: success" do
    test "returns the result map, its JSON and the rate-limit headers", %{token: token} do
      assert {:ok, %{result: result, json: json}, headers} =
               Executor.execute(authed(token), :admin, "testkit.read_items", %{"limit" => 3})

      assert result["limit"] == 3
      assert is_binary(json)
      assert JSON.decode!(json) == result
      assert header?(headers, "ratelimit-limit")
      assert header?(headers, "ratelimit-remaining")
      assert_received {:read_items, %{"limit" => 3}, _ctx}
    end

    test "call/4 sends byte for byte the JSON that execute/4 returns", %{token: token} do
      conn = authed(token)
      {:ok, %{json: json}, _headers} = Executor.execute(conn, :admin, "testkit.read_items", %{})

      sent = Executor.call(conn, :admin, "testkit.read_items", %{})

      assert sent.status == 200
      assert sent.resp_body == json
    end

    test "effects of a handler are part of the result and of the JSON", %{token: token} do
      assert {:ok, %{result: result, json: json}, _} =
               Executor.execute(authed(token), :admin, "testkit.write_item", %{"name" => "x"})

      assert result["written"] == "x"
      assert result["effects"] == [%{"code" => "item_indexed"}]
      assert JSON.decode!(json)["effects"] == [%{"code" => "item_indexed"}]
    end

    test "a public tool runs for an anonymous actor" do
      conn = :post |> api_conn("/") |> Auth.call(Auth.init(audience: :public))

      assert {:ok, %{result: %{"echo" => "hi", "client_token_hash" => nil}}, headers} =
               Executor.execute(conn, :public, "testkit.public_echo", %{"text" => "hi"})

      assert header?(headers, "ratelimit-limit")
    end
  end

  describe "execute/4: errors" do
    test "an unknown tool", %{token: token} do
      assert {:error, :not_found, detail, %{tool: "testkit.nope"}, headers} =
               Executor.execute(authed(token), :admin, "testkit.nope", %{})

      assert is_binary(detail)
      assert is_list(headers)
    end

    test "a missing scope", %{owner: owner} do
      {_key, read_only} = issue_key(owner, [@read])

      assert {:error, :forbidden, _, %{required_scope: @write}, _} =
               Executor.execute(authed(read_only), :admin, "testkit.write_item", %{})

      refute_received {:write_item, _}
    end

    test "a disabled module", %{token: token} do
      ApiTools.set_enabled(false)

      assert {:error, :module_disabled, _, %{tool: "testkit.read_items"}, _} =
               Executor.execute(authed(token), :admin, "testkit.read_items", %{})
    end

    test "invalid input", %{token: token} do
      assert {:error, :validation_failed, _, %{errors: [_ | _] = errors}, _} =
               Executor.execute(authed(token), :admin, "testkit.write_item", %{
                 "unknown_field" => 5
               })

      assert inspect(errors) =~ "unknown_field"
      refute_received {:write_item, _}
    end

    test "an error the handler returns", %{token: token} do
      assert {:error, :insufficient_stock, "Three lines are short.", %{lines: [%{product: "a"}]},
              _} =
               Executor.execute(authed(token), :admin, "testkit.fail_write", %{})
    end

    test "a handler that raises is a generic internal_error and only its class stays in the log",
         %{
           token: token
         } do
      log =
        capture_log(fn ->
          send(
            self(),
            {:outcome, Executor.execute(authed(token), :admin, "testkit.crash_write", %{})}
          )
        end)

      assert_received {:outcome,
                       {:error, :internal_error, "The tool failed unexpectedly.", %{}, _}}

      assert log =~ "RuntimeError"
      refute log =~ "secret-detail"
    end

    test "a rate limit carries retry_after and the headers", %{token: token} do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 1)

      assert {:ok, _, _} = Executor.execute(authed(token), :admin, "testkit.read_items", %{})

      assert {:error, :rate_limited, _, %{retry_after: retry_after}, headers} =
               Executor.execute(authed(token), :admin, "testkit.read_items", %{})

      assert is_integer(retry_after) and retry_after > 0
      assert header?(headers, "ratelimit-limit")
    end

    test "no actor at all is unauthorized" do
      assert {:error, :unauthorized, _, %{}, []} =
               Executor.execute(api_conn(:post, "/"), :admin, "testkit.read_items", %{})
    end
  end

  describe "execute/4: the audit entry" do
    test "one entry per write call, written by execute/4 itself", %{token: token, key: key} do
      {:ok, _, _} =
        Executor.execute(authed(token), :admin, "testkit.write_item", %{"name" => "x"})

      assert [%{metadata: %{"tool" => "testkit.write_item", "outcome" => "ok"}}] =
               audit_entries(key)
    end

    test "a failed write is logged with its code", %{token: token, key: key} do
      {:error, :insufficient_stock, _, _, _} =
        Executor.execute(authed(token), :admin, "testkit.fail_write", %{})

      assert [%{metadata: %{"outcome" => "error", "code" => "insufficient_stock"}}] =
               audit_entries(key)
    end

    test "a read writes nothing", %{token: token, key: key} do
      {:ok, _, _} = Executor.execute(authed(token), :admin, "testkit.read_items", %{})
      assert audit_entries(key) == []
    end

    test "call/4 still writes exactly one entry, not two", %{token: token, key: key} do
      Executor.call(authed(token), :admin, "testkit.write_item", %{})
      assert [_one] = audit_entries(key)
    end
  end

  describe "visible/2" do
    test "the tools the key's scopes unlock, system tools included", %{owner: owner} do
      {_key, token} = issue_key(owner, [@read])

      assert {:ok, tools, headers} = Executor.visible(authed(token), :admin)
      names = Enum.map(tools, & &1.name)

      assert "testkit.read_items" in names
      assert "system.get_identity" in names
      refute "testkit.write_item" in names
      refute "testkit.public_echo" in names
      assert header?(headers, "ratelimit-limit")
    end

    test "the public audience sees its tools" do
      conn = :get |> api_conn("/") |> Auth.call(Auth.init(audience: :public))
      assert {:ok, [tool], _} = Executor.visible(conn, :public)
      assert tool.name == "testkit.public_echo"
    end

    test "a module switched off drops out", %{token: token} do
      ApiTools.set_enabled(false)
      assert {:ok, tools, _} = Executor.visible(authed(token), :admin)
      refute Enum.any?(tools, &String.starts_with?(&1.name, "testkit."))
    end

    test "a rate limit is an error tuple", %{token: token} do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 1)
      assert {:ok, _, _} = Executor.visible(authed(token), :admin)

      assert {:error, :rate_limited, _, %{retry_after: _}, _} =
               Executor.visible(authed(token), :admin)
    end

    test "no actor is unauthorized" do
      assert {:error, :unauthorized, _, _, _} = Executor.visible(api_conn(:get, "/"), :admin)
    end
  end

  describe "list/2: REST discovery shows the schema the validator enforces" do
    test "a tool whose own schema is open is listed closed, exactly as input_schema/1 builds it",
         %{token: token} do
      %{"tools" => tools} = token |> authed() |> Executor.list(:admin) |> json()
      listed = Enum.find(tools, &(&1["name"] == "testkit.open_schema_write"))

      {:ok, tool} = Registry.find("testkit.open_schema_write", :admin)
      refute Map.has_key?(tool.input_schema, "additionalProperties")

      assert listed["input_schema"] == Executor.input_schema(tool)
      assert listed["input_schema"]["additionalProperties"] == false
    end
  end

  describe "input_schema/1" do
    test "closes a schema whose author forgot additionalProperties", %{} do
      {:ok, tool} = Registry.find("testkit.open_schema_write", :admin)
      refute Map.has_key?(tool.input_schema, "additionalProperties")

      schema = Executor.input_schema(tool)
      assert schema["additionalProperties"] == false

      # A write tool also lists the control fields the executor adds.
      assert Map.drop(schema["properties"], ControlFields.names()) == %{
               "name" => %{"type" => "string"}
             }

      assert Enum.all?(ControlFields.names(), &Map.has_key?(schema["properties"], &1))
    end

    test "keeps a schema that is already closed, with string keys" do
      {:ok, tool} = Registry.find("testkit.read_items", :admin)
      schema = Executor.input_schema(tool)

      assert schema["type"] == "object"
      assert schema["additionalProperties"] == false
      assert Map.keys(schema["properties"]) |> Enum.sort() == ["fields", "limit"]
    end

    test "is what the validator enforces: the executor refuses what the schema does not list", %{
      token: token
    } do
      {:ok, tool} = Registry.find("testkit.open_schema_write", :admin)
      refute Map.has_key?(Executor.input_schema(tool)["properties"], "unlisted")

      assert {:error, :validation_failed, _, _, _} =
               Executor.execute(authed(token), :admin, "testkit.open_schema_write", %{
                 "unlisted" => true
               })
    end

    test "a read tool lists no control field and refuses one", %{token: token} do
      {:ok, tool} = Registry.find("testkit.read_items", :admin)

      assert Enum.all?(
               ControlFields.names(),
               &(not Map.has_key?(Executor.input_schema(tool)["properties"], &1))
             )

      assert {:error, :validation_failed, _, _, _} =
               Executor.execute(authed(token), :admin, "testkit.read_items", %{"dry_run" => true})
    end
  end
end
