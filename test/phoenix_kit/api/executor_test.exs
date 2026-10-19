defmodule PhoenixKit.API.ExecutorTest do
  @moduledoc """
  `PhoenixKit.API.Executor`: tool visibility, rights, rate limits,
  validation, the handler contract, the `api.request` audit entry and
  discovery. Plug level, real keys, real database, the fake module
  `PhoenixKit.Test.ApiTools`.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness
  import Plug.Conn

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Registry
  alias PhoenixKit.API.RequestContext
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Test.ApiShapeTools
  alias PhoenixKit.Test.ApiTools
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RateLimiter.Backend

  @read "testkit.items:read"
  @write "testkit.items:write"

  defmodule ShopHook do
    @moduledoc false
    def resolve(_conn), do: %{language: "de", currency: "EUR", hosts: ["shop.example"]}
  end

  setup do
    setup_api()

    # The handlers that break the contract, and the public write, are not part
    # of the shared `ApiTools` fixture.
    :ok = ModuleRegistry.register(ApiShapeTools)
    on_exit(fn -> ModuleRegistry.unregister(ApiShapeTools) end)

    {owner, role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{owner: owner, role: role, key: key, token: token}
  end

  # An authenticated admin request, as the REST plug hands it to the executor.
  defp authed(token, opts \\ []) do
    :post
    |> api_conn("/", Keyword.put(opts, :token, token))
    |> Auth.call(Auth.init(audience: :admin))
  end

  defp call(token, tool, input, opts \\ []),
    do: Executor.call(authed(token, opts), :admin, tool, input)

  defp remaining(conn),
    do: conn |> get_resp_header("ratelimit-remaining") |> hd() |> String.to_integer()

  defp tool!(name, audience), do: elem(Registry.find(name, audience), 1)
  defp lines(count), do: List.duplicate(%{}, count)

  # An anonymous request on the public audience, as the REST plug hands it
  # to the executor.
  defp public_call(tool, input, opts \\ []) do
    conn =
      :post
      |> api_conn("/", opts)
      |> Auth.call(Auth.init(audience: :public))

    Executor.call(conn, :public, tool, input)
  end

  defp audit_entries(key) do
    Repo.all(
      from(e in Entry,
        where: e.action == "api.request" and e.resource_uuid == ^key.uuid,
        order_by: e.inserted_at
      )
    )
  end

  describe "a read call" do
    test "runs the handler and answers 200 JSON", %{token: token, owner: owner} do
      conn = call(token, "testkit.read_items", %{"limit" => 7})

      assert conn.status == 200
      assert ["application/json" <> _] = get_resp_header(conn, "content-type")
      assert ["no-store"] = get_resp_header(conn, "cache-control")
      assert %{"limit" => 7, "dry_run" => false} = json(conn)

      assert_received {:read_items, %{"limit" => 7}, ctx}
      assert ctx.actor.user_uuid == owner.uuid
      assert ctx.scopes |> Enum.sort() == [@read, @write]
      assert ctx.audience == :admin
      assert ctx.language == PhoenixKit.Utils.Multilang.primary_language()
      assert ctx.currency == nil
      assert ctx.base_url == "http://www.example.com"
      assert [_ | _] = ctx.hosts
      assert ctx.hosts == RequestContext.resolve(conn).hosts
      assert ctx.request_id == conn.assigns.phoenix_kit_api_request_id
    end

    test "the handler gets the language, currency and hosts the host app's hook names",
         %{token: token} do
      Application.put_env(:phoenix_kit, :api_request_context, {ShopHook, :resolve})
      on_exit(fn -> Application.delete_env(:phoenix_kit, :api_request_context) end)

      assert 200 == call(token, "testkit.read_items", %{}).status

      assert_received {:read_items, _input, ctx}
      assert ctx.hosts == ["shop.example"]
      assert ctx.language == "de"
      assert ctx.currency == "EUR"
    end

    test "carries the rate-limit headers", %{token: token} do
      conn = call(token, "testkit.read_items", %{})

      assert [_] = get_resp_header(conn, "ratelimit-limit")
      assert [_] = get_resp_header(conn, "ratelimit-remaining")
      assert [_] = get_resp_header(conn, "ratelimit-reset")
    end

    test "writes no audit entry", %{token: token, key: key} do
      call(token, "testkit.read_items", %{})
      assert audit_entries(key) == []
    end
  end

  describe "tool visibility" do
    test "an unknown tool is 404 not_found", %{token: token} do
      conn = call(token, "testkit.no_such_tool", %{})
      assert conn.status == 404

      assert %{"code" => "not_found", "context" => %{"tool" => "testkit.no_such_tool"}} =
               json(conn)
    end

    test "a very long tool name is clipped in the answer", %{token: token} do
      conn = call(token, String.duplicate("a", 5_000), %{})
      assert conn.status == 404
      assert String.length(json(conn)["context"]["tool"]) <= 100
    end

    test "a tool name made of one grapheme with many combining marks is clipped too",
         %{token: token} do
      name = "e" <> String.duplicate("\u0301", 5_000)
      conn = call(token, name, %{})

      assert conn.status == 404
      assert length(String.codepoints(json(conn)["context"]["tool"])) == 100
    end

    test "a 2 MB tool name is clipped with work bounded by the clip, not by the name",
         %{token: token} do
      conn = authed(token)
      name = String.duplicate("a", 2_000_000)

      {:reductions, before} = Process.info(self(), :reductions)
      conn = Executor.call(conn, :admin, name, %{})
      {:reductions, after_call} = Process.info(self(), :reductions)

      assert conn.status == 404
      assert %{"code" => "not_found", "context" => %{"tool" => clipped}} = json(conn)
      assert clipped == String.duplicate("a", 100)

      # Clipping by walking the whole name costs millions of reductions
      # (about 4.6 million for 2 MB); clipping by the output, a few thousand.
      assert after_call - before < 200_000
    end

    test "a tool name that is not valid UTF-8 is still a 404", %{token: token} do
      name = "testkit." <> <<0xFF, 0xFE>> <> String.duplicate("b", 500)

      conn = call(token, name, %{})

      assert conn.status == 404
      assert %{"code" => "not_found", "detail" => "Unknown tool " <> _} = json(conn)
    end

    test "a tool of the other audience does not exist here", %{token: token} do
      assert 404 == call(token, "testkit.public_echo", %{}).status
    end

    test "a disabled module answers 404 module_disabled", %{token: token} do
      ApiTools.set_enabled(false)
      conn = call(token, "testkit.read_items", %{})
      assert conn.status == 404
      assert json(conn)["code"] == "module_disabled"
      refute_received {:read_items, _, _}
    end

    test "a tool in api_disabled_tools is 404 not_found", %{token: token} do
      put_setting("api_disabled_tools", "testkit.read_items\ntestkit.other_tool")
      conn = call(token, "testkit.read_items", %{})
      assert conn.status == 404
      assert json(conn)["code"] == "not_found"
      refute_received {:read_items, _, _}

      # Other tools of the module are untouched.
      assert 200 == call(token, "testkit.write_item", %{}).status
    end

    test "a module whose API is switched off answers 404 not_found, like a hidden tool; back on it works",
         %{token: token} do
      put_setting("api_disabled_modules", "api_test_tools")

      for name <- ["testkit.read_items", "testkit.write_item"] do
        conn = call(token, name, %{})
        assert conn.status == 404, name
        assert json(conn)["code"] == "not_found", name
      end

      refute_received {:read_items, _, _}

      # Core's own tools belong to no module, so no module switch reaches them.
      assert 200 == call(token, "system.get_identity", %{}).status

      put_setting("api_disabled_modules", "")
      assert 200 == call(token, "testkit.read_items", %{}).status
    end

    test "a module that is both disabled and API-off answers not_found, not module_disabled",
         %{token: token} do
      ApiTools.set_enabled(false)
      assert json(call(token, "testkit.read_items", %{}))["code"] == "module_disabled"

      put_setting("api_disabled_modules", "api_test_tools")
      assert json(call(token, "testkit.read_items", %{}))["code"] == "not_found"
    end

    test "a key without the scope is 403 forbidden and the handler does not run", %{owner: owner} do
      {_key, token} = issue_key(owner, [@read])

      conn = call(token, "testkit.write_item", %{"name" => "x"})

      assert conn.status == 403
      assert %{"code" => "forbidden", "context" => %{"required_scope" => @write}} = json(conn)
      assert [~s(Bearer error="insufficient_scope")] = get_resp_header(conn, "www-authenticate")
      refute_received {:write_item, _}
    end

    test "a permission the owner lost fails the very next call",
         %{token: token, role: role, key: key} do
      assert 200 == call(token, "testkit.write_item", %{}).status
      assert_received {:write_item, _}

      # The key row is cached by now (proved, not assumed); the owner's rights
      # are not.
      assert_row_cached(key.prefix)
      assert :ok = Permissions.revoke_permission(role.uuid, "settings")
      assert_row_cached(key.prefix)

      conn = call(token, "testkit.write_item", %{})
      assert conn.status == 403
      assert json(conn)["context"]["required_scope"] == @write
      refute_received {:write_item, _}

      # What the owner still holds still works.
      assert 200 == call(token, "testkit.read_items", %{}).status
    end

    test "without an actor the admin audience is 401" do
      conn = Executor.call(api_conn(:post, "/"), :admin, "testkit.read_items", %{})
      assert conn.status == 401
    end

    test "an anonymous actor (what the public Auth assigns) is 401 on the admin audience" do
      conn = :post |> api_conn("/") |> Auth.call(Auth.init(audience: :public))
      assert %PhoenixKit.API.Actor{kind: :anonymous} = conn.assigns.phoenix_kit_api_actor

      for tool <- ["system.get_identity", "testkit.read_items"] do
        assert 401 == Executor.call(conn, :admin, tool, %{}).status, tool
      end
    end

    test "a tool name that is not a string is 404 not_found", %{token: token} do
      for name <- [nil, 123, ["testkit.read_items"], %{}] do
        conn = call(token, name, %{})
        assert conn.status == 404, inspect(name)
        assert json(conn)["code"] == "not_found"
      end
    end
  end

  describe "rate limiting" do
    test "past the limit: 429 with Retry-After and the limit headers; nothing runs, nothing is logged",
         %{token: token, key: key} do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 2)

      assert 200 == call(token, "testkit.write_item", %{}).status
      assert 200 == call(token, "testkit.write_item", %{}).status
      assert_received {:write_item, _}
      assert_received {:write_item, _}

      conn = call(token, "testkit.write_item", %{})

      assert conn.status == 429
      assert json(conn)["code"] == "rate_limited"
      assert [retry_after] = get_resp_header(conn, "retry-after")
      assert String.to_integer(retry_after) > 0
      assert ["2"] = get_resp_header(conn, "ratelimit-limit")
      assert ["0"] = get_resp_header(conn, "ratelimit-remaining")
      refute_received {:write_item, _}

      # Two accepted write calls, two entries; the refused one added none.
      assert length(audit_entries(key)) == 2
    end

    test "a call the lookup or the scope check refuses still costs one unit: unknown, forbidden and disabled-module names are throttled",
         %{owner: owner, key: key} do
      {_key, read_only} = issue_key(owner, [@read])
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 3)

      unknown = call(read_only, "testkit.nope", %{})
      assert unknown.status == 404
      assert json(unknown)["code"] == "not_found"
      assert ["2"] = get_resp_header(unknown, "ratelimit-remaining")

      forbidden = call(read_only, "testkit.write_item", %{})
      assert forbidden.status == 403
      assert json(forbidden)["code"] == "forbidden"

      ApiTools.set_enabled(false)
      disabled = call(read_only, "testkit.read_items", %{})
      assert disabled.status == 404
      assert json(disabled)["code"] == "module_disabled"
      assert ["0"] = get_resp_header(disabled, "ratelimit-remaining")

      refused = call(read_only, "testkit.nope", %{})
      assert refused.status == 429
      assert json(refused)["code"] == "rate_limited"
      assert [_] = get_resp_header(refused, "retry-after")

      # The refusals themselves wrote nothing.
      assert audit_entries(key) == []
    end

    test "a call the limiter itself refuses is charged once, not again as a refusal",
         %{token: token, key: key} do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 5)

      for _ <- 1..3, do: assert(200 == call(token, "testkit.read_items", %{}).status)

      # A 200-row batch costs 4 units; only 2 are left, so the limiter refuses it.
      refused = call(token, "testkit.write_batch", %{"items" => lines(200)})
      assert refused.status == 429
      assert json(refused)["code"] == "rate_limited"
      assert ["0"] = get_resp_header(refused, "ratelimit-remaining")

      # 3 read units + 4 for the batch; the refusal added nothing on top.
      assert Backend.get("api:admin:key:" <> key.uuid, 60_000) == 7
    end

    test "an admin write batch costs one unit per 50 rows", %{token: token} do
      put_setting("api_confirm_batch_over", 500)
      wait_for_window_room()
      one = call(token, "testkit.write_batch", %{"items" => [%{}]})
      many = call(token, "testkit.write_batch", %{"items" => List.duplicate(%{}, 120)})

      assert one.status == 200 and many.status == 200
      assert remaining(one) - remaining(many) == 3
    end

    test "an admin read with a long list costs one unit", %{token: token} do
      wait_for_window_room()
      short = call(token, "testkit.read_items", %{})
      long = call(token, "testkit.read_items", %{"fields" => List.duplicate("name", 120)})

      assert short.status == 200 and long.status == 200
      assert remaining(short) - remaining(long) == 1
    end

    test "an oversized write is refused by max_items and does not use up the key's budget",
         %{token: token} do
      # More rows than the whole minute's budget could pay at 1 unit per 50.
      rows = (Config.rate_limits().admin_per_min + 1) * 50
      conn = call(token, "testkit.write_batch", %{"items" => List.duplicate(0, rows)})

      assert conn.status == 422
      assert [%{"path" => "items", "limit" => 500}] = json(conn)["context"]["errors"]
      refute_received {:write_batch, _}

      # Charged as a 500-row batch (10 units), not as 100 000 rows.
      assert remaining(conn) == Config.rate_limits().admin_per_min - 10

      # The next valid call still has its budget.
      assert 200 == call(token, "testkit.read_items", %{}).status
    end

    test "a write tool without max_items is charged at most 20 units, whatever its list",
         %{token: token} do
      # `testkit.open_schema_write` declares no max_items and no list; the
      # 422 for the unknown field `rows` is the point: a refused request.
      rows = (Config.rate_limits().admin_per_min + 1) * 50
      conn = call(token, "testkit.open_schema_write", %{"rows" => List.duplicate(0, rows)})

      assert conn.status == 422
      assert remaining(conn) == Config.rate_limits().admin_per_min - 20

      # The next valid call still has its budget.
      assert 200 == call(token, "testkit.read_items", %{}).status
    end

    test "the discovery list is rate limited too", %{token: token} do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 1)

      assert Executor.list(authed(token), :admin).status == 200
      assert Executor.list(authed(token), :admin).status == 429
    end
  end

  describe "validation" do
    test "a schema error is 422 validation_failed with the path; the handler does not run",
         %{token: token} do
      conn = call(token, "testkit.read_items", %{"limit" => 1_000})

      assert conn.status == 422
      assert %{"code" => "validation_failed", "context" => %{"errors" => [error]}} = json(conn)
      assert error["path"] =~ "limit"
      refute_received {:read_items, _, _}
    end

    test "an unknown field is refused", %{token: token} do
      assert 422 == call(token, "testkit.read_items", %{"nope" => 1}).status
    end

    test "the control fields are refused on a read tool, not ignored", %{token: token} do
      for field <- ["dry_run", "confirm_token", "idempotency_key"] do
        conn = call(token, "testkit.read_items", %{field => "x"})
        assert conn.status == 422, field
        refute_received {:read_items, _, _}
      end
    end

    test "a write tool refuses a control field of the wrong shape", %{token: token} do
      # `dry_run` is a boolean and `idempotency_key` is 16 to 128 characters: neither
      # reaches a real write as something else.
      for {field, value} <- [{"dry_run", "x"}, {"dry_run", "false"}, {"idempotency_key", "x"}] do
        conn = call(token, "testkit.write_item", %{field => value})
        assert conn.status == 422, field
        refute_received {:write_item, _}
      end
    end

    test "a tool whose own schema is open still refuses unknown fields", %{token: token} do
      # `testkit.open_schema_write` forgot `additionalProperties: false`; the
      # executor closes the schema, so a field nobody declared cannot reach a write.
      conn = call(token, "testkit.open_schema_write", %{"anything_else" => true})

      assert conn.status == 422
      assert json(conn)["code"] == "validation_failed"
      assert [%{"path" => path}] = json(conn)["context"]["errors"]
      assert path =~ "anything_else"
      refute_received {:open_schema_write, _}
    end

    test "closing the schema leaves the declared fields alone", %{token: token} do
      conn = call(token, "testkit.open_schema_write", %{"name" => "Hinge"})

      assert conn.status == 200
      assert %{"written" => "Hinge"} = json(conn)
      assert_received {:open_schema_write, %{"name" => "Hinge"}}
    end

    test "an input that is not a JSON object is refused", %{token: token} do
      conn = call(token, "testkit.read_items", ["not", "a", "map"])
      assert conn.status == 422
      assert [%{"path" => ""}] = json(conn)["context"]["errors"]
    end

    test "max_items is a hard limit, checked before the schema", %{token: token} do
      put_setting("api_confirm_batch_over", 500)
      conn = call(token, "testkit.write_batch", %{"items" => List.duplicate(%{}, 501)})

      assert conn.status == 422
      assert [%{"path" => "items", "limit" => 500}] = json(conn)["context"]["errors"]
      refute_received {:write_batch, _}

      assert 200 ==
               call(token, "testkit.write_batch", %{"items" => List.duplicate(%{}, 500)}).status
    end
  end

  describe "the handler contract" do
    test "{:ok, result, effects} adds the effects to the answer", %{token: token} do
      conn = call(token, "testkit.write_item", %{"name" => "Hinge"})

      assert conn.status == 200
      assert %{"written" => "Hinge", "effects" => [%{"code" => "item_indexed"}]} = json(conn)
    end

    test "{:error, code, message, context} becomes that problem", %{token: token} do
      conn = call(token, "testkit.fail_write", %{})

      assert conn.status == 422

      assert %{
               "code" => "insufficient_stock",
               "detail" => "Three lines are short.",
               "context" => %{"lines" => [%{"product" => "a"}]}
             } = json(conn)
    end

    test "a crash is a generic 500 that leaks nothing, and the key keeps working", %{token: token} do
      log = capture_log(fn -> send(self(), {:conn, call(token, "testkit.crash_write", %{})}) end)
      assert_received {:conn, conn}

      assert conn.status == 500
      assert json(conn)["code"] == "internal_error"
      refute conn.resp_body =~ "secret-detail"
      assert log =~ "testkit.crash_write"
      assert log =~ "RuntimeError"
      assert log =~ "PhoenixKit.Test.ApiTools.crash_write/2"

      assert 200 == call(token, "testkit.read_items", %{}).status
    end
  end

  describe "a handler that breaks its contract" do
    for {tool, leak} <- [
          {"testkit.bad_shape", nil},
          {"testkit.bad_text", "secret-detail"},
          {"testkit.bad_utf8", "secret-detail"},
          {"testkit.throw_write", nil},
          {"testkit.exit_write", nil}
        ] do
      test "#{tool}: a generic 500, nothing leaked, logged as an error",
           %{token: token, key: key} do
        tool = unquote(tool)
        leak = unquote(leak)

        log = capture_log(fn -> send(self(), {:conn, call(token, tool, %{})}) end)
        assert_received {:conn, conn}

        assert conn.status == 500

        assert %{"code" => "internal_error", "detail" => "The tool failed unexpectedly."} =
                 json(conn)

        if leak, do: refute(conn.resp_body =~ leak)
        assert log =~ tool

        assert [%{metadata: %{"outcome" => "error", "code" => "internal_error"}}] =
                 audit_entries(key)

        # The key keeps working.
        assert 200 == call(token, "testkit.read_items", %{}).status
      end
    end

    test "the log names the shape of a bad result, never its values", %{token: token} do
      log =
        capture_log(fn ->
          call(token, "testkit.bad_shape", %{})
          call(token, "testkit.bad_text", %{})
          call(token, "testkit.bad_utf8", %{})
        end)

      assert log =~ "returned :ok"
      assert log =~ "returned a binary of 30 bytes"
      assert log =~ "returned an error whose message is not valid UTF-8"
      refute log =~ "secret-detail"
    end

    test "a RuntimeError is logged by module only, however long its message", %{token: token} do
      log = capture_log(fn -> call(token, "testkit.long_crash_write", %{}) end)

      assert log =~ "** (RuntimeError)\n"
      assert log =~ "PhoenixKit.Test.ApiShapeTools.long_crash_write/2"
      refute log =~ "e\u0301"
    end

    test "an ArithmeticError keeps its fixed message in the log", %{token: token} do
      log = capture_log(fn -> call(token, "testkit.arith_write", %{}) end)

      assert log =~ "** (ArithmeticError) bad argument in arithmetic expression"
    end

    for {tool, logged} <- [
          {"testkit.echo_raise_write", "** (RuntimeError)\n"},
          {"testkit.echo_argument_write", "** (ArgumentError)\n"},
          {"testkit.echo_date_write", "** (ArgumentError)\n"},
          {"testkit.echo_module_write", "** (UndefinedFunctionError)\n"},
          {"testkit.echo_atom_throw_write", "throw: an atom"},
          {"testkit.echo_code_write", "unknown error code (an atom)"}
        ] do
      test "#{tool}: a value taken from the request never reaches the log", %{token: token} do
        sentinel = "SENTINEL-7f3a91c2-PII"

        for input <- [sentinel, sentinel <> "%zz"] do
          log = capture_log(fn -> call(token, unquote(tool), %{"v" => input}) end)

          assert log =~ unquote(logged)
          refute log =~ "SENTINEL", "#{unquote(tool)} logged the request value"
        end
      end
    end

    test "the stacktrace of a crash carries no argument values", %{token: token} do
      log = capture_log(fn -> call(token, "testkit.clause_write", %{}) end)

      assert log =~ "FunctionClauseError"
      assert log =~ "PhoenixKit.Test.ApiShapeTools.only_atoms/1"
      refute log =~ "secret-argument"
    end

    for {tool, logged} <- [
          {"testkit.key_error_write", "** (KeyError)\n"},
          {"testkit.match_error_write", "** (MatchError)\n"},
          {"testkit.changeset_write", "** (Ecto.InvalidChangesetError)\n"},
          {"testkit.secret_throw_write", "throw: a tuple of size 2 tagged :error"},
          {"testkit.secret_exit_write", "exit: a tuple of size 2 tagged :error"}
        ] do
      test "#{tool}: the log names the kind and keeps the values of the reason out",
           %{token: token} do
        log = capture_log(fn -> call(token, unquote(tool), %{}) end)

        assert log =~ unquote(tool)
        assert log =~ unquote(logged)
        refute log =~ "secret-argument"
      end
    end

    test "a thrown or exited reason is bounded in the log", %{token: token} do
      log =
        capture_log(fn ->
          call(token, "testkit.throw_write", %{})
          call(token, "testkit.exit_write", %{})
        end)

      assert log =~ "throw: "
      assert log =~ "exit: "
      refute log =~ String.duplicate("t", 300)
      refute log =~ String.duplicate("x", 300)
    end
  end

  describe "without_arguments/1" do
    test "a frame with the arguments keeps the arity only" do
      location = [file: ~c"lib/x.ex", line: 3]

      assert Executor.without_arguments({X, :f, ["secret-argument", 2], location}) ==
               {X, :f, 2, location}
    end

    test "a function frame with the arguments keeps the arity only" do
      location = [file: ~c"lib/x.ex", line: 3]
      fun = fn _value -> :ok end

      assert Executor.without_arguments({fun, ["secret-argument"], location}) ==
               {fun, 1, location}
    end

    test "a frame that carries an arity is left alone" do
      location = [file: ~c"lib/x.ex", line: 3]
      fun = fn _value -> :ok end

      assert Executor.without_arguments({X, :f, 2, location}) == {X, :f, 2, location}
      assert Executor.without_arguments({fun, 1, location}) == {fun, 1, location}
    end
  end

  describe "the api.request audit entry" do
    test "one entry per write call: tool, key prefix, rows, outcome", %{
      token: token,
      key: key,
      owner: owner
    } do
      conn = call(token, "testkit.write_batch", %{"items" => List.duplicate(%{}, 7)})

      assert [entry] = audit_entries(key)
      assert entry.module == "api"
      assert entry.actor_uuid == owner.uuid
      assert entry.resource_type == "api_key"
      refute entry.permanent

      assert entry.metadata == %{
               "via" => "api",
               "tool" => "testkit.write_batch",
               "key_prefix" => key.prefix,
               "request_id" => conn.assigns.phoenix_kit_api_request_id,
               "rows" => 7,
               "outcome" => "ok",
               "code" => nil
             }
    end

    test "a failed write is logged with its error code", %{token: token, key: key} do
      call(token, "testkit.fail_write", %{})

      assert [%{metadata: %{"outcome" => "error", "code" => "insufficient_stock"}}] =
               audit_entries(key)
    end

    test "a write refused by validation is logged", %{token: token, key: key} do
      call(token, "testkit.write_item", %{"unknown_field" => 5})

      assert [%{metadata: %{"outcome" => "error", "code" => "validation_failed"}}] =
               audit_entries(key)
    end

    test "a crashed write is logged", %{token: token, key: key} do
      capture_log(fn -> call(token, "testkit.crash_write", %{}) end)

      assert [%{metadata: %{"outcome" => "error", "code" => "internal_error"}}] =
               audit_entries(key)
    end

    test "an anonymous public write writes nothing" do
      conn = public_call("testkit.public_write", %{"text" => "hi"})

      assert conn.status == 200
      assert %{"echo" => "hi"} = json(conn)
      assert Repo.aggregate(from(e in Entry, where: e.action == "api.request"), :count) == 0
    end

    test "a refused request costs no write: unknown tool, missing scope, module off",
         %{owner: owner, key: key} do
      {_key, read_only} = issue_key(owner, [@read])

      call(read_only, "testkit.write_item", %{})
      call(read_only, "testkit.nope", %{})
      ApiTools.set_enabled(false)
      call(read_only, "testkit.write_item", %{})

      assert audit_entries(key) == []
      assert Repo.aggregate(from(e in Entry, where: e.action == "api.request"), :count) == 0
    end
  end

  describe "cost/2" do
    test "an admin write costs one unit per 50 rows of its longest list" do
      write = tool!("testkit.write_batch", :admin)

      assert Executor.cost(write, %{}) == 1
      assert Executor.cost(write, %{"items" => lines(1)}) == 1
      assert Executor.cost(write, %{"items" => lines(50)}) == 1
      assert Executor.cost(write, %{"items" => lines(51)}) == 2
      assert Executor.cost(write, %{"items" => lines(120)}) == 3
      assert Executor.cost(write, %{"items" => lines(500)}) == 10

      # The longest top-level list decides, not the sum.
      assert Executor.cost(write, %{"a" => lines(10), "b" => lines(120)}) == 3
    end

    test "a list is counted up to max_items, or up to 1000 rows when the tool has none" do
      write = tool!("testkit.write_batch", :admin)
      open = tool!("testkit.open_schema_write", :admin)

      assert write.max_items == 500
      assert Executor.cost(write, %{"items" => lines(5_000)}) == 10

      assert open.max_items == nil
      assert Executor.cost(open, %{"rows" => lines(1_000)}) == 20
      assert Executor.cost(open, %{"rows" => lines(1_001)}) == 20
      assert Executor.cost(open, %{"rows" => lines(30_050)}) == 20
      assert Executor.cost(open, %{"rows" => lines(51)}) == 2
    end

    test "an admin read costs one unit whatever the list" do
      read = tool!("testkit.read_items", :admin)

      assert Executor.cost(read, %{"fields" => List.duplicate("name", 500)}) == 1
    end

    test "a public call costs one unit whatever the list, writes included" do
      echo = tool!("testkit.public_echo", :public)
      public_write = %{echo | annotations: %{echo.annotations | read_only: false}}

      assert Executor.cost(echo, %{"lines" => lines(50)}) == 1
      assert Executor.cost(public_write, %{"lines" => lines(50)}) == 1
      assert Executor.cost(public_write, %{"lines" => lines(500)}) == 1
    end

    test "the discovery list (no tool) and an input that is not an object cost one unit" do
      assert Executor.cost(nil, %{"items" => lines(500)}) == 1
      assert Executor.cost(tool!("testkit.write_batch", :admin), lines(500)) == 1
    end
  end

  describe "the public audience" do
    test "runs a public tool with no key", %{} do
      conn = public_call("testkit.public_echo", %{"text" => "hi"})

      assert conn.status == 200
      assert %{"echo" => "hi", "cart_token_hash" => nil} = json(conn)
    end

    test "gives the handler a hash of the cart token, never the token" do
      conn =
        public_call("testkit.public_echo", %{"text" => "hi", "cart_token" => "my-cart-token"})

      assert %{"cart_token_hash" => hash} = json(conn)
      assert is_binary(hash) and hash != "my-cart-token"
      refute conn.resp_body =~ "my-cart-token"
    end

    test "a 50-line list costs one unit, as a call without lines" do
      wait_for_window_room()
      ip = unique_ip()

      plain = public_call("testkit.public_echo", %{}, ip: ip)
      long = public_call("testkit.public_echo", %{"lines" => List.duplicate(%{}, 50)}, ip: ip)

      assert plain.status == 200 and long.status == 200
      assert remaining(plain) - remaining(long) == 1
    end

    test "cannot call an admin tool", %{} do
      assert 404 == public_call("testkit.read_items", %{}).status
    end

    test "is rate limited per IP", %{} do
      wait_for_window_room()
      put_setting("api_public_ip_rate_per_min", 1)
      ip = unique_ip()

      assert 200 == public_call("testkit.public_echo", %{}, ip: ip).status
      assert 429 == public_call("testkit.public_echo", %{}, ip: ip).status
    end

    test "is charged before the tool lookup: unknown names end in 429 once the bucket is used up" do
      wait_for_window_room()
      put_setting("api_public_ip_rate_per_min", 3)
      ip = unique_ip()

      statuses =
        for n <- 1..5 do
          public_call("testkit.no_such_tool_#{n}", %{}, ip: ip).status
        end

      # While the bucket has room the lookup runs and answers 404 not_found;
      # after that the call is refused before the lookup, which would answer
      # 404 again for the same unknown names.
      assert statuses == [404, 404, 404, 429, 429]
    end
  end

  describe "list/2" do
    test "lists the tools the key's scopes unlock, system tools included", %{owner: owner} do
      {_key, token} = issue_key(owner, [@read])

      conn = Executor.list(authed(token), :admin)
      assert conn.status == 200

      %{"tools" => tools, "count" => count} = json(conn)
      names = Enum.map(tools, & &1["name"])

      assert "testkit.read_items" in names
      assert "system.get_identity" in names
      refute "testkit.write_item" in names
      refute "testkit.public_echo" in names
      assert count == length(names)

      read = Enum.find(tools, &(&1["name"] == "testkit.read_items"))
      assert read["scope"] == @read
      assert read["input_schema"]["additionalProperties"] == false
    end

    test "lists the closed schema of a tool whose own schema is open", %{token: token} do
      %{"tools" => tools} = Executor.list(authed(token), :admin) |> json()
      open = Enum.find(tools, &(&1["name"] == "testkit.open_schema_write"))

      assert %{"properties" => %{"name" => _}, "additionalProperties" => false} =
               open["input_schema"]
    end

    test "the public list shows the public tools" do
      conn = :get |> api_conn("/") |> Auth.call(Auth.init(audience: :public))
      conn = Executor.list(conn, :public)

      assert conn.status == 200

      assert ["testkit.public_echo", "testkit.public_write"] =
               json(conn)["tools"] |> Enum.map(& &1["name"]) |> Enum.sort()
    end

    test "a module switched off drops out of the list", %{token: token} do
      ApiTools.set_enabled(false)

      names =
        Executor.list(authed(token), :admin)
        |> json()
        |> Map.fetch!("tools")
        |> Enum.map(& &1["name"])

      refute Enum.any?(names, &String.starts_with?(&1, "testkit."))
      assert "system.get_identity" in names
    end
  end
end
