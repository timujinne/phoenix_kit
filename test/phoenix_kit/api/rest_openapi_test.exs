defmodule PhoenixKit.API.RESTOpenAPITest do
  @moduledoc """
  `GET .../openapi.json` through the REST plug at plug level: who gets which
  document, and the checks that come first.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness
  import Plug.Conn

  alias PhoenixKit.API.REST
  alias PhoenixKit.API.ToolLint
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Test.ApiTools
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Utils.Routes

  @read "testkit.items:read"
  @write "testkit.items:write"

  defmodule BrokenTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    # An annotation may hold any term as far as the validator walks it; the verdict is seeded below.
    @schema %{"type" => "object", "properties" => %{}, "default" => {:not, :encodable}}

    def module_key, do: "api_broken_doc_tools"
    def module_name, do: "Broken document tools"
    def enabled?, do: true

    # A struct literal, not Tool.new!: Tool.validate/1 refuses this schema (a tuple is not
    # JSON), so the verdict on it is seeded in the cache that stands between a tool and the
    # validator. JSON encoding of the document then raises.
    def api_tools do
      [
        struct!(Tool,
          name: "broken.list_things",
          audience: :admin,
          scope: "broken.items:read",
          permission: "dashboard",
          title: "Broken",
          description: "A tool whose schema cannot be encoded.",
          handler: {__MODULE__, :run},
          input_schema: @schema,
          output_schema: nil,
          annotations: %{
            read_only: true,
            destructive: false,
            idempotent: false,
            open_world: false
          }
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}

    # Seed BEFORE ModuleRegistry.register/1, forget in on_exit. The key layout is private to
    # Tool: if it changes, the tool is dropped (a warning, HTTP 200) and the test fails on
    # `conn.status == 500`, loudly, never vacuously.
    def seed_verdict, do: :persistent_term.put(verdict_key(), [])
    def forget_verdict, do: :persistent_term.erase(verdict_key())

    defp verdict_key do
      {Tool, :schema_problems, :input,
       @schema |> :erlang.term_to_binary([:deterministic]) |> :erlang.md5()}
    end
  end

  setup do
    setup_api()
    {owner, role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{owner: owner, role: role, key: key, token: token}
  end

  defp admin(conn), do: REST.call(conn, REST.init(audience: :admin))
  defp public(conn), do: REST.call(conn, REST.init(audience: :public))

  defp fetch(token, opts \\ []) do
    :get |> api_conn("/openapi.json", Keyword.put(opts, :token, token)) |> admin()
  end

  defp paths(conn), do: conn |> json() |> Map.fetch!("paths") |> Map.keys() |> Enum.sort()

  defp refs(term, acc \\ [])
  defp refs(%{"$ref" => ref}, acc) when is_binary(ref), do: [ref | acc]
  defp refs(%{} = map, acc), do: Enum.reduce(Map.values(map), acc, &refs/2)
  defp refs(list, acc) when is_list(list), do: Enum.reduce(list, acc, &refs/2)
  defp refs(_other, acc), do: acc

  describe "the admin document" do
    test "is JSON, never cached, OpenAPI 3.1, for the tools the key can use", %{token: token} do
      conn = fetch(token)

      assert conn.status == 200
      assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")
      assert ["no-store"] = get_resp_header(conn, "cache-control")
      assert [_] = get_resp_header(conn, "ratelimit-limit")
      assert [] = get_resp_header(conn, "access-control-allow-origin")

      document = json(conn)
      assert document["openapi"] == "3.1.0"
      assert document["info"]["title"] =~ "admin API"

      assert document["servers"] == [
               %{"url" => "http://www.example.com" <> Routes.path("/api/admin/v1")}
             ]

      assert document["security"] == [%{"bearerAuth" => []}]

      assert paths(conn) == [
               "/",
               "/system.get_approval",
               "/system.get_identity",
               "/testkit.crash_write",
               "/testkit.fail_write",
               "/testkit.open_schema_write",
               "/testkit.read_items",
               "/testkit.write_batch",
               "/testkit.write_item"
             ]
    end

    test "operations carry the vendor extensions", %{token: token} do
      ops = fetch(token) |> json() |> Map.fetch!("paths")

      assert ops["/testkit.read_items"]["post"]["x-agent-safety"] == "read"
      assert ops["/testkit.read_items"]["post"]["x-idempotent"] == true
      assert ops["/testkit.write_item"]["post"]["x-agent-safety"] == "write"
      assert ops["/testkit.write_item"]["post"]["x-required-scope"] == @write
      assert ops["/system.get_identity"]["post"]["x-agent-safety"] == "read"
    end

    test "a read-only key's document lists no write tool", %{owner: owner} do
      {_key, token} = issue_key(owner, [@read])

      listed = fetch(token) |> paths()

      assert "/testkit.read_items" in listed
      assert "/system.get_identity" in listed
      refute "/testkit.write_item" in listed
      refute "/testkit.write_batch" in listed
    end

    test "a permission the owner lost drops its tools on the next request", %{
      token: token,
      role: role,
      key: key
    } do
      assert "/testkit.write_item" in paths(fetch(token))
      assert_row_cached(key.prefix)

      assert :ok = Permissions.revoke_permission(role.uuid, "settings")

      assert_row_cached(key.prefix)
      listed = paths(fetch(token))
      refute "/testkit.write_item" in listed
      assert "/testkit.read_items" in listed
    end

    test "a module switched off and a tool in api_disabled_tools are absent", %{token: token} do
      put_setting("api_disabled_tools", "testkit.write_item")
      listed = paths(fetch(token))
      refute "/testkit.write_item" in listed
      assert "/testkit.write_batch" in listed

      ApiTools.set_enabled(false)
      listed = paths(fetch(token))

      # contains, not equals: core also lists the tool system.get_approval
      assert "/" in listed
      assert "/system.get_identity" in listed
      refute Enum.any?(listed, &String.starts_with?(&1, "/testkit."))
    end

    test "a module whose API is switched off is absent, and back on it returns", %{
      token: token
    } do
      put_setting("api_disabled_modules", "api_test_tools")
      listed = paths(fetch(token))

      assert "/system.get_identity" in listed
      refute Enum.any?(listed, &String.starts_with?(&1, "/testkit."))

      put_setting("api_disabled_modules", "")
      assert "/testkit.read_items" in paths(fetch(token))
    end

    test "every $ref resolves and every schema passes the lint", %{token: token} do
      document = fetch(token) |> json()

      found = refs(document)
      assert found != []

      for "#/" <> pointer <- Enum.uniq(found) do
        assert get_in(document, String.split(pointer, "/")) != nil, pointer
      end

      for {path, %{"post" => op}} <- document["paths"] do
        assert :ok =
                 ToolLint.check_schema(
                   op["requestBody"]["content"]["application/json"]["schema"],
                   :input
                 ),
               path

        assert :ok =
                 ToolLint.check_schema(
                   op["responses"]["200"]["content"]["application/json"]["schema"],
                   :output
                 ),
               path
      end
    end
  end

  describe "the checks that come first" do
    setup do
      wait_for_window_room()
    end

    test "no key is a 401 problem" do
      conn = :get |> api_conn("/openapi.json") |> admin()
      assert conn.status == 401
      assert %{"code" => "unauthorized"} = json(conn)
    end

    test "a wrong key is a 401 problem" do
      assert fetch("pk_00000000_" <> String.duplicate("A", 43)).status == 401
    end

    test "a credential in the URL is a 400", %{token: token} do
      conn = :get |> api_conn("/openapi.json?api_key=abc", token: token) |> admin()
      assert conn.status == 400
      assert %{"code" => "token_in_url"} = json(conn)
    end

    test "with the admin switch off it is a bare 404", %{token: token} do
      switch(:admin, false)
      assert fetch(token).status == 404
    end

    test "it costs a rate-limit unit, and a refusal is a 429 problem", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      assert fetch(token).status == 200
      conn = fetch(token)

      assert conn.status == 429
      assert %{"code" => "rate_limited"} = json(conn)
      assert [_] = get_resp_header(conn, "retry-after")
    end
  end

  describe "a document that cannot be built" do
    test "is a 500 problem, only its class is logged, and the key keeps working", %{owner: owner} do
      BrokenTools.seed_verdict()
      on_exit(&BrokenTools.forget_verdict/0)
      :ok = ModuleRegistry.register(BrokenTools)
      on_exit(fn -> ModuleRegistry.unregister(BrokenTools) end)

      {_key, token} = issue_key(owner, ["broken.items:read"])

      {conn, log} = ExUnit.CaptureLog.with_log(fn -> fetch(token) end)

      assert conn.status == 500
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
      assert %{"code" => "internal_error"} = json(conn)
      refute conn.resp_body =~ "UndefinedError"

      assert log =~ "the OpenAPI document could not be built"
      assert log =~ "** ("
      assert log =~ "Protocol.UndefinedError"
      refute log =~ ":encodable"
      refute log =~ "lib/phoenix_kit/"
      refute log =~ token
      refute String.downcase(log) =~ "authorization"
      refute String.downcase(log) =~ "bearer"

      # GET / would encode the broken tool too (Executor.list/2 has no rescue): probe a tool call.
      probe = :post |> api_conn("/system.get_identity", token: token, body: %{}) |> admin()
      assert probe.status == 200
    end
  end

  describe "the public document" do
    test "needs no key and answers any origin" do
      conn = :get |> api_conn("/openapi.json") |> public()

      assert conn.status == 200
      assert ["*"] = get_resp_header(conn, "access-control-allow-origin")

      document = json(conn)
      assert document["info"]["title"] =~ "shop API"

      assert document["servers"] == [
               %{"url" => "http://www.example.com" <> Routes.path("/api/shop/v1")}
             ]

      refute Map.has_key?(document, "security")
      refute Map.has_key?(document["components"], "securitySchemes")
      assert paths(conn) == ["/", "/testkit.public_echo"]
    end

    test "with the public switch off it is a bare 404" do
      switch(:public, false)
      assert (:get |> api_conn("/openapi.json") |> public()).status == 404
    end

    test "the preflight is a 204" do
      conn = :options |> api_conn("/openapi.json") |> public()
      assert conn.status == 204
      assert ["*"] = get_resp_header(conn, "access-control-allow-origin")
    end
  end

  describe "other methods and paths" do
    test "only GET: the rest are 405 problems with Allow: GET", %{token: token} do
      for method <- [:post, :put, :patch, :delete] do
        admin = method |> api_conn("/openapi.json", token: token, body: %{}) |> admin()
        assert admin.status == 405, "#{method}"
        assert ["GET"] = get_resp_header(admin, "allow")

        public = method |> api_conn("/openapi.json", body: %{}) |> public()
        assert public.status == 405, "#{method}"
      end

      options = :options |> api_conn("/openapi.json", token: token) |> admin()
      assert options.status == 405
      assert ["GET"] = get_resp_header(options, "allow")
    end

    test "a path below openapi.json is a 404 problem", %{token: token} do
      conn = :get |> api_conn("/openapi.json/x", token: token) |> admin()
      assert conn.status == 404
    end

    test "the tool paths still work beside it", %{token: token} do
      conn =
        :post |> api_conn("/testkit.read_items", token: token, body: %{"limit" => 2}) |> admin()

      assert conn.status == 200
      assert json(conn)["limit"] == 2
    end
  end
end
