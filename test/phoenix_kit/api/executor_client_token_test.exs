defmodule PhoenixKit.API.ExecutorClientTokenTest do
  @moduledoc """
  How the executor finds and charges the client token of a public caller: the tool
  declares the input field (`Tool.client_token`), so the token is hashed after the tool
  lookup, the lookup itself is paid from the network bucket only, and the call then pays
  its full price to the token bucket and the rest to the network bucket. A tool written
  before the field existed, with a `cart_token` property, is still read through
  `PhoenixKit.API.Legacy`.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Users.RateLimiter.Backend

  defmodule ClientTokenTools do
    @moduledoc false

    @read %{read_only: true, destructive: false, idempotent: true, open_world: false}

    def module_key, do: "api_client_token_tools"
    def module_name, do: "Client token tools"
    def enabled?, do: true

    def api_tools do
      [
        tool("ctk.declared", %{"session_token" => %{"type" => "string"}},
          client_token: "session_token"
        ),
        tool("ctk.priced", %{"session_token" => %{"type" => "string"}},
          client_token: "session_token",
          cost: 3
        ),
        tool("ctk.undeclared", %{"session_token" => %{"type" => "string"}}, []),
        tool("ctk.legacy", %{"cart_token" => %{"type" => "string"}}, []),
        tool("ctk.priced_legacy", %{"cart_token" => %{"type" => "string"}}, cost: 3),
        tool(
          "ctk.both",
          %{"cart_token" => %{"type" => "string"}, "session_token" => %{"type" => "string"}},
          client_token: "session_token"
        )
      ]
    end

    defp tool(name, properties, opts) do
      Tool.new!(
        [
          name: name,
          audience: :public,
          title: name,
          description: "Test tool #{name}.",
          input_schema: %{
            "type" => "object",
            "properties" => properties,
            "additionalProperties" => false
          },
          output_schema: %{"type" => "object"},
          handler: {__MODULE__, :echo},
          annotations: @read
        ] ++ opts
      )
    end

    def echo(_input, ctx), do: {:ok, %{"hash" => ctx.actor.client_token_hash}}
  end

  setup do
    setup_api()
    wait_for_window_room()
    :ok = ModuleRegistry.register(ClientTokenTools)
    on_exit(fn -> ModuleRegistry.unregister(ClientTokenTools) end)
  end

  defp public_call(tool, input, ip) do
    conn = :post |> api_conn("/", ip: ip) |> Auth.call(Auth.init(audience: :public))
    Executor.call(conn, :public, tool, input)
  end

  defp hash(token), do: :crypto.hash(:sha256, token) |> Base.url_encode64(padding: false)
  defp token_used(token), do: Backend.get("api:public:token:" <> hash(token), 60_000)
  defp network_used(ip), do: Backend.get("api:public:ip:" <> ip, 60_000)

  describe "the client token hash" do
    test "is taken from the field the tool declares" do
      conn = public_call("ctk.declared", %{"session_token" => "abc"}, unique_ip())

      assert json(conn)["hash"] == hash("abc")
    end

    test "is nil when the call sends no token or an empty one" do
      assert json(public_call("ctk.declared", %{}, unique_ip()))["hash"] == nil

      assert json(public_call("ctk.declared", %{"session_token" => ""}, unique_ip()))["hash"] ==
               nil
    end

    test "is nil for a tool that declares none, whatever fields it has" do
      conn = public_call("ctk.undeclared", %{"session_token" => "abc"}, unique_ip())

      assert conn.status == 200
      assert json(conn)["hash"] == nil
    end

    test "is taken from cart_token for a tool that predates the declaration (legacy)" do
      conn = public_call("ctk.legacy", %{"cart_token" => "abc"}, unique_ip())

      assert json(conn)["hash"] == hash("abc")
    end

    test "a declared field wins over cart_token" do
      conn =
        public_call("ctk.both", %{"cart_token" => "old", "session_token" => "new"}, unique_ip())

      assert json(conn)["hash"] == hash("new")
    end
  end

  describe "charging" do
    test "an unknown tool pays the network bucket only, whatever token the call carries" do
      ip = unique_ip()

      assert public_call("ctk.nonexistent", %{"session_token" => "ghost"}, ip).status == 404
      assert network_used(ip) == 1
      assert token_used("ghost") == 0
    end

    test "a call with a token and a price of 1 costs one unit in each bucket" do
      ip = unique_ip()

      assert public_call("ctk.declared", %{"session_token" => "one"}, ip).status == 200
      assert token_used("one") == 1
      assert network_used(ip) == 1
    end

    test "a call with a token and a higher price pays the full price to each bucket" do
      ip = unique_ip()

      assert public_call("ctk.priced", %{"session_token" => "dear"}, ip).status == 200
      assert token_used("dear") == 3
      assert network_used(ip) == 3
    end

    test "a call without a token pays the network bucket only" do
      ip = unique_ip()

      assert public_call("ctk.priced", %{}, ip).status == 200
      assert network_used(ip) == 3
    end

    test "a legacy cart_token is charged like a declared one" do
      ip = unique_ip()

      assert public_call("ctk.priced_legacy", %{"cart_token" => "old"}, ip).status == 200
      assert token_used("old") == 3
      assert network_used(ip) == 3
    end

    test "a tool that declares none charges no token bucket" do
      ip = unique_ip()

      assert public_call("ctk.undeclared", %{"session_token" => "plain"}, ip).status == 200
      assert token_used("plain") == 0
      assert network_used(ip) == 1
    end

    test "a token over its limit is refused, and the lookup unit is all the network was charged" do
      put_setting("api_public_token_rate_per_min", 2)
      ip = unique_ip()

      conn = public_call("ctk.priced", %{"session_token" => "greedy"}, ip)

      assert conn.status == 429
      assert json(conn)["code"] == "rate_limited"
      assert network_used(ip) == 1
    end

    test "a token's bucket is its own: another token on the same network still passes" do
      put_setting("api_public_token_rate_per_min", 1)
      ip = unique_ip()

      assert public_call("ctk.declared", %{"session_token" => "first"}, ip).status == 200
      assert public_call("ctk.declared", %{"session_token" => "first"}, ip).status == 429
      assert public_call("ctk.declared", %{"session_token" => "second"}, ip).status == 200
    end
  end
end
