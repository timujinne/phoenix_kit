defmodule PhoenixKit.API.RequestContextTest do
  @moduledoc """
  `PhoenixKit.API.RequestContext.resolve/1`: core's defaults and the
  per-domain override a host app configures.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias PhoenixKit.API.RequestContext
  alias PhoenixKit.Utils.Multilang

  defmodule Hook do
    @moduledoc false
    def full(_conn), do: %{language: "de", currency: "EUR", hosts: ["a.test", "b.test"], junk: 1}
    def partial(conn), do: %{currency: "CHF", hosts: [conn.host, "other.test"]}
    def blank_currency(_conn), do: %{currency: nil}
    def wrong_types(_conn), do: %{language: 5, currency: 3, hosts: ["ok", 1]}
    def empty_language(_conn), do: %{language: "", hosts: []}
    def raises(_conn), do: raise("hook bug")
    def returns_junk(_conn), do: :not_a_map
    def returns_conn(conn), do: conn
    def returns_tuple(_conn), do: {:ok, "secret-cart-token"}
    def key_error(conn), do: Map.fetch!(conn.body_params, "missing")
    def runtime_error(conn), do: raise("bad cart #{conn.body_params["cart_token"]}")

    def argument_error(conn),
      do: raise(ArgumentError, "bad cart #{conn.body_params["cart_token"]}")

    def date_error(conn), do: Date.from_iso8601!(conn.body_params["cart_token"])
    def match_error(conn), do: %{"x" => _} = conn.body_params
    def throws_secret(conn), do: throw(conn.body_params["cart_token"])
    def exits_secret(conn), do: exit({:error, conn.body_params["cart_token"]})
    def throws_atom(conn), do: throw(String.to_atom(conn.body_params["cart_token"]))
  end

  setup do
    on_exit(fn -> Application.delete_env(:phoenix_kit, :api_request_context) end)
  end

  defp hook(fun), do: Application.put_env(:phoenix_kit, :api_request_context, {Hook, fun})
  defp resolve(url \\ "http://shop.test/x"), do: :get |> conn(url) |> RequestContext.resolve()

  describe "the defaults" do
    test "primary language, no currency, the request host, its base URL" do
      assert %{
               language: language,
               currency: nil,
               hosts: ["shop.test"],
               base_url: "http://shop.test"
             } = resolve()

      assert language == Multilang.primary_language()
    end

    test "a non-default port stays in the base URL; the default port does not" do
      assert resolve("http://shop.test:4000/x").base_url == "http://shop.test:4000"
      assert resolve("https://shop.test/x").base_url == "https://shop.test"
      assert resolve("https://shop.test:443/x").base_url == "https://shop.test"
    end

    test "X-Forwarded-Proto is believed from a local proxy only" do
      forwarded =
        :get |> conn("http://shop.test/x") |> put_req_header("x-forwarded-proto", "https")

      assert RequestContext.resolve(forwarded).base_url == "https://shop.test"

      stranger = %{forwarded | remote_ip: {203, 0, 113, 9}}
      assert RequestContext.resolve(stranger).base_url == "http://shop.test"

      junk = :get |> conn("http://shop.test/x") |> put_req_header("x-forwarded-proto", "gopher")
      assert RequestContext.resolve(junk).base_url == "http://shop.test"
    end
  end

  describe "the host's :api_request_context hook" do
    test "overrides language, currency and hosts" do
      hook(:full)
      ctx = resolve()

      assert %{language: "de", currency: "EUR", hosts: ["a.test", "b.test"]} = ctx
      refute Map.has_key?(ctx, :junk)
      assert ctx.base_url == "http://shop.test"
    end

    test "overrides only what it returns" do
      hook(:partial)

      assert %{currency: "CHF", hosts: ["shop.test", "other.test"]} = ctx = resolve()
      assert ctx.language == Multilang.primary_language()
    end

    test "may set the currency back to nil" do
      hook(:blank_currency)
      assert resolve().currency == nil
    end

    test "ignores values of the wrong type" do
      hook(:wrong_types)
      ctx = resolve()

      assert ctx.language == Multilang.primary_language()
      assert ctx.currency == nil
      assert ctx.hosts == ["shop.test"]

      hook(:empty_language)
      assert resolve().language == Multilang.primary_language()
      assert resolve().hosts == ["shop.test"]
    end

    test "a hook that raises or returns junk is logged and the defaults are used" do
      for fun <- [:raises, :returns_junk] do
        hook(fun)
        log = capture_log(fn -> send(self(), {:ctx, resolve()}) end)

        assert_received {:ctx, ctx}
        assert ctx.hosts == ["shop.test"]
        assert log =~ "using the defaults"
      end
    end

    test "the log never carries the request: not the bearer token, not the body params" do
      secret_conn =
        :post
        |> conn("http://shop.test/x", %{"cart_token" => "secret-cart-token"})
        |> put_req_header("authorization", "Bearer pk_secret-bearer")

      for fun <- [
            :returns_conn,
            :returns_tuple,
            :key_error,
            :runtime_error,
            :argument_error,
            :date_error,
            :match_error,
            :throws_secret,
            :throws_atom,
            :exits_secret
          ] do
        hook(fun)
        log = capture_log(fn -> send(self(), {:ctx, RequestContext.resolve(secret_conn)}) end)

        assert_received {:ctx, %{hosts: ["shop.test"]}}
        assert log =~ "using the defaults", "#{fun}: no log line"
        assert log =~ "#{inspect(Hook)}.#{fun}/1", "#{fun}: hook not named"
        refute log =~ "secret-cart-token", "#{fun}: cart token in the log"
        refute log =~ "pk_secret-bearer", "#{fun}: bearer token in the log"
        refute log =~ "Bearer", "#{fun}: authorization header in the log"
      end
    end

    test "the log names the shape of a bad result and the module of an exception" do
      for {fun, expected} <- [
            returns_conn: "returned a Plug.Conn struct",
            returns_junk: "returned an atom",
            returns_tuple: "returned a tuple of size 2 tagged :ok",
            key_error: "raised ** (KeyError)",
            throws_secret: "throw: a binary of 17 bytes",
            throws_atom: "throw: an atom",
            exits_secret: "exit: a tuple of size 2 tagged :error"
          ] do
        hook(fun)

        log =
          capture_log(fn ->
            send(
              self(),
              {:ctx,
               :post
               |> conn("http://shop.test/x", %{"cart_token" => "secret-cart-token"})
               |> RequestContext.resolve()}
            )
          end)

        assert log =~ expected, "#{fun}: expected #{expected}"
      end
    end

    test "a hook that does not exist is logged and the defaults are used" do
      Application.put_env(:phoenix_kit, :api_request_context, {Hook, :no_such_function})
      log = capture_log(fn -> send(self(), {:ctx, resolve()}) end)

      assert_received {:ctx, %{hosts: ["shop.test"]}}
      assert log =~ "using the defaults"
    end

    test "a malformed setting is logged and ignored" do
      Application.put_env(:phoenix_kit, :api_request_context, "Hook.full")
      log = capture_log(fn -> send(self(), {:ctx, resolve()}) end)

      assert_received {:ctx, %{hosts: ["shop.test"]}}
      assert log =~ "must be {module, function}"
    end
  end

  describe "from_options/1" do
    test "takes the given context, and the defaults for what is missing or malformed" do
      assert RequestContext.from_options(
               language: "et",
               currency: "EUR",
               hosts: ["shop.example"],
               base_url: "https://shop.example"
             ) == %{
               language: "et",
               currency: "EUR",
               hosts: ["shop.example"],
               base_url: "https://shop.example"
             }

      defaults = %{
        language: Multilang.primary_language(),
        currency: nil,
        hosts: [],
        base_url: nil
      }

      assert RequestContext.from_options([]) == defaults
      assert RequestContext.from_options(language: 1, hosts: [1], base_url: "") == defaults

      assert RequestContext.from_options([:junk, {"language", "et"}, {:currency, "EUR", 1}]) ==
               defaults
    end
  end
end
