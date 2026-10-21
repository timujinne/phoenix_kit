defmodule PhoenixKit.API.BodyGuardMCPTest do
  @moduledoc """
  `PhoenixKit.API.BodyGuard` on the MCP paths: which switch decides for
  `/mcp/admin` and `/mcp/public`, and the JSON-RPC parse error. The 1a tests of
  the guard (`body_guard_test.exs`) cover the REST paths.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness, only: [switch: 2]
  import Plug.Conn
  import Plug.Test

  alias PhoenixKit.API.BodyGuard
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Utils.Routes

  @max 2_097_152
  @message ~s({"jsonrpc":"2.0","id":1,"method":"ping"})

  setup do
    KeyTestSupport.start_cache_registry!()
  end

  defp admin_path, do: Routes.prefix_base() <> "/mcp/admin"
  defp public_path, do: Routes.prefix_base() <> "/mcp/public"
  defp bare_path, do: Routes.prefix_base() <> "/mcp"
  defp rest_path, do: Routes.path("/api/admin/v1/system.get_identity")

  defp run(method, path, body) do
    method |> conn(path, body) |> BodyGuard.call(BodyGuard.init([]))
  end

  defp parse_error?(conn) do
    assert conn.halted
    assert conn.status == 400
    assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")

    assert %{
             "jsonrpc" => "2.0",
             "id" => nil,
             "error" => %{"code" => -32_700, "message" => message}
           } =
             JSON.decode!(conn.resp_body)

    assert is_binary(message)
  end

  describe "/mcp/admin follows the admin switch" do
    test "admin on, public off: /mcp/admin is read, /mcp/public is not" do
      switch(:admin, true)
      switch(:public, false)

      assert %{"method" => "ping"} = run(:post, admin_path(), @message).body_params

      shop = run(:post, public_path(), @message)
      assert shop.body_params == %{}
      refute shop.halted
    end

    test "admin off, public on: /mcp/public is read, /mcp/admin is not (not even judged)" do
      switch(:admin, false)
      switch(:public, true)

      assert %{"method" => "ping"} = run(:post, public_path(), @message).body_params

      for body <- [@message, "{broken", String.duplicate("x", @max + 10)] do
        admin = run(:post, admin_path(), body)
        assert admin.body_params == %{}
        refute admin.halted
      end
    end

    test "both on: both are read" do
      switch(:admin, true)
      switch(:public, true)

      assert %{"id" => 1} = run(:post, admin_path(), @message).body_params
      assert %{"id" => 1} = run(:post, public_path(), @message).body_params
    end

    test "both off: nothing is read or judged" do
      switch(:admin, false)
      switch(:public, false)

      for path <- [admin_path(), public_path()] do
        conn = run(:post, path, "{broken")
        assert conn.body_params == %{}, path
        refute conn.halted, path
      end
    end

    test "everything below /mcp/admin follows the admin switch" do
      switch(:admin, true)
      switch(:public, false)

      assert %{"id" => 1} = run(:post, admin_path() <> "/anything", @message).body_params
    end

    test "matching is by whole segments: /mcp/administrator is not /mcp/admin" do
      switch(:admin, true)
      switch(:public, false)

      conn = run(:post, Routes.prefix_base() <> "/mcp/administrator", @message)
      assert %Plug.Conn.Unfetched{} = conn.body_params
      refute conn.halted
    end

    test "everything below /mcp/public follows the public switch" do
      switch(:admin, false)
      switch(:public, true)

      assert %{"id" => 1} = run(:post, public_path() <> "/anything", @message).body_params
    end

    test "bare /mcp and any other path under /mcp are not guarded: nothing is read or judged, whatever the switches" do
      for {admin, public} <- [{true, true}, {true, false}, {false, true}, {false, false}],
          path <- [
            bare_path(),
            bare_path() <> "/other",
            bare_path() <> "/public2",
            bare_path() <> "/administrator"
          ],
          body <- [@message, "{broken", String.duplicate("x", @max + 10)] do
        switch(:admin, admin)
        switch(:public, public)

        conn = run(:post, path, body)

        assert %Plug.Conn.Unfetched{} = conn.body_params,
               "#{path} admin=#{admin} public=#{public}"

        refute conn.halted, path
      end
    end
  end

  describe "malformed JSON on /mcp is a JSON-RPC parse error" do
    setup do
      switch(:admin, true)
      switch(:public, true)
    end

    test "on every guarded MCP path" do
      for path <- [admin_path(), public_path(), admin_path() <> "/x", public_path() <> "/x"],
          body <- ["{nope", ~s({"a":}), "not json", ~s({"a":1} trailing)] do
        conn = run(:post, path, body)
        parse_error?(conn)
      end
    end

    test "REST paths are still problem+json" do
      conn = run(:post, rest_path(), "{nope")

      assert conn.status == 400
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
      assert %{"code" => "invalid_json"} = JSON.decode!(conn.resp_body)
    end

    test "a body over 2 MB is still a 413 problem+json on /mcp" do
      conn = run(:post, admin_path(), ~s({"a":") <> String.duplicate("x", @max) <> ~s("}))

      assert conn.status == 413
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
      assert %{"code" => "payload_too_large"} = JSON.decode!(conn.resp_body)
    end

    test "a JSON array or scalar is left for the MCP plug to judge" do
      assert %{"_json" => [_, _]} = run(:post, public_path(), "[1,2]").body_params
      assert %{"_json" => 7} = run(:post, public_path(), "7").body_params
    end

    test "an empty body is an empty map" do
      assert run(:post, admin_path(), "").body_params == %{}
    end

    test "other paths are untouched, bare /mcp and /mcp/other included" do
      for path <- [Routes.prefix_base() <> "/mcpx", bare_path(), bare_path() <> "/other"] do
        conn = run(:post, path, "{broken")
        assert %Plug.Conn.Unfetched{} = conn.body_params, path
        refute conn.halted, path
      end
    end
  end
end
