defmodule PhoenixKit.API.OAuth.RequestLogTest do
  @moduledoc """
  What is written to the log for a request to the consent page: its token is a capability, so the
  endpoint's request line is switched off for it and the kit's timer line shows `[FILTERED]`.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.OAuth.RequestLog
  alias PhoenixKit.Utils.Routes

  @token String.duplicate("a", 43)

  defp conn(path), do: %Plug.Conn{request_path: path}

  describe "level/1" do
    test "is false for the consent page and its disconnect form" do
      assert RequestLog.level(conn(Routes.path("/oauth/consent/" <> @token))) == false

      assert RequestLog.level(conn(Routes.path("/oauth/consent/" <> @token <> "/revoke"))) ==
               false
    end

    test "is :info, the default of Plug.Telemetry, for every other path" do
      for path <- ["/oauth/authorize", "/oauth/token", "/oauth/consent", "/users/log-in", "/"] do
        assert RequestLog.level(conn(Routes.path(path))) == :info
      end
    end
  end

  describe "path/1" do
    test "hides the token of a consent path" do
      assert RequestLog.path(conn(Routes.path("/oauth/consent/" <> @token))) ==
               Routes.path("/oauth/consent/[FILTERED]")

      assert RequestLog.path(conn(Routes.path("/oauth/consent/" <> @token <> "/revoke"))) ==
               Routes.path("/oauth/consent/[FILTERED]/revoke")
    end

    test "leaves any other path as it is" do
      for path <- ["/oauth/authorize", "/oauth/consent", "/mcp/admin", "/"] do
        assert RequestLog.path(conn(Routes.path(path))) == Routes.path(path)
      end
    end
  end
end
