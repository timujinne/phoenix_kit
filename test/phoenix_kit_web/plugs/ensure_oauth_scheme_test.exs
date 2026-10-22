defmodule PhoenixKitWeb.Plugs.EnsureOAuthSchemeTest do
  # Reads and writes global application env.
  use ExUnit.Case, async: false

  alias PhoenixKitWeb.Plugs.EnsureOAuthScheme

  defmodule FakeEndpoint do
    def config(:otp_app), do: :ensure_oauth_scheme_test_app
  end

  @otp_app :ensure_oauth_scheme_test_app

  setup do
    previous = Application.fetch_env(:phoenix_kit, :oauth_base_url)
    previous_proxies = Application.fetch_env(:phoenix_kit, :trusted_proxies)
    Application.delete_env(:phoenix_kit, :oauth_base_url)
    Application.delete_env(:phoenix_kit, :trusted_proxies)

    on_exit(fn ->
      Application.delete_env(@otp_app, FakeEndpoint)
      restore(:oauth_base_url, previous)
      restore(:trusted_proxies, previous_proxies)
    end)
  end

  defp restore(key, {:ok, value}), do: Application.put_env(:phoenix_kit, key, value)
  defp restore(key, :error), do: Application.delete_env(:phoenix_kit, key)

  defp endpoint_url(url), do: Application.put_env(@otp_app, FakeEndpoint, url: url)

  defp run(url, headers \\ [], remote_ip \\ {203, 0, 113, 7}) do
    conn =
      url
      |> then(&Plug.Test.conn(:get, &1))
      |> Map.put(:remote_ip, remote_ip)
      |> Plug.Conn.put_private(:phoenix_endpoint, FakeEndpoint)

    conn = Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_req_header(c, k, v) end)
    r = EnsureOAuthScheme.call(conn, [])
    {r.scheme, r.host, r.port}
  end

  describe "no oauth_base_url (unset or empty), step 3" do
    test "a plain-http dev server on localhost stays http on its own port" do
      assert run("http://localhost:4000/users/auth/google") == {:http, "localhost", 4000}

      Application.put_env(:phoenix_kit, :oauth_base_url, "")
      assert run("http://localhost:4000/users/auth/google") == {:http, "localhost", 4000}
    end

    test "a dev endpoint that only names localhost stays http" do
      endpoint_url(host: "localhost")
      assert run("http://localhost:4000/x") == {:http, "localhost", 4000}
    end

    test "endpoint url https://example.com wins over the request host" do
      endpoint_url(host: "example.com", scheme: "https", port: 443)
      assert run("http://internal.svc:4000/x") == {:https, "example.com", 443}
    end

    test "endpoint url with host only is https on 443 for a real host" do
      endpoint_url(host: "example.com")
      assert run("http://internal.svc:4000/x") == {:https, "example.com", 443}
    end

    test "endpoint url with port 443 and no scheme is https" do
      endpoint_url(host: "example.com", port: 443)
      assert run("http://internal.svc:4000/x") == {:https, "example.com", 443}
    end

    test "an explicit http scheme and port are honoured" do
      endpoint_url(host: "staging.example.com", scheme: "http", port: 8080)
      assert run("http://internal.svc:4000/x") == {:http, "staging.example.com", 8080}
    end

    test "a leftover localhost endpoint host does not make another host http" do
      endpoint_url(host: "localhost")
      assert run("http://shop.example.com/x") == {:https, "localhost", 443}
    end

    test "every loopback spelling keeps a plain-http dev request http" do
      for {url_host, host} <- [
            {"127.0.0.1", "127.0.0.1"},
            {"[::1]", "::1"},
            {"app.localhost", "app.localhost"},
            {"localhost", "localhost"}
          ] do
        assert {:http, ^host, 4000} = run("http://#{url_host}:4000/x"), host
      end
    end

    test "a look-alike of localhost is not loopback" do
      for host <- ["fakelocalhost", "localhost.example.com"] do
        assert {:https, ^host, 443} = run("http://#{host}:4000/x"), host
      end
    end

    test "https with an endpoint port of 8443 keeps that port" do
      endpoint_url(host: "example.com", scheme: "https", port: 8443)
      assert run("http://example.com:4000/x") == {:https, "example.com", 8443}
    end

    test "a loopback dev endpoint with port 4001 uses that port" do
      endpoint_url(host: "localhost", port: 4001)
      assert run("http://localhost:4000/x") == {:http, "localhost", 4001}
    end

    test "endpoint host localhost with port 443 is https" do
      endpoint_url(host: "localhost", port: 443)
      assert run("http://localhost:4000/x") == {:https, "localhost", 443}
    end

    test "a real host with endpoint port 4000 and no scheme is https on 4000" do
      endpoint_url(host: "example.com", port: 4000)
      assert run("http://example.com:4000/x") == {:https, "example.com", 4000}
    end

    test "no endpoint url on a non-loopback host keeps the https:443 default of existing installs" do
      assert run("http://shop.example.com:4000/x") == {:https, "shop.example.com", 443}
    end
  end

  describe "endpoint url port forms and a missing endpoint" do
    test "a numeric-string port 443 is https and the port stays an integer" do
      endpoint_url(host: "localhost", port: "443")
      assert run("http://localhost:4000/x") == {:https, "localhost", 443}
    end

    test "a numeric-string port is used as an integer" do
      endpoint_url(host: "example.com", port: "8443")
      assert run("http://example.com:4000/x") == {:https, "example.com", 8443}
    end

    test "a {:system, var} port is read from the environment" do
      System.put_env("ENSURE_OAUTH_SCHEME_TEST_PORT", "443")
      on_exit(fn -> System.delete_env("ENSURE_OAUTH_SCHEME_TEST_PORT") end)

      endpoint_url(host: "localhost", port: {:system, "ENSURE_OAUTH_SCHEME_TEST_PORT"})
      assert run("http://localhost:4000/x") == {:https, "localhost", 443}
    end

    test "an unreadable port is treated as unset" do
      endpoint_url(host: "localhost", port: "not-a-port")
      assert run("http://localhost:4000/x") == {:http, "localhost", 4000}
    end

    test "a conn that never went through an endpoint follows the same defaults" do
      call = fn url ->
        r = EnsureOAuthScheme.call(Plug.Test.conn(:get, url), [])
        {r.scheme, r.host, r.port}
      end

      assert call.("http://localhost:4000/x") == {:http, "localhost", 4000}
      assert call.("http://shop.example.com:4000/x") == {:https, "shop.example.com", 443}
    end
  end

  describe "other steps" do
    test "an explicit oauth_base_url wins over the endpoint url" do
      Application.put_env(:phoenix_kit, :oauth_base_url, "https://auth.example.org")
      endpoint_url(host: "example.com", scheme: "https", port: 443)
      assert run("http://localhost:4000/x") == {:https, "auth.example.org", 443}
    end

    test "X-Forwarded-Proto from a trusted proxy applies as before" do
      Application.put_env(:phoenix_kit, :trusted_proxies, ["203.0.113.0/24"])
      endpoint_url(host: "localhost")

      assert run("http://localhost:4000/x", [{"x-forwarded-proto", "https"}]) ==
               {:https, "localhost", 443}
    end

    test "X-Forwarded-Proto from an untrusted peer is ignored" do
      Application.put_env(:phoenix_kit, :trusted_proxies, ["198.51.100.0/24"])
      endpoint_url(host: "localhost")

      assert run("http://localhost:4000/x", [{"x-forwarded-proto", "https"}]) ==
               {:http, "localhost", 4000}
    end
  end
end
