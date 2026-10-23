defmodule PhoenixKit.Modules.Storage.EndpointTest do
  @moduledoc """
  `Storage.Endpoint` — the one reading of an endpoint and the one guard on
  where the server may connect. Pure: DNS is injected, nothing touches the
  network.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage.Endpoint

  defp resolver(answers) do
    fn name, family ->
      case Map.fetch(answers, {to_string(name), family}) do
        {:ok, ips} -> {:ok, ips}
        :error -> {:error, :nxdomain}
      end
    end
  end

  describe "parse/1" do
    test "reads a bare host, host:port and an http(s) URL" do
      assert Endpoint.parse("s3.us-west-002.backblazeb2.com") ==
               %{scheme: "https", host: "s3.us-west-002.backblazeb2.com", port: 443}

      assert Endpoint.parse("https://abc.r2.cloudflarestorage.com/") ==
               %{scheme: "https", host: "abc.r2.cloudflarestorage.com", port: 443}

      assert Endpoint.parse("http://minio.local:9000") ==
               %{scheme: "http", host: "minio.local", port: 9000}
    end

    test "nothing set is plain AWS" do
      assert Endpoint.parse(nil) == nil
      assert Endpoint.parse("") == nil
      assert Endpoint.parse("   ") == nil
    end

    test "a set but unusable endpoint is an error, never plain AWS" do
      for endpoint <- ["ftp://nope", "https://h/prefix", "https://h/?x=1", "::1"] do
        assert Endpoint.parse(endpoint) == {:error, :invalid_endpoint}, endpoint
      end
    end
  end

  describe "classify/1" do
    test "IPv4 ranges" do
      assert Endpoint.classify({8, 8, 8, 8}) == :public
      assert Endpoint.classify({0, 0, 0, 0}) == :unspecified
      assert Endpoint.classify({127, 0, 0, 1}) == :loopback
      assert Endpoint.classify({10, 1, 2, 3}) == :private
      assert Endpoint.classify({172, 16, 0, 1}) == :private
      assert Endpoint.classify({172, 32, 0, 1}) == :public
      assert Endpoint.classify({192, 168, 1, 1}) == :private
      assert Endpoint.classify({169, 254, 169, 254}) == :link_local
      assert Endpoint.classify({100, 64, 0, 1}) == :shared
      assert Endpoint.classify({224, 0, 0, 1}) == :multicast
      assert Endpoint.classify({255, 255, 255, 255}) == :reserved
    end

    test "IPv6 ranges" do
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0, 1}) == :loopback
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0, 0}) == :unspecified
      assert Endpoint.classify({0xFC00, 0, 0, 0, 0, 0, 0, 1}) == :unique_local
      assert Endpoint.classify({0xFD12, 0, 0, 0, 0, 0, 0, 1}) == :unique_local
      assert Endpoint.classify({0xFE80, 0, 0, 0, 0, 0, 0, 1}) == :link_local
      assert Endpoint.classify({0xFF02, 0, 0, 0, 0, 0, 0, 1}) == :multicast
      assert Endpoint.classify({0x2606, 0x4700, 0, 0, 0, 0, 0, 1}) == :public
    end

    test "an IPv4 address wrapped in IPv6 is classified as the IPv4 address" do
      # ::ffff:169.254.169.254 and ::ffff:10.0.0.1 would otherwise slip past
      # an IPv4-only list.
      assert Endpoint.classify({0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE}) == :link_local
      assert Endpoint.classify({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001}) == :private
      assert Endpoint.classify({0x64, 0xFF9B, 0, 0, 0, 0, 0xA9FE, 0xA9FE}) == :link_local
      assert Endpoint.classify({0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808}) == :public
    end

    test "the IPv4-compatible form ::a.b.c.d is classified as the IPv4 address" do
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0x7F00, 0x0001}) == :loopback
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0x0A00, 0x0001}) == :private
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0xA9FE, 0xA9FE}) == :link_local
      assert Endpoint.classify({0, 0, 0, 0, 0, 0, 0x0808, 0x0808}) == :public
    end

    test "6to4 (2002::/16) is classified as the IPv4 address it embeds" do
      assert Endpoint.classify({0x2002, 0x7F00, 0x0001, 0, 0, 0, 0, 0}) == :loopback
      assert Endpoint.classify({0x2002, 0x0A00, 0x0001, 0, 0, 0, 0, 1}) == :private
      assert Endpoint.classify({0x2002, 0xA9FE, 0xA9FE, 0, 0, 0, 0, 1}) == :link_local
      assert Endpoint.classify({0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1}) == :public
    end

    test "well-known NAT64 (64:ff9b::/96) is classified by the embedded IPv4" do
      assert Endpoint.classify({0x64, 0xFF9B, 0, 0, 0, 0, 0x7F00, 0x0001}) == :loopback
      assert Endpoint.classify({0x64, 0xFF9B, 0, 0, 0, 0, 0x0808, 0x0808}) == :public
    end

    test "local-use NAT64 (64:ff9b:1::/48) is local as a whole" do
      # RFC 8215: the operator picks where the IPv4 address sits inside the
      # /48 (RFC 6052 layouts), so the last 32 bits mean nothing on their own.
      assert Endpoint.classify({0x64, 0xFF9B, 1, 0, 0, 0, 0x7F00, 0x0001}) == :unique_local
      assert Endpoint.classify({0x64, 0xFF9B, 1, 0, 0, 0, 0x0808, 0x0808}) == :unique_local
      # 64:ff9b:1:a00:0:100:808:808 — 10.0.0.1 in the /64 layout, 8.8.8.8 at the end.
      assert Endpoint.classify({0x64, 0xFF9B, 1, 0xA00, 0, 0x100, 0x808, 0x808}) ==
               :unique_local
    end

    test "deprecated site-local (fec0::/10) is local, like unique-local" do
      assert Endpoint.classify({0xFEC0, 0, 0, 0, 0, 0, 0, 1}) == :unique_local
      assert Endpoint.classify({0xFEFF, 0xFFFF, 0, 0, 0, 0, 0, 1}) == :unique_local
    end

    test "Teredo (2001::/32) and documentation (2001:db8::/32) are reserved" do
      assert Endpoint.classify({0x2001, 0, 0x4136, 0xE378, 0x8000, 0x63BF, 0x3FFF, 0xFDD2}) ==
               :reserved

      assert Endpoint.classify({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}) == :reserved
      assert Endpoint.classify({0x2001, 0xDB8, 0xFFFF, 0, 0, 0, 0, 1}) == :reserved
      # Neighbouring global unicast stays public.
      assert Endpoint.classify({0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888}) == :public
      assert Endpoint.classify({0x2001, 0xDB9, 0, 0, 0, 0, 0, 1}) == :public
    end

    test "the documentation range 3fff::/20 is reserved, its neighbours are not" do
      assert Endpoint.classify({0x3FFF, 0, 0, 0, 0, 0, 0, 1}) == :reserved
      assert Endpoint.classify({0x3FFF, 0x0FFF, 0xFFFF, 0, 0, 0, 0, 1}) == :reserved
      assert Endpoint.classify({0x3FFF, 0x1000, 0, 0, 0, 0, 0, 1}) == :public
      assert Endpoint.classify({0x3FFE, 0, 0, 0, 0, 0, 0, 1}) == :public
    end
  end

  describe "check/3 under :system (an admin set it)" do
    test "a local or private endpoint is allowed: a MinIO on the same network is normal" do
      assert Endpoint.check("http://127.0.0.1:9000", :system) == :ok
      assert Endpoint.check("http://10.0.0.5:9000", :system) == :ok
      assert Endpoint.check("http://[::1]:9000", :system) == :ok
    end

    test "metadata, link-local, unspecified and multicast are refused" do
      for endpoint <- [
            "http://169.254.169.254",
            "http://[fe80::1]:9000",
            "http://0.0.0.0:9000",
            "http://224.0.0.1",
            "http://[::ffff:169.254.169.254]",
            "http://[::169.254.169.254]",
            "http://[2002:a9fe:a9fe::1]",
            "http://[2001:db8::1]",
            "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]"
          ] do
        assert Endpoint.check(endpoint, :system) == {:error, :blocked_address}, endpoint
      end

      assert Endpoint.check("http://metadata.google.internal", :system) ==
               {:error, :blocked_host}
    end

    test "no endpoint is plain AWS, and an unparseable one stays an error" do
      assert Endpoint.check(nil, :system) == :ok
      assert Endpoint.check("ftp://nope", :system) == {:error, :invalid_endpoint}
    end
  end

  describe "check/3 under :personal (a user typed it)" do
    test "plain http is refused, https is fine" do
      assert Endpoint.check("http://8.8.8.8", :personal) == {:error, :insecure_scheme}
      assert Endpoint.check("https://8.8.8.8", :personal) == :ok
    end

    test "loopback, private, shared and unique-local addresses are refused" do
      for endpoint <- [
            "https://127.0.0.1",
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://100.64.0.1",
            "https://[fd00::1]",
            "https://[::1]",
            "https://169.254.169.254",
            "https://[::127.0.0.1]",
            "https://[2002:7f00:1::1]",
            "https://[64:ff9b:1::a00:1]",
            "https://[fec0::1]"
          ] do
        assert Endpoint.check(endpoint, :personal) == {:error, :blocked_address}, endpoint
      end
    end
  end

  describe "check/3 resolving a hostname" do
    test "every address the name yields is checked, not just the first" do
      dns =
        resolver(%{
          {"mixed.example.com", :inet} => [{8, 8, 8, 8}, {10, 0, 0, 1}],
          {"public.example.com", :inet} => [{8, 8, 8, 8}],
          {"public.example.com", :inet6} => [{0x2606, 0x4700, 0, 0, 0, 0, 0, 1}]
        })

      assert Endpoint.check("https://mixed.example.com", :personal, resolve: true, resolver: dns) ==
               {:error, :blocked_address}

      assert Endpoint.check("https://public.example.com", :personal,
               resolve: true,
               resolver: dns
             ) == :ok
    end

    test "an IPv6-only private record is caught too" do
      dns = resolver(%{{"v6.example.com", :inet6} => [{0xFD00, 0, 0, 0, 0, 0, 0, 1}]})

      assert Endpoint.check("https://v6.example.com", :personal, resolve: true, resolver: dns) ==
               {:error, :blocked_address}
    end

    test "a name that does not resolve is not refused: the request reports it" do
      assert Endpoint.check("https://nope.example.com", :personal,
               resolve: true,
               resolver: resolver(%{})
             ) == :ok
    end

    test "names are only resolved when asked to" do
      boom = fn _name, _family -> flunk("resolved without :resolve") end

      assert Endpoint.check("https://anything.example.com", :personal, resolver: boom) == :ok
    end
  end
end
