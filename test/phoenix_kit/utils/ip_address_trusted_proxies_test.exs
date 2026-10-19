defmodule PhoenixKit.Utils.IpAddressTrustedProxiesTest do
  # The option is global application env and the warning flag is per-VM.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Utils.IpAddress

  @warned_key {IpAddress, :unconfigured_proxies_warned}
  @invalid_key {IpAddress, :invalid_proxies_warned}

  setup do
    previous = Application.fetch_env(:phoenix_kit, :trusted_proxies)
    Application.delete_env(:phoenix_kit, :trusted_proxies)
    :persistent_term.erase(@warned_key)
    :persistent_term.erase(@invalid_key)

    # test_helper.exs marks both warnings as already said so other tests'
    # capture_log stays clean; leave it that way.
    on_exit(fn ->
      :persistent_term.put(@warned_key, true)
      :persistent_term.put(@invalid_key, true)

      case previous do
        {:ok, value} -> Application.put_env(:phoenix_kit, :trusted_proxies, value)
        :error -> Application.delete_env(:phoenix_kit, :trusted_proxies)
      end
    end)
  end

  defp trust(value), do: Application.put_env(:phoenix_kit, :trusted_proxies, value)
  defp conn(ip, headers), do: %Plug.Conn{remote_ip: ip, req_headers: headers}

  defp socket(ip, x_headers) do
    %Phoenix.LiveView.Socket{
      private: %{connect_info: %{peer_data: %{address: ip}, x_headers: x_headers}}
    }
  end

  @xff [{"x-forwarded-for", "9.9.9.9, 203.0.113.7"}]
  @real_ip [{"x-real-ip", "203.0.113.9"}]

  describe "a list of blocks" do
    test "a peer inside a block is believed (x-forwarded-for and x-real-ip)" do
      trust(["172.18.0.0/16"])
      assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "203.0.113.7"
      assert IpAddress.client_address(conn({172, 18, 0, 7}, @real_ip)) == "203.0.113.9"
    end

    test "a bare address is a single host" do
      trust(["172.18.0.7"])
      assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "203.0.113.7"
      assert IpAddress.client_address(conn({172, 18, 0, 8}, @xff)) == "172.18.0.8"
    end

    test "a private peer outside every block is the client, headers ignored" do
      trust(["172.18.0.7/32"])
      assert IpAddress.client_address(conn({172, 18, 0, 8}, @xff)) == "172.18.0.8"
      assert IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) == "127.0.0.1"
      assert IpAddress.client_address(conn({10, 0, 0, 5}, @real_ip)) == "10.0.0.5"
    end

    test "a public peer inside a block is believed; outside it is not" do
      trust(["198.51.100.0/24"])
      assert IpAddress.client_address(conn({198, 51, 100, 4}, @xff)) == "203.0.113.7"
      assert IpAddress.client_address(conn({203, 0, 113, 50}, @xff)) == "203.0.113.50"
    end

    test "a trusted peer without a usable header is itself" do
      trust(["172.18.0.0/16"])
      assert IpAddress.client_address(conn({172, 18, 0, 7}, [])) == "172.18.0.7"

      assert IpAddress.client_address(conn({172, 18, 0, 7}, [{"x-forwarded-for", "junk"}])) ==
               "172.18.0.7"
    end

    test "IPv6 blocks and IPv6 peers" do
      trust(["2001:db8:1::/48", "::1"])
      inside = {0x2001, 0xDB8, 1, 0, 0, 0, 0, 5}
      outside = {0x2001, 0xDB8, 2, 0, 0, 0, 0, 5}

      assert IpAddress.client_address(conn(inside, @xff)) == "203.0.113.7"
      assert IpAddress.client_address(conn(outside, @xff)) == "2001:db8:2::5"
      assert IpAddress.client_address(conn({0, 0, 0, 0, 0, 0, 0, 1}, @xff)) == "203.0.113.7"
    end

    test "a forwarded IPv6 client is read from a trusted IPv4 peer" do
      trust(["172.18.0.7/32"])
      headers = [{"x-forwarded-for", "[2001:db8::7]:28858"}]
      assert IpAddress.client_address(conn({172, 18, 0, 7}, headers)) == "2001:db8::7"
    end

    test "an IPv4-mapped peer matches an IPv4 block, and an IPv4 peer never an IPv6 one" do
      trust(["172.18.0.0/16"])
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0xAC12, 7}
      assert IpAddress.client_address(conn(mapped, @xff)) == "203.0.113.7"

      trust(["2001:db8::/32"])
      assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "172.18.0.7"
    end

    test "a malformed entry matches nothing" do
      trust(["not a block", "172.18.0.0/99"])

      capture_log(fn ->
        assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "172.18.0.7"
      end)
    end
  end

  describe "an empty list" do
    test "trusts nobody: the client is the peer" do
      trust([])
      assert IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) == "127.0.0.1"
      assert IpAddress.client_address(conn({172, 18, 0, 7}, @real_ip)) == "172.18.0.7"
      assert IpAddress.client_address(conn({203, 0, 113, 50}, @xff)) == "203.0.113.50"
    end

    test "never logs the unconfigured warning" do
      trust([])
      log = capture_log(fn -> IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) end)
      refute log =~ "trusted_proxies"
    end
  end

  describe "a misconfigured value" do
    test "a string instead of a list trusts nobody and warns once" do
      trust("172.18.0.7/32")

      first =
        capture_log(fn ->
          assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "172.18.0.7"
        end)

      assert first =~ "is invalid"
      assert first =~ "172.18.0.7/32"

      second = capture_log(fn -> IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) end)
      refute second =~ "is invalid"
    end

    test "an unreadable entry matches nothing, the rest still works, and it warns" do
      trust([{172, 18, 0, 7}, "172.18.0.0/99", "10.0.0.0/8"])

      log =
        capture_log(fn ->
          assert IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) == "172.18.0.7"
          assert IpAddress.client_address(conn({10, 0, 0, 5}, @xff)) == "203.0.113.7"
        end)

      assert log =~ "is invalid"
      assert log =~ "172.18.0.0/99"
    end

    test "the socket path fails closed too" do
      trust(:everyone)

      capture_log(fn ->
        assert IpAddress.client_address_from_socket(socket({172, 18, 0, 7}, @xff)) ==
                 "172.18.0.7"
      end)
    end

    test "a valid list and [] do not warn" do
      trust(["172.18.0.0/16"])
      log = capture_log(fn -> IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) end)
      refute log =~ "is invalid"

      trust([])
      log = capture_log(fn -> IpAddress.client_address(conn({172, 18, 0, 7}, @xff)) end)
      refute log =~ "is invalid"
    end
  end

  describe "not set" do
    test "behaves as before: a local peer is believed, a public one is not" do
      capture_log(fn ->
        assert IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) == "203.0.113.7"
        assert IpAddress.client_address(conn({172, 18, 0, 7}, @real_ip)) == "203.0.113.9"
        assert IpAddress.client_address(conn({203, 0, 113, 50}, @xff)) == "203.0.113.50"
      end)
    end

    test "warns once per VM, on the first honoured header" do
      first = capture_log(fn -> IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) end)
      assert first =~ "trusted_proxies"

      second = capture_log(fn -> IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) end)
      refute second =~ "trusted_proxies"
    end

    test "does not warn when no header was honoured" do
      log =
        capture_log(fn ->
          IpAddress.client_address(conn({127, 0, 0, 1}, []))
          IpAddress.client_address(conn({203, 0, 113, 50}, @xff))
          IpAddress.client_address(conn({127, 0, 0, 1}, [{"x-forwarded-for", "junk"}]))
        end)

      refute log =~ "trusted_proxies"
    end

    test "a configured list never warns" do
      trust(["127.0.0.1/32"])
      log = capture_log(fn -> IpAddress.client_address(conn({127, 0, 0, 1}, @xff)) end)
      refute log =~ "trusted_proxies"
    end
  end

  describe "client_address_from_socket/1" do
    test "a listed peer is a proxy: the forwarded address is the visitor" do
      trust(["172.18.0.7/32"])
      assert IpAddress.client_address_from_socket(socket({172, 18, 0, 7}, @xff)) == "203.0.113.7"

      assert IpAddress.client_address_from_socket(socket({172, 18, 0, 7}, @real_ip)) ==
               "203.0.113.9"
    end

    test "a listed peer with no forwarded header cannot tell" do
      trust(["172.18.0.7/32"])
      assert IpAddress.client_address_from_socket(socket({172, 18, 0, 7}, [])) == nil
    end

    test "a private peer outside the list is the visitor, headers ignored" do
      trust(["172.18.0.7/32"])
      assert IpAddress.client_address_from_socket(socket({172, 18, 0, 8}, @xff)) == "172.18.0.8"
    end

    test "an IPv6 peer is matched against IPv6 blocks" do
      trust(["2001:db8:1::/48"])
      peer = {0x2001, 0xDB8, 1, 0, 0, 0, 0, 5}
      assert IpAddress.client_address_from_socket(socket(peer, @xff)) == "203.0.113.7"

      other = {0x2001, 0xDB8, 2, 0, 0, 0, 0, 5}
      assert IpAddress.client_address_from_socket(socket(other, @xff)) == "2001:db8:2::5"
    end

    test "an empty list trusts nobody" do
      trust([])
      assert IpAddress.client_address_from_socket(socket({127, 0, 0, 1}, @xff)) == "127.0.0.1"
    end

    test "not set: a local peer is a proxy and warns once" do
      log =
        capture_log(fn ->
          assert IpAddress.client_address_from_socket(socket({127, 0, 0, 1}, @xff)) ==
                   "203.0.113.7"

          assert IpAddress.client_address_from_socket(socket({127, 0, 0, 1}, [])) == nil

          assert IpAddress.client_address_from_socket(socket({203, 0, 113, 50}, @xff)) ==
                   "203.0.113.50"
        end)

      assert log =~ "trusted_proxies"
    end
  end

  test "extract_from_conn/1 follows the same rule" do
    trust(["172.18.0.7/32"])
    assert IpAddress.extract_from_conn(conn({172, 18, 0, 7}, @xff)) == "203.0.113.7"
    assert IpAddress.extract_from_conn(conn({172, 18, 0, 8}, @xff)) == "172.18.0.8"
  end
end
