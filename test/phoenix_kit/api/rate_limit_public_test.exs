defmodule PhoenixKit.API.RateLimitPublicTest do
  @moduledoc """
  The public buckets: the client network's room first, then the client token, then
  the network is charged.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport

  alias PhoenixKit.API.RateLimit
  alias PhoenixKit.Users.RateLimiter.Backend

  @unknown_ip_key "api:public:ip:unknown"

  setup do
    start_cache_registry!()
    wait_for_window_room()
    # The one counter every request without a client address shares; start each
    # test from zero and leave it that way.
    Backend.set(@unknown_ip_key, 60_000, 0)
    on_exit(fn -> Backend.set(@unknown_ip_key, 60_000, 0) end)
    :ok
  end

  describe "check_public/3 and /4" do
    test "an anonymous request is counted against the network only" do
      set_limit("api_public_ip_rate_per_min", 2)
      ip = unique_ip()

      assert {:ok, headers} = RateLimit.check_public(ip, nil, 1)
      assert header_value(headers, "ratelimit-limit") == 2
      assert header_value(headers, "ratelimit-remaining") == 1
      assert {:ok, _} = RateLimit.check_public(ip, nil, 1)
      assert {:error, retry_after, headers} = RateLimit.check_public(ip, nil, 1)
      assert retry_after in 1..60
      assert header_value(headers, "retry-after") == retry_after
    end

    test "a client token has its own bucket; other tokens from the same network are unaffected" do
      set_limit("api_public_token_rate_per_min", 2)
      set_limit("api_public_ip_rate_per_min", 100)
      ip = unique_ip()
      token_a = unique_token()
      token_b = unique_token()

      assert {:ok, _} = RateLimit.check_public(ip, token_a, 1)
      assert {:ok, headers} = RateLimit.check_public(ip, token_a, 1)
      assert header_value(headers, "ratelimit-limit") == 2
      assert header_value(headers, "ratelimit-remaining") == 0
      assert {:error, _, _} = RateLimit.check_public(ip, token_a, 1)

      assert {:ok, _} = RateLimit.check_public(ip, token_b, 1)
    end

    test "a request without a client address is still counted, in one shared bucket" do
      set_limit("api_public_ip_rate_per_min", 2)

      assert {:ok, headers} = RateLimit.check_public(nil, nil, 1)
      assert header_value(headers, "ratelimit-limit") == 2
      assert header_value(headers, "ratelimit-remaining") == 1
      assert {:ok, headers} = RateLimit.check_public(nil, nil, 1)
      assert header_value(headers, "ratelimit-remaining") == 0
      assert {:error, _, _} = RateLimit.check_public(nil, nil, 1)
    end

    test "the network bucket caps all tokens behind one address" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 3)
      ip = unique_ip()

      for _ <- 1..3, do: assert({:ok, _} = RateLimit.check_public(ip, unique_token(), 1))
      assert {:error, _, headers} = RateLimit.check_public(ip, unique_token(), 1)
      assert header_value(headers, "ratelimit-limit") == 3
    end

    test "a request refused by the token bucket is not charged to the network bucket" do
      set_limit("api_public_token_rate_per_min", 1)
      set_limit("api_public_ip_rate_per_min", 3)
      ip = unique_ip()
      noisy = unique_token()

      assert {:ok, _} = RateLimit.check_public(ip, noisy, 1)
      for _ <- 1..10, do: assert({:error, _, _} = RateLimit.check_public(ip, noisy, 1))

      # Only one unit of the network bucket was spent: two more clients fit.
      assert {:ok, _} = RateLimit.check_public(ip, unique_token(), 1)
      assert {:ok, _} = RateLimit.check_public(ip, unique_token(), 1)
      assert {:error, _, _} = RateLimit.check_public(ip, unique_token(), 1)
    end

    test "a client over its network limit creates no token counters with fresh tokens" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 2)
      ip = unique_ip()

      for _ <- 1..2, do: assert({:ok, _} = RateLimit.check_public(ip, unique_token(), 1))

      for _ <- 1..20 do
        token = unique_token()
        assert {:error, retry_after, headers} = RateLimit.check_public(ip, token, 1)
        assert retry_after in 1..60
        assert header_value(headers, "retry-after") == retry_after
        assert header_value(headers, "ratelimit-limit") == 2
        assert header_value(headers, "ratelimit-remaining") == 0
        assert Backend.get("api:public:token:" <> token, 60_000) == 0
      end
    end

    test "a cost that does not fit the network window is refused without a token counter" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 5)
      ip = unique_ip()
      token = unique_token()

      assert {:ok, _} = RateLimit.check_public(ip, unique_token(), 3)
      assert {:error, _, _} = RateLimit.check_public(ip, token, 3)
      assert Backend.get("api:public:token:" <> token, 60_000) == 0
      # The refused call took nothing from the window: two units still fit.
      assert {:ok, headers} = RateLimit.check_public(ip, token, 2)
      assert header_value(headers, "ratelimit-remaining") == 0
    end

    test "the headers describe the bucket with the least room left" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 5)

      assert {:ok, headers} = RateLimit.check_public(unique_ip(), unique_token(), 2)
      assert header_value(headers, "ratelimit-limit") == 5
      assert header_value(headers, "ratelimit-remaining") == 3
    end

    test "weights a call by its cost" do
      set_limit("api_public_ip_rate_per_min", 10)
      ip = unique_ip()

      assert {:ok, headers} = RateLimit.check_public(ip, nil, 7)
      assert header_value(headers, "ratelimit-remaining") == 3
      assert {:error, _, _} = RateLimit.check_public(ip, nil, 4)
    end

    test "a separate network cost charges the token the full cost and the network the given part" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 100)
      ip = unique_ip()
      token = unique_token()

      assert {:ok, _} = RateLimit.check_public(ip, token, 5, 2)
      assert Backend.get("api:public:token:" <> token, 60_000) == 5
      assert Backend.get("api:public:ip:" <> ip, 60_000) == 2
    end

    test "a network cost of 0 charges the token only, and the headers still weigh the network" do
      set_limit("api_public_token_rate_per_min", 100)
      set_limit("api_public_ip_rate_per_min", 5)
      ip = unique_ip()
      token = unique_token()

      assert {:ok, _} = RateLimit.check_public(ip, nil, 3)
      assert {:ok, headers} = RateLimit.check_public(ip, token, 1, 0)

      assert Backend.get("api:public:token:" <> token, 60_000) == 1
      assert Backend.get("api:public:ip:" <> ip, 60_000) == 3
      assert header_value(headers, "ratelimit-limit") == 5
      assert header_value(headers, "ratelimit-remaining") == 2
    end

    test "a token over its limit is refused although the network has room, and the network is not charged" do
      set_limit("api_public_token_rate_per_min", 2)
      set_limit("api_public_ip_rate_per_min", 100)
      ip = unique_ip()

      assert {:error, _, _} = RateLimit.check_public(ip, unique_token(), 3, 2)
      assert Backend.get("api:public:ip:" <> ip, 60_000) == 0
    end

    test "refuses a cost that is not a positive integer" do
      for bad <- [0, -1, 1.5, nil] do
        assert_raise FunctionClauseError, fn -> RateLimit.check_public(unique_ip(), nil, bad) end
      end
    end
  end
end
