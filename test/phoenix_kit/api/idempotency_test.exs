defmodule PhoenixKit.API.IdempotencyTest do
  @moduledoc """
  `PhoenixKit.API.Idempotency` against the real table: the claim rules, the lease and
  the takeover, expired rows, the exact replay, which bodies may be stored, release and
  prune. Time is a parameter, so nothing sleeps.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.API.Idempotency
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.API.KeyTestSupport

  setup do
    KeyTestSupport.start_cache_registry!()
  end

  @hash String.duplicate("a", 64)
  @other String.duplicate("b", 64)

  defp unique_key,
    do:
      "key-" <> String.pad_leading(Integer.to_string(System.unique_integer([:positive])), 20, "0")

  defp row(claim), do: Repo.get!(Record, claim.uuid)
  defp later(time, seconds), do: DateTime.add(time, seconds, :second)

  describe "claim/4" do
    test "the first claim wins: the row is in_progress and lives a day" do
      key = unique_key()
      t0 = DateTime.utc_now()

      assert {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)

      record = row(claim)
      assert record.state == "in_progress"
      assert record.response == nil
      assert record.request_hash == @hash
      assert record.locked_at == claim.locked_at
      assert DateTime.diff(record.expires_at, t0) in 86_398..86_401
    end

    test "the same request while the lease is alive is in_progress" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, _} = Idempotency.claim("scope", key, @hash, t0)

      assert {:error, :in_progress} = Idempotency.claim("scope", key, @hash, later(t0, 119))
    end

    test "another request with the same key is reused, while the first runs and after it is done" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)

      assert {:error, :reused} = Idempotency.claim("scope", key, @other, later(t0, 1))

      :ok = Idempotency.store(claim, ~s({"ok":true}))
      assert {:error, :reused} = Idempotency.claim("scope", key, @other, later(t0, 2))
    end

    test "a stored answer is replayed, byte for byte" do
      key = unique_key()
      t0 = DateTime.utc_now()
      body = ~s({"written":"x","n":[1,2],"z":{"b":1,"a":2}})
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)

      assert :ok = Idempotency.store(claim, body)

      assert {:replay, ^body} = Idempotency.claim("scope", key, @hash, later(t0, 5))
      assert row(claim).state == "done"
    end

    test "an expired lease lets the same request take over, and the first run can no longer store" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, first} = Idempotency.claim("scope", key, @hash, t0)

      assert {:claimed, second} = Idempotency.claim("scope", key, @hash, later(t0, 121))
      assert second.uuid == first.uuid
      assert DateTime.compare(second.locked_at, first.locked_at) == :gt

      assert :lost = Idempotency.store(first, ~s({"late":true}))
      assert row(first).state == "in_progress"

      assert :ok = Idempotency.store(second, ~s({"ok":true}))
      assert {:replay, ~s({"ok":true})} = Idempotency.claim("scope", key, @hash, later(t0, 130))
    end

    test "an expired lease with a different request is still reused" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, _} = Idempotency.claim("scope", key, @hash, t0)

      assert {:error, :reused} = Idempotency.claim("scope", key, @other, later(t0, 500))
    end

    test "an expired row nobody pruned yet is a new claim, never a replay" do
      key = unique_key()
      t0 = DateTime.utc_now()
      t1 = later(t0, 25 * 3600)
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)
      :ok = Idempotency.store(claim, ~s({"old":true}))

      assert {:claimed, again} = Idempotency.claim("scope", key, @other, t1)

      record = row(again)
      assert record.response == nil
      assert record.state == "in_progress"
      assert record.request_hash == @other
    end

    test "a takeover gives the row a new lifetime, so the next retry replays" do
      key = unique_key()
      t0 = DateTime.utc_now()
      t1 = later(t0, 25 * 3600)
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)
      :ok = Idempotency.store(claim, ~s({"old":true}))

      assert {:claimed, again} = Idempotency.claim("scope", key, @hash, t1)
      assert DateTime.diff(row(again).expires_at, t1) in 86_398..86_401

      body = ~s({"new":true})
      assert :ok = Idempotency.store(again, body)
      assert {:replay, ^body} = Idempotency.claim("scope", key, @hash, later(t1, 60))
    end

    test "scopes and keys are independent" do
      key = unique_key()
      t0 = DateTime.utc_now()

      assert {:claimed, _} = Idempotency.claim("scope-a", key, @hash, t0)
      assert {:claimed, _} = Idempotency.claim("scope-b", key, @hash, t0)
      assert {:claimed, _} = Idempotency.claim("scope-a", unique_key(), @hash, t0)
    end

    test "a stored answer or a running claim never crosses into another scope" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, a} = Idempotency.claim("scope-a", key, @hash, t0)
      {:claimed, b} = Idempotency.claim("scope-b", key, @hash, t0)

      :ok = Idempotency.store(a, ~s({"owner":"a"}))

      assert {:error, :in_progress} = Idempotency.claim("scope-b", key, @hash, later(t0, 1))
      assert {:replay, ~s({"owner":"a"})} = Idempotency.claim("scope-a", key, @hash, later(t0, 1))

      :ok = Idempotency.store(b, ~s({"owner":"b"}))
      assert {:replay, ~s({"owner":"b"})} = Idempotency.claim("scope-b", key, @hash, later(t0, 2))
      assert {:replay, ~s({"owner":"a"})} = Idempotency.claim("scope-a", key, @hash, later(t0, 2))
    end

    test "a clock with second precision is accepted" do
      t0 = DateTime.truncate(DateTime.utc_now(), :second)
      key = unique_key()

      assert {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)
      assert {:error, :in_progress} = Idempotency.claim("scope", key, @hash, later(t0, 1))
      assert :ok = Idempotency.store(claim, ~s({"ok":true}))
    end

    test "the lease is a setting" do
      KeyTestSupport.put_setting("api_idempotency_lease_seconds", 5)
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, _} = Idempotency.claim("scope", key, @hash, t0)

      assert {:error, :in_progress} = Idempotency.claim("scope", key, @hash, later(t0, 4))
      assert {:claimed, _} = Idempotency.claim("scope", key, @hash, later(t0, 6))
    end

    test "the time to live is a setting" do
      KeyTestSupport.put_setting("api_idempotency_ttl_hours", 1)
      t0 = DateTime.utc_now()
      {:claimed, claim} = Idempotency.claim("scope", unique_key(), @hash, t0)

      assert DateTime.diff(row(claim).expires_at, t0) in 3598..3601
    end

    # Serial on purpose: the claim race over real connections is in
    # IdempotencyConcurrencyTest.
    test "twelve claims of one key in a row give one winner" do
      key = unique_key()

      results = Enum.map(1..12, fn _ -> Idempotency.claim("scope", key, @hash) end)

      assert Enum.count(results, &match?({:claimed, _}, &1)) == 1
      assert Enum.count(results, &(&1 == {:error, :in_progress})) == 11
      assert Repo.aggregate(from(r in Record, where: r.key == ^key), :count) == 1
    end
  end

  describe "store/2 and release/1" do
    test "release drops a running claim, so the key can be used again" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)

      assert :ok = Idempotency.release(claim)
      assert Repo.get(Record, claim.uuid) == nil
      assert {:claimed, _} = Idempotency.claim("scope", key, @other, later(t0, 1))
    end

    test "release of a claim that was taken over leaves the new claim alone" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, first} = Idempotency.claim("scope", key, @hash, t0)
      {:claimed, second} = Idempotency.claim("scope", key, @hash, later(t0, 121))

      assert :ok = Idempotency.release(first)

      assert row(second).state == "in_progress"
      assert row(second).locked_at == second.locked_at
    end

    test "a second store does not overwrite an answer that was already stored" do
      key = unique_key()
      t0 = DateTime.utc_now()
      {:claimed, claim} = Idempotency.claim("scope", key, @hash, t0)
      first = ~s({"first":true})
      :ok = Idempotency.store(claim, first)

      assert :lost = Idempotency.store(claim, ~s({"second":true}))
      assert {:replay, ^first} = Idempotency.claim("scope", key, @hash, later(t0, 1))
    end

    test "release never deletes a stored answer" do
      key = unique_key()
      {:claimed, claim} = Idempotency.claim("scope", key, @hash)
      :ok = Idempotency.store(claim, ~s({"ok":true}))

      assert :ok = Idempotency.release(claim)
      assert row(claim).state == "done"
    end
  end

  describe "storable?/2 and credential_bearing?/2" do
    test "a plain body is storable" do
      assert Idempotency.storable?(~s({"written":"x","rows":[{"id":"a"},{"id":"b"}]}))
    end

    test "a client token, a confirmation code or a claim token anywhere in the body is not" do
      for body <- [
            ~s({"session_token":"abc"}),
            ~s({"session":{"session_token":"abc"}}),
            ~s({"lines":[{"ok":true},{"nested":{"confirm_token":"ct_x"}}]}),
            ~s({"claim_token":"abc"}),
            ~s({"Session_Token":"abc"})
          ] do
        refute Idempotency.storable?(body), body
        assert Idempotency.credential_bearing?(body), body
      end
    end

    test "every name core treats as a credential is refused, at any depth and in any case" do
      for name <-
            ~w(confirm_token api_key apikey api-key authorization bearer access_token token secret
               session_token refresh_token cart_token) do
        refute Idempotency.storable?(JSON.encode!(%{name => "x"})), name

        refute Idempotency.storable?(JSON.encode!(%{"a" => [%{String.upcase(name) => "x"}]})),
               name
      end
    end

    test "a field the tool declares as a credential is refused, and only for that tool" do
      body = ~s({"url":"https://shop.example/x","count":1})

      assert Idempotency.storable?(body)
      assert Idempotency.storable?(body, ["other"])
      refute Idempotency.storable?(body, ["url"])
      refute Idempotency.storable?(body, ["URL"])
      refute Idempotency.storable?(~s({"a":[{"url":"x"}]}), ["url"])
      assert Idempotency.credential_bearing?(body, ["url"])
      refute Idempotency.credential_bearing?(body)
    end

    test "the names and the marker of the old checkout links are still credentials (legacy)" do
      for name <- ~w(claim_url checkout_url claim_token) do
        refute Idempotency.storable?(JSON.encode!(%{name => "x"})), name
      end

      refute Idempotency.storable?(~s({"url":"https://shop.example/checkout/claim/AbC123"}))
      refute Idempotency.storable?(~s({"url":"https://shop.example/Checkout/Claim/AbC123"}))
      refute Idempotency.storable?(~s({"link":{"href":"https://shop.example/checkout/claim/x"}}))
    end

    test "an API key anywhere in the body is not" do
      refute Idempotency.storable?(~s({"note":"pk_0123abcd_secretsecret"}))
      refute Idempotency.storable?(~s({"api_key":"x"}))
    end

    test "a field that merely resembles a credential name is fine" do
      assert Idempotency.storable?(
               ~s({"token_count":3,"tokens_issued":0,"session-token":"x","url":"https://shop.example/item/x"})
             )
    end

    test "a body over 1 MB is not storable, one of exactly 1 MB is" do
      overhead = byte_size(JSON.encode!(%{"pad" => ""}))
      at_limit = JSON.encode!(%{"pad" => String.duplicate("a", 1_048_576 - overhead)})
      over = JSON.encode!(%{"pad" => String.duplicate("a", 1_048_576 - overhead + 1)})

      assert byte_size(at_limit) == 1_048_576
      assert Idempotency.storable?(at_limit)
      assert byte_size(over) == 1_048_577
      refute Idempotency.storable?(over)
    end

    test "a body that is not JSON is not storable" do
      refute Idempotency.storable?("not json")
      refute Idempotency.storable?("")
    end
  end

  describe "prune/1" do
    test "deletes rows whose time has passed and keeps the others" do
      t0 = DateTime.utc_now()
      {:claimed, old} = Idempotency.claim("scope", unique_key(), @hash, later(t0, -48 * 3600))
      {:claimed, fresh} = Idempotency.claim("scope", unique_key(), @hash, t0)

      assert Idempotency.prune(t0) >= 1

      assert Repo.get(Record, old.uuid) == nil
      assert Repo.get(Record, fresh.uuid)
    end

    test "a row that expires exactly now is deleted" do
      t0 = DateTime.utc_now()
      {:claimed, claim} = Idempotency.claim("scope", unique_key(), @hash, later(t0, -24 * 3600))
      assert row(claim).expires_at == DateTime.truncate(t0, :second)

      Idempotency.prune(t0)

      assert Repo.get(Record, claim.uuid) == nil
    end
  end
end
