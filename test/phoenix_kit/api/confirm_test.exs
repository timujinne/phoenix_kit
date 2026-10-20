defmodule PhoenixKit.API.ConfirmTest do
  @moduledoc """
  `PhoenixKit.API.Confirm`: issuing a code, the cheap checks (`lookup_token/5`), the
  atomic claim (`claim_token/3`) and `live_actor/1`. Real keys, real rows, the clock is
  a parameter.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport

  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Confirm
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Confirm.Token
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Keys.Key
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions

  @tool "testkit.write_item"
  @hash String.duplicate("1", 64)
  @fp String.duplicate("f", 64)

  setup do
    register_fake_module!()
    start_key_cache!()
    {user, role, scope} = api_holder(["media", "media.manage"])
    scopes = [read_scope(), write_scope()]
    {key, _token} = create_key!(user, scope, %{name: "confirm", scopes: scopes})

    actor = %Actor{
      kind: :key,
      key_uuid: key.uuid,
      key_prefix: key.prefix,
      user_uuid: user.uuid,
      scopes: scopes
    }

    %{user: user, role: role, scope: scope, key: key, actor: actor}
  end

  defp issue(actor, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    {:ok, issued} =
      Confirm.issue_token(
        actor,
        @tool,
        Keyword.get(opts, :hash, @hash),
        %{"rows" => [1, 2]},
        Keyword.get(opts, :fp, @fp),
        now
      )

    issued
  end

  defp later(time, seconds), do: DateTime.add(time, seconds, :second)
  defp past, do: DateTime.utc_now() |> DateTime.add(-5, :second) |> DateTime.truncate(:second)

  describe "issue_token/6" do
    test "stores an unused row bound to the key, the tool, the arguments and the values", %{
      actor: actor,
      key: key
    } do
      t0 = DateTime.utc_now()
      issued = issue(actor, now: t0)

      row = Repo.get!(Confirmation, issued.row.uuid)
      assert row.kind == "token"
      assert row.status == "unused"
      assert row.actor_key_uuid == key.uuid
      assert row.client_token_hash == nil
      assert row.tool == @tool
      assert row.input_hash == @hash
      assert row.fingerprint == @fp
      assert row.preview == %{"rows" => [1, 2]}
      assert row.input == nil
      assert DateTime.diff(row.expires_at, t0) in 119..121
      assert issued.expires_in_seconds == 120
      assert {:ok, uuid} = Token.verify(issued.token)
      assert uuid == row.uuid
    end

    test "the lifetime is a setting, capped at 600 seconds", %{actor: actor} do
      put_setting("api_confirm_ttl_seconds", 300)
      assert issue(actor).expires_in_seconds == 300

      put_setting("api_confirm_ttl_seconds", 9000)
      # Another call: the same call would be handed its live code again.
      assert issue(actor, hash: String.duplicate("2", 64)).expires_in_seconds == 600
    end

    test "a public actor's code is bound to the client token hash" do
      hash = String.duplicate("c", 43)
      actor = %Actor{kind: :anonymous, client_token_hash: hash}

      row = issue(actor).row

      assert row.client_token_hash == hash
      assert row.actor_key_uuid == nil
    end

    test "an actor with nothing to bind a code to is refused" do
      assert {:error, :no_binding} =
               Confirm.issue_token(
                 %Actor{kind: :anonymous},
                 @tool,
                 @hash,
                 %{},
                 @fp,
                 DateTime.utc_now()
               )
    end

    test "the same call again, while its code is live, gets the same code with the time left", %{
      actor: actor
    } do
      t0 = DateTime.utc_now()
      first = issue(actor, now: t0)
      again = issue(actor, now: later(t0, 50))

      assert again.token == first.token
      assert again.row.uuid == first.row.uuid
      assert again.expires_in_seconds in 69..71

      assert Repo.aggregate(
               from(c in Confirmation, where: c.actor_key_uuid == ^actor.key_uuid),
               :count
             ) == 1
    end

    test "other arguments, other values or another tool get a code of their own", %{actor: actor} do
      first = issue(actor)

      for other <- [
            issue(actor, hash: String.duplicate("2", 64)),
            issue(actor, fp: String.duplicate("e", 64))
          ] do
        refute other.token == first.token
      end

      {:ok, other_tool} =
        Confirm.issue_token(actor, "testkit.other_tool", @hash, %{}, @fp, DateTime.utc_now())

      refute other_tool.token == first.token

      assert Repo.aggregate(
               from(c in Confirmation, where: c.actor_key_uuid == ^actor.key_uuid),
               :count
             ) == 4
    end

    test "a used or an expired code is never handed out again", %{actor: actor} do
      t0 = DateTime.utc_now()
      used = issue(actor, now: t0)
      :ok = Confirm.claim_token(used.row, @fp, t0)

      fresh = issue(actor, now: t0)
      refute fresh.token == used.token

      after_expiry = issue(actor, now: later(t0, 130))
      refute after_expiry.token == fresh.token
    end

    test "another key does not share a code", %{actor: actor} do
      {other_user, _role, other_scope} = api_holder(["media"])

      {other_key, _} =
        create_key!(other_user, other_scope, %{name: "other", scopes: [read_scope()]})

      other = %Actor{kind: :key, key_uuid: other_key.uuid, user_uuid: other_user.uuid}

      refute issue(actor).token == issue(other).token
    end

    test "a public actor gets a row per call: its client token is its own choice", %{} do
      actor = %Actor{kind: :anonymous, client_token_hash: String.duplicate("d", 43)}

      refute issue(actor).token == issue(actor).token
    end
  end

  describe "lookup_token/5" do
    test "accepts the code for the same actor, tool and arguments", %{actor: actor} do
      issued = issue(actor)
      assert {:ok, row} = Confirm.lookup_token(issued.token, actor, @tool, @hash)
      assert row.uuid == issued.row.uuid
    end

    test "garbage is malformed, a signed code with no row is unknown", %{actor: actor} do
      assert {:error, :malformed} = Confirm.lookup_token("nonsense", actor, @tool, @hash)
      assert {:error, :malformed} = Confirm.lookup_token("", actor, @tool, @hash)

      {:ok, orphan} = Token.sign(UUIDv7.generate())
      assert {:error, :unknown} = Confirm.lookup_token(orphan, actor, @tool, @hash)
    end

    test "the code of an approval is not a code", %{actor: actor, key: key} do
      row =
        Repo.insert!(%Confirmation{
          kind: "approval",
          tool: @tool,
          input_hash: @hash,
          fingerprint: @fp,
          status: "pending",
          actor_key_uuid: key.uuid,
          expires_at:
            DateTime.utc_now() |> DateTime.add(60, :second) |> DateTime.truncate(:second)
        })

      {:ok, token} = Token.sign(row.uuid)
      assert {:error, :unknown} = Confirm.lookup_token(token, actor, @tool, @hash)
    end

    test "another key may not use it", %{actor: actor} do
      {other_user, _role, other_scope} = api_holder(["media"])

      {other_key, _} =
        create_key!(other_user, other_scope, %{name: "other", scopes: [read_scope()]})

      other = %Actor{kind: :key, key_uuid: other_key.uuid, user_uuid: other_user.uuid}

      issued = issue(actor)
      assert {:error, :wrong_binding} = Confirm.lookup_token(issued.token, other, @tool, @hash)
    end

    test "another client token may not use a public code" do
      mine = %Actor{kind: :anonymous, client_token_hash: String.duplicate("a", 43)}
      theirs = %Actor{kind: :anonymous, client_token_hash: String.duplicate("b", 43)}

      issued = issue(mine)
      assert {:ok, _} = Confirm.lookup_token(issued.token, mine, @tool, @hash)
      assert {:error, :wrong_binding} = Confirm.lookup_token(issued.token, theirs, @tool, @hash)

      assert {:error, :wrong_binding} =
               Confirm.lookup_token(issued.token, %Actor{kind: :anonymous}, @tool, @hash)
    end

    test "other arguments or another tool are refused", %{actor: actor} do
      issued = issue(actor)

      assert {:error, :wrong_input} =
               Confirm.lookup_token(issued.token, actor, @tool, String.duplicate("2", 64))

      assert {:error, :wrong_input} =
               Confirm.lookup_token(issued.token, actor, "testkit.other_tool", @hash)
    end

    test "an expired code is refused, at and after the moment it runs out", %{actor: actor} do
      t0 = DateTime.utc_now()
      issued = issue(actor, now: t0)

      assert {:ok, _} = Confirm.lookup_token(issued.token, actor, @tool, @hash, later(t0, 100))

      assert {:error, :expired} =
               Confirm.lookup_token(issued.token, actor, @tool, @hash, later(t0, 121))

      assert {:error, :expired} =
               Confirm.lookup_token(issued.token, actor, @tool, @hash, later(t0, 5000))
    end

    test "a used code is refused", %{actor: actor} do
      issued = issue(actor)
      :ok = Confirm.claim_token(issued.row, @fp)

      assert {:error, :used} = Confirm.lookup_token(issued.token, actor, @tool, @hash)
    end

    test "looking a code up does not spend it", %{actor: actor} do
      issued = issue(actor)

      for _ <- 1..3,
          do: assert({:ok, _} = Confirm.lookup_token(issued.token, actor, @tool, @hash))

      assert Repo.get!(Confirmation, issued.row.uuid).status == "unused"
    end
  end

  describe "claim_token/3" do
    test "marks the code used, once", %{actor: actor} do
      issued = issue(actor)

      assert :ok = Confirm.claim_token(issued.row, @fp)

      row = Repo.get!(Confirmation, issued.row.uuid)
      assert row.status == "used"
      assert %DateTime{} = row.used_at
      assert {:error, :used} = Confirm.claim_token(issued.row, @fp)
    end

    test "twelve simultaneous claims of one code give one winner", %{actor: actor} do
      issued = issue(actor)

      results =
        1..12
        |> Task.async_stream(fn _ -> Confirm.claim_token(issued.row, @fp) end,
          max_concurrency: 12,
          timeout: :infinity
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Enum.count(results, &(&1 == {:error, :used})) == 11
    end

    test "changed values refuse the claim and leave the code usable", %{actor: actor} do
      issued = issue(actor)
      changed = String.duplicate("0", 64)

      assert {:error, :changed} = Confirm.claim_token(issued.row, changed)
      assert Repo.get!(Confirmation, issued.row.uuid).status == "unused"

      assert :ok = Confirm.claim_token(issued.row, @fp)
    end

    test "an expired code cannot be claimed, even before the sweep marked it", %{actor: actor} do
      t0 = DateTime.utc_now()
      issued = issue(actor, now: t0)

      assert {:error, :expired} = Confirm.claim_token(issued.row, @fp, later(t0, 121))
      assert Repo.get!(Confirmation, issued.row.uuid).status == "unused"
    end

    test "a code is claimable up to the second before it runs out", %{actor: actor} do
      t0 = DateTime.utc_now()
      issued = issue(actor, now: t0)

      assert :ok = Confirm.claim_token(issued.row, @fp, later(t0, 119))
    end
  end

  describe "live_actor/1" do
    test "gives an actor with the key's effective scopes and its approval flag", %{
      key: key,
      user: user
    } do
      assert {:ok, %Actor{} = actor} = Confirm.live_actor(key.uuid)

      assert actor.kind == :key
      assert actor.key_uuid == key.uuid
      assert actor.key_prefix == key.prefix
      assert actor.user_uuid == user.uuid
      assert Enum.sort(actor.scopes) == Enum.sort([read_scope(), write_scope()])
      assert actor.requires_approval == false
    end

    test "is the actor Keys.verify/2 returns for the same key, field for field except ip", %{
      user: user,
      scope: scope
    } do
      {key, token} =
        create_key!(user, scope, %{
          name: "parity key",
          scopes: [read_scope()],
          requires_approval: true
        })

      assert {:ok, %Actor{} = verified} = Keys.verify(token, "203.0.113.7")
      assert verified.ip == "203.0.113.7"
      assert {:ok, %Actor{} = live} = Confirm.live_actor(key.uuid)

      assert live == %{verified | ip: nil}
      assert live.scopes == [read_scope()]
      assert live.requires_approval
    end

    test "carries requires_approval from the key", %{user: user, scope: scope} do
      {key, _} =
        create_key!(user, scope, %{
          name: "approval key",
          scopes: [read_scope()],
          requires_approval: true
        })

      assert {:ok, %Actor{requires_approval: true}} = Confirm.live_actor(key.uuid)
    end

    test "an unknown or malformed uuid is not_found" do
      assert {:error, :not_found} = Confirm.live_actor(UUIDv7.generate())
      assert {:error, :not_found} = Confirm.live_actor("nope")
    end

    test "a revoked key is revoked, a key whose revocation is only scheduled still works", %{
      key: key
    } do
      future = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid), set: [revoked_at: future])
      assert {:ok, _} = Confirm.live_actor(key.uuid)

      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid), set: [revoked_at: past()])
      assert {:error, :revoked} = Confirm.live_actor(key.uuid)
    end

    test "an expired key is expired", %{key: key} do
      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid), set: [expires_at: past()])
      assert {:error, :expired} = Confirm.live_actor(key.uuid)
    end

    test "a blocked owner makes the key dead", %{key: key, user: user} do
      {:ok, _} = Auth.update_user_status(user, %{is_active: false})
      assert {:error, :owner_inactive} = Confirm.live_actor(key.uuid)
    end

    test "scopes the owner lost are gone at once", %{key: key, role: role} do
      assert :ok = Permissions.revoke_permission(role.uuid, "media.manage")

      assert {:ok, %Actor{scopes: scopes}} = Confirm.live_actor(key.uuid)
      assert scopes == [read_scope()]
    end
  end

  describe "Keys.active?/1 (not revoked, not expired, owner active)" do
    test "a live key of an active owner is active", %{key: key} do
      assert Keys.active?(Repo.get!(Key, key.uuid))
    end

    test "a revoked or an expired key is not, a scheduled revocation still is", %{key: key} do
      future = DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid), set: [revoked_at: future])
      assert Keys.active?(Repo.get!(Key, key.uuid))

      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid), set: [revoked_at: past()])
      refute Keys.active?(Repo.get!(Key, key.uuid))

      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid),
        set: [revoked_at: nil, expires_at: past()]
      )

      refute Keys.active?(Repo.get!(Key, key.uuid))
    end

    test "a key whose owner was blocked is not active, though the row is alive", %{
      key: key,
      user: user
    } do
      {:ok, _} = Auth.update_user_status(user, %{is_active: false})

      assert Keys.dead_reason(Repo.get!(Key, key.uuid)) == nil
      refute Keys.active?(Repo.get!(Key, key.uuid))
    end
  end
end
