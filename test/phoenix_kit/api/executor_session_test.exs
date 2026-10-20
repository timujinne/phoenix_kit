defmodule PhoenixKit.API.ExecutorSessionTest do
  @moduledoc """
  `PhoenixKit.API.Executor.visible_for/3` and `execute_as/5`: tools called in process on
  behalf of a person's live browser session (`kind: :user`), without a `Plug.Conn`. The
  scope is rebuilt from the session on every call; only read tools run (`allow: :read`);
  a session pays into its own per-user rate-limit bucket. Real sessions, real roles and
  permissions, the fake modules `PhoenixKit.Test.ApiTools` and
  `PhoenixKit.Test.ApiSessionTools`.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0, header_value: 2]
  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Auth, as: ApiAuth
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.ApiSessionTools
  alias PhoenixKit.Test.ApiTools
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Auth.UserToken
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Multilang

  @read_items "testkit.read_items"
  @write_item "testkit.write_item"
  @shared_a "sessiontest.read_a"
  @shared_b "sessiontest.read_b"

  defmodule HostHook do
    @moduledoc false
    def resolve(conn) do
      send(self(), {:host_hook_called, conn})
      %{language: "de"}
    end
  end

  setup do
    setup_api()
    :ok = ModuleRegistry.register(ApiSessionTools)
    on_exit(fn -> ModuleRegistry.unregister(ApiSessionTools) end)
    :ok
  end

  # A user holding one new role per permission list, and a live session of theirs.
  defp user_with_roles(permission_lists) do
    user = KeyTestSupport.register_user!()

    roles =
      for permissions <- permission_lists do
        {role, _} = KeyTestSupport.role_with(permissions)
        {:ok, _} = Roles.assign_role(user, role.name)
        role
      end

    {user, roles}
  end

  defp session!(%User{} = user) do
    token = Auth.generate_user_session_token(user)
    %UserToken{uuid: uuid} = Auth.get_session_token_record(token)
    {uuid, user.uuid}
  end

  defp acting_as({token_uuid, _user_uuid}, role) do
    Repo.update_all(from(t in UserToken, where: t.uuid == ^token_uuid),
      set: [active_role_uuid: role.uuid]
    )
  end

  defp visible_names(ref, opts \\ []) do
    assert {:ok, tools, _headers} = Executor.visible_for(ref, :admin, opts)
    tools |> Enum.map(& &1.name) |> Enum.sort()
  end

  defp run(ref, tool, input \\ %{}, opts \\ []),
    do: Executor.execute_as(ref, :admin, tool, input, opts)

  describe "visible_for/3" do
    test "shows the read tools the session's permissions reach, never a write or system tool" do
      {user, _} = user_with_roles([["dashboard", "settings"]])
      ref = session!(user)

      names = visible_names(ref)

      assert @read_items in names
      refute @write_item in names
      refute Enum.any?(names, &String.starts_with?(&1, "system."))
      refute Enum.any?(names, &String.starts_with?(&1, "sessiontest."))
    end

    test "without the permission there is no tool" do
      {user, _} = user_with_roles([[]])
      assert visible_names(session!(user)) == []
    end

    test "a switched-off module has no tools" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)
      assert @read_items in visible_names(ref)

      ApiTools.set_enabled(false)

      refute @read_items in visible_names(ref)
    end

    test "a refused session gets no list" do
      {user, _} = user_with_roles([["dashboard"]])
      {token_uuid, user_uuid} = session!(user)

      assert {:error, :unauthorized, _detail, %{reason: :mismatch}, []} =
               Executor.visible_for({token_uuid, UUIDv7.generate()}, :admin, [])

      assert {:error, :unauthorized, _detail, %{reason: :session_gone}, []} =
               Executor.visible_for({UUIDv7.generate(), user_uuid}, :admin, [])
    end

    test "only allow: :read exists in this version" do
      {user, _} = user_with_roles([["dashboard"]])

      assert_raise ArgumentError, ~r/allow/, fn ->
        Executor.visible_for(session!(user), :admin, allow: :all)
      end
    end
  end

  describe "the session's active role" do
    setup do
      :ok =
        KeyTestSupport.write_setting(fn ->
          Settings.update_boolean_setting("role_switcher_enabled", true)
        end)

      {user, [reader, writer]} = user_with_roles([["dashboard"], ["settings"]])
      %{user: user, reader: reader, writer: writer}
    end

    test "a session acting as a narrow role sees nothing wider than that role", ctx do
      ref = session!(ctx.user)
      acting_as(ref, ctx.writer)

      assert visible_names(ref) == []

      assert {:error, :forbidden, _detail, _context, _headers} = run(ref, @read_items)
      refute_received {:read_items, _, _}
    end

    test "the same user's session acting as the role that holds the permission sees the tool",
         ctx do
      ref = session!(ctx.user)
      acting_as(ref, ctx.reader)

      assert @read_items in visible_names(ref)
      assert {:ok, %{result: %{"limit" => 10}}, _headers} = run(ref, @read_items)
    end

    test "a key's handler still gets the owner's full scope, not narrowed to a role" do
      {owner, _roles} = user_with_roles([["api", "dashboard"], ["api", "settings"]])
      {_key, token} = issue_key(owner, ["testkit.items:read"])

      conn =
        :post
        |> api_conn("/", token: token)
        |> ApiAuth.call(ApiAuth.init(audience: :admin))

      assert {:ok, _, _} = Executor.execute(conn, :admin, @read_items, %{})
      assert_received {:read_items, _input, key_ctx}

      # The owner holds two switchable roles and the switcher is on, so a narrowed scope
      # would act as one of them; the key's scope must be the union.
      assert Scope.active_role(key_ctx.scope) == nil
      assert Scope.can?(key_ctx.scope, "dashboard")
      assert Scope.can?(key_ctx.scope, "settings")
    end
  end

  describe "a service user's session" do
    test "is refused as gone and the handler does not run" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      Repo.update_all(from(u in User, where: u.uuid == ^user.uuid), set: [api_only: true])

      assert {:error, :unauthorized, _detail, %{reason: :session_gone}, []} =
               run(ref, @read_items)

      refute_received {:read_items, _, _}
    end
  end

  describe "a session that can no longer act" do
    test "a revoked session is refused and the handler does not run" do
      {user, _} = user_with_roles([["dashboard"]])
      token = Auth.generate_user_session_token(user)
      ref = {Auth.get_session_token_record(token).uuid, user.uuid}

      assert {:ok, _, _} = run(ref, @read_items)
      assert_received {:read_items, _, _}

      :ok = Auth.delete_user_session_token(token)

      assert {:error, :unauthorized, _detail, %{reason: :session_gone}, []} =
               run(ref, @read_items)

      refute_received {:read_items, _, _}
    end

    test "a blocked user is refused and the handler does not run" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      Repo.update_all(from(u in User, where: u.uuid == ^user.uuid), set: [is_active: false])

      capture_log(fn ->
        assert {:error, :unauthorized, _detail, %{reason: :inactive}, []} = run(ref, @read_items)
        assert {:error, :unauthorized, _, _, []} = Executor.visible_for(ref, :admin, [])
      end)

      refute_received {:read_items, _, _}
    end

    test "a user the web's account gate stops is refused and the handler does not run" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      Repo.update_all(from(u in User, where: u.uuid == ^user.uuid), set: [confirmed_at: nil])

      assert {:error, :unauthorized, _detail, %{reason: :unconfirmed}, []} =
               run(ref, @read_items)

      assert {:error, :unauthorized, _, %{reason: :unconfirmed}, []} =
               Executor.visible_for(ref, :admin, [])

      refute_received {:read_items, _, _}
    end

    test "a reference that is not a pair is refused as gone, never an exception" do
      for ref <- [nil, "token", {:a, :b, :c}, %{}] do
        assert {:error, :unauthorized, _, %{reason: :session_gone}, []} = run(ref, @read_items)

        assert {:error, :unauthorized, _, %{reason: :session_gone}, []} =
                 Executor.visible_for(ref, :admin, [])
      end

      refute_received {:read_items, _, _}
    end

    test "a permission taken away takes effect on the next call" do
      {user, [role]} = user_with_roles([["dashboard"]])
      ref = session!(user)
      assert {:ok, _, _} = run(ref, @read_items)

      :ok = Permissions.revoke_permission(role.uuid, "dashboard")

      assert {:error, :forbidden, _, _, _} = run(ref, @read_items)
      refute @read_items in visible_names(ref)
    end
  end

  describe "a module switched off" do
    test "its tool is refused" do
      {user, _} = user_with_roles([["dashboard"]])
      ApiTools.set_enabled(false)

      assert {:error, :module_disabled, _, _, _} = run(session!(user), @read_items)
      refute_received {:read_items, _, _}
    end
  end

  describe "two tools on one scope with different permissions" do
    test "holding one of the permissions unlocks neither tool" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      refute @shared_a in visible_names(ref)
      refute @shared_b in visible_names(ref)
      assert {:error, :forbidden, _, _, _} = run(ref, @shared_b)
      assert {:error, :forbidden, _, _, _} = run(ref, @shared_a)
      refute_received {:session_tool, _, _}
    end

    test "holding both unlocks both" do
      {user, _} = user_with_roles([["dashboard", "users"]])
      ref = session!(user)

      assert [@shared_a, @shared_b] =
               Enum.filter(visible_names(ref), &(&1 in [@shared_a, @shared_b]))

      assert {:ok, %{result: %{"tool" => @shared_b}}, _} = run(ref, @shared_b)
    end
  end

  describe "allow: :read" do
    test "a write tool is refused before anything runs, with no audit entry" do
      {user, _} = user_with_roles([["settings"]])
      ref = session!(user)

      assert {:error, :forbidden, detail, %{tool: @write_item}, _headers} =
               run(ref, @write_item, %{"name" => "x"})

      assert detail =~ "reads only"

      assert {:error, :forbidden, _, _, _} =
               run(ref, @write_item, %{"name" => "x", "dry_run" => true})

      refute_received {:write_item, _}

      assert Repo.aggregate(
               from(e in Entry, where: e.action == "api.request" and e.actor_uuid == ^user.uuid),
               :count
             ) == 0
    end

    test "is the default, and the only value this version takes" do
      {user, _} = user_with_roles([["settings"]])
      ref = session!(user)

      assert {:error, :forbidden, _, _, _} = run(ref, @write_item, %{"name" => "x"}, allow: :read)

      assert_raise ArgumentError, fn -> run(ref, @write_item, %{"name" => "x"}, allow: :all) end
      refute_received {:write_item, _}
    end

    test "a system tool is not callable by a session" do
      {user, _} = user_with_roles([["dashboard"]])

      assert {:error, :forbidden, _, _, _} = run(session!(user), "system.get_identity")
    end
  end

  describe "rate limit" do
    setup do
      wait_for_window_room()
      put_setting("api_admin_rate_per_min", 3)
      :ok
    end

    test "every session of one user shares the user's bucket" do
      {user, _} = user_with_roles([["dashboard"]])
      first = session!(user)
      second = session!(user)

      assert {:ok, _, headers} = run(first, @read_items)
      assert header_value(headers, "ratelimit-remaining") == 2
      assert {:ok, _tools, _} = Executor.visible_for(second, :admin, [])
      assert {:ok, _, _} = run(second, @read_items)

      assert {:error, :rate_limited, _, %{retry_after: retry_after}, _} =
               run(first, @read_items)

      assert retry_after in 1..60
    end

    test "a refused call still costs a unit, so invented names are not free" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      for _ <- 1..3, do: assert({:error, :not_found, _, _, _} = run(ref, "testkit.nope"))

      assert {:error, :rate_limited, _, _, _} = run(ref, @read_items)
    end

    test "another user, and a key of the same user, have their own buckets" do
      {user, _} = user_with(["dashboard"])
      {other, _} = user_with_roles([["dashboard"]])
      ref = session!(user)
      for _ <- 1..3, do: assert({:ok, _, _} = run(ref, @read_items))
      assert {:error, :rate_limited, _, _, _} = run(ref, @read_items)

      assert {:ok, _, _} = run(session!(other), @read_items)

      {_key, token} = issue_key(user, ["testkit.items:read"])

      conn =
        :post
        |> api_conn("/", token: token)
        |> ApiAuth.call(ApiAuth.init(audience: :admin))

      assert {:ok, _, _} = Executor.execute(conn, :admin, @read_items, %{})
    end
  end

  describe "the handler context" do
    test "a session's handler gets the session's scope, its actor and the given request context" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      Application.put_env(:phoenix_kit, :api_request_context, {HostHook, :resolve})
      on_exit(fn -> Application.delete_env(:phoenix_kit, :api_request_context) end)

      assert {:ok, %{result: result}, _} =
               run(ref, @read_items, %{},
                 request_context: [
                   language: "et",
                   base_url: "https://shop.example",
                   hosts: ["shop.example"],
                   currency: "EUR",
                   request_id: "req-1",
                   ip: "203.0.113.5"
                 ]
               )

      assert_received {:read_items, _input, ctx}
      refute_received {:host_hook_called, _}

      assert result["language"] == "et"
      assert ctx.language == "et"
      assert ctx.base_url == "https://shop.example"
      assert ctx.hosts == ["shop.example"]
      assert ctx.currency == "EUR"
      assert ctx.request_id == "req-1"

      assert %Actor{kind: :user, key_uuid: nil, user_uuid: user_uuid, ip: "203.0.113.5"} =
               ctx.actor

      assert user_uuid == user.uuid
      assert "testkit.items:read" in ctx.scopes
      assert %Scope{} = ctx.scope
      assert ctx.scope.user.uuid == user.uuid
      assert ctx.actor.scope == ctx.scope
      assert Enum.sort(Map.keys(ctx)) == Enum.sort(Executor.context_keys())
    end

    test "without a request context the session's handler gets the defaults" do
      {user, _} = user_with_roles([["dashboard"]])

      assert {:ok, _, _} = run(session!(user), @read_items)
      assert_received {:read_items, _input, ctx}

      assert ctx.language == Multilang.primary_language()
      assert ctx.base_url == nil
      assert ctx.hosts == []
      assert ctx.currency == nil
      assert ctx.request_id == nil
    end

    test "a malformed request context gives the defaults, never an exception" do
      {user, _} = user_with_roles([["dashboard"]])
      ref = session!(user)

      assert {:ok, _, _} =
               run(ref, @read_items, %{}, request_context: [:junk, {"language", "et"}, ip: 42])

      assert_received {:read_items, _input, ctx}
      assert ctx.language == Multilang.primary_language()
      assert ctx.actor.ip == nil

      assert {:ok, _, _} = run(ref, @read_items, %{}, request_context: %{language: "et"})
      assert_received {:read_items, _input, %{language: "et"}}

      assert {:ok, _, _} = run(ref, @read_items, %{}, request_context: "et")
      assert_received {:read_items, _input, _ctx}
    end

    test "a key's handler gets the owner's full scope, the one its scopes are computed from" do
      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["testkit.items:read"])

      conn =
        :post
        |> api_conn("/", token: token)
        |> ApiAuth.call(ApiAuth.init(audience: :admin))

      assert {:ok, _, _} = Executor.execute(conn, :admin, @read_items, %{})
      assert_received {:read_items, _input, ctx}

      assert %Scope{} = ctx.scope
      assert ctx.scope.user.uuid == owner.uuid
      assert Scope.can?(ctx.scope, "dashboard")
      assert Scope.active_role(ctx.scope) == nil
      assert ctx.actor.kind == :key
    end
  end
end
