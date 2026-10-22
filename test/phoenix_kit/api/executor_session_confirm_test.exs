defmodule PhoenixKit.API.ExecutorSessionConfirmTest do
  @moduledoc """
  Writes of a person's live session (`kind: :user`): `allow: :all` of
  `PhoenixKit.API.Executor.visible_for/3` and `execute_as/5`, the confirmation every write
  of a session waits for, `redeem_as/6` that runs it after the person confirms, the
  `api_session_write_modules` allow-list, the session functions of
  `PhoenixKit.API.Confirm` and the audit entry. Keys keep their own flow, which the
  allow-list does not touch. Real sessions, roles, permissions and rows; the tools of
  `PhoenixKit.Test.ApiSessionTools`.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Auth, as: ApiAuth
  alias PhoenixKit.API.Confirm
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Confirm.Token
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings.Setting
  alias PhoenixKit.Test.ApiSessionTools
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Auth.UserToken
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles

  @set "sessiontest.set_note"
  @wipe "sessiontest.wipe_note"
  @module "api_session_tools"
  @input %{"id" => "n1", "text" => "new"}

  setup do
    setup_api()
    :ok = ModuleRegistry.register(ApiSessionTools)
    ApiSessionTools.reset_notes()

    on_exit(fn ->
      ModuleRegistry.unregister(ApiSessionTools)
      ApiSessionTools.reset_notes()
    end)

    {user, role} = person(["settings"])
    %{user: user, role: role, ref: session!(user)}
  end

  defp person(permissions) do
    user = KeyTestSupport.register_user!()
    {role, _} = KeyTestSupport.role_with(permissions)
    {:ok, _} = Roles.assign_role(user, role.name)
    {user, role}
  end

  defp session!(%User{} = user) do
    token = Auth.generate_user_session_token(user)
    %UserToken{uuid: uuid} = Auth.get_session_token_record(token)
    {uuid, user.uuid}
  end

  # A setting cannot hold an empty value; no row is the empty list.
  defp open_writes([]),
    do: Repo.delete_all(from(s in Setting, where: s.key == "api_session_write_modules"))

  defp open_writes(keys), do: put_setting("api_session_write_modules", Enum.join(keys, "\n"))

  defp names(ref, opts) do
    assert {:ok, tools, _headers} = Executor.visible_for(ref, :admin, opts)
    tools |> Enum.map(& &1.name) |> Enum.sort()
  end

  defp ask(ref, tool \\ @set, input \\ @input, opts \\ []),
    do: Executor.execute_as(ref, :admin, tool, input, Keyword.put_new(opts, :allow, :all))

  defp confirm(ref, id, tool \\ @set, input \\ @input, opts \\ []),
    do: Executor.redeem_as(ref, :admin, id, tool, input, opts)

  # Asks for the write and returns the uuid of the row it is held in.
  defp held!(ref, tool \\ @set, input \\ @input) do
    assert {:ok, %{result: %{"status" => "confirmation_required", "confirmation_id" => id}}, _} =
             ask(ref, tool, input)

    id
  end

  defp row(id), do: Repo.get!(Confirmation, id)
  defp rows, do: Repo.aggregate(Confirmation, :count)

  defp entries(user) do
    Repo.all(
      from(e in Entry,
        where: e.action == "api.request" and e.actor_uuid == ^user.uuid,
        order_by: [asc: e.inserted_at]
      )
    )
  end

  defp key_conn(token),
    do: :post |> api_conn("/", token: token) |> ApiAuth.call(ApiAuth.init(audience: :admin))

  describe "visible_for/3 with allow: :all" do
    test "lists the write tools of a module in api_session_write_modules, and only then", %{
      ref: ref
    } do
      refute @set in names(ref, allow: :all)

      open_writes([@module])

      assert [@set, @wipe] = Enum.filter(names(ref, allow: :all), &(&1 in [@set, @wipe]))
      # The write tool of a module that is not in the list stays hidden.
      refute "testkit.write_item" in names(ref, allow: :all)
    end

    test "allow: :read never lists a write tool, whatever the list says", %{ref: ref} do
      open_writes([@module, "api_test_tools"])

      names = names(ref, allow: :read)
      refute @set in names
      refute "testkit.write_item" in names
      assert names(ref, []) == names
    end

    test "a write tool whose permission the session does not hold is not listed" do
      open_writes([@module])
      {user, _role} = person(["dashboard"])

      refute @set in names(session!(user), allow: :all)
    end

    test "any other value of :allow raises", %{ref: ref} do
      for allow <- [:write, "all", nil] do
        assert_raise ArgumentError, ~r/allow/, fn ->
          Executor.visible_for(ref, :admin, allow: allow)
        end
      end
    end
  end

  describe "the allow-list" do
    test "a module that is not listed: module_write_disabled, nothing runs or is stored", %{
      ref: ref
    } do
      assert {:error, :module_write_disabled, _detail, %{tool: @set}, _headers} = ask(ref)

      assert {:error, :module_write_disabled, _, _, _} =
               ask(ref, @set, Map.put(@input, "dry_run", true))

      open_writes(["api_test_tools"])
      assert {:error, :module_write_disabled, _, _, _} = ask(ref)

      assert rows() == 0
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end

    test "the list is read on every call", %{ref: ref} do
      open_writes([@module])
      assert {:ok, _, _} = ask(ref)

      open_writes([])
      assert {:error, :module_write_disabled, _, _, _} = ask(ref)
    end

    test "allow: :read still refuses a write of a listed module as forbidden", %{ref: ref} do
      open_writes([@module])

      assert {:error, :forbidden, detail, _, _} = ask(ref, @set, @input, allow: :read)
      assert detail =~ "reads only"
      assert rows() == 0
    end
  end

  describe "a write of a session is held for the person" do
    setup do
      open_writes([@module])
      :ok
    end

    test "a write that is not dangerous answers a preview and a confirmation id, and writes nothing",
         %{ref: ref, user: user} do
      assert {:ok, %{result: result, json: json}, _headers} = ask(ref)

      assert %{
               "executed" => false,
               "status" => "confirmation_required",
               "confirmation_id" => id,
               "preview" => %{"rows" => [%{"ref" => "n1"}]},
               "expires_at" => expires_at,
               "expires_in_seconds" => expires_in
             } = result

      assert expires_in in 599..600
      refute Map.has_key?(result, "confirm_token")
      refute json =~ "ct_"
      assert is_binary(expires_at)

      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}

      assert %Confirmation{
               kind: "token",
               status: "unused",
               tool: @set,
               actor_key_uuid: nil,
               client_token_hash: nil,
               actor_user_uuid: user_uuid,
               expires_at: stored_expiry
             } = row(id)

      assert user_uuid == user.uuid
      assert_in_delta DateTime.diff(stored_expiry, DateTime.utc_now()), 600, 5
    end

    test "a dangerous write is held the same way", %{ref: ref} do
      assert {:ok, %{result: %{"status" => "confirmation_required"}}, _} =
               ask(ref, @wipe, %{"id" => "n1"})

      assert ApiSessionTools.notes() == %{"n1" => "old"}
    end

    test "the lifetime is api_user_confirm_ttl_seconds", %{ref: ref} do
      put_setting("api_user_confirm_ttl_seconds", 60)

      assert {:ok, %{result: %{"expires_in_seconds" => expires_in, "confirmation_id" => id}}, _} =
               ask(ref)

      assert expires_in in 59..60
      assert_in_delta DateTime.diff(row(id).expires_at, DateTime.utc_now()), 60, 5
    end

    test "every call holds a new row, never the earlier one again", %{ref: ref} do
      first = held!(ref)
      second = held!(ref)

      assert first != second
      assert rows() == 2
    end

    test "Confirm.issue_token/6 never makes a code for a session", %{user: user} do
      actor = %PhoenixKit.API.Actor{kind: :user, user_uuid: user.uuid}

      assert {:error, :no_binding} =
               Confirm.issue_token(actor, @set, String.duplicate("a", 64), %{}, "fp")

      assert rows() == 0
    end

    test "dry_run still answers the preview alone, with no row", %{ref: ref} do
      assert {:ok, %{result: %{"dry_run" => true, "preview" => _}}, _} =
               ask(ref, @set, Map.put(@input, "dry_run", true))

      assert rows() == 0
    end

    test "a confirm_token is refused and nothing runs, even a valid code for the person's own row",
         %{ref: ref} do
      id = held!(ref)
      {:ok, token} = Token.sign(id)

      for code <- [token, "ct_nonsense"] do
        assert {:error, :confirm_token_invalid, _, %{reason: "invalid"}, _} =
                 ask(ref, @set, Map.put(@input, "confirm_token", code))
      end

      assert row(id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end
  end

  describe "redeem_as/6" do
    setup do
      open_writes([@module])
      :ok
    end

    test "runs the held write once, with ctx.confirmation_uuid, and spends the row", %{ref: ref} do
      id = held!(ref)

      assert {:ok, %{result: %{"id" => "n1", "updated" => true}}, _headers} = confirm(ref, id)

      assert ApiSessionTools.notes() == %{"n1" => "new"}
      assert_received {:session_write, @set, %{"id" => "n1", "text" => "new"}, ctx}
      assert ctx.confirmation_uuid == id
      assert ctx.dry_run? == false
      assert %Confirmation{status: "used", used_at: %DateTime{}} = row(id)
    end

    test "another session of the same person may confirm, with its own rights", %{
      ref: ref,
      user: user
    } do
      id = held!(ref)

      assert {:ok, _, _} = confirm(session!(user), id)
      assert ApiSessionTools.notes() == %{"n1" => "new"}
    end

    test "a second confirmation of the same row runs nothing: used", %{ref: ref} do
      id = held!(ref)
      assert {:ok, _, _} = confirm(ref, id)
      assert_received {:session_write, _, _, _}

      assert {:error, :confirm_token_invalid, _, %{reason: "used"}, _} = confirm(ref, id)
      refute_received {:session_write, _, _, _}
    end

    test "other arguments or another tool are refused and the row keeps waiting", %{ref: ref} do
      id = held!(ref)

      assert {:error, :confirm_token_invalid, _, %{reason: "other_arguments"}, _} =
               confirm(ref, id, @set, %{"id" => "n1", "text" => "other"})

      assert {:error, :confirm_token_invalid, _, %{reason: "other_arguments"}, _} =
               confirm(ref, id, @wipe, %{"id" => "n1"})

      assert row(id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end

    test "somebody else's row and a row that does not exist get the same answer", %{ref: ref} do
      id = held!(ref)
      {stranger, _role} = person(["settings"])
      stranger_ref = session!(stranger)

      answers =
        for candidate <- [id, UUIDv7.generate(), "not-a-uuid", 42] do
          assert {:error, code, detail, context, _headers} = confirm(stranger_ref, candidate)
          {code, detail, context}
        end

      assert [{:confirm_token_invalid, _, %{reason: "invalid"}} = first | rest] = answers
      assert Enum.all?(rest, &(&1 == first))

      assert row(id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}

      # The owner can still confirm it.
      assert {:ok, _, _} = confirm(ref, id)
    end

    test "after its lifetime the row is expired and nothing runs", %{ref: ref} do
      id = held!(ref)
      past = DateTime.utc_now() |> DateTime.add(-1, :second) |> DateTime.truncate(:second)
      Repo.update_all(from(c in Confirmation, where: c.uuid == ^id), set: [expires_at: past])

      assert {:error, :confirm_token_invalid, _, %{reason: "expired"}, _} = confirm(ref, id)

      # Marked by the sweep too.
      other = held!(ref)
      Repo.update_all(from(c in Confirmation, where: c.uuid == ^other), set: [expires_at: past])
      Confirm.expire_due()
      assert {:error, :confirm_token_invalid, _, %{reason: "expired"}, _} = confirm(ref, other)

      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end

    test "a rejected row cannot be confirmed", %{ref: ref} do
      id = held!(ref)
      assert :ok = Confirm.reject_for_user(id, ref)

      assert {:error, :confirm_token_invalid, _, %{reason: "rejected"}, _} = confirm(ref, id)
      assert row(id).status == "rejected"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end

    test "values that changed since the preview give a new row with a fresh preview, and nothing runs",
         %{ref: ref} do
      id = held!(ref)
      ApiSessionTools.put_note("n1", "edited meanwhile")

      assert {:ok, %{result: result}, _} = confirm(ref, id)

      assert %{
               "executed" => false,
               "status" => "confirmation_required",
               "reason" => "changed",
               "confirmation_id" => new_id,
               "preview" => %{
                 "rows" => [%{"changes" => %{"text" => %{"from" => "edited meanwhile"}}}]
               }
             } = result

      assert new_id != id
      assert row(id).status == "expired"
      assert row(new_id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "edited meanwhile"}
      refute_received {:session_write, _, _, _}

      # The old row is spent for good; the new one runs.
      assert {:error, :confirm_token_invalid, _, %{reason: "expired"}, _} = confirm(ref, id)
      assert {:ok, %{result: %{"updated" => true}}, _} = confirm(ref, new_id)
      assert ApiSessionTools.notes() == %{"n1" => "new"}
    end

    test "the box taken off after the row was held: module_write_disabled, the row keeps waiting",
         %{ref: ref} do
      id = held!(ref)
      open_writes([])

      assert {:error, :module_write_disabled, _, _, _} = confirm(ref, id)
      assert row(id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
    end

    test "a permission taken away after the row was held: forbidden, nothing runs", %{
      ref: ref,
      role: role
    } do
      id = held!(ref)
      :ok = Permissions.revoke_permission(role.uuid, "settings")

      assert {:error, :forbidden, _, _, _} = confirm(ref, id)
      assert row(id).status == "unused"
      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}
    end

    test "a role taken away after the row was held: forbidden", %{
      ref: ref,
      user: user,
      role: role
    } do
      id = held!(ref)
      {:ok, _} = Roles.remove_role(user, role.name)

      assert {:error, :forbidden, _, _, _} = confirm(ref, id)
      assert ApiSessionTools.notes() == %{"n1" => "old"}
    end

    test "a session that ended cannot confirm", %{user: user} do
      token = Auth.generate_user_session_token(user)
      ref = {Auth.get_session_token_record(token).uuid, user.uuid}
      id = held!(ref)

      :ok = Auth.delete_user_session_token(token)

      assert {:error, :unauthorized, _, %{reason: :session_gone}, _} = confirm(ref, id)
      assert row(id).status == "unused"
    end

    test "the module's API switched off: the tool does not exist", %{ref: ref} do
      id = held!(ref)
      put_setting("api_disabled_modules", @module)

      assert {:error, :not_found, _, _, _} = confirm(ref, id)
      assert row(id).status == "unused"
    end

    test "control fields are refused, so a dry_run cannot spend the row", %{ref: ref} do
      id = held!(ref)

      for field <- [
            {"dry_run", true},
            {"confirm_token", "ct_x"},
            {"idempotency_key", String.duplicate("k", 20)}
          ] do
        {name, value} = field

        assert {:error, :validation_failed, _, %{errors: [%{path: ^name}]}, _} =
                 confirm(ref, id, @set, Map.put(@input, name, value))
      end

      assert row(id).status == "unused"
      assert {:ok, _, _} = confirm(ref, id)
    end

    test "a read tool has nothing to confirm" do
      {user, _role} = person(["settings", "dashboard"])
      ref = session!(user)
      id = held!(ref)

      assert {:error, :forbidden, detail, _, _} = confirm(ref, id, "testkit.read_items", %{})
      assert detail =~ "nothing to confirm"
    end

    test "the option :allow cannot narrow it, :via must be a string", %{ref: ref} do
      assert_raise ArgumentError, ~r/via/, fn ->
        confirm(ref, UUIDv7.generate(), @set, @input, via: :agent)
      end

      assert_raise ArgumentError, ~r/via/, fn -> ask(ref, @set, @input, via: "") end
    end
  end

  describe "Confirm.get_for_user/2 and reject_for_user/2" do
    setup do
      open_writes([@module])
      :ok
    end

    test "the person reads their row for the page", %{ref: ref} do
      id = held!(ref)

      assert {:ok,
              %{
                uuid: ^id,
                tool: @set,
                status: "unused",
                preview: preview,
                expires_at: %DateTime{}
              }} =
               Confirm.get_for_user(id, ref)

      assert %{"rows" => [%{"ref" => "n1"}]} = preview
    end

    test "an unused row past its time reads expired", %{ref: ref} do
      id = held!(ref)
      past = DateTime.utc_now() |> DateTime.add(-1, :second) |> DateTime.truncate(:second)
      Repo.update_all(from(c in Confirmation, where: c.uuid == ^id), set: [expires_at: past])

      assert {:ok, %{status: "expired"}} = Confirm.get_for_user(id, ref)
    end

    test "somebody else's row, an unknown uuid and garbage are the same :unknown", %{ref: ref} do
      id = held!(ref)
      {stranger, _} = person(["settings"])
      stranger_ref = session!(stranger)

      for candidate <- [id, UUIDv7.generate(), "nope", nil] do
        assert Confirm.get_for_user(candidate, stranger_ref) == {:error, :unknown}
        assert Confirm.reject_for_user(candidate, stranger_ref) == {:error, :unknown}
      end

      assert row(id).status == "unused"
    end

    test "a session that cannot act gets nothing", %{
      ref: {token_uuid, _user_uuid} = ref,
      user: user
    } do
      id = held!(ref)

      assert Confirm.get_for_user(id, {token_uuid, UUIDv7.generate()}) == {:error, :unauthorized}
      assert Confirm.get_for_user(id, :not_a_ref) == {:error, :unauthorized}

      Repo.update_all(from(u in User, where: u.uuid == ^user.uuid), set: [is_active: false])

      capture_log(fn ->
        assert Confirm.get_for_user(id, ref) == {:error, :unauthorized}
        assert Confirm.reject_for_user(id, ref) == {:error, :unauthorized}
      end)

      assert row(id).status == "unused"
    end

    test "rejecting is atomic and one-way", %{ref: ref} do
      id = held!(ref)

      assert :ok = Confirm.reject_for_user(id, ref)
      assert {:error, :rejected} = Confirm.reject_for_user(id, ref)
      assert {:ok, %{status: "rejected"}} = Confirm.get_for_user(id, ref)

      used = held!(ref)
      assert {:ok, _, _} = confirm(ref, used)
      assert {:error, :used} = Confirm.reject_for_user(used, ref)
      assert row(used).status == "used"
    end

    test "a rejected row of a session goes with the early prune of unused codes", %{ref: ref} do
      id = held!(ref)
      :ok = Confirm.reject_for_user(id, ref)

      later = DateTime.add(row(id).expires_at, 2 * 3_600, :second)
      Confirm.prune(later)

      assert Repo.get(Confirmation, id) == nil
    end
  end

  describe "the audit entry" do
    setup do
      open_writes([@module])
      :ok
    end

    test "a held write and its confirmation are logged with via, never with the input or the preview",
         %{ref: ref, user: user} do
      secret = "secret-note-#{System.unique_integer([:positive])}"
      input = %{"id" => "n1", "text" => secret}

      assert {:ok, %{result: %{"confirmation_id" => id}}, _} = ask(ref, @set, input, via: "agent")
      assert {:ok, _, _} = confirm(ref, id, @set, input)

      assert [held, done] = entries(user)

      assert %Entry{resource_type: "user", mode: "auto"} = held
      assert held.resource_uuid == user.uuid

      assert %{
               "via" => "agent",
               "tool" => @set,
               "outcome" => "confirmation_required",
               "confirmation_uuid" => ^id
             } = held.metadata

      assert %{"via" => "session", "outcome" => "ok", "confirmation_uuid" => ^id} = done.metadata

      for entry <- [held, done] do
        assert Enum.sort(Map.keys(entry.metadata)) ==
                 ~w(code confirmation_uuid outcome request_id tool via)

        refute JSON.encode!(entry.metadata) =~ secret
        refute JSON.encode!(entry.metadata) =~ "old"
      end
    end

    test "a refused confirmation is logged as an error with its code", %{ref: ref, user: user} do
      id = held!(ref)
      assert {:ok, _, _} = confirm(ref, id)
      assert {:error, _, _, _, _} = confirm(ref, id)

      assert %{"outcome" => "error", "code" => "confirm_token_invalid"} =
               List.last(entries(user)).metadata
    end

    test "a write refused by the allow-list or a read writes no entry" do
      {user, _role} = person(["settings", "dashboard"])
      ref = session!(user)
      open_writes([])
      assert {:error, :module_write_disabled, _, _, _} = ask(ref)

      assert {:ok, _, _} =
               Executor.execute_as(ref, :admin, "testkit.read_items", %{}, allow: :all)

      assert entries(user) == []
    end

    test "nothing the person typed or the preview shows reaches the log", %{ref: ref} do
      secret = "secret-log-#{System.unique_integer([:positive])}"
      input = %{"id" => "n1", "text" => secret}

      log =
        capture_log([level: :debug], fn ->
          {:ok, %{result: %{"confirmation_id" => id}}, _} = ask(ref, @set, input)
          ApiSessionTools.put_note("n1", "changed")
          {:ok, %{result: %{"confirmation_id" => new_id}}, _} = confirm(ref, id, @set, input)
          {:ok, _, _} = confirm(ref, new_id, @set, input)
          {:error, _, _, _, _} = confirm(ref, new_id, @set, input)
        end)

      refute log =~ secret
    end
  end

  describe "API keys are not touched" do
    setup do
      {owner, _role} = user_with(["settings"])
      {_key, token} = issue_key(owner, [ApiSessionTools.write_scope()])
      %{token: token}
    end

    test "a key's write of a tool with danger :always waits for a code: nothing is written", %{
      token: token
    } do
      assert {:ok, %{result: %{"status" => "confirmation_required", "confirm_token" => code}}, _} =
               Executor.execute(key_conn(token), :admin, @wipe, %{"id" => "n1"})

      assert ApiSessionTools.notes() == %{"n1" => "old"}
      refute_received {:session_write, _, _, _}

      assert {:ok, %{result: %{"deleted" => true}}, _} =
               Executor.execute(key_conn(token), :admin, @wipe, %{
                 "id" => "n1",
                 "confirm_token" => code
               })

      assert ApiSessionTools.notes() == %{}
    end

    test "the box changes nothing for a key", %{token: token} do
      for listed <- [[], [@module]] do
        open_writes(listed)
        ApiSessionTools.reset_notes()

        assert {:ok, tools, _} = Executor.visible(key_conn(token), :admin)
        assert @set in Enum.map(tools, & &1.name)

        # A write that is not dangerous still runs at once for a key.
        assert {:ok, %{result: %{"updated" => true}}, _} =
                 Executor.execute(key_conn(token), :admin, @set, @input)

        assert ApiSessionTools.notes() == %{"n1" => "new"}

        assert {:ok, %{result: %{"confirm_token" => _}}, _} =
                 Executor.execute(key_conn(token), :admin, @wipe, %{"id" => "n1"})
      end
    end
  end
end
