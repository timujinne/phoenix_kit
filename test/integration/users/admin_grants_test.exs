defmodule PhoenixKit.Integration.Users.AdminGrantsTest.FaultyRepo do
  @moduledoc false
  # `PhoenixKit.Test.Repo` with faults switched on through `:persistent_term`:
  # no DDL, so nothing here locks a table other tests write to.
  #
  #   * `block/1`   — the Admin grant of those keys raises a connection error
  #   * `:race`     — another writer saves the flag between its read and write
  #   * `:fail_flag` — saving the flag comes back as an error tuple
  #   * `:undefined_table` — reading a setting raises "relation does not exist"
  @real PhoenixKit.Test.Repo
  @overridden [
    query!: 1,
    query!: 2,
    query!: 3,
    get_by: 2,
    get_by: 3,
    insert: 1,
    insert: 2,
    all: 1,
    all: 2
  ]

  for {name, arity} <- @real.__info__(:functions), {name, arity} not in @overridden do
    args = Macro.generate_arguments(arity, __MODULE__)
    def unquote(name)(unquote_splicing(args)), do: @real.unquote(name)(unquote_splicing(args))
  end

  def block(keys), do: :persistent_term.put({__MODULE__, :blocked}, keys)
  def race(flag_key, skip), do: :persistent_term.put({__MODULE__, :race}, {flag_key, skip})
  def fail_flag(flag_key), do: :persistent_term.put({__MODULE__, :fail_flag}, flag_key)
  def undefined_table(on?), do: :persistent_term.put({__MODULE__, :undefined_table}, on?)
  def fail_role_reads(on?), do: :persistent_term.put({__MODULE__, :fail_role_reads}, on?)

  def reset do
    for fault <- [:blocked, :race, :fail_flag, :undefined_table, :fail_role_reads],
        do: :persistent_term.erase({__MODULE__, fault})
  end

  def query!(sql, params \\ [], opts \\ []) do
    blocked = :persistent_term.get({__MODULE__, :blocked}, [])

    if Enum.any?(params, fn param ->
         is_binary(param) and String.starts_with?(param, "pk_role_perm:") and
           Enum.any?(blocked, &String.ends_with?(param, ":" <> &1))
       end),
       do: raise(DBConnection.ConnectionError, "simulated connection failure")

    @real.query!(sql, params, opts)
  end

  # `:fail_role_reads` — every read of `phoenix_kit_role_permissions` raises.
  def all(queryable, opts \\ []) do
    if :persistent_term.get({__MODULE__, :fail_role_reads}, false) and
         role_permissions?(queryable),
       do: raise(DBConnection.ConnectionError, "simulated read failure")

    @real.all(queryable, opts)
  end

  defp role_permissions?(%Ecto.Query{from: %{source: {"phoenix_kit_role_permissions", _}}}),
    do: true

  defp role_permissions?(_), do: false

  def get_by(queryable, clauses, opts \\ []) do
    if :persistent_term.get({__MODULE__, :undefined_table}, false) do
      raise %Postgrex.Error{postgres: %{code: :undefined_table, message: "no such table"}}
    end

    result = @real.get_by(queryable, clauses, opts)
    key = clauses[:key]

    case :persistent_term.get({__MODULE__, :race}, nil) do
      {^key, 0} when is_nil(result) ->
        # The winner saves the flag after we looked and found nothing.
        :persistent_term.erase({__MODULE__, :race})
        {:ok, _} = PhoenixKit.Settings.update_setting(key, "true")
        result

      {^key, skip} when skip > 0 ->
        :persistent_term.put({__MODULE__, :race}, {key, skip - 1})
        result

      _ ->
        result
    end
  end

  def insert(struct, opts \\ []) do
    with %Ecto.Changeset{changes: %{key: key}} <- struct,
         ^key <- :persistent_term.get({__MODULE__, :fail_flag}, nil) do
      {:error, Ecto.Changeset.add_error(struct, :key, "simulated write failure")}
    else
      _ -> @real.insert(struct, opts)
    end
  end
end

defmodule PhoenixKit.Integration.Users.AdminGrantsTest do
  # async: false — the grants run in their own process (shared sandbox) and
  # the repo is swapped for a faulty wrapper in application env.
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Dashboard.Registry
  alias PhoenixKit.Integration.Users.AdminGrantsTest.FaultyRepo
  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries, as: SettingsQueries
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Permissions.AdminGrants
  alias PhoenixKit.Users.Roles

  @key "languages"
  @flag "auto_granted_perm:languages"
  @media_flag "media_sub_permissions_backfilled"
  @settings_flag "settings_security_backfilled"

  setup do
    admin_uuid = Roles.get_role_by_name("Admin").uuid

    Repo.query!("DELETE FROM phoenix_kit_role_permissions WHERE module_key = $1", [@key])
    Repo.query!("DELETE FROM phoenix_kit_settings WHERE key IN ($1, $2)", [@flag, @media_flag])

    Repo.query!(
      "DELETE FROM phoenix_kit_role_permissions WHERE module_key IN ('media.view_all', 'media.manage')"
    )

    previous_repo = Application.fetch_env(:phoenix_kit, :repo)
    Application.put_env(:phoenix_kit, :repo, FaultyRepo)

    on_exit(fn ->
      FaultyRepo.reset()

      case previous_repo do
        {:ok, repo} -> Application.put_env(:phoenix_kit, :repo, repo)
        :error -> Application.delete_env(:phoenix_kit, :repo)
      end
    end)

    {:ok, admin_uuid: admin_uuid}
  end

  defp flag, do: Settings.get_setting(@flag)
  defp held?(admin_uuid, key), do: key in Permissions.get_permissions_for_role(admin_uuid)
  defp errors(log, text), do: length(Regex.scan(~r/\[error\].*#{Regex.escape(text)}/, log))

  defp start_grants(opts) do
    opts = Keyword.merge([name: :test_admin_grants, sync_registry: false], opts)
    start_supervised!({AdminGrants, opts})
    opts[:name]
  end

  # The first pass is over before anything is judged.
  defp wait_initial(server), do: poll(fn -> :sys.get_state(server).initial_done? end)

  defp poll(fun, tries \\ 300) do
    cond do
      fun.() -> :ok
      tries == 0 -> flunk("condition never became true")
      true -> poll_again(fun, tries)
    end
  end

  defp poll_again(fun, tries) do
    receive do
    after
      10 -> poll(fun, tries - 1)
    end
  end

  describe "a grant that hits a database error" do
    test "returns the error, logs it once with the key and leaves the flag unset", %{
      admin_uuid: admin_uuid
    } do
      FaultyRepo.block([@key])

      log =
        capture_log(fn -> assert {:error, _} = Permissions.auto_grant_to_admin_roles(@key) end)

      assert errors(log, ~s(auto-grant of "languages")) == 1
      assert flag() != "true"
      refute held?(admin_uuid, @key)
    end

    test "is granted, and flagged, once the database recovers", %{admin_uuid: admin_uuid} do
      FaultyRepo.block([@key])
      capture_log(fn -> assert {:error, _} = Permissions.auto_grant_to_admin_roles(@key) end)

      FaultyRepo.block([])

      assert :ok = Permissions.auto_grant_to_admin_roles(@key)
      assert held?(admin_uuid, @key)
      assert flag() == "true"
    end

    test "makes the sweep return the failed keys" do
      FaultyRepo.block([@key])

      capture_log(fn ->
        assert {:error, failed} = Permissions.auto_grant_new_keys_to_admin()
        assert {@key, _} = List.keyfind(failed, @key, 0)
      end)

      FaultyRepo.block([])
      assert :ok = Permissions.auto_grant_new_keys_to_admin()
    end

    test "a rejected changeset is returned once, not flagged and not retried" do
      start_supervised!({AdminGrants, retry_base_ms: 20, sync_registry: false})
      wait_initial(AdminGrants)

      log =
        capture_log(fn ->
          assert {:error, %Ecto.Changeset{}} = Permissions.auto_grant_to_admin_roles("Bad Key!")
        end)

      assert errors(log, ~s("Bad Key!")) == 1
      assert Settings.get_setting("auto_granted_perm:Bad Key!") != "true"
      assert MapSet.size(:sys.get_state(AdminGrants).pending) == 0
      assert :ok = AdminGrants.await(1_000)
    end

    test "a flag another writer saved first is not a failure", %{admin_uuid: admin_uuid} do
      # The sweep and the tab registry grant the same built-in keys at the same
      # time; the loser's write meets the unique index.
      FaultyRepo.race(@flag, 1)

      assert :ok = Permissions.auto_grant_to_admin_roles(@key)
      assert held?(admin_uuid, @key)
      assert flag() == "true"
    end

    test "a flag that cannot be saved fails the grant and is queued for a retry" do
      start_supervised!({AdminGrants, retry_base_ms: 5_000, sync_registry: false})
      wait_initial(AdminGrants)
      Repo.query!("DELETE FROM phoenix_kit_role_permissions WHERE module_key = $1", [@key])
      Repo.query!("DELETE FROM phoenix_kit_settings WHERE key = $1", [@flag])
      FaultyRepo.fail_flag(@flag)

      capture_log(fn ->
        assert {:error, {:flag_not_saved, _}} = Permissions.auto_grant_to_admin_roles(@key)
      end)

      assert flag() != "true"
      poll(fn -> @key in :sys.get_state(AdminGrants).pending end)
    end

    test "a missing table is an expected :ok, not an error" do
      FaultyRepo.undefined_table(true)

      log =
        capture_log(fn ->
          assert :ok = Permissions.auto_grant_to_admin_roles(@key)
          assert :ok = Permissions.backfill_media_sub_permissions()
        end)

      refute log =~ "[error]"
    end

    test "only database errors are retried" do
      refute Permissions.retriable_grant_error?(%Ecto.Changeset{valid?: false})
      refute Permissions.retriable_grant_error?(:role_not_found)
      refute Permissions.retriable_grant_error?({:no_owner, %DBConnection.OwnershipError{}})
      assert Permissions.retriable_grant_error?(%Postgrex.Error{})
      assert Permissions.retriable_grant_error?({:exit, :noproc})
      assert Permissions.retriable_grant_error?({:flag_not_saved, :boom})
    end
  end

  describe "AdminGrants" do
    test "retries a failed key until it is granted, and await returns :ok", %{
      admin_uuid: admin_uuid
    } do
      FaultyRepo.block([@key])

      capture_log(fn ->
        server = start_grants(retry_base_ms: 20, max_attempts: 50)
        wait_initial(server)

        assert {:error, :timeout} = AdminGrants.await(100, server)
        refute held?(admin_uuid, @key)
        assert flag() != "true"

        FaultyRepo.block([])
        assert :ok = AdminGrants.await(5_000, server)
      end)

      assert held?(admin_uuid, @key)
      assert flag() == "true"
    end

    test "a key registered after startup that fails is retried by the running server", %{
      admin_uuid: admin_uuid
    } do
      # A custom key: the boot sweep does not know it, so only the report from
      # `register_custom_key/2` can bring it into the retry.
      custom = "pk_custom_grant_probe"
      on_exit(fn -> Permissions.unregister_custom_key(custom) end)

      start_supervised!({AdminGrants, retry_base_ms: 20, sync_registry: false})
      wait_initial(AdminGrants)
      FaultyRepo.block([custom])

      capture_log(fn ->
        Permissions.register_custom_key(custom)
        assert {:error, :timeout} = AdminGrants.await(100)

        FaultyRepo.block([])
        assert :ok = AdminGrants.await(5_000)
      end)

      assert held?(admin_uuid, custom)
    end

    test "the dashboard registry's grant of a core tab key reaches the server", %{
      admin_uuid: admin_uuid
    } do
      start_supervised!({AdminGrants, retry_base_ms: 20, sync_registry: false})
      wait_initial(AdminGrants)
      assert :ok = AdminGrants.await(5_000)

      Repo.query!("DELETE FROM phoenix_kit_role_permissions WHERE module_key = $1", [@key])
      Repo.query!("DELETE FROM phoenix_kit_settings WHERE key = $1", [@flag])
      FaultyRepo.block([@key])

      capture_log(fn ->
        Registry.auto_register_custom_permission(%{permission: @key})
        assert {:error, :timeout} = AdminGrants.await(100)

        FaultyRepo.block([])
        assert :ok = AdminGrants.await(5_000)
      end)

      assert held?(admin_uuid, @key)
    end

    test "the pause between retries doubles" do
      FaultyRepo.block([@key])

      capture_log(fn ->
        server = start_grants(retry_base_ms: 1_000, max_attempts: 5)
        wait_initial(server)

        first = Process.read_timer(:sys.get_state(server).timer)
        assert first in 1..1_000

        send(server, :retry)
        poll(fn -> :sys.get_state(server).attempts == 2 end)
        second = Process.read_timer(:sys.get_state(server).timer)
        assert second > 1_000 and second <= 2_000
      end)
    end

    test "a failed media backfill is returned, retried and flagged only on success" do
      FaultyRepo.block(["media"])

      capture_log(fn ->
        assert {:error, _} = Permissions.backfill_media_sub_permissions()
        assert Settings.get_setting(@media_flag) != "true"

        server = start_grants(retry_base_ms: 20, max_attempts: 50)
        wait_initial(server)
        assert {:error, :timeout} = AdminGrants.await(100, server)
        assert :media_subs in :sys.get_state(server).pending

        FaultyRepo.block([])
        assert :ok = AdminGrants.await(5_000, server)
      end)

      assert Settings.get_setting(@media_flag) == "true"
    end

    test "a failed settings backfill is returned, retried and flagged only on success", %{
      admin_uuid: admin_uuid
    } do
      Repo.query!("DELETE FROM phoenix_kit_settings WHERE key = $1", [@settings_flag])
      {:ok, _} = Permissions.grant_permission(admin_uuid, "settings")
      FaultyRepo.block(["settings"])

      capture_log(fn ->
        assert {:error, _} = Permissions.backfill_settings_sub_permissions()
        assert Settings.get_setting(@settings_flag) != "true"

        server = start_grants(retry_base_ms: 20, max_attempts: 50)
        wait_initial(server)
        assert {:error, :timeout} = AdminGrants.await(100, server)
        assert :settings_subs in :sys.get_state(server).pending

        FaultyRepo.block([])
        assert :ok = AdminGrants.await(5_000, server)
      end)

      assert Settings.get_setting(@settings_flag) == "true"
      assert held?(admin_uuid, "settings.security")
    end

    test "a failed read of who holds settings leaves the backfill flag unset", %{
      admin_uuid: admin_uuid
    } do
      Repo.query!("DELETE FROM phoenix_kit_settings WHERE key = $1", [@settings_flag])

      Repo.query!(
        "DELETE FROM phoenix_kit_role_permissions WHERE role_uuid = $1::text::uuid AND module_key = 'settings.security'",
        [admin_uuid]
      )

      FaultyRepo.fail_role_reads(true)

      capture_log(fn ->
        assert {:error, _} = Permissions.backfill_settings_subs(report: false)
      end)

      FaultyRepo.fail_role_reads(false)

      refute match?(
               %{value: "true"},
               SettingsQueries.get_setting_by_key(@settings_flag)
             )

      refute held?(admin_uuid, "settings.security")
    end

    test "gives up after max_attempts, says which keys are missing, and logs each level once" do
      FaultyRepo.block([@key])

      log =
        capture_log(fn ->
          server = start_grants(retry_base_ms: 5, max_attempts: 3)
          assert {:error, {:failed, keys}} = AdminGrants.await(5_000, server)
          assert @key in keys
        end)

      # Error on the first pass only; each retry is a warning; one verdict.
      assert errors(log, ~s(auto-grant of "languages")) == 1
      assert length(Regex.scan(~r/\[warning\].*auto-grant of "languages"/, log)) == 3
      assert errors(log, "Giving up") == 1
      assert flag() != "true"
    end

    test "a sweep that raises is retried instead of crashing the server" do
      {:ok, calls} = Agent.start_link(fn -> 0 end)

      sweep = fn _opts ->
        case Agent.get_and_update(calls, &{&1, &1 + 1}) do
          0 -> raise "sweep blew up"
          _ -> []
        end
      end

      log =
        capture_log(fn ->
          server = start_grants(retry_base_ms: 10, sweep_fun: sweep)
          pid = Process.whereis(server)
          wait_initial(server)

          assert :ok = AdminGrants.await(5_000, server)
          assert Process.whereis(server) == pid
        end)

      assert log =~ "Admin grant sweep crashed"
      assert Agent.get(calls, & &1) == 2
    end

    test "a key that cannot be retried is reported, also after a retried sweep" do
      cs = %Ecto.Changeset{valid?: false}
      {:ok, calls} = Agent.start_link(fn -> 0 end)

      sweep = fn _opts ->
        case Agent.get_and_update(calls, &{&1, &1 + 1}) do
          0 -> raise "sweep blew up"
          _ -> [{"Bad Key!", cs}]
        end
      end

      capture_log(fn ->
        server = start_grants(retry_base_ms: 10, sweep_fun: sweep)
        assert {:error, {:failed, ["Bad Key!"]}} = AdminGrants.await(5_000, server)
        assert :sys.get_state(server).timer == nil
      end)
    end

    test "a registry wait that did not finish is retried" do
      {:ok, calls} = Agent.start_link(fn -> 0 end)

      registry = fn _timeout ->
        case Agent.get_and_update(calls, &{&1, &1 + 1}) do
          0 -> {:error, :timeout}
          _ -> :ok
        end
      end

      server =
        start_grants(retry_base_ms: 10, sync_registry: true, registry_fun: registry)

      assert :registry in :sys.get_state(server).pending or Agent.get(calls, & &1) > 1
      assert :ok = AdminGrants.await(5_000, server)
      assert Agent.get(calls, & &1) == 2
    end

    test "await returns an error, not an exit, when the server dies while waiting" do
      FaultyRepo.block([@key])

      capture_log(fn ->
        server = start_grants(retry_base_ms: 5_000, max_attempts: 5)
        wait_initial(server)
        pid = Process.whereis(server)

        task = Task.async(fn -> AdminGrants.await(5_000, server) end)
        poll(fn -> :sys.get_state(server).waiters != [] end)
        Process.exit(pid, :kill)

        assert {:error, {:exit, _}} = Task.await(task)
      end)
    end

    test "await returns :ok when no server is running" do
      assert :ok = AdminGrants.await(10, :no_such_admin_grants)
    end
  end

  describe "Registry.await_initialized/1" do
    test "is :ok when the registry is not running" do
      if Process.whereis(Registry), do: :ok, else: assert(:ok = Registry.await_initialized(10))
    end

    test "is an error, not :ok, when the registry does not answer in time" do
      if Process.whereis(Registry) do
        :ok
      else
        pid = spawn(fn -> Process.sleep(:infinity) end)
        Process.register(pid, Registry)
        on_exit(fn -> Process.exit(pid, :kill) end)

        assert {:error, _} = Registry.await_initialized(30)
      end
    end
  end
end

defmodule PhoenixKit.Integration.Users.AdminGrantsNoOwnerTest do
  # No sandbox checkout: the connection pool is in manual mode and has no owner
  # for this process, as in a host test suite after `Sandbox.mode(:manual)`.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Users.Permissions

  @moduletag :integration

  # A test before this one may have left the pool in shared mode with an owner that has
  # since exited, which answers a checkout with an exit instead of an ownership error.
  setup do
    Sandbox.mode(PhoenixKit.Test.Repo, :manual)
  end

  test "a missing database owner is a warning, returned and never retried" do
    log =
      capture_log(fn ->
        assert {:error, {:no_owner, %DBConnection.OwnershipError{}} = reason} =
                 Permissions.auto_grant_to_admin_roles("languages")

        refute Permissions.retriable_grant_error?(reason)
      end)

    assert log =~ "[warning]"
    assert log =~ "no database owner"
    refute log =~ "[error]"
  end
end
