defmodule PhoenixKit.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use PhoenixKit.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @moduletag :integration

      alias PhoenixKit.Test.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import PhoenixKit.DataCase
    end
  end

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Test.Repo, as: TestRepo
  alias PhoenixKit.Users.Auth, as: UsersAuth
  alias PhoenixKit.Users.RoleAssignment

  setup tags do
    pid = Sandbox.start_owner!(TestRepo, shared: not tags[:async])

    on_exit(fn -> Sandbox.stop_owner(pid) end)

    # Names this test's DB connection, so a deadlock report (40P01) or a
    # `log_lock_waits` line carries the test that held the lock instead of an
    # anonymous PID. Postgres truncates application_name at 63 bytes.
    if name = tags[:test] do
      TestRepo.query!("SELECT set_config('application_name', $1, false)", [
        String.slice(to_string(name), 0, 63)
      ])
    end

    :ok
  end

  @doc """
  Removes the suite's committed seed Owner from the picture, for THIS test only.

  `test_helper.exs` seeds one committed Owner so ordinary registrations skip
  the bootstrap lock (see the comment there). Tests that assert BOOTSTRAP
  semantics — "the first user becomes Owner", "the last Owner cannot be
  removed", owner counts — need a world where that seed does not hold Owner.
  Deleting its role assignment inside the test's own sandbox transaction gives
  them exactly that, invisibly to every concurrent test.
  """
  def demote_seed_owner(_context \\ %{}) do
    case UsersAuth.get_user_by_email("seed-owner@phoenixkit.test") do
      nil ->
        :ok

      seed ->
        import Ecto.Query, only: [from: 2]

        TestRepo.delete_all(from(a in RoleAssignment, where: a.user_uuid == ^seed.uuid))

        # The user row goes too: get_first_user/0 and friends answer by
        # registration order, and a lingering seed row would still be
        # "first" for every test asserting on it.
        TestRepo.delete!(seed)

        :ok
    end
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
