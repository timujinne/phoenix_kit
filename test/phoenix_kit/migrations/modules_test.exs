defmodule PhoenixKit.Migrations.ModulesTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Covers the classification and filtering that `mix phoenix_kit.status` and
  `mix phoenix_kit.update` both read.

  Discovery itself (beam scanning) needs real dependent packages compiled into
  the build, so it isn't exercised here — `list/1` is asserted to degrade to
  `[]` rather than raise, which is the contract the CLI tasks depend on.
  """

  alias PhoenixKit.Migrations.Modules

  doctest PhoenixKit.Migrations.Modules, only: [classify: 2]

  describe "list/1" do
    test "returns a list and never raises, even with nothing installed" do
      assert is_list(Modules.list())
      assert is_list(Modules.list(prefix: "public"))
    end

    test "every entry carries the full shape both tasks read" do
      for entry <- Modules.list() do
        assert %{
                 name: name,
                 module: module,
                 migration_module: migration_module,
                 installed: installed,
                 status: status
               } = entry

        assert is_binary(name)
        assert is_atom(module)
        assert is_atom(migration_module)
        assert is_integer(installed) and installed >= 0
        assert status in [:not_installed, :needs_update, :up_to_date, :ahead_of_code, :error]
      end
    end

    test "an entry's status agrees with classify/2 on its own versions" do
      # Ties the discovery path to the classifier, so a change to one that
      # contradicts the other cannot pass.
      for %{status: status, installed: installed, target: target} <- Modules.list(),
          status != :error do
        assert Modules.classify(installed, target) == status
      end
    end
  end

  describe "pending/1" do
    test "selects modules whose tables are missing or behind" do
      entries = [
        entry("Fresh", 0, 1, :not_installed),
        entry("Behind", 1, 2, :needs_update),
        entry("Current", 2, 2, :up_to_date),
        error_entry("Broken")
      ]

      assert Modules.pending(entries) |> Enum.map(& &1.name) == ["Fresh", "Behind"]
    end

    test "a broken module is not treated as pending — migrating it blind would be worse" do
      assert Modules.pending([error_entry("Broken")]) == []
    end

    test "an empty list stays empty" do
      assert Modules.pending([]) == []
    end
  end

  describe "failed/1" do
    test "isolates modules whose coordinator raised" do
      entries = [entry("Current", 1, 1, :up_to_date), error_entry("Broken")]

      assert Modules.failed(entries) |> Enum.map(& &1.name) == ["Broken"]
    end

    test "an empty list stays empty" do
      assert Modules.failed([]) == []
    end
  end

  describe "classify/2" do
    test "installed exactly at target is up to date" do
      assert Modules.classify(2, 2) == :up_to_date
    end

    test "installed above target is ahead of code, not up to date" do
      # This is the state a rollback/downgrade produces: the schema was
      # migrated by a later release than the one now running. Folding it into
      # :up_to_date (an `installed >= target` guard) hides the downgrade
      # entirely — this must stay a distinct value.
      assert Modules.classify(3, 2) == :ahead_of_code
    end

    test "equal stays up to date even when ahead is also possible nearby" do
      # Guards against the opposite mutation: swapping `==` for `>=` on the
      # up_to_date clause would make this pass too, but the ahead test above
      # would then fail since :ahead_of_code could never be reached first —
      # together the two tests pin both boundaries of `installed == target`.
      assert Modules.classify(5, 5) == :up_to_date
    end

    test "zero installed with a target has never been installed" do
      assert Modules.classify(0, 1) == :not_installed
    end

    test "installed below target needs an update" do
      assert Modules.classify(1, 5) == :needs_update
      assert Modules.classify(1, 2) == :needs_update
    end

    test "a non-integer version is an error, never up to date" do
      # Under Erlang term ordering every atom sorts above every integer, so an
      # unguarded `installed >= target` reads nil as "ahead of target" and the
      # module's migration is skipped forever. Each of these must be :error.
      assert Modules.classify(nil, 2) == :error
      assert Modules.classify(2, nil) == :error
      assert Modules.classify("2", 2) == :error
      assert Modules.classify(:latest, 2) == :error
      assert Modules.classify(nil, nil) == :error
    end

    test "an error classification is not pending — blind migration is worse" do
      refute Modules.classify(nil, 2) in [:not_installed, :needs_update]
    end
  end

  defp entry(name, installed, target, status) do
    %{
      name: name,
      module: SomeModule,
      migration_module: SomeModule.Migrations,
      installed: installed,
      target: target,
      status: status,
      error: nil
    }
  end

  defp error_entry(name) do
    %{
      name: name,
      module: SomeModule,
      migration_module: SomeModule.Migrations,
      installed: 0,
      target: nil,
      status: :error,
      error: "boom"
    }
  end
end
