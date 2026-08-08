defmodule PhoenixKit.Settings.SettingTest do
  use ExUnit.Case, async: true

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Setting

  describe "@optional_settings ⊇ empty-string defaults invariant" do
    test "every key with an empty-string default is in @optional_settings" do
      empty_string_keys =
        Settings.get_defaults()
        |> Enum.filter(fn {_k, v} -> v == "" end)
        |> Enum.map(fn {k, _} -> k end)
        |> Enum.sort()

      optional = Setting.optional_settings()

      missing = empty_string_keys -- optional

      assert missing == [],
             """
             The following setting keys have empty-string defaults in \
             `PhoenixKit.Settings.get_defaults/0` but are missing from \
             `@optional_settings` in `PhoenixKit.Settings.Setting`:

               #{inspect(missing)}

             Batch-saving these from an empty form field will trip \
             `validate_value_exclusivity/1` and roll back the whole save. \
             Add them to `@optional_settings`. See PR #502.
             """
    end
  end

  describe "SettingsForm — main_page_path" do
    # `changeset/2` itself is pure, but its pipeline calls
    # `validate_new_user_default_role/1` → `Roles.list_roles/0`, which needs a
    # repository — so the whole form changeset is DB-bound regardless of which
    # field is under test.
    @describetag :integration

    alias PhoenixKit.Settings.Setting.SettingsForm

    # This module is a plain `ExUnit.Case`, not a `PhoenixKit.DataCase` — the
    # other describes here must keep running on the database-less half — so
    # nothing checks a sandbox connection out for us. Without an owner these
    # tests raise `DBConnection.OwnershipError` the moment `Roles.list_roles/0`
    # runs; they only looked green while the suite had no database and the
    # `:integration` tag excluded them.
    #
    # `shared: false` because the module is `async: true`.
    setup do
      pid = Sandbox.start_owner!(PhoenixKit.Test.Repo, shared: false)
      on_exit(fn -> Sandbox.stop_owner(pid) end)
      :ok
    end

    defp change(value) do
      SettingsForm.changeset(%SettingsForm{}, %{"main_page_path" => value})
    end

    defp error_on(changeset) do
      changeset.errors |> Keyword.get(:main_page_path) |> elem(0)
    end

    test "a blank value is accepted and produces no change" do
      for value <- ["", "   "] do
        changeset = change(value)

        assert changeset.errors[:main_page_path] == nil

        # `cast/3` treats a blank string as an EMPTY VALUE, so both of these
        # drop out before `validate_local_path/2` runs: there is nothing to
        # trim, nothing lands in `changes`, and `get_field/2` answers the
        # struct default. Clearing the stored setting is the WRITER's job, not
        # the changeset's — `update_all_settings_from_changeset/1` reads
        # `changeset.params` and substitutes the default ("") for a submitted
        # value that is nil or "".
        assert changeset.changes[:main_page_path] == nil
        assert Ecto.Changeset.get_field(changeset, :main_page_path) == nil
      end
    end

    test "a local path is accepted and lands in changes" do
      changeset = change("/shop")

      assert changeset.errors[:main_page_path] == nil
      # Proves the field is in the `cast/3` list. Without it the value would
      # still be PERSISTED (update_all_settings_from_changeset/1 writes from
      # `changeset.params`, not from the changes) but never validated.
      assert changeset.changes[:main_page_path] == "/shop"
    end

    test "rejects anything that is not a local path" do
      for value <- [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/\t/evil.example",
            "evil.example"
          ] do
        changeset = change(value)
        refute changeset.valid?, "expected #{inspect(value)} to be rejected"
        assert error_on(changeset) =~ "local path"
      end
    end

    test "rejects a sign-in page — it would loop" do
      for value <- ["/users/log-out", "/et/users/log-in"] do
        changeset = change(value)
        refute changeset.valid?, "expected #{inspect(value)} to be rejected"
        assert error_on(changeset) =~ "sign-in page"
      end
    end
  end

  describe "main_page_path default" do
    test "defaults to empty, never \"/\"" do
      # `update_all_settings_from_changeset/1` writes the DEFAULT back when a
      # field is submitted empty, so a "/" default would silently re-introduce
      # the unowned root as a positively-configured destination.
      assert Settings.get_defaults()["main_page_path"] == ""
    end
  end
end
