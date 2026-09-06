defmodule PhoenixKit.Users.RegistrationAccountTypeTest do
  @moduledoc """
  The `"registration_account_type"` policy: what the PUBLIC signup forms are
  allowed to create.

  Two halves, and the second is the one that matters. `registration_account_type/0`
  reads a setting, so this file starts the settings cache and primes it —
  `get_setting_cached/2` is consulted BEFORE the update-mode short-circuit
  `test_helper.exs` turns on when there is no database, so a primed key reads
  exactly as it would from a live one (the arrangement documented in
  `safe_destination_settings_test.exs`).

  `enforce_registration_account_type/2` is pure and needs none of that. It is
  the actual control — the hidden `<select>` is not — so it is exercised
  against the payloads a hidden picker invites: the forged ones.

  `async: false`, cache torn down per test: the cache is a globally named
  process and a primed `enable_organization_accounts` visible to a concurrent
  test would change that test's answer.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKitWeb.Live.Settings.Users, as: UsersSettings

  setup do
    # A cache miss falls through to the database, which this file has no
    # sandbox connection for. Checking out keeps the behaviour identical with
    # and without PostgreSQL.
    if Application.get_env(:phoenix_kit, :test_repo_available, false) do
      :ok = Sandbox.checkout(PhoenixKit.Test.Repo)
    end

    start_supervised!({PhoenixKit.Cache.Registry, []})
    start_supervised!({PhoenixKit.Cache, name: :settings})
    :ok
  end

  defp put_setting(key, value), do: PhoenixKit.Cache.put(:settings, key, value)

  defp orgs_on, do: put_setting("enable_organization_accounts", "true")

  describe "registration_account_type/0" do
    test "defaults to \"choice\" once organization accounts are on" do
      orgs_on()

      assert Auth.registration_account_type() == "choice"
    end

    test "is \"person\" while organization accounts are off, whatever the mode says" do
      put_setting("enable_organization_accounts", "false")
      put_setting("registration_account_type", "organization")

      assert Auth.registration_account_type() == "person"
    end

    test "reads each stored mode back" do
      orgs_on()

      for mode <- Settings.registration_account_types() do
        put_setting("registration_account_type", mode)
        assert Auth.registration_account_type() == mode
      end
    end

    test "an unrecognised stored value falls back rather than raising" do
      orgs_on()
      put_setting("registration_account_type", "company-only")

      assert Auth.registration_account_type() == "choice"
    end
  end

  describe "enforce_registration_account_type/2 in \"choice\" mode" do
    test "honours an explicit organization pick, name and all" do
      params = %{"account_type" => "organization", "organization_name" => "Acme"}

      assert Auth.enforce_registration_account_type(params, "choice") == params
    end

    test "anything that is not \"organization\" normalises to a person" do
      # The registration changeset has no `validate_inclusion` of its own, so an
      # unknown string would otherwise reach the insert and hit a CHECK
      # constraint as a 500 instead of a validation error.
      for forged <- ["person", "admin", "", "ORGANIZATION", nil] do
        params = %{"account_type" => forged, "organization_name" => "Acme"}

        assert Auth.enforce_registration_account_type(params, "choice") == %{
                 "account_type" => "person"
               }
      end
    end

    test "a payload with no account_type at all becomes a person" do
      assert Auth.enforce_registration_account_type(%{"email" => "a@b.c"}, "choice") == %{
               "email" => "a@b.c",
               "account_type" => "person"
             }
    end
  end

  describe "enforce_registration_account_type/2 in a fixed mode" do
    test "\"organization\" overrides a forged person pick" do
      params = %{"account_type" => "person", "organization_name" => "Acme"}

      assert Auth.enforce_registration_account_type(params, "organization") == %{
               "account_type" => "organization",
               "organization_name" => "Acme"
             }
    end

    test "\"person\" overrides a forged organization pick and drops the name" do
      params = %{"account_type" => "organization", "organization_name" => "Acme"}

      assert Auth.enforce_registration_account_type(params, "person") == %{
               "account_type" => "person"
             }
    end

    test "an unknown mode is treated as the safe one, not as \"choice\"" do
      params = %{"account_type" => "organization", "organization_name" => "Acme"}

      assert Auth.enforce_registration_account_type(params, "nonsense") == %{
               "account_type" => "person"
             }
    end

    test "other form fields survive untouched" do
      params = %{
        "email" => "a@b.c",
        "password" => "secret1234",
        "account_type" => "organization",
        "organization_name" => "Acme"
      }

      enforced = Auth.enforce_registration_account_type(params, "person")

      assert enforced["email"] == "a@b.c"
      assert enforced["password"] == "secret1234"
    end
  end

  describe "the picker's vocabulary" do
    test "every value the context offers has a translated label" do
      values = Settings.registration_account_types()

      assert "choice" in values
      assert Settings.default_registration_account_type() == "choice"

      for value <- values do
        label = UsersSettings.registration_account_type_label(value)

        assert is_binary(label) and label != "",
               "#{value} has no label"

        # The fallback clause returns the raw value — which is what a missing
        # `gettext/1` clause would silently ship to the settings page.
        refute label == value,
               "#{value} is missing a registration_account_type_label/1 clause"
      end
    end

    test "options carry the same values, in the same order" do
      assert Enum.map(Settings.registration_account_type_options(), &elem(&1, 1)) ==
               Settings.registration_account_types()
    end
  end
end
