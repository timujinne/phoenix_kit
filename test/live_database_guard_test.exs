defmodule PhoenixKit.Test.LiveDatabaseGuardTest do
  @moduledoc """
  S014 / PK-B: pure unit coverage for `check!/1`'s own decision — separate
  from `LiveDatabaseGuardWiringTest`, which proves the module is actually
  reachable from `test_helper.exs`'s real boot sequence, not just that its
  logic is correct in isolation.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Test.LiveDatabaseGuard

  describe "check!/1 — built-in suffix pattern (zero configuration)" do
    test "still raises for each of this container's three known live databases" do
      for db <- ~w(phoenix_kit_dev decor_3d_print_dev phoenixkit_hello_world_dev) do
        assert_raise LiveDatabaseGuard.LiveDatabaseError, ~r/#{db}/, fn ->
          LiveDatabaseGuard.check!(db)
        end
      end
    end

    test "generalizes beyond this container's three hardcoded names" do
      # None of these ever appeared in the old literal list — proof the
      # refusal now comes from the suffix pattern, not a name that merely
      # happens to still be in a hardcoded set somewhere.
      for db <- ~w(acme_production shop_staging widgets_development other_app_prod) do
        assert_raise LiveDatabaseGuard.LiveDatabaseError, fn ->
          LiveDatabaseGuard.check!(db)
        end
      end
    end

    test "suffix match is case-insensitive" do
      assert_raise LiveDatabaseGuard.LiveDatabaseError, fn ->
        LiveDatabaseGuard.check!("Acme_PRODUCTION")
      end
    end

    test "the raised message says WHY, not just which database" do
      assert_raise LiveDatabaseGuard.LiveDatabaseError,
                   ~r/non-test environment/,
                   fn -> LiveDatabaseGuard.check!("phoenix_kit_dev") end
    end
  end

  describe "check!/1 — a foreign host's legitimately different test database name" do
    test "an arbitrary pre-provisioned scratch name (no CREATEDB workflow) passes through" do
      # This is exactly the case config/test.exs's own PGDATABASE-honoring
      # comment describes: "a database you already have instead of one
      # this role is allowed to CREATE". Nothing about these names
      # resembles a non-test environment, so none of them are refused.
      for db <- ~w(ci_runner_42 pk_scratch_7 shared_ci_db build_42_scratch) do
        assert :ok = LiveDatabaseGuard.check!(db)
      end
    end

    test "passes an isolated test database name straight through" do
      assert :ok = LiveDatabaseGuard.check!("phoenix_kit_test")
    end

    test "an empty or unusual name is never mistaken for a live database" do
      assert :ok = LiveDatabaseGuard.check!("")
      assert :ok = LiveDatabaseGuard.check!("phoenix_kit_test1")
    end

    test "a name that merely CONTAINS a dangerous suffix, not ENDS with it, is not a match" do
      # Substring-anywhere matching would be its own bug: a scratch DB
      # deliberately named to mention "dev" mid-string must not be refused
      # — only a database name actually ENDING in a dangerous suffix is.
      assert :ok = LiveDatabaseGuard.check!("dev_tools_scratch")
      assert :ok = LiveDatabaseGuard.check!("phoenix_kit_dev_backup")
    end
  end

  describe "check!/1 — PHOENIX_KIT_TEST_DB_DENYLIST (opt-in extra names)" do
    setup do
      on_exit(fn -> System.delete_env("PHOENIX_KIT_TEST_DB_DENYLIST") end)
    end

    test "refuses an exact name a host declares, even without a dangerous suffix" do
      System.put_env("PHOENIX_KIT_TEST_DB_DENYLIST", "acme_main,other_live_db")

      assert_raise LiveDatabaseGuard.LiveDatabaseError, ~r/acme_main/, fn ->
        LiveDatabaseGuard.check!("acme_main")
      end

      assert :ok = LiveDatabaseGuard.check!("acme_scratch")
    end

    test "denylist comparison is case-insensitive and trims whitespace" do
      System.put_env("PHOENIX_KIT_TEST_DB_DENYLIST", " Acme_Main , other_db ")

      assert_raise LiveDatabaseGuard.LiveDatabaseError, fn ->
        LiveDatabaseGuard.check!("acme_main")
      end
    end

    test "unset (the upstream default) refuses nothing beyond the suffix pattern" do
      System.delete_env("PHOENIX_KIT_TEST_DB_DENYLIST")
      assert :ok = LiveDatabaseGuard.check!("acme_main")
    end
  end
end
