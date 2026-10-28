defmodule PhoenixKit.API.ConfigLimitsTest do
  @moduledoc """
  `PhoenixKit.API.Config.int/2`, `rate_limits/0` and `max_body_bytes/0`
  against the real Settings table.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.API.Config
  alias PhoenixKit.Settings

  describe "int/2" do
    test "returns the default when the setting is missing" do
      assert Config.int("api_test_missing_int", 7) == 7
    end

    test "returns the stored positive integer" do
      {:ok, _} = Settings.update_setting("api_test_int", "42")
      assert Config.int("api_test_int", 7) == 42
    end

    test "falls back to the default for text, zero and negative values" do
      for bad <- ["abc", "", "0", "-5"] do
        {:ok, _} = Settings.update_setting("api_test_int", bad)
        assert Config.int("api_test_int", 7) == 7, "stored #{inspect(bad)}"
      end
    end
  end

  describe "int/2 with a value that only starts like a number" do
    test "is not read by its prefix" do
      for bad <- ["12abc", "1.5", "12 requests", "1e3"] do
        {:ok, _} = Settings.update_setting("api_test_int", bad)
        assert Config.int("api_test_int", 7) == 7, "stored #{inspect(bad)}"
      end
    end

    test "ignores whitespace around a whole number" do
      {:ok, _} = Settings.update_setting("api_test_int", " 42\n")
      assert Config.int("api_test_int", 7) == 42
    end
  end

  describe "rate_limits/0 and max_body_bytes/0" do
    test "carry the documented defaults" do
      assert Config.rate_limits() == %{
               preauth_fail_per_min: 20,
               admin_per_min: 600,
               public_token_per_min: 120,
               public_ip_per_min: 300,
               new_rows_ip_hour: 120,
               new_rows_global_hour: 2000
             }

      assert Config.max_body_bytes() == 2_097_152
    end

    test "each limit follows its own setting" do
      {:ok, _} = Settings.update_setting("api_admin_rate_per_min", "5")
      {:ok, _} = Settings.update_setting("api_public_new_rows_global_hour", "9")

      limits = Config.rate_limits()
      assert limits.admin_per_min == 5
      assert limits.new_rows_global_hour == 9
      assert limits.public_ip_per_min == 300
    end
  end

  describe "the settings that were renamed" do
    test "the old keys are not read: only the new key counts" do
      {:ok, _} = Settings.update_setting("api_public_cart_rate_per_min", "77")
      {:ok, _} = Settings.update_setting("api_public_cart_rows_per_ip_hour", "88")
      {:ok, _} = Settings.update_setting("api_public_cart_rows_global_hour", "99")

      limits = Config.rate_limits()

      assert limits.public_token_per_min == 120
      assert limits.new_rows_ip_hour == 120
      assert limits.new_rows_global_hour == 2000
    end
  end
end
