defmodule PhoenixKit.SettingsJsonCacheMissFillUnitTest do
  @moduledoc """
  I157 follow-up (F2): `get_json_settings_cached/2` carried the exact same
  miss-fill defect `get_settings_cached/2` had — `Cache.get_multiple/3` does
  NOT omit keys it does not hold; `handle_call` always writes every
  requested key into the returned map, substituting `Map.get(defaults, key)`
  on a miss. Passing `%{}` as those defaults (as this function did) made a
  miss read back as plain `nil`, indistinguishable from "cached, and the
  value happens to be nil" — so `Map.has_key?/2` saw every key as present
  and `missing` was always `[]`. `fill_missing_json_settings/1` — the only
  place that goes to the database for the JSON path — was never called on a
  genuine miss.

  Same reproduction technique as `settings_cache_missfill_unit_test.exs`:
  hit a REAL `PhoenixKit.Cache` GenServer (ETS-backed, no database) with
  `:update_mode` on, so `fill_missing_json_settings/1` short-circuits to
  `%{}` cleanly instead of raising against an absent pool. A key never
  written to the cache is then a clean, deterministic miss.
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Cache
  alias PhoenixKit.Settings

  @cache :settings

  setup do
    previous_update_mode = Application.get_env(:phoenix_kit, :update_mode, false)
    Application.put_env(:phoenix_kit, :update_mode, true)

    on_exit(fn ->
      Application.put_env(:phoenix_kit, :update_mode, previous_update_mode)
    end)

    start_supervised!({PhoenixKit.Cache.Registry, []})
    start_supervised!({PhoenixKit.Cache, name: @cache})
    :ok
  end

  defp probe_key, do: "json_missfill_unit_probe_#{System.unique_integer([:positive])}"

  describe "a JSON key the settings cache never held (genuine miss, no database)" do
    test "resolves to the caller's own default, not a silently substituted nil" do
      key = probe_key()
      default = %{"theme" => "fallback"}

      assert Settings.get_json_settings_cached([key], %{key => default}) == %{key => default}
    end

    test "with no caller default either, still comes back as the caller's nil default" do
      key = probe_key()

      assert Settings.get_json_settings_cached([key]) == %{key => nil}
    end
  end

  describe "a JSON key genuinely cached with a nil value (not a miss)" do
    test "is still returned as nil, not overridden by the caller's default" do
      key = probe_key()
      Cache.put(@cache, key, nil)

      assert Settings.get_json_settings_cached([key], %{key => %{"theme" => "fallback"}}) ==
               %{key => nil}
    end
  end
end
