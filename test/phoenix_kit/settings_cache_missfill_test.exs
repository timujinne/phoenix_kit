defmodule PhoenixKit.SettingsCacheMissFillTest do
  @moduledoc """
  The settings cache now has a TTL, so entries expire. That is only safe
  because `get_settings_cached/2` fills on a miss — and it did not.

  `Cache.get_multiple/3` does NOT simply omit keys it does not hold. Its
  `handle_call` always writes every requested key into the returned map,
  substituting `Map.get(defaults, key)` on a miss (expired, or never cached)
  rather than leaving the key out. `get_settings_cached/2` used to pass `%{}`
  as those defaults, so a miss read back as plain `nil` — indistinguishable
  from "cached, and the value happens to be nil" — and `Map.has_key?/2` saw
  every requested key as present. `fill_missing_settings/1`, the only place
  that actually goes to the database, was therefore never called. Nothing
  surfaced that while the cache had no TTL: entries were written once and
  never expired. The first expiry wave would have left the OAuth credential
  helpers and the user-list date formats silently reading `nil` site-wide
  until something happened to re-warm them.

  These are the guard on that: they read keys the cache does not hold.

  The fix tags every requested key with a private sentinel as the
  cache-level default, then detects a miss by matching that sentinel instead
  of by key presence in the result — the caller's own `defaults` never reach
  `Cache.get_multiple/3`, so a genuinely cached value equal to one is never
  mistaken for a miss either. The test environment does not run the cache
  process (`Cache.get_multiple/3`'s own `:noproc` fallback returns whatever
  was passed as `defaults` verbatim), which makes every read here take the
  miss path regardless; that is the path under test, not a workaround.
  `test/phoenix_kit/settings_cache_missfill_unit_test.exs` proves the same
  defect and fix at the cache layer alone, with no database at all.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Cache
  alias PhoenixKit.Settings

  @cache :settings

  defp probe_key, do: "missfill_probe_#{System.unique_integer([:positive])}"

  # Evicts without touching the row, for the case where the cache IS running.
  # Deliberately a probe key: the settings docs warn never to evict a real key
  # in a test.
  defp forget(key), do: Cache.invalidate(@cache, key)

  describe "a batch read whose keys are not cached" do
    test "returns the stored values, not nil" do
      key = probe_key()
      {:ok, _} = Settings.update_setting(key, "stored-value")

      forget(key)

      assert %{^key => "stored-value"} = Settings.get_settings_cached([key])
    end

    test "returns the stored values, not the caller's defaults" do
      # The subtler half: a caller passing defaults would get its default and
      # never know the real value existed. That is how a configured OAuth
      # credential reads as "not configured".
      key = probe_key()
      {:ok, _} = Settings.update_setting(key, "real")

      forget(key)

      assert %{^key => "real"} = Settings.get_settings_cached([key], %{key => "fallback"})
    end

    test "a failed query does not negatively cache every requested key" do
      # `get_settings_direct/1` swallows query errors and returns `%{}`, which
      # is indistinguishable from "none of these keys exist". Caching on that
      # would write a "does not exist" entry for every key and hold it for a
      # full TTL — so one transient database blip during an expiry wave would
      # make configured OAuth credentials read as unconfigured, site-wide, for
      # five minutes.
      key = probe_key()
      {:ok, _} = Settings.update_setting(key, "real")
      forget(key)

      # `update_mode` is the one switch that makes the settings query refuse to
      # run without raising — the same silent-empty shape a pool failure has.
      Application.put_env(:phoenix_kit, :update_mode, true)

      try do
        assert %{^key => "fallback"} = Settings.get_settings_cached([key], %{key => "fallback"})
      after
        Application.delete_env(:phoenix_kit, :update_mode)
      end

      # …and the real value is still readable afterwards, because nothing was
      # poisoned on the way through.
      assert %{^key => "real"} = Settings.get_settings_cached([key])
    end

    test "a key with no row still falls back to the caller's default" do
      key = probe_key()

      assert %{^key => "fallback"} = Settings.get_settings_cached([key], %{key => "fallback"})
    end

    test "a mix of cached, uncached and absent keys all resolve correctly" do
      cached = probe_key()
      uncached = probe_key()
      absent = probe_key()

      {:ok, _} = Settings.update_setting(cached, "c")
      {:ok, _} = Settings.update_setting(uncached, "u")

      # Warm one, forget the other.
      Settings.get_setting_cached(cached)
      forget(uncached)

      result = Settings.get_settings_cached([cached, uncached, absent], %{absent => "d"})

      assert result[cached] == "c"
      assert result[uncached] == "u"
      assert result[absent] == "d"
    end
  end
end
