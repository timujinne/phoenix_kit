defmodule PhoenixKit.SettingsCacheMissFillTest do
  @moduledoc """
  The settings cache now has a TTL, so entries expire. That is only safe
  because `get_settings_cached/2` fills on a miss — and it did not.

  `Cache.get_multiple/3` simply omits keys it does not hold, so an absent key
  was absent from the returned map and every caller read it as `nil`. Nothing
  ever surfaced that, because with no TTL an entry written once never expired.
  The first expiry wave would have left the OAuth credential helpers and the
  user-list date formats silently reading `nil` site-wide until something
  happened to re-warm them.

  These are the guard on that: they read keys the cache does not hold.

  `Cache.get_multiple/3` returns a map without the key in exactly two cases —
  the entry expired, or the cache is not answering — and `get_settings_cached/2`
  cannot tell them apart, so either one exercises the same branch. The test
  environment does not run the cache process, which makes every read here take
  the miss path; that is the path under test, not a workaround.
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
