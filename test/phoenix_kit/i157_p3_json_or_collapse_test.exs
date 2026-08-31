defmodule PhoenixKit.I157P3JsonOrCollapseTest do
  @moduledoc """
  I157 point 3 (round 2 of the Pi verdict): the `||` collapse the F1/F2
  follow-ups fixed for `get_settings_cached/2` and `get_json_settings_cached/2`
  is still present in two spots the earlier patch never touched:

    * the JSON WRITER, `fill_missing_json_settings/1`:
      `Map.get(found, &1) || @not_found_sentinel` — a key
      `query_json_settings_batch/1` found with a JSON value of `nil` gets
      written to cache as `@not_found_sentinel`, indistinguishable from "no
      row at all".

    * the JSON READER, `get_json_settings_cached/2`'s `cache_miss_sentinel`
      branch: `Map.get(fetched, key) || Map.get(defaults, key)` — the same
      collapse, one step later, on the value the writer just fetched from
      the database for a genuine miss.

  Each `describe` below isolates ONE of the two points: mutating only the
  OTHER point back to `||` must leave that describe's test green. See the
  per-test comment for how the isolation holds.

  `value_json` is schema-typed `:map | nil`
  (`lib/phoenix_kit/settings/setting.ex`), so a top-level JSON `false` can
  never actually be stored through the changeset — `nil` is the only
  reachable falsy top-level JSON value. It is reached here the same way
  `query_json_settings_batch/1` reaches it for any row that genuinely
  exists without a JSON value (a plain string-only setting):
  `Map.put(acc, setting.key, nil)`.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings

  @cache :settings

  setup do
    start_supervised!({PhoenixKit.Cache.Registry, []})
    # No warmer — cold cache, never warmed. fill_missing_json_settings/1 is
    # what's under test.
    start_supervised!({PhoenixKit.Cache, name: @cache})
    :ok
  end

  defp probe_key, do: "i157_p3_json_probe_#{System.unique_integer([:positive])}"

  describe "JSON reader: get_json_settings_cached/2, cache_miss_sentinel branch" do
    test "a key whose row exists with no JSON value resolves to nil on the first (miss-fill) read, not the caller's default" do
      key = probe_key()
      # Row exists (plain string setting) but carries no JSON value, so
      # query_json_settings_batch/1 legitimately returns nil for this key —
      # NOT because the row is missing.
      {:ok, _} = Settings.update_setting(key, "legacy-string-value")

      # Genuine cache miss: fill_missing_json_settings/1 (the writer) runs
      # and returns `found` straight through — untouched by the writer's own
      # cache-WRITE bug, which only corrupts what later gets cached, not
      # this function's return value. So this assertion is governed solely
      # by the reader's cache_miss_sentinel clause, regardless of whether
      # the writer point is mutated back to `||`.
      result = Settings.get_json_settings_cached([key], %{key => %{"fallback" => true}})

      assert result[key] == nil
    end
  end

  describe "JSON writer: fill_missing_json_settings/1" do
    test "a key whose row exists with no JSON value is cached as nil, not as the not-found sentinel" do
      key = probe_key()
      {:ok, _} = Settings.update_setting(key, "legacy-string-value")

      # First call warms the cache — the writer under test runs here. Its
      # return value is not asserted on; that is the reader test's job.
      _first = Settings.get_json_settings_cached([key], %{key => %{"fallback" => true}})

      # Second call hits the now-warm cache directly: cached_results[key] is
      # exactly what the writer wrote (nil, or the not-found sentinel if the
      # writer regresses to `||`), and that lands in the reduce's
      # unconditional `{:ok, cached} -> cached` clause or the
      # `{:ok, @not_found_sentinel} -> defaults` clause — never the
      # cache_miss_sentinel clause the reader test above isolates. So this
      # assertion is governed solely by what the writer cached, regardless
      # of whether the reader point is mutated back to `||`.
      second = Settings.get_json_settings_cached([key], %{key => %{"fallback" => true}})

      assert second[key] == nil
    end
  end
end
