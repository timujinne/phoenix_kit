defmodule PhoenixKit.SettingsCacheMissFillUnitTest do
  @moduledoc """
  `PhoenixKit.SettingsCacheMissFillTest` proves the miss-fill end to end, but
  it is tagged `:integration` (`PhoenixKit.DataCase`) and gets excluded on any
  run without a reachable database — including this repo's own CI-less
  default. This file proves the same defect without touching Postgres at all.

  The bug was never in the database path. `Cache.get_multiple/3` is a
  GenServer over ETS — it needs no database — and `handle_call({:get_multiple,
  …})` always writes every requested key into the returned map, substituting
  `Map.get(defaults, key)` on a miss instead of omitting the key. Passing `%{}`
  as `defaults` (as `get_settings_cached/2` did) means a miss reads back as
  `nil` in the result, indistinguishable from "key present, value nil" — so
  `Map.has_key?/2` sees every requested key as present and `missing` is always
  `[]`.

  To observe that without a database: force `:update_mode` on so
  `fill_missing_settings/1` short-circuits to `:error` cleanly (no query
  attempted, no exception, no log — see `query_settings_or_error/1`) instead
  of raising against an absent pool. A key that was never written to the cache
  is then a clean, deterministic miss, and what the caller gets back for it —
  their own default, or a silently substituted `nil` — is exactly the
  observable the defect is about.
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
    # No warmer — warming would try the database this file exists to avoid.
    start_supervised!({PhoenixKit.Cache, name: @cache})
    :ok
  end

  defp probe_key, do: "missfill_unit_probe_#{System.unique_integer([:positive])}"

  describe "a key the settings cache never held (genuine miss, no database)" do
    test "resolves to the caller's own default, not a silently substituted nil" do
      key = probe_key()

      # Never cached, never warmed — a true miss, not an invalidation.
      assert Settings.get_settings_cached([key], %{key => "fallback"}) == %{key => "fallback"}
    end

    test "with no caller default either, still comes back as the caller's nil default" do
      key = probe_key()

      # No default supplied at all: the correct answer is still `nil`, but it
      # must come from "no default given", not from the cache mistaking the
      # miss for a hit whose value happens to be nil.
      assert Settings.get_settings_cached([key]) == %{key => nil}
    end
  end

  describe "a key genuinely cached with a nil value (not a miss)" do
    test "is still returned as nil, not overridden by the caller's default" do
      key = probe_key()
      Cache.put(@cache, key, nil)

      assert Settings.get_settings_cached([key], %{key => "fallback"}) == %{key => nil}
    end
  end
end
