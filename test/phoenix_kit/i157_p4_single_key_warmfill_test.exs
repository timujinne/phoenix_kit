defmodule PhoenixKit.I157P4SingleKeyWarmfillTest do
  @moduledoc """
  I157 follow-up, round 3 (point 4): the F1 fix closed the "restricted-key
  decrypt failure cached as bare nil" gap for the BATCH paths
  (`fill_missing_settings/1`, `warm_cache_data/0`) — both route through
  `cacheable_setting_value/2` before caching. The SINGLE-key path,
  `query_and_cache_setting/1` (used by `get_setting_cached/2` on a cache
  miss), still cached the bare `nil` `decrypt_if_restricted/2` returns on a
  decrypt failure directly, with no such routing.

  `get_setting_cached/2` calls `query_and_cache_setting/1` directly and
  never touches `fill_missing_settings/1`, `get_settings_cached/2`, or
  `warm_cache_data/0` — there is no shared code between this path and the
  batch ones. So this test is structurally incapable of being satisfied by
  a batch-path fix: mutating either batch-path `cacheable_setting_value/2`
  call back to a bare value cannot turn it red, and mutating only this
  single-key path's own fix does. Both are verified by mutation in the
  round-3 report, not asserted here.

  Reproduced against a REAL `PhoenixKit.Cache` GenServer (not the `:noproc`
  fallback `PhoenixKit.DataCase` would otherwise take) and a REAL corrupted
  ciphertext row, mirroring `i157_restricted_key_warmfill_test.exs`'s
  technique for the batch path.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries

  @cache :settings
  @key "oauth_google_client_secret"

  setup do
    start_supervised!({PhoenixKit.Cache.Registry, []})
    # No warmer — cold cache, never warmed. query_and_cache_setting/1 (via
    # get_setting_cached/2's cache-miss branch) is what's under test.
    start_supervised!({PhoenixKit.Cache, name: @cache})
    :ok
  end

  defp corrupt_ciphertext_for(key, plaintext) do
    {:ok, _} = Settings.update_setting(key, plaintext)
    raw = Queries.get_setting_by_key(key)
    assert String.starts_with?(raw.value, "enc:v1:")

    corrupted_ciphertext = String.slice(raw.value, 0..-6//1)

    {:ok, _} =
      raw
      |> Ecto.Changeset.change(value: corrupted_ciphertext)
      |> Queries.update_setting()

    :ok
  end

  test "a restricted key whose decryption fails on the single-key path does not stay cached as nil past the first read" do
    :ok = corrupt_ciphertext_for(@key, "i157-p4-single-probe-secret")

    # First read: a genuine miss (never cached). query_and_cache_setting/1
    # returns the bare `nil` decrypt failure straight through, and
    # get_setting_cached/2's own `value || default` already covers THIS
    # call regardless of what gets cached — that part is not what point 4
    # is about.
    first = Settings.get_setting_cached(@key, "fallback-default")
    assert first == "fallback-default"

    # What matters is what got written to the cache by that first read. A
    # second read must NOT see the stale decrypt failure served back as a
    # bare cached `nil` — it must fall back to the caller's own default,
    # exactly like a row that does not exist would.
    second = Settings.get_setting_cached(@key, "fallback-default")
    assert second == "fallback-default"

    refute second == nil,
           "a restricted key with a failed decrypt on the single-key path must not be served as cached nil"
  end
end
