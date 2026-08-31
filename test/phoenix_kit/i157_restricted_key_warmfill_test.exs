defmodule PhoenixKit.I157RestrictedKeyWarmfillTest do
  @moduledoc """
  I157 follow-up (F1): the miss-fill fix in `get_settings_cached/2` closed
  the "cache miss reads as nil" gap, but not this one — a restricted key
  (`@restricted_setting_keys`, S015) whose decryption fails on the miss-fill
  or boot-warm path used to be cached as a bare `nil`, indistinguishable
  from "cached, and the value genuinely is nil", for the rest of the entry's
  life instead of retrying the decrypt on the next read.

  `decrypt_if_restricted/2` only returns `nil` from its `{:error, reason}`
  branch (a decrypt failure) — never from a genuinely stored value, since
  `update_setting/2` coerces a `nil` write to `""` before it reaches the
  database. `fill_missing_settings/1` and `warm_cache_data/0` now route
  that specific `nil` through `@not_found_sentinel` before writing to the
  cache instead, so a decrypt failure reads back exactly like a row that
  never existed — the caller's own `defaults`, not a silently substituted
  `nil` — and the next read re-attempts the decrypt rather than serving a
  stale failure.

  Reproduced against a REAL `PhoenixKit.Cache` GenServer (not the `:noproc`
  fallback `PhoenixKit.DataCase` would otherwise take) and a REAL corrupted
  ciphertext row, mirroring the corruption technique
  `settings_test.exs`'s "the read path never returns raw ciphertext when
  decryption fails" already uses.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries

  @cache :settings
  @key "oauth_google_client_secret"

  setup do
    start_supervised!({PhoenixKit.Cache.Registry, []})
    # No warmer — this is the "cold cache, never warmed" scenario, not an
    # expiry; fill_missing_settings/1 is what's under test.
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

  test "a restricted key whose decryption fails does not stay cached as nil past the first read" do
    :ok = corrupt_ciphertext_for(@key, "i157-f1-probe-secret")

    # First read: a genuine miss (never cached). Undecryptable on this very
    # query too, so the immediate answer for THIS call is allowed to be
    # `nil` (matches `decrypt_if_restricted/2`'s own contract for a direct,
    # non-cached read) — that part is not what F1 is about.
    first = Settings.get_settings_cached([@key], %{@key => "fallback-default"})
    assert first[@key] == nil

    # What matters is what got written to the cache by that first read. A
    # second read must NOT see the stale decrypt failure served back as a
    # bare cached `nil` — it must fall back to the caller's own default,
    # exactly like a row that does not exist would.
    second = Settings.get_settings_cached([@key], %{@key => "fallback-default"})
    assert second[@key] == "fallback-default"

    refute second[@key] == nil,
           "a restricted key with a failed decrypt must not be served as cached nil"
  end

  test "the boot-time warmer does not seed the cache with a bare nil for a failed decrypt" do
    :ok = corrupt_ciphertext_for(@key, "i157-f1-warm-probe-secret")

    warmed = Settings.warm_cache_data()
    :ok = PhoenixKit.Cache.put_multiple(@cache, warmed)

    result = Settings.get_settings_cached([@key], %{@key => "fallback-default"})

    assert result[@key] == "fallback-default"
    refute result[@key] == nil
  end
end
