defmodule PhoenixKit.SitemapExclusionsTest do
  @moduledoc """
  Two bugs that combined into a one-way door.

  Saving `sitemap_router_discovery_exclude_patterns` used to *replace* the
  built-in defaults, so adding a single pattern of your own silently
  un-excluded every admin, auth and infrastructure route — and no later
  PhoenixKit version could ship a new default to that install.

  Saving the defaults back was not a workaround either: the list serializes to
  more characters than `phoenix_kit_settings.value` could hold, and the
  changeset happily let it through to a raw Postgrex error. V160 widened the
  column; the round-trip test below is what proves it.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Sitemap.Sources.RouterDiscovery
  alias PhoenixKit.Settings

  @key "sitemap_router_discovery_exclude_patterns"

  setup do
    on_exit(fn -> Settings.update_setting(@key, nil) end)
    :ok
  end

  describe "the settings column is wide enough for a list" do
    test "the full default pattern list round-trips byte-identically" do
      encoded = JSON.encode!(RouterDiscovery.default_exclude_patterns())

      # The specific number matters less than the fact that it is well past
      # varchar(255) — that is the failure this pins.
      assert byte_size(encoded) > 255

      assert {:ok, _} = Settings.update_setting(@key, encoded)
      assert Settings.get_setting(@key) == encoded
    end

    test "a value between the old column width and the changeset limit saves" do
      value = String.duplicate("x", 900)

      assert {:ok, _} = Settings.update_setting(@key, value)
      assert Settings.get_setting(@key) == value
    end

    test "an over-long value is a changeset error, not a database crash" do
      # The point of the changeset limit is that the caller gets something it
      # can render. A raw Postgrex.Error is a 500.
      assert {:error, %Ecto.Changeset{}} =
               Settings.update_setting(@key, String.duplicate("x", 1001))
    end
  end

  describe "custom exclude patterns extend the defaults" do
    test "the built-in exclusions survive a custom list" do
      Settings.update_setting(@key, JSON.encode!(["^/private"]))

      patterns = RouterDiscovery.effective_exclude_patterns()

      assert "^/private" in patterns
      assert "^/admin" in patterns
      assert "/users/log-in" in patterns
    end

    test "an empty saved list changes nothing" do
      # Previously this meant "exclude nothing", which published every admin
      # URL — an easy thing to do by clearing the textarea.
      Settings.update_setting(@key, JSON.encode!([]))

      assert RouterDiscovery.effective_exclude_patterns() ==
               RouterDiscovery.default_exclude_patterns()
    end

    test "duplicating a default does not duplicate it in the result" do
      Settings.update_setting(@key, JSON.encode!(["^/admin", "^/private"]))

      patterns = RouterDiscovery.effective_exclude_patterns()

      assert Enum.count(patterns, &(&1 == "^/admin")) == 1
    end

    test "the sentinel replaces them, for the host that means it" do
      Settings.update_setting(
        @key,
        JSON.encode!([RouterDiscovery.replace_defaults_sentinel(), "^/private"])
      )

      assert RouterDiscovery.effective_exclude_patterns() == ["^/private"]
    end

    test "malformed JSON falls back to the defaults rather than excluding nothing" do
      Settings.update_setting(@key, "not json at all")

      assert RouterDiscovery.effective_exclude_patterns() ==
               RouterDiscovery.default_exclude_patterns()
    end
  end

  describe "storage-serving routes" do
    test "are excluded by name, not only by the /phoenix_kit prefix" do
      # A root-mounted install has no /phoenix_kit prefix for these to hide
      # behind, and they serve files rather than pages.
      for pattern <- ["^/file/", "^/tiles/", "^/api/files"] do
        assert pattern in RouterDiscovery.default_exclude_patterns()
      end
    end

    test "the invite-only referral screen is excluded like the other auth pages" do
      assert "/users/referral" in RouterDiscovery.default_exclude_patterns()
    end
  end
end
