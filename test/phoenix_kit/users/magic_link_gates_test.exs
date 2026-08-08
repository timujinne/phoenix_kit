defmodule PhoenixKit.Users.MagicLinkGatesTest do
  @moduledoc """
  The `magic_link_login_enabled` and `magic_link_registration_enabled` settings
  used to control button visibility and nothing else — `/users/magic-link` and
  `/users/register/magic-link` stayed fully reachable by anyone holding the URL
  after an admin switched them off.

  These pin the predicates the four gate sites read. They are the settings
  contract; the routes themselves are exercised through the LiveView suites.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKitWeb.Users.Auth, as: WebAuth

  setup do
    # Both default to on, so a test that flips one has to put it back or it
    # leaks into every later test in the file.
    on_exit(fn ->
      Settings.update_setting("magic_link_login_enabled", "true")
      Settings.update_setting("magic_link_registration_enabled", "true")
    end)

    :ok
  end

  describe "magic_link_login_enabled?/0" do
    test "defaults to true when the setting was never written" do
      assert WebAuth.magic_link_login_enabled?()
    end

    test "follows the setting" do
      Settings.update_setting("magic_link_login_enabled", "false")
      refute WebAuth.magic_link_login_enabled?()

      Settings.update_setting("magic_link_login_enabled", "true")
      assert WebAuth.magic_link_login_enabled?()
    end
  end

  describe "magic_link_registration_enabled?/0" do
    test "defaults to true when the setting was never written" do
      assert WebAuth.magic_link_registration_enabled?()
    end

    test "follows the setting" do
      Settings.update_setting("magic_link_registration_enabled", "false")
      refute WebAuth.magic_link_registration_enabled?()

      Settings.update_setting("magic_link_registration_enabled", "true")
      assert WebAuth.magic_link_registration_enabled?()
    end
  end

  describe "the two settings are independent" do
    test "disabling registration leaves login available, and vice versa" do
      # They gate different routes and are separate switches on the admin page.
      # Collapsing them would silently close a route an operator left open.
      Settings.update_setting("magic_link_registration_enabled", "false")
      assert WebAuth.magic_link_login_enabled?()
      refute WebAuth.magic_link_registration_enabled?()

      Settings.update_setting("magic_link_registration_enabled", "true")
      Settings.update_setting("magic_link_login_enabled", "false")
      refute WebAuth.magic_link_login_enabled?()
      assert WebAuth.magic_link_registration_enabled?()
    end
  end
end
