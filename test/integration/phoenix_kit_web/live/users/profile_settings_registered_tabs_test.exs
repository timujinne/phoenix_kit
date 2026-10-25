defmodule PhoenixKitWeb.Live.Users.ProfileSettingsRegisteredTabsTest do
  @moduledoc """
  A tab registered through `config :phoenix_kit, :profile_settings_tabs`, on
  the real profile page: offered in the strip as a link out, and a tab
  whose page is not routed lands back on the first tab.
  """
  # async: false - the tabs are read from application config.
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.Routes

  setup %{conn: conn} do
    previous = Application.get_env(:phoenix_kit, :profile_settings_tabs)

    Application.put_env(:phoenix_kit, :profile_settings_tabs, [
      %{id: "extra", label: "Extra tab", icon: "hero-star", after: "account"},
      %{id: "hidden-extra", label: "Hidden tab", visible: {__MODULE__, :never}}
    ])

    on_exit(fn ->
      if previous,
        do: Application.put_env(:phoenix_kit, :profile_settings_tabs, previous),
        else: Application.delete_env(:phoenix_kit, :profile_settings_tabs)
    end)

    {:ok, user} =
      Auth.register_user(%{
        email: "registered_tabs_#{System.unique_integer([:positive])}@example.com",
        password: "TestPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    %{conn: log_in_user(conn, user)}
  end

  def never(_scope), do: false

  test "the strip offers the registered tab as a link out, after the one it names", %{conn: conn} do
    {:ok, _view, html} = live(conn, Routes.path("/profile/settings"))

    extra = Routes.path("/profile/settings/extra")
    assert html =~ "Extra tab"
    assert html =~ ~s(href="#{extra}")
    refute html =~ "Hidden tab"

    {account_at, _} = :binary.match(html, ~s(href="#{Routes.path("/profile/settings/account")}"))
    {extra_at, _} = :binary.match(html, ~s(href="#{extra}"))

    {security_at, _} =
      :binary.match(html, ~s(href="#{Routes.path("/profile/settings/security")}"))

    assert account_at < extra_at and extra_at < security_at
  end

  test "a registered tab with no page routed goes to the first tab", %{conn: conn} do
    assert {:error, {:live_redirect, %{to: to}}} =
             live(conn, Routes.path("/profile/settings/extra"))

    assert to == Routes.path("/profile/settings/account")
  end
end
