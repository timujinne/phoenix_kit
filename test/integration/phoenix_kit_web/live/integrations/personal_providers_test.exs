defmodule PhoenixKitWeb.Live.Integrations.PersonalProvidersTest do
  @moduledoc """
  Which services users may connect on their own (the personal "add" picker) is a
  site-wide choice: a checkbox per provider that may be personal, on
  Settings → Integrations. Until an admin saves one the providers that declare
  `:personal_default` are offered (what users had before the choice existed);
  Object Storage is also offered while users may keep a library on their own
  bucket. The picker refuses a provider it did not offer, even to a hand-made
  event.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import Ecto.Query

  alias PhoenixKit.Integrations.Providers
  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Setting
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Utils.Routes

  @key "personal_integration_providers"

  setup do
    forget = fn ->
      Repo.delete_all(from s in Setting, where: s.key == ^@key)
      PhoenixKit.Cache.invalidate(:settings, @key)
    end

    forget.()
    {:ok, _} = Settings.update_boolean_setting("storage_user_buckets_enabled", false)
    on_exit(forget)
    :ok
  end

  defp offered, do: Enum.map(Providers.personal_offered(), & &1.key)

  defp personal_user(conn) do
    {:ok, role} = Roles.create_role(%{name: "Personal #{System.unique_integer([:positive])}"})
    {:ok, _} = Permissions.grant_permission(role.uuid, "integrations")

    {:ok, user} =
      Auth.register_user(%{
        "email" => "personal-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    {:ok, _} = Roles.assign_role(user, role.name)
    log_in_user(conn, Repo.get!(Auth.User, user.uuid))
  end

  defp admin(conn) do
    {user, _token} = create_admin_user()
    admin_role = Roles.get_role_by_name("Admin")
    {:ok, _} = Permissions.grant_permission(admin_role.uuid, "integrations_system")
    log_in_user(conn, user)
  end

  describe "the list" do
    test "starts as what users were offered before the choice existed" do
      assert Enum.sort(offered()) == ["openrouter", "telegram"]
      assert Enum.sort(Providers.personal_enabled_keys()) == ["openrouter", "telegram"]
    end

    test "a saved choice replaces it, and an empty one offers nothing" do
      assert {:ok, ["github"]} = Providers.put_personal_enabled(["github"])
      assert offered() == ["github"]

      assert {:ok, []} = Providers.put_personal_enabled([])
      assert offered() == []
    end

    test "only providers that may be personal are kept" do
      system_only = Enum.find(Providers.all(), &(:personal not in Providers.scopes_of(&1)))

      assert {:ok, ["telegram"]} =
               Providers.put_personal_enabled([
                 "telegram",
                 system_only.key,
                 "nonsense",
                 "telegram"
               ])
    end

    test "Object Storage is also offered while users may keep a library on their own bucket" do
      {:ok, []} = Providers.put_personal_enabled([])
      refute "object_storage" in offered()

      {:ok, _} = Settings.update_boolean_setting("storage_user_buckets_enabled", true)
      assert "object_storage" in offered()
    end
  end

  describe "the personal picker" do
    test "offers the enabled providers and refuses any other", %{conn: conn} do
      {:ok, _} = Providers.put_personal_enabled(["telegram"])

      {:ok, view, html} =
        live(personal_user(conn), Routes.path("/profile/settings/integrations/new"))

      assert html =~ "Telegram"
      refute html =~ "OpenRouter"

      # A hand-made event naming a provider the picker did not offer.
      html = render_click(view, "select_provider", %{"provider" => "openrouter"})
      refute html =~ "Choose a different service"

      html = render_click(view, "select_provider", %{"provider" => "telegram"})
      assert html =~ "Choose a different service"
    end
  end

  describe "the personal Object Storage form" do
    test "opens on the service choice and follows it, like the site-wide one", %{conn: conn} do
      {:ok, _} = Providers.put_personal_enabled(["object_storage"])

      {:ok, view, _html} =
        live(personal_user(conn), Routes.path("/profile/settings/integrations/new"))

      html = render_click(view, "select_provider", %{"provider" => "object_storage"})
      assert html =~ ~s(name="service" id="field-service")
      refute html =~ ~s(name="access_key")

      html =
        view
        |> element("#personal-integration-setup-form")
        |> render_change(%{"service" => "cloudflare_r2"})

      assert html =~ ~s(name="account_id" id="field-account_id")
      assert html =~ ~s(name="access_key")
      refute html =~ ~s(name="endpoint" id="field-endpoint")
    end
  end

  describe "the personal SMTP form with the personal SMTP policy on" do
    setup do
      Application.put_env(:phoenix_kit, :personal_smtp_policy, :restricted)
      on_exit(fn -> Application.delete_env(:phoenix_kit, :personal_smtp_policy) end)
    end

    test "testing an internal host before saving says why it is refused", %{conn: conn} do
      {:ok, _} = Providers.put_personal_enabled(["smtp"])

      {:ok, view, _html} =
        live(personal_user(conn), Routes.path("/profile/settings/integrations/new"))

      render_click(view, "select_provider", %{"provider" => "smtp"})

      html =
        view
        |> element("#personal-integration-setup-form")
        |> render_submit(%{
          "_intent" => "test",
          "name" => "Mine",
          "host" => "127.0.0.1",
          "port" => "587",
          "username" => "u",
          "password" => "p"
        })

      assert html =~ "The SMTP host must resolve to a public address"
    end
  end

  describe "Settings → Integrations" do
    test "lists every provider that may be personal, ticked as offered", %{conn: conn} do
      {:ok, view, _html} = live(admin(conn), Routes.path("/admin/settings/integrations"))

      html = render(view)
      assert html =~ "Personal integrations"

      for provider <- Providers.for_scope(:personal) do
        assert html =~ ~s(value="#{provider.key}"), provider.key
      end
    end

    test "saving stores the ticked providers, none included", %{conn: conn} do
      {:ok, view, _html} = live(admin(conn), Routes.path("/admin/settings/integrations"))

      view
      |> form("#personal-integrations-form",
        personal: %{providers: ["", "github", "telegram"]}
      )
      |> render_submit()

      assert Enum.sort(offered()) == ["github", "telegram"]

      view |> form("#personal-integrations-form", personal: %{providers: [""]}) |> render_submit()
      assert offered() == []
    end
  end
end
