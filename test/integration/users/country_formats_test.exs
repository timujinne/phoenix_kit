defmodule PhoenixKit.Integration.Users.CountryFormatsTest do
  @moduledoc """
  A user's country, end to end: the admin form writes it, the profile form writes it,
  Settings validates the site default, and the pages show dates the way the viewer's
  country writes them.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  defp unique_email, do: "country_#{System.unique_integer([:positive])}@example.com"

  defp plain_user(attrs \\ []) do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)

    user = Repo.get!(Auth.User, user.uuid)

    if attrs == [],
      do: user,
      else: user |> Ecto.Changeset.change(attrs) |> Repo.update!()
  end

  defp admin_user(attrs \\ []) do
    user = plain_user(attrs)
    Roles.assign_role(user, "Admin")
    Repo.get!(Auth.User, user.uuid)
  end

  describe "the admin user form" do
    test "saves a country", %{conn: conn} do
      target = plain_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))
      assert html =~ "Dates are written the way this country does"

      render_submit(view, "save_user", %{"user" => %{"first_name" => "Ada", "country" => "de"}})

      assert Repo.get!(Auth.User, target.uuid).country == "DE"
    end

    test "refuses a code no country has, and keeps the stored one", %{conn: conn} do
      target = plain_user(country: "EE")
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))
      render_submit(view, "save_user", %{"user" => %{"country" => "ZZ"}})

      assert Repo.get!(Auth.User, target.uuid).country == "EE"
    end

    test "an empty choice clears it", %{conn: conn} do
      target = plain_user(country: "EE")
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))
      render_submit(view, "save_user", %{"user" => %{"country" => ""}})

      assert Repo.get!(Auth.User, target.uuid).country == nil
    end

    test "a custom field named country stays a custom field", %{conn: conn} do
      target = plain_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))

      render_submit(view, "save_user", %{
        "user" => %{"first_name" => "Ada", "custom_fields" => %{"country" => "Narnia"}}
      })

      reloaded = Repo.get!(Auth.User, target.uuid)
      assert reloaded.country == nil
    end
  end

  describe "the profile page" do
    test "shows the country select and saves the choice", %{conn: conn} do
      user = admin_user()
      conn = log_in_user(conn, user)

      {:ok, view, html} = live(conn, Routes.path("/profile/settings"))
      assert html =~ "Dates are written the way your country does."

      view
      |> element("form[phx-submit=update_profile]")
      |> render_submit(%{"user" => %{"country" => "fi"}})

      assert Repo.get!(Auth.User, user.uuid).country == "FI"
    end
  end

  describe "dates on admin pages follow the viewer's country" do
    # Noon UTC, so no time zone moves the day.
    setup do
      target = plain_user(inserted_at: ~U[2026-03-07 12:00:00Z])
      %{target: target}
    end

    test "a German admin reads 07.03.2026", %{conn: conn, target: target} do
      conn = log_in_user(conn, admin_user(country: "DE"))
      {:ok, _view, html} = live(conn, Routes.path("/admin/users/view/#{target.uuid}"))

      assert html =~ "07.03.2026"
      refute html =~ "2026-03-07"
    end

    test "an American admin reads 3/7/2026", %{conn: conn, target: target} do
      conn = log_in_user(conn, admin_user(country: "US"))
      {:ok, _view, html} = live(conn, Routes.path("/admin/users/view/#{target.uuid}"))

      assert html =~ "3/7/2026"
    end

    test "an admin with no country keeps the site's date format", %{conn: conn, target: target} do
      conn = log_in_user(conn, admin_user())
      {:ok, _view, html} = live(conn, Routes.path("/admin/users/view/#{target.uuid}"))

      assert html =~ "2026-03-07"
    end

    test "the sign-up country is the fallback", %{conn: conn, target: target} do
      conn = log_in_user(conn, admin_user(registration_country: "GB"))
      {:ok, _view, html} = live(conn, Routes.path("/admin/users/view/#{target.uuid}"))

      assert html =~ "07/03/2026"
    end
  end

  describe "the site default country" do
    defp settings_changeset(code) do
      Settings.get_defaults()
      |> Map.put("format_country", code)
      |> Settings.change_settings()
    end

    test "is validated like a user's" do
      changeset = settings_changeset("ZZ")

      refute changeset.valid?
      assert Keyword.has_key?(changeset.errors, :format_country)
    end

    test "accepts a code, in either case, and blank" do
      assert settings_changeset("EE").valid?
      assert settings_changeset("ee").valid?
      assert settings_changeset("").valid?
    end
  end
end
