defmodule PhoenixKit.Users.FormatCountryTest do
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.Fixtures, only: [user_fixture: 0]

  alias PhoenixKit.Cache
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.FormatCountry
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKitWeb.Users.Auth, as: WebAuth

  setup do
    FormatCountry.clear_viewer()
    on_exit(&FormatCountry.clear_viewer/0)
    :ok
  end

  defp put_user(user, attrs) do
    user |> Ecto.Changeset.change(attrs) |> Repo.update!()
  end

  # `async: false`, but the settings cache outlives a test: prime and restore one key.
  defp with_site_default(code, fun) do
    ensure_settings_cache()
    previous = Cache.get(:settings, "format_country", "")
    Cache.put(:settings, "format_country", code)

    try do
      fun.()
    after
      Cache.put(:settings, "format_country", previous)
    end
  end

  defp ensure_settings_cache do
    case Process.whereis(PhoenixKit.Cache.Registry) do
      nil -> start_supervised!({Registry, keys: :unique, name: PhoenixKit.Cache.Registry})
      _ -> :ok
    end

    case Registry.lookup(PhoenixKit.Cache.Registry, :settings) do
      [] -> start_supervised!({Cache, name: :settings})
      _ -> :ok
    end
  end

  describe "resolve/1" do
    test "the user's own country comes first" do
      org = put_user(user_fixture(), account_type: "organization", country: "FR")

      user =
        put_user(user_fixture(),
          country: "DE",
          organization_uuid: org.uuid,
          registration_country: "GB"
        )

      assert FormatCountry.resolve(user) == "DE"
    end

    test "then the company's" do
      org = put_user(user_fixture(), account_type: "organization", country: "FR")
      user = put_user(user_fixture(), organization_uuid: org.uuid, registration_country: "GB")

      assert FormatCountry.resolve(user) == "FR"
    end

    test "then the registration country" do
      user = put_user(user_fixture(), registration_country: "GB")
      assert FormatCountry.resolve(user) == "GB"
    end

    test "then the site default, and nil when there is none" do
      user = user_fixture()
      assert FormatCountry.resolve(user) == nil
      with_site_default("EE", fn -> assert FormatCountry.resolve(user) == "EE" end)
    end

    test "an unknown code in one source does not hide the next" do
      org = put_user(user_fixture(), account_type: "organization", country: "FR")

      user =
        put_user(user_fixture(),
          country: "ZZ",
          organization_uuid: org.uuid,
          registration_country: "GB"
        )

      assert FormatCountry.resolve(user) == "FR"
      assert FormatCountry.resolve(%{user | organization_uuid: nil}) == "GB"
    end

    test "a company without a country gives way to the registration country" do
      org = put_user(user_fixture(), account_type: "organization")
      user = put_user(user_fixture(), organization_uuid: org.uuid, registration_country: "GB")

      assert FormatCountry.resolve(user) == "GB"
    end

    test "a lower-case code is read as its upper-case one" do
      assert FormatCountry.resolve(%User{country: "de"}) == "DE"
    end

    test "something that is not a user row is treated as no user" do
      assert FormatCountry.resolve(%{user_timezone: nil}) == nil
      assert FormatCountry.for_user(%{user_timezone: nil}) == nil

      assert UtilsDate.format_date_with_user_timezone(~D[2026-11-09], %{user_timezone: nil}) ==
               "2026-11-09"
    end

    test "nobody signed in gets the site default" do
      assert FormatCountry.resolve(nil) == nil
      with_site_default("US", fn -> assert FormatCountry.resolve(nil) == "US" end)
    end
  end

  describe "the viewer" do
    test "is the site default until one is set" do
      assert FormatCountry.viewer() == nil
      with_site_default("US", fn -> assert FormatCountry.viewer() == "US" end)
    end

    test "a viewer without a personal country follows a changed site default" do
      FormatCountry.put_viewer(%User{})
      assert FormatCountry.viewer() == nil

      with_site_default("US", fn -> assert FormatCountry.viewer() == "US" end)
      with_site_default("DE", fn -> assert FormatCountry.viewer() == "DE" end)
      assert FormatCountry.viewer() == nil
    end

    test "an explicit user without a country follows a changed site default" do
      user = %User{uuid: Ecto.UUID.generate()}
      FormatCountry.put_viewer(user)
      with_site_default("US", fn -> assert FormatCountry.for_user(user) == "US" end)
      with_site_default("DE", fn -> assert FormatCountry.for_user(user) == "DE" end)
    end

    test "a personal country still wins when the site default changes" do
      FormatCountry.put_viewer(%User{country: "GB"})
      assert FormatCountry.viewer() == "GB"
      with_site_default("DE", fn -> assert FormatCountry.viewer() == "GB" end)
    end

    test "is resolved from the user put, company included" do
      org = put_user(user_fixture(), account_type: "organization", country: "FR")
      user = put_user(user_fixture(), organization_uuid: org.uuid)

      FormatCountry.put_viewer(user)
      assert FormatCountry.viewer() == "FR"
    end

    test "for_user/1 reuses the viewer's answer and resolves anyone else" do
      viewer = put_user(user_fixture(), country: "DE")
      other = put_user(user_fixture(), country: "US")

      FormatCountry.put_viewer(viewer)

      assert FormatCountry.for_user(viewer) == "DE"
      assert FormatCountry.for_user(other) == "US"
      assert FormatCountry.viewer() == "DE"
    end

    test "embedded identity sets the viewer too" do
      user = put_user(user_fixture(), country: "DE")
      socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}}}

      socket =
        WebAuth.assign_embedded_current_user(socket, %{
          "current_user_uuid" => user.uuid
        })

      assert socket.assigns.phoenix_kit_current_user.uuid == user.uuid
      assert FormatCountry.viewer() == "DE"
    end

    test "putting a newly saved user changes what the next render reads" do
      user = put_user(user_fixture(), country: "DE")
      FormatCountry.put_viewer(user)
      assert FormatCountry.viewer() == "DE"

      FormatCountry.put_viewer(%{user | country: "GB"})
      assert FormatCountry.viewer() == "GB"
    end
  end

  describe "dates" do
    test "follow the viewer's country, and the date_format setting when there is none" do
      date = ~D[2026-11-09]

      assert UtilsDate.format_date_with_user_format(date) == "2026-11-09"

      FormatCountry.put_viewer(%User{country: "DE"})
      assert UtilsDate.format_date_with_user_format(date) == "09.11.2026"

      FormatCountry.put_viewer(%User{country: "GB"})
      assert UtilsDate.format_date_with_user_format(date) == "09/11/2026"

      FormatCountry.put_viewer(%User{country: "US"})
      assert UtilsDate.format_date_with_user_format(date) == "11/9/2026"

      FormatCountry.put_viewer(%User{})
      assert UtilsDate.format_date_with_user_format(date) == "2026-11-09"
    end

    test "the cached-settings functions follow the viewer too" do
      FormatCountry.put_viewer(%User{country: "DE"})
      settings = %{"date_format" => "Y-m-d"}

      assert UtilsDate.format_date_with_cached_settings(~D[2026-11-09], settings) == "09.11.2026"

      assert UtilsDate.format_datetime_with_cached_settings(~N[2026-11-09 10:00:00], settings) ==
               "09.11.2026"
    end

    test "a function given a user follows that user, not the viewer" do
      FormatCountry.put_viewer(%User{country: "DE"})
      recipient = %User{country: "US"}

      assert UtilsDate.format_date_with_user_timezone(~D[2026-11-09], recipient) == "11/9/2026"

      assert UtilsDate.format_date_with_user_timezone_cached(
               ~D[2026-11-09],
               recipient,
               %{"date_format" => "Y-m-d"}
             ) == "11/9/2026"

      assert UtilsDate.format_date_with_user_format(~D[2026-11-09]) == "09.11.2026"
    end

    test "format_date/2 takes {:country, code} and falls back to ISO for an unknown one" do
      assert UtilsDate.format_date(~D[2026-11-09], {:country, "DE"}) == "09.11.2026"
      assert UtilsDate.format_date(~D[2026-11-09], {:country, "ZZ"}) == "2026-11-09"
    end
  end
end
