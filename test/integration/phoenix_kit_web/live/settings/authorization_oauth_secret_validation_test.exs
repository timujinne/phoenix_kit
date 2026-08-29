defmodule PhoenixKitWeb.Live.Settings.AuthorizationOAuthSecretValidationTest do
  @moduledoc """
  Defect 2 from dev_docs I135: `phoenix_kit_settings` had no format check on
  `:value` at all, so a 9-character Google OAuth secret saved silently and
  stayed live for four days. This covers the save-time gate added in
  `PhoenixKitWeb.Live.Settings.Authorization` (`validate_oauth_secret_formats/1`,
  backed by `PhoenixKit.Users.OAuthConfig.validate_secret_format/2`) —
  requires a live database (`PGHOST`/`PGDATABASE`, see AGENTS.md); could not
  be run in the sandbox this was written in (no CONNECT to `phoenix_kit_*`).
  Written and reviewed against the same pattern as
  `authorization_secret_leak_test.exs` in this directory; not executed.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.Routes

  defp login(conn) do
    {admin, _token} = create_admin_user()
    log_in_user(conn, admin)
  end

  test "a short secret is rejected on save, with a clear reason, and nothing is persisted", %{
    conn: conn
  } do
    conn = login(conn)
    {:ok, view, _html} = live(conn, Routes.path("/admin/settings/authorization"))

    html =
      view
      |> form("#authorization_settings_form", %{
        "settings" => %{"oauth_google_client_secret" => "123456789"}
      })
      |> render_submit()

    assert html =~ "too short"
    assert Settings.get_setting("oauth_google_client_secret") in [nil, ""]
  end

  test "a whitespace-only secret is rejected on save, not silently treated as unset", %{
    conn: conn
  } do
    conn = login(conn)
    {:ok, view, _html} = live(conn, Routes.path("/admin/settings/authorization"))

    html =
      view
      |> form("#authorization_settings_form", %{
        "settings" => %{"oauth_google_client_secret" => "   "}
      })
      |> render_submit()

    assert html =~ "whitespace"
    assert Settings.get_setting("oauth_google_client_secret") in [nil, ""]
  end

  test "the reverse direction: a real-length secret still saves and reads back", %{conn: conn} do
    conn = login(conn)
    {:ok, view, _html} = live(conn, Routes.path("/admin/settings/authorization"))

    good_secret = "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cret-value"

    view
    |> form("#authorization_settings_form", %{
      "settings" => %{"oauth_google_client_secret" => good_secret}
    })
    |> render_submit()

    assert Settings.get_setting("oauth_google_client_secret") == good_secret
  end

  test "actively typing a bad secret blocks the whole submission, unrelated field included", %{
    conn: conn
  } do
    conn = login(conn)
    {:ok, view, _html} = live(conn, Routes.path("/admin/settings/authorization"))

    html =
      view
      |> form("#authorization_settings_form", %{
        "settings" => %{
          "project_title" => "New Title",
          "oauth_google_client_secret" => "short"
        }
      })
      |> render_submit()

    assert html =~ "too short"
    assert Settings.get_setting("project_title") != "New Title"
  end

  # This is the scenario the gate is deliberately ordered around (see the
  # comment on `validate_oauth_secret_formats/1`): a secret saved BEFORE this
  # fix existed, still short, sitting untouched in the database. The
  # template never re-renders a real secret into the password field (S009),
  # so an admin who does not touch that field submits it blank — this must
  # NOT be read as "the admin just typed a bad secret".
  test "an already-stored short legacy secret does not block saving an unrelated field", %{
    conn: conn
  } do
    conn = login(conn)
    {:ok, _} = Settings.update_setting("oauth_google_client_secret", "123456789")

    {:ok, view, _html} = live(conn, Routes.path("/admin/settings/authorization"))

    view
    |> form("#authorization_settings_form", %{
      "settings" => %{"project_title" => "New Title"}
    })
    |> render_submit()

    assert Settings.get_setting("project_title") == "New Title"
    assert Settings.get_setting("oauth_google_client_secret") == "123456789"
  end
end
