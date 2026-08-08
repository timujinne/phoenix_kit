defmodule PhoenixKit.Integration.Users.AuthLocaleTest do
  @moduledoc """
  Pins the locale-aware redirect behaviour in
  `PhoenixKitWeb.Users.Auth`:

    * `redirect_invalid_locale/2` — swap-vs-strip behaviour gated on
      `Languages.default_language_no_prefix?/0`.
    * `process_valid_locale/2`'s canonical redirect — only fires for
      non-admin primary-locale URLs when the setting is ON.

  Both behaviours need a DB-backed setting for the gate to read, so
  this file uses `DataCase` rather than the no-DB unit
  `auth_test.exs`.
  """

  use PhoenixKit.DataCase, async: false

  import Phoenix.ConnTest
  @endpoint PhoenixKit.Test.Endpoint

  alias PhoenixKit.Modules.Languages
  alias PhoenixKit.Settings
  alias PhoenixKitWeb.Users.Auth

  setup do
    config = %{
      "languages" => [
        %{"code" => "en", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "es", "name" => "Spanish", "is_default" => false, "is_enabled" => true}
      ]
    }

    Settings.update_setting("languages_enabled", "true")
    Settings.update_json_setting("languages_config", config)

    on_exit(fn ->
      # Use the typed setter (mirrors the `setup` block in the
      # `setting ON` describe further down) so any future cache /
      # invalidation logic Languages.set_* wires up runs in cleanup
      # too — the raw Settings call would skip it.
      Languages.set_default_language_no_prefix(false)
      Settings.update_setting("languages_enabled", "false")
    end)

    :ok
  end

  describe "redirect_invalid_locale/2 with setting OFF (default)" do
    test "swaps invalid locale for the primary base code (preserves prefixed canonical shape)" do
      conn = build_invalid_locale_conn("/phoenix_kit/xx/admin/users")

      conn = Auth.redirect_invalid_locale(conn, "xx")

      assert conn.halted
      assert redirected_to(conn) == "/phoenix_kit/en/admin/users"
    end

    test "handles invalid locale at the end of the path" do
      conn = build_invalid_locale_conn("/phoenix_kit/xx")

      conn = Auth.redirect_invalid_locale(conn, "xx")

      assert redirected_to(conn) == "/phoenix_kit/en"
    end
  end

  describe "redirect_invalid_locale/2 with setting ON" do
    setup do
      Languages.set_default_language_no_prefix(true)
      :ok
    end

    test "strips the invalid locale entirely (canonical is prefixless)" do
      conn = build_invalid_locale_conn("/phoenix_kit/xx/admin/users")

      conn = Auth.redirect_invalid_locale(conn, "xx")

      assert conn.halted
      assert redirected_to(conn) == "/phoenix_kit/admin/users"
    end

    test "handles invalid locale at the end of the path (strips to bare prefix)" do
      conn = build_invalid_locale_conn("/phoenix_kit/xx")

      conn = Auth.redirect_invalid_locale(conn, "xx")

      # With setting ON, the invalid trailing segment is stripped
      # entirely, leaving the bare PhoenixKit URL prefix.
      assert redirected_to(conn) == "/phoenix_kit"
    end
  end

  describe "validate_and_set_locale/2 — primary-locale canonical redirect" do
    # `process_valid_locale/2` (private) decides whether to 301-redirect
    # `/<default>/<non-admin>` to `/<non-admin>` so there's one canonical
    # URL when the site-wide setting is ON. With setting OFF (default)
    # the `/<default>/...` shape IS canonical and must NOT redirect —
    # the 301 would discard POST bodies. Reference incident: the bug
    # that broke login mid-browser-test before this gate was added.

    test "primary locale on non-admin URL is NOT redirected when setting is OFF" do
      conn =
        build_conn(:get, "/phoenix_kit/en/users/log-in")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
      assert conn.status != 301
      assert conn.assigns.current_locale_base == "en"
    end

    test "primary locale on non-admin URL IS redirected when setting is ON" do
      Languages.set_default_language_no_prefix(true)

      conn =
        build_conn(:get, "/phoenix_kit/en/users/log-in")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn = Auth.validate_and_set_locale(conn, [])

      assert conn.halted
      # `Phoenix.Controller.redirect/2` passes status: 301 here, but the
      # test conn may report 302 depending on how the redirect helper
      # composes the response; assert on the target path which is what
      # matters for canonical-URL behavior.
      assert redirected_to(conn) == "/phoenix_kit/users/log-in"
    end

    test "primary locale on admin URL is NEVER redirected (both settings)" do
      # Admin paths share a dual-scope router emission; both shapes
      # resolve to the same live_session so a redirect would create a
      # wasteful round-trip mid-session.

      conn_off =
        build_conn(:get, "/phoenix_kit/en/admin/users")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn_off = Auth.validate_and_set_locale(conn_off, [])
      refute conn_off.halted

      Languages.set_default_language_no_prefix(true)

      conn_on =
        build_conn(:get, "/phoenix_kit/en/admin/users")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn_on = Auth.validate_and_set_locale(conn_on, [])
      refute conn_on.halted
    end

    test "non-primary locale on non-admin URL is never redirected" do
      conn =
        build_conn(:get, "/phoenix_kit/es/blog/post")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "es"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
      assert conn.assigns.current_locale_base == "es"
    end
  end

  describe "validate_and_set_locale/2 — reserved segments" do
    test "a reserved segment 307s to the stripped path, query intact" do
      # `/<prefix>/api/shop` binds `:locale = "api"` on any `/:locale/...`
      # route. The corrected URL has to keep the query — this pipeline
      # also carries `post "/:locale/users/log-in"`, which is why the
      # redirect is a 307 (method + body preserved) rather than a 302.
      conn =
        build_conn(:get, "/phoenix_kit/api/shop?page=2")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "api"})

      conn = Auth.validate_and_set_locale(conn, [])

      assert conn.halted
      assert conn.status == 307
      assert redirected_to(conn, 307) == "/phoenix_kit/shop?page=2"
    end

    test "a segment that is not where the prefix says renders instead of looping" do
      # `strip_locale_segment/2` returns :error when the path is not
      # `<prefix>/<locale>/...`, and the plug must then fall through.
      # Redirecting to an unchanged path is what used to spin the browser.
      conn =
        build_conn(:get, "/somewhere/else/entirely")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "admin"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end
  end

  describe "validate_and_set_locale/2 — percent-encoded admin segment" do
    setup do
      Languages.set_default_language_no_prefix(true)
      :ok
    end

    test "an encoded /admin still counts as an admin request" do
      # Phoenix binds routes against a DECODED copy of the path but leaves
      # `conn.path_info` encoded, so `%61dmin` reaches the admin route
      # while a raw `"admin" in path_info` reports "not admin" and hands
      # the request to the canonicaliser — a redirect on a URL that is
      # already where it belongs.
      conn =
        build_conn(:get, "/phoenix_kit/en/%61dmin/users")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
    end

    test "the canonical redirect still fires for genuinely non-admin URLs, with its query" do
      conn =
        build_conn(:get, "/phoenix_kit/en/users/log-in?return_to=%2Fadmin%2Fusers")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en"})

      conn = Auth.validate_and_set_locale(conn, [])

      assert conn.halted
      assert redirected_to(conn) == "/phoenix_kit/users/log-in?return_to=%2Fadmin%2Fusers"
    end
  end

  describe "enabled full-dialect locale segments" do
    # Sibling-dialect public URLs (phoenix_kit_publishing): when two dialects
    # of one base are enabled (en-US + en-GB), the non-primary sibling is
    # addressed by its lowercase full code (/en-gb/...). The plug used to
    # 301 EVERY hyphenated segment to its base, which made those URLs
    # structurally impossible — an enabled dialect must process, matched
    # case-insensitively; any other hyphenated segment keeps the redirect.

    setup do
      config = %{
        "languages" => [
          %{
            "code" => "en-US",
            "name" => "English (US)",
            "is_default" => true,
            "is_enabled" => true
          },
          %{
            "code" => "en-GB",
            "name" => "English (UK)",
            "is_default" => false,
            "is_enabled" => true
          },
          %{"code" => "es", "name" => "Spanish", "is_default" => false, "is_enabled" => true}
        ]
      }

      Settings.update_json_setting("languages_config", config)
      :ok
    end

    test "a lowercase enabled dialect processes with the stored-case locale" do
      conn =
        build_conn(:get, "/phoenix_kit/en-gb/blog")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en-gb"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
      assert conn.assigns.current_locale == "en-GB"
      assert conn.assigns.current_locale_base == "en"
    end

    test "the stored-case form processes identically" do
      conn =
        build_conn(:get, "/phoenix_kit/en-GB/blog")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "en-GB"})

      conn = Auth.validate_and_set_locale(conn, [])

      refute conn.halted
      assert conn.assigns.current_locale == "en-GB"
    end

    test "a NON-enabled dialect keeps the historical redirect to its base" do
      conn =
        build_conn(:get, "/phoenix_kit/es-MX/blog")
        |> Plug.Conn.fetch_query_params()
        |> Map.put(:path_params, %{"locale" => "es-MX"})

      conn = Auth.validate_and_set_locale(conn, [])

      assert conn.halted
      assert redirected_to(conn) =~ "/es/"
    end
  end

  defp build_invalid_locale_conn(path) do
    build_conn(:get, path)
    |> Plug.Conn.fetch_query_params()
  end
end
