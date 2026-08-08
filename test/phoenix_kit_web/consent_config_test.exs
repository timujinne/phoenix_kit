defmodule PhoenixKitWeb.ConsentConfigTest do
  @moduledoc """
  `GET /api/consent-config` used to exist only when `phoenix_kit_legal` was
  loaded, so every other install answered with a `Phoenix.Router.NoRouteError`
  — a 404 in the console and a logged exception on **every page load**, because
  the vendored bundle asks for it unconditionally.

  These run without `phoenix_kit_legal` installed, which is the case that was
  broken.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Utils.Routes

  defp config_path, do: Routes.path("/api/consent-config")

  test "the route exists even with the Legal module absent", %{conn: conn} do
    # The failure this replaces was a raised NoRouteError, not a 404 body.
    conn = get(conn, config_path())

    assert conn.status == 204
  end

  @tag :privacy_regression_guard
  test "the response body is EMPTY — do not turn this into JSON", %{conn: conn} do
    # ⚠️ Load-bearing, and not a style preference. Bundles vendored before this
    # endpoint existed treat ANY JSON body as a live configuration: seeing
    # `enabled: false` they call `resetGoogleConsentMode()`, which pushes
    # `gtag("consent", "update", ...)` GRANTING every category. A body saying
    # "consent is off" would therefore grant consent, on precisely the installs
    # that never opted into consent management.
    #
    # If a future change wants to answer with `{"enabled": false}`, it has to
    # deal with those old bundles first. 204 has no body to misread.
    conn = get(conn, config_path())

    assert conn.resp_body == ""
  end

  test "the route does NOT use the module name phoenix_kit_legal published" do
    # ⚠️ `PhoenixKitWeb.Controllers.ConsentConfigController` is the name
    # phoenix_kit_legal <= 0.1.9 ships its own copy of. Moving the
    # responsibility into core does not un-publish those versions, and a host
    # that resolves new core against an older legal would have one module name
    # compiled into two applications — with code-path order, not either
    # package, deciding which one answers.
    #
    # The route is this module's only reference, so the collision costs nothing
    # to avoid; keeping the distinct name is what makes the pair safe in both
    # upgrade orders rather than only the one where legal moves first.
    route =
      Enum.find(
        PhoenixKitWeb.Router.__routes__(),
        &(&1.verb == :get and String.ends_with?(&1.path, "/api/consent-config"))
      )

    assert route, "/api/consent-config is not routed"
    assert route.plug == PhoenixKitWeb.Controllers.ConsentConfig
    refute route.plug == PhoenixKitWeb.Controllers.ConsentConfigController
  end

  test "the absent-module answer is never cached", %{conn: conn} do
    # A cached 204 outlives installing phoenix_kit_legal, leaving the widget
    # dead until every visitor's cache expires.
    conn = get(conn, config_path())

    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end
end
