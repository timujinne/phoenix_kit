defmodule PhoenixKitWeb.Controllers.ConsentConfig do
  @moduledoc """
  Cookie consent widget configuration, for the JS bundle's manual
  `window.PhoenixKitConsent.init()` entry point.

  ## Why this lives in core

  The route used to be declared only when `phoenix_kit_legal` was loaded, so an
  install without that package answered `GET /api/consent-config` with a
  `Phoenix.Router.NoRouteError` — a 404 in the browser console and a logged
  exception on every single page load, because the vendored bundle asks for it
  unconditionally. The route is now always present and this controller decides
  what to say.

  ## Why the name is not `…ConsentConfigController`

  That is the name `phoenix_kit_legal` used for its own copy, and moving the
  responsibility into core does not un-publish the versions that still ship it.
  A host resolving new core against `phoenix_kit_legal <= 0.1.9` would have the
  same module compiled into two applications, and which one answers is decided
  by code-path order rather than by anything either package states. Renaming
  costs nothing here — the route is the only reference — and it makes the pair
  safe in *both* upgrade orders instead of only the one where legal moves first.

  ## Why 204 and not `{"enabled": false}`

  An empty 204 is the only safe answer, and this is a privacy property rather
  than a style choice. Bundles vendored before the consent config existed treat
  *any* JSON body as a live configuration and call `resetGoogleConsentMode()`,
  which pushes `gtag("consent", "update", ...)` granting every category. A body
  saying consent is disabled would therefore *grant* consent on exactly the
  installs that never opted into the feature. 204 has no body to misread.

  Do not "simplify" this into a JSON response.

  ## Caching

  The absent-module answer is `no-store`: a cached 204 would outlive installing
  `phoenix_kit_legal` and leave the widget dead until every visitor's cache
  expired. The present-module answer keeps Legal's own `private, max-age=60`,
  which is deliberate — the payload embeds locale-dependent translations, so it
  is cacheable per user but must never be shared.

  ## Auth

  Auth-agnostic by design: it performs no per-request user check. Whether an
  authenticated user should see the widget is decided server-side by the
  `cookie_consent` component at render time. Manual callers of `init()` on pages
  where authenticated users should not see the widget are responsible for their
  own check.
  """
  use PhoenixKitWeb, :controller

  @legal PhoenixKit.Modules.Legal

  @doc """
  Returns the consent widget configuration, or 204 when the Legal module is not
  installed.
  """
  def config(conn, _params) do
    if Code.ensure_loaded?(@legal) and function_exported?(@legal, :get_consent_widget_config, 0) do
      # `apply/3` rather than a direct call: `PhoenixKit.Modules.Legal` lives in
      # an optional package, and the compiler resolves a direct call (or a
      # variable-indirected one) statically and warns that it is undefined.
      # `Code.ensure_loaded?/1` above is the runtime correctness check; this is
      # only shielding the compiler's static pass. Same idiom, same reason, as
      # `PhoenixKitWeb.Integration`'s publishing dispatch.
      # credo:disable-for-next-line Credo.Check.Refactor.Apply
      config = apply(@legal, :get_consent_widget_config, [])

      conn
      |> put_resp_header("cache-control", "private, max-age=60")
      |> json(config)
    else
      conn
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(:no_content, "")
    end
  end
end
