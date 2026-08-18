defmodule PhoenixKitWeb.Users.AuthSEO do
  @moduledoc """
  Canonical / hreflang assigns for the auth LiveViews whose path is stable
  and token-free (registration, log-in, magic-link registration request).

  Mirrors `PhoenixKitEcommerce.Web.SEOHelpers`'s contract so a multi-domain
  host wires one resolver for both the shop and auth surfaces: the canonical
  host per language comes from the workspace-wide
  `config :phoenix_kit, :canonical_host_resolver, {mod, fun}` MFA (nil or
  absent ⇒ the site-wide `PhoenixKit.Utils.Routes.base_url/0`, today's
  behavior). On a language's own resolved host the locale segment is dropped
  (`Routes.path(url_path, locale: :none)`) — the domain itself carries the
  language, so a `/en` (or any other) prefix on top of it would be redundant.

  Deliberately excludes every token-bearing auth page (email confirmation,
  password reset, magic-link verify, QR-login confirm): a one-time token in
  the URL makes canonical/hreflang meaningless — there is no duplicate-content
  signal to consolidate — and actively wrong, since the link a search engine
  would be told about goes dead the moment the token is spent.

  Setting these assigns is enough on its own: the root layout that renders
  `@canonical_url` / `@hreflang_links` into `<head>` is the HOST app's, per
  the same cross-package contract `phoenix_kit_ecommerce`'s catalog pages
  already rely on (see `PhoenixKitEcommerce.Web.SEOHelpers`). Nothing here
  renders anything itself.
  """

  require Logger

  alias PhoenixKit.Modules.Languages
  alias PhoenixKit.Modules.Languages.DialectMapper
  alias PhoenixKit.Utils.Routes

  @doc """
  Canonical + hreflang assigns for a stable, token-free auth path, e.g.
  `"/users/register"`.

  `hreflang_links` is `[]` when Languages is disabled or fewer than two
  languages are enabled — one language is not a hreflang set.
  """
  @spec seo_assigns(String.t()) :: %{canonical_url: String.t(), hreflang_links: [map()]}
  def seo_assigns(url_path) when is_binary(url_path) do
    %{
      canonical_url: canonical_absolute_url(current_language(), url_path),
      hreflang_links: hreflang_links(url_path)
    }
  end

  defp hreflang_links(url_path) do
    links =
      enabled_languages()
      |> Enum.map(&DialectMapper.extract_base(&1.code))
      |> Enum.uniq()
      |> Enum.map(&%{code: &1, url: canonical_absolute_url(&1, url_path)})

    if length(links) < 2, do: [], else: links
  end

  defp enabled_languages do
    if Languages.enabled?(), do: Languages.get_enabled_languages(), else: []
  end

  # These assigns are computed from inside `mount/3`, before the locale
  # `handle_params` hook (`PhoenixKitWeb.Users.Auth.attach_locale_hook/1`)
  # has run — so `socket.assigns[:current_locale_base]` is still unset here.
  # The HTTP-layer locale plug already put the right value into Gettext
  # before the LiveView mounted, which is exactly what `Routes.path/2` (called
  # elsewhere in the same `do_mount`, e.g. for presence tracking) relies on
  # too when it's not given an explicit `:locale`.
  defp current_language do
    PhoenixKitWeb.Gettext
    |> Gettext.get_locale()
    |> DialectMapper.extract_base()
  end

  defp canonical_absolute_url(language, url_path) do
    case resolve_canonical_host(language) do
      nil ->
        Routes.base_url() <> Routes.path(url_path, locale: language)

      host ->
        # The language's own home domain implies the language — no locale
        # segment needed on top of it, for the primary language or any other.
        "https://#{host}" <> Routes.path(url_path, locale: :none)
    end
  end

  defp resolve_canonical_host(language) do
    case Application.get_env(:phoenix_kit, :canonical_host_resolver) do
      {mod, fun} -> apply(mod, fun, [language])
      _ -> nil
    end
  rescue
    error ->
      Logger.warning(
        "[AuthSEO] canonical_host_resolver raised, falling back to site base: " <>
          Exception.message(error)
      )

      nil
  catch
    # A connection-pool failure under the host's resolver EXITS rather than
    # raising (see `Routes.get_default_language_base/0` for the same class of
    # bug) — `rescue` alone does not catch it.
    :exit, reason ->
      Logger.warning(
        "[AuthSEO] canonical_host_resolver exited, falling back to site base: " <>
          inspect(reason)
      )

      nil
  end
end
