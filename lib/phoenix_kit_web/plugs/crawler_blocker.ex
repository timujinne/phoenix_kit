defmodule PhoenixKitWeb.Plugs.CrawlerBlocker do
  @moduledoc """
  Best-effort application-level enforcement of the Crawlers module's bot
  policy: requests whose `User-Agent` matches a **blocked** group's bots are
  answered `403` instead of the page.

  ## What this is, honestly

  robots.txt is a request; this plug is for bots that ignore it. It is
  **advisory-grade**: anything can send any `User-Agent`, so a scraper that
  lies passes through, and real enforcement belongs at the CDN or reverse
  proxy. The settings page says the same to the operator. It is also
  deliberately **default-off** (`crawlers_block_at_app` setting) — three
  settings reads per request is a real cost, even ETS-cached, and silent 403s
  are a support burden the operator should opt into knowingly.

  Robots.txt-only tokens (`Google-Extended`, `Applebot-Extended`) have no
  request UA of their own and are excluded from matching by the registry
  (`Bots.ua_fragments/1`), so blocking AI training can never 403 Googlebot.

  ## Wiring

  Core pipes its own kit routes through this plug. The host's routes are the
  host's: add it to the host `:browser` pipeline for full coverage —

      pipeline :browser do
        # ...
        plug PhoenixKitWeb.Plugs.CrawlerBlocker
      end

  All reads are guarded: with no database (installer context, doctor) the plug
  passes everything through.
  """

  @behaviour Plug

  import Plug.Conn

  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.Bots

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    if blocking_active?() do
      enforce(conn)
    else
      conn
    end
  end

  defp enforce(conn) do
    ua =
      conn
      |> get_req_header("user-agent")
      |> List.first()

    if is_binary(ua) and blocked_ua?(String.downcase(ua)) do
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(403, "Forbidden")
      |> halt()
    else
      conn
    end
  end

  defp blocking_active? do
    Crawlers.module_enabled?() and Crawlers.block_at_app_enabled?()
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  defp blocked_ua?(downcased_ua) do
    Crawlers.blocked_groups()
    |> Bots.ua_fragments()
    |> Enum.any?(&String.contains?(downcased_ua, &1))
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end
end
