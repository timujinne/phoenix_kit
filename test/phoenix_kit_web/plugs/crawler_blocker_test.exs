defmodule PhoenixKitWeb.Plugs.CrawlerBlockerTest do
  @moduledoc """
  The blocker's contract, exercised without PostgreSQL by priming the settings
  cache (`get_boolean_setting` consults it before the update-mode
  short-circuit — same pattern as `safe_destination_settings_test.exs`).

  `async: false` because the cache is a globally named process.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn, only: [put_req_header: 3]

  alias PhoenixKitWeb.Plugs.CrawlerBlocker

  setup do
    start_supervised!({PhoenixKit.Cache.Registry, []})
    start_supervised!({PhoenixKit.Cache, name: :settings})
    :ok
  end

  defp put_setting(key, value), do: PhoenixKit.Cache.put(:settings, key, value)

  defp call(ua) do
    :get
    |> conn("/")
    |> put_req_header("user-agent", ua)
    |> CrawlerBlocker.call([])
  end

  defp arm(blocked_group) do
    put_setting("crawlers_module_enabled", "true")
    put_setting("crawlers_block_at_app", "true")
    put_setting("crawlers_allow_#{blocked_group}", "false")
  end

  test "does nothing while the module or enforcement is off" do
    # Nothing primed: both read false.
    conn = call("GPTBot/1.0")
    refute conn.halted

    put_setting("crawlers_module_enabled", "true")
    conn = call("GPTBot/1.0")
    refute conn.halted
  end

  test "403s a blocked group's bot, case-insensitively" do
    arm(:ai_training)

    conn = call("Mozilla/5.0 (compatible; gptbot/1.1; +https://openai.com/gptbot)")
    assert conn.halted
    assert conn.status == 403
  end

  test "passes bots from groups that are still allowed" do
    arm(:ai_training)

    conn = call("Mozilla/5.0 (compatible; Googlebot/2.1)")
    refute conn.halted

    conn = call("Mozilla/5.0 (compatible; AhrefsBot/7.0)")
    refute conn.halted
  end

  test "passes ordinary browsers and requests with no user-agent" do
    arm(:ai_training)

    refute call("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15").halted
    refute CrawlerBlocker.call(conn(:get, "/"), []).halted
  end

  test "robots.txt-only tokens never match a request UA" do
    arm(:ai_training)

    # A crawl honoring Google-Extended arrives as Googlebot; blocking the
    # training group must not 403 it.
    refute call("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").halted
  end
end
