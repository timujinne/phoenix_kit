defmodule PhoenixKitWeb.Live.Notifications.InboxEventsTest do
  @moduledoc """
  The inbox reacts to every per-user notification event the library
  broadcasts.

  Its `handle_info` guards on an explicit whitelist with a silent catch-all
  below it — the safe shape for a LiveView sharing a topic, and exactly the
  shape that fails silently when a NEW event is added: `upsert_inapp/3`
  shipped broadcasting `:notification_updated`, the bell learned it, and the
  inbox didn't — so an open inbox kept stale text and position while the
  bell refreshed. Nothing crashed, nothing logged; the message just hit the
  catch-all.

  Pinned by scraping the broadcast call sites, so the NEXT event added to
  the library fails this test until the inbox handles it too.
  """
  use ExUnit.Case, async: true

  @lib "lib/phoenix_kit"
  @inbox "lib/phoenix_kit_web/live/notifications/inbox.ex"

  defp broadcast_events do
    @lib
    |> Path.join("**/*.ex")
    |> Path.wildcard()
    |> Enum.flat_map(fn file ->
      content = File.read!(file)

      ~r/Events\.broadcast\([^,]+,\s*\{:(\w+)/
      |> Regex.scan(content)
      |> Enum.map(fn [_, event] -> String.to_atom(event) end)
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp inbox_whitelist do
    content = File.read!(@inbox)

    [_, guard] = Regex.run(~r/when event in \[([^\]]+)\]/s, content)

    ~r/:(\w+)/
    |> Regex.scan(guard)
    |> Enum.map(fn [_, event] -> String.to_atom(event) end)
    |> Enum.sort()
  end

  test "every broadcast event is in the inbox whitelist" do
    events = broadcast_events()

    assert events != [], "found no Events.broadcast call sites — the scrape regex went stale"

    missing = events -- inbox_whitelist()

    assert missing == [],
           "the inbox silently ignores #{inspect(missing)} — an open inbox will show " <>
             "stale rows for those events while the bell refreshes"
  end

  test "the event this pin was written for is broadcast and handled" do
    assert :notification_updated in broadcast_events()
    assert :notification_updated in inbox_whitelist()
  end
end
