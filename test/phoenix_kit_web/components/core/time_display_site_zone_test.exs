defmodule PhoenixKitWeb.Components.Core.TimeDisplaySiteZoneTest do
  @moduledoc """
  The `time_ago/1` tooltip shows the moment in the site time zone
  (Settings → `time_zone`), read from the real settings table.
  """

  use PhoenixKit.DataCase, async: false

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.TimeDisplay

  alias PhoenixKit.Settings

  # The zone is read through the settings cache, which outlives the sandbox
  # rollback: evict it after each write and on the way out.
  defp put_zone(zone) do
    {:ok, _} = Settings.update_setting("time_zone", zone)
    PhoenixKit.Cache.invalidate_now(:settings, ["time_zone"])
  end

  setup do
    on_exit(fn -> PhoenixKit.Cache.invalidate_now(:settings, ["time_zone"]) end)
    :ok
  end

  defp title(datetime) do
    assigns = %{datetime: datetime}

    ~H|<.time_ago datetime={@datetime} />|
    |> rendered_to_string()
    |> Floki.parse_fragment!()
    |> Floki.attribute("time", "title")
    |> List.first()
  end

  # 22:30 UTC on the last day of the year is 00:30 the next day in Tallinn
  # (EET, UTC+2).
  @late ~U[2026-12-31 22:30:00Z]

  test "the title is the moment in the site time zone" do
    put_zone("Europe/Tallinn")
    assert title(@late) == "2027-01-01 00:30"
  end

  test "a NaiveDateTime is read as UTC" do
    put_zone("Europe/Tallinn")
    assert title(~N[2026-12-31 22:30:00]) == "2027-01-01 00:30"
  end

  test "a site with no zone set shows UTC" do
    put_zone("0")
    assert title(@late) == "2026-12-31 22:30"
  end
end
