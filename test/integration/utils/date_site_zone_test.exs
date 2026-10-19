defmodule PhoenixKit.Integration.Utils.DateSiteZoneTest do
  @moduledoc """
  The Settings-aware formatters of `PhoenixKit.Utils.Date` against the real
  settings table: an instant is shown in the site time zone, not as the
  stored UTC clock.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKit.Utils.TimeZone

  # The zone is read through the settings cache, which a write only invalidates
  # by cast and which outlives the sandbox rollback: evict it synchronously
  # after each write and again on the way out, so no value leaks to a later test.
  defp put_zone(zone) do
    {:ok, _} = Settings.update_setting("time_zone", zone)
    PhoenixKit.Cache.invalidate_now(:settings, ["time_zone"])
  end

  setup do
    {:ok, _} = Settings.update_setting("date_format", "d.m.Y")
    {:ok, _} = Settings.update_setting("time_format", "H:i")
    put_zone("Europe/Tallinn")
    on_exit(fn -> PhoenixKit.Cache.invalidate_now(:settings, ["time_zone"]) end)
    :ok
  end

  # 15:31 UTC on a summer day is 18:31 in Tallinn (EEST, UTC+3).
  @summer ~U[2026-10-07 15:31:28Z]
  # 22:30 UTC in winter is 00:30 the next day in Tallinn (EET, UTC+2).
  @winter_late ~U[2026-12-31 22:30:00Z]

  describe "format_datetime_full_with_user_format/1" do
    test "shows a DateTime in the site time zone" do
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 18:31"
    end

    test "reads a NaiveDateTime as UTC" do
      assert UtilsDate.format_datetime_full_with_user_format(~N[2026-10-07 15:31:28]) ==
               "07.10.2026 18:31"
    end

    test "applies the zone's offset for the instant shown (UTC+2 in winter)" do
      assert UtilsDate.format_datetime_full_with_user_format(@winter_late) == "01.01.2027 00:30"
    end

    test "a site with no zone set keeps UTC" do
      put_zone("0")
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 15:31"
    end

    test "a blank zone keeps UTC" do
      put_zone("")
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 15:31"
    end

    test "a legacy numeric offset still shifts by its hours, fractional too" do
      put_zone("2")
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 17:31"

      put_zone("5.5")
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 21:01"
    end

    test "a zone west of UTC can move the date back a day" do
      put_zone("America/New_York")

      assert UtilsDate.format_datetime_full_with_user_format(~U[2026-10-08 02:00:00Z]) ==
               "07.10.2026 22:00"
    end

    test "an unknown zone leaves the clock as stored instead of failing" do
      put_zone("Mars/Olympus")
      assert UtilsDate.format_datetime_full_with_user_format(@summer) == "07.10.2026 15:31"
    end

    test "a DateTime already in another zone is not shifted twice" do
      tallinn = DateTime.shift_zone!(@summer, "Europe/Tallinn", TimeZone.database())

      assert UtilsDate.format_datetime_full_with_user_format(tallinn) == "07.10.2026 18:31"

      put_zone("2")
      assert UtilsDate.format_datetime_full_with_user_format(tallinn) == "07.10.2026 17:31"

      # No zone is UTC, whatever zone the value came in.
      put_zone("0")
      assert UtilsDate.format_datetime_full_with_user_format(tallinn) == "07.10.2026 15:31"
    end

    test "nil is still \"Never\"" do
      assert UtilsDate.format_datetime_full_with_user_format(nil) == "Never"
    end
  end

  describe "the date-only and time-only formatters" do
    test "format_datetime_with_user_format/1 gives the local date" do
      assert UtilsDate.format_datetime_with_user_format(@winter_late) == "01.01.2027"
    end

    test "format_date_with_user_format/1 gives the local date of an instant" do
      assert UtilsDate.format_date_with_user_format(@winter_late) == "01.01.2027"
      assert UtilsDate.format_date_with_user_format(~N[2026-12-31 22:30:00]) == "01.01.2027"
    end

    test "format_date_with_user_format/1 leaves a Date as it is" do
      assert UtilsDate.format_date_with_user_format(~D[2026-12-31]) == "31.12.2026"
    end

    test "format_time_with_user_format/1 gives the local time of an instant" do
      assert UtilsDate.format_time_with_user_format(@summer) == "18:31"
      assert UtilsDate.format_time_with_user_format(~N[2026-10-07 15:31:28]) == "18:31"
    end

    test "format_time_with_user_format/1 leaves a Time as it is" do
      assert UtilsDate.format_time_with_user_format(~T[15:31:00]) == "15:31"
    end

    test "format_short_datetime/1 is in the site time zone too" do
      Gettext.with_locale(PhoenixKitWeb.Gettext, "en", fn ->
        assert UtilsDate.format_short_datetime(@summer) == "Oct 07, 2026 at 18:31"
      end)
    end
  end

  describe "to_site_date/1 and site_today/0" do
    test "a DateTime is the date in the site zone, which can be the next day" do
      assert UtilsDate.to_site_date(@winter_late) == ~D[2027-01-01]
      assert UtilsDate.to_site_date(@summer) == ~D[2026-10-07]
    end

    test "a NaiveDateTime is read as UTC, then shown in the site zone" do
      assert UtilsDate.to_site_date(~N[2026-12-31 22:30:00]) == ~D[2027-01-01]
    end

    test "a zone west of UTC can give the previous day" do
      put_zone("America/New_York")
      assert UtilsDate.to_site_date(~U[2026-10-08 02:00:00Z]) == ~D[2026-10-07]
      assert UtilsDate.to_site_date(~N[2026-10-08 02:00:00]) == ~D[2026-10-07]
    end

    test "no zone is UTC and a Date is returned as it is" do
      put_zone("0")
      assert UtilsDate.to_site_date(@winter_late) == ~D[2026-12-31]
      assert UtilsDate.to_site_date(~D[2026-12-31]) == ~D[2026-12-31]
    end

    test "site_today/0 is the current UTC instant seen in the site zone" do
      put_zone("0")
      assert UtilsDate.site_today() == Date.utc_today()

      # The zone is applied, not ignored: the same instant converted by hand,
      # taken before and after the call so midnight cannot flake it. UTC+14 and
      # UTC-11 are over a day apart, so at least one differs from the UTC date
      # whatever the hour the suite runs at.
      for zone <- ["Pacific/Kiritimati", "Pacific/Pago_Pago"] do
        put_zone(zone)

        local_today = fn ->
          DateTime.utc_now()
          |> DateTime.shift_zone!(zone, TimeZone.database())
          |> DateTime.to_date()
        end

        before_call = local_today.()
        today = UtilsDate.site_today()
        assert today in [before_call, local_today.()], zone
      end
    end
  end
end
