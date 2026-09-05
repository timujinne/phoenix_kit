defmodule PhoenixKit.Utils.TimeZoneTest do
  @moduledoc """
  Pins the reported timezone bugs so they cannot come back.

  Every case here failed under the previous integer-offset scheme.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Utils.TimeZone

  # Northern-hemisphere summer and winter, so a DST transition sits between.
  @summer DateTime.new!(~D[2026-08-24], ~T[12:00:00], "Etc/UTC")
  @winter DateTime.new!(~D[2026-01-15], ~T[12:00:00], "Etc/UTC")

  defp offset_hours(datetime, zone) do
    shifted = TimeZone.shift(datetime, zone)
    (shifted.utc_offset + shifted.std_offset) / 3600
  end

  describe "the grouped picker" do
    test "is short enough to browse, and every row is a real zone" do
      options = TimeZone.options()

      # The whole point of grouping: 59-ish rows, not 447.
      assert length(options) < 80

      for {_label, id} <- options do
        assert TimeZone.identifier?(id)
        assert TimeZone.representative?(id)
      end
    end

    test "Johannesburg and Helsinki cannot share a row" do
      # The original bug. They are only equal in winter, so grouping by
      # behaviour puts them in different groups by construction.
      refute TimeZone.same_group?("Africa/Johannesburg", "Europe/Helsinki")
    end

    test "cities that behave identically all year do share a row" do
      assert TimeZone.same_group?("Europe/Tallinn", "Europe/Helsinki")
      assert TimeZone.same_group?("Europe/Warsaw", "Europe/Berlin")
    end
  end

  describe "effectively_same?/2" do
    # A site's `time_zone` setting is the legacy offset "0" on every install
    # that has never touched it. `same_group?/2` has no entry for a legacy
    # offset, so it always answered false here — the "you have not set a
    # timezone" notice fired for literally everyone, including a browser
    # genuinely on UTC+0. Both zones below are fixed year-round (no DST), so
    # the assertions hold regardless of when the suite runs.
    test "a legacy offset matches an identifier at the same current offset" do
      assert TimeZone.effectively_same?("Africa/Accra", "0")
      assert TimeZone.effectively_same?("Africa/Johannesburg", "2")
    end

    test "a legacy offset does not match an identifier at a different offset" do
      refute TimeZone.effectively_same?("Africa/Johannesburg", "0")
      refute TimeZone.effectively_same?("Africa/Accra", "2")
    end

    test "two identifiers defer to same_group?/2" do
      assert TimeZone.effectively_same?("Europe/Tallinn", "Europe/Helsinki")
      refute TimeZone.effectively_same?("Africa/Johannesburg", "Europe/Helsinki")
    end

    test "blank or invalid input never matches" do
      refute TimeZone.effectively_same?("Africa/Accra", "")
      refute TimeZone.effectively_same?("Africa/Accra", nil)
      refute TimeZone.effectively_same?(nil, "0")
    end

    test "labels name cities that really belong to the group" do
      # Guards the one hand-curated part of the table. If a country changes its
      # rules and moves group, the label must not keep advertising it.
      for {label, rep} <- TimeZone.options() do
        "(UTC" <> rest = label

        cities =
          rest
          |> String.split(") ", parts: 2)
          |> List.last()
          |> String.replace(" — summer time", "")
          |> String.split(", ")

        for city <- cities do
          assert Enum.any?(TimeZone.identifiers(), fn id ->
                   TimeZone.same_group?(id, rep) and
                     String.ends_with?(id, String.replace(city, " ", "_"))
                 end),
                 "#{label} names #{city}, which is not in the group #{rep} represents"
        end
      end
    end

    test "labels carry the offset as of now, not a frozen winter value" do
      {label, _id} =
        Enum.find(TimeZone.options(), fn {_l, id} -> id == "Europe/Paris" end)

      assert label =~ ~r/^\(UTC[+-]\d\d:\d\d\)/
      assert label =~ "summer time"
    end

    test "a saved zone that is not a representative is added as its own row" do
      # What auto-detection stores: somewhere precise, not a group stand-in.
      plain = TimeZone.options()
      with_tallinn = TimeZone.options(selected: "Europe/Tallinn")

      refute Enum.any?(plain, fn {_l, id} -> id == "Europe/Tallinn" end)
      assert length(with_tallinn) == length(plain) + 1
      assert {label, "Europe/Tallinn"} = hd(with_tallinn)
      assert label =~ "your location"
    end

    test "a saved representative does not get duplicated" do
      assert length(TimeZone.options(selected: "Europe/Paris")) ==
               length(TimeZone.options())
    end
  end

  describe "the identifier list" do
    test "every identifier resolves against the compiled tz database" do
      unresolvable =
        Enum.reject(TimeZone.identifiers(), fn id ->
          match?({:ok, _}, DateTime.shift_zone(@summer, id, TimeZone.database()))
        end)

      assert unresolvable == [],
             "these ids are in the picker but the tz database cannot place them: " <>
               inspect(unresolvable)
    end

    test "Warsaw is present — the omission that started this" do
      assert "Europe/Warsaw" in TimeZone.identifiers()
    end

    test "zones tzdata links to another are kept, so people can find their own city" do
      # Oslo, Stockholm and Copenhagen are links to Europe/Berlin. Filtering the
      # list to canonical entries would drop them and repeat the Warsaw problem.
      for id <- ["Europe/Oslo", "Europe/Stockholm", "Europe/Copenhagen"] do
        assert id in TimeZone.identifiers()
      end
    end

    test "every identifier belongs to exactly one group" do
      for id <- TimeZone.identifiers() do
        assert TimeZone.group_for(id) != nil, "#{id} is in no group"
      end
    end
  end

  describe "the bugs from the report" do
    test "Helsinki and Kyiv are UTC+3 in summer, not the winter +2 they were labelled" do
      assert offset_hours(@summer, "Europe/Helsinki") == 3.0
      assert offset_hours(@summer, "Europe/Kyiv") == 3.0
    end

    test "Johannesburg is UTC+2 year round, so it cannot share a row with them" do
      assert offset_hours(@summer, "Africa/Johannesburg") == 2.0
      assert offset_hours(@winter, "Africa/Johannesburg") == 2.0

      refute offset_hours(@summer, "Europe/Helsinki") ==
               offset_hours(@summer, "Africa/Johannesburg")
    end

    test "Warsaw follows DST without being re-saved" do
      assert offset_hours(@summer, "Europe/Warsaw") == 2.0
      assert offset_hours(@winter, "Europe/Warsaw") == 1.0
    end

    test "Almaty is UTC+5 — it was listed under +6, wrong in every season" do
      assert offset_hours(@summer, "Asia/Almaty") == 5.0
      assert offset_hours(@winter, "Asia/Almaty") == 5.0
    end
  end

  describe "legacy numeric offsets" do
    test "a stored whole-hour offset still shifts exactly as before" do
      assert TimeZone.shift(@summer, "2") == DateTime.add(@summer, 2 * 3600, :second)
      assert TimeZone.shift(@summer, "-5") == DateTime.add(@summer, -5 * 3600, :second)
      assert TimeZone.shift(@summer, "+3") == DateTime.add(@summer, 3 * 3600, :second)
    end

    test "half-hour offsets shift — Integer.parse/1 used to drop them silently" do
      # "5.5" left a ".5" remainder, failed the `{offset, ""}` match, and the
      # timestamp came back unshifted: every UTC+5:30 account read UTC.
      assert TimeZone.shift(@summer, "5.5") == DateTime.add(@summer, 19_800, :second)
      assert TimeZone.shift(@summer, "9.5") == DateTime.add(@summer, 34_200, :second)
    end

    test "legacy values are recognised as such, so the UI can offer a real zone" do
      for value <- ["2", "-5", "+3", "5.5"] do
        assert TimeZone.legacy_offset?(value)
        refute TimeZone.identifier?(value)
      end
    end

    test "an identifier is not mistaken for an offset" do
      assert TimeZone.identifier?("Europe/Warsaw")
      refute TimeZone.legacy_offset?("Europe/Warsaw")
    end
  end

  describe "shift/2 tolerance" do
    test "blank values pass the datetime through untouched" do
      assert TimeZone.shift(@summer, nil) == @summer
      assert TimeZone.shift(@summer, "") == @summer
    end

    test "an unusable value returns the datetime rather than raising" do
      # A page of timestamps is worth more than a crash over a preference.
      assert TimeZone.shift(@summer, "Mars/Olympus_Mons") == @summer
      assert TimeZone.shift(@summer, "not a zone") == @summer
      assert TimeZone.shift(@summer, "99") == @summer
    end
  end

  describe "valid?/1" do
    test "accepts identifiers, legacy offsets and blank" do
      assert TimeZone.valid?("Europe/Warsaw")
      assert TimeZone.valid?("5.5")
      assert TimeZone.valid?(nil)
      assert TimeZone.valid?("")
    end

    test "rejects anything else" do
      refute TimeZone.valid?("Mars/Olympus_Mons")
      refute TimeZone.valid?("99")
    end
  end

  describe "offset_seconds/2" do
    # Exists because `Float.parse/1` answered 0 for every IANA id, and three
    # module packages (bookings' availability window, calendar's day bounds and
    # its "same timezone?" comparison) took that 0 as "UTC" — silently, on any
    # site that had used the picker.

    test "reads a legacy offset, including the half-hour zones" do
      assert TimeZone.offset_seconds("2") == 7200
      assert TimeZone.offset_seconds("-5") == -18_000
      assert TimeZone.offset_seconds("5.5") == 19_800
    end

    test "resolves an IANA id at the given instant, and follows DST" do
      # The whole point: one id, two answers, decided by the date.
      winter = TimeZone.offset_seconds("Europe/Warsaw", ~U[2026-01-15 12:00:00Z])
      summer = TimeZone.offset_seconds("Europe/Warsaw", ~U[2026-07-15 12:00:00Z])

      assert winter == 3600
      assert summer == 7200
    end

    test "a zone that does not observe DST answers the same all year" do
      jan = TimeZone.offset_seconds("Africa/Johannesburg", ~U[2026-01-15 12:00:00Z])
      jul = TimeZone.offset_seconds("Africa/Johannesburg", ~U[2026-07-15 12:00:00Z])

      assert jan == 7200
      assert jul == 7200
    end

    test "unresolvable and empty values are 0, the previous safe default" do
      assert TimeZone.offset_seconds("Not/AZone") == 0
      assert TimeZone.offset_seconds(nil) == 0
      assert TimeZone.offset_seconds("") == 0
    end
  end

  describe "day_start/2" do
    # "How many today" has to mean the operator's today. From UTC midnight it
    # is right until evening and then wrong every night east of UTC.

    test "UTC is plain midnight" do
      assert TimeZone.day_start("0", ~U[2026-09-05 14:00:00Z]) == ~U[2026-09-05 00:00:00Z]
    end

    test "an eastern zone starts its day before UTC midnight" do
      # Tallinn is UTC+3 in September: local Sep 5 began at 21:00 UTC on Sep 4.
      assert TimeZone.day_start("Europe/Tallinn", ~U[2026-09-05 14:00:00Z]) ==
               ~U[2026-09-04 21:00:00Z]
    end

    test "just after UTC midnight an eastern zone is already a day ahead" do
      # 00:30 UTC on Sep 5 is 03:30 local — still Sep 5 there, which began
      # 21:00 UTC on Sep 4. This is the window the old code got wrong.
      assert TimeZone.day_start("Europe/Tallinn", ~U[2026-09-05 00:30:00Z]) ==
               ~U[2026-09-04 21:00:00Z]
    end

    test "a western zone starts its day after UTC midnight" do
      assert TimeZone.day_start("America/New_York", ~U[2026-09-05 14:00:00Z]) ==
               ~U[2026-09-05 04:00:00Z]
    end

    test "it tracks DST rather than a fixed offset" do
      winter = TimeZone.day_start("Europe/Warsaw", ~U[2026-01-15 12:00:00Z])
      summer = TimeZone.day_start("Europe/Warsaw", ~U[2026-07-15 12:00:00Z])

      assert winter == ~U[2026-01-14 23:00:00Z]
      assert summer == ~U[2026-07-14 22:00:00Z]
    end

    test "a legacy offset still works" do
      assert TimeZone.day_start("2", ~U[2026-09-05 00:30:00Z]) == ~U[2026-09-04 22:00:00Z]
    end
  end
end
