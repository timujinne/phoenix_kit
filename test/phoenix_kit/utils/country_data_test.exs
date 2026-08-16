defmodule PhoenixKit.Utils.CountryDataTest do
  use ExUnit.Case, async: false

  # No `doctest` here: this module's examples are written against the bare
  # `CountryData.` alias, which a doctest has no way to resolve.

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Utils.CountryData

  setup do
    previous = Application.get_env(:phoenix_kit, :country_select_priority)
    on_exit(fn -> restore(:country_select_priority, previous) end)
    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore(key, value), do: Application.put_env(:phoenix_kit, key, value)

  defp by_code(entries), do: Map.new(entries, fn {display, code} -> {code, display} end)

  # The display name carries a flag emoji, which sorts by country code rather
  # than by name — compare the names the sort actually keys on.
  defp without_flag(display), do: display |> String.split(" ", parts: 2) |> List.last()

  describe "countries_for_select/1 locale" do
    test "translates names into the requested locale" do
      names = by_code(CountryData.countries_for_select(locale: "ru"))
      assert names["EE"] == "🇪🇪 Эстония"
      assert names["DE"] == "🇩🇪 Германия"
    end

    test "falls back to English for a locale with no translations" do
      names = by_code(CountryData.countries_for_select(locale: "xx"))
      assert names["EE"] == "🇪🇪 Estonia"
    end

    test "reduces a dialect to its base code" do
      assert CountryData.countries_for_select(locale: "ru-RU") ==
               CountryData.countries_for_select(locale: "ru")
    end

    test "keeps every country regardless of locale" do
      # Same country *codes*, not just the same count — a locale-dependent
      # filter bug could drop one country and pick up another while leaving
      # the length unchanged at 250.
      codes = fn locale ->
        CountryData.countries_for_select(locale: locale)
        |> Enum.map(&elem(&1, 1))
        |> MapSet.new()
      end

      assert codes.("ru") == codes.("en")
    end
  end

  describe "countries_for_select/1 priority" do
    test "pins the given codes to the top, in the order given" do
      result = CountryData.countries_for_select(locale: "en", priority: ["EE", "FI", "LV"])

      assert Enum.take(result, 3) == [
               {"🇪🇪 Estonia", "EE"},
               {"🇫🇮 Finland", "FI"},
               {"🇱🇻 Latvia", "LV"}
             ]
    end

    test "lists each pinned country exactly once" do
      codes =
        CountryData.countries_for_select(locale: "en", priority: ["EE", "FI"])
        |> Enum.map(&elem(&1, 1))

      assert Enum.count(codes, &(&1 == "EE")) == 1
      assert length(codes) == length(Enum.uniq(codes))
    end

    test "ignores unknown codes and normalizes case" do
      result = CountryData.countries_for_select(locale: "en", priority: ["zz", "ee"])
      assert hd(result) == {"🇪🇪 Estonia", "EE"}
    end

    test "pins nothing when no priority is given or stored" do
      # There is no compile-time config underneath the setting, so an
      # untouched install must be plain alphabetical. Setting the old config
      # key must have no effect whatsoever.
      Application.put_env(:phoenix_kit, :country_select_priority, ["FI"])

      assert hd(CountryData.countries_for_select(locale: "en")) == {"🇦🇫 Afghanistan", "AF"}
    end

    test "sorts the unpinned remainder alphabetically, accents folded" do
      names =
        CountryData.countries_for_select(locale: "en", priority: [])
        |> Enum.map(&without_flag(elem(&1, 0)))

      index = fn name -> Enum.find_index(names, &(&1 == name)) end

      # Literal neighbours from the real sorted (English) output, so that
      # changing the sort key breaks this test — unlike the previous version,
      # which re-derived the same NFD-fold-and-downcase key the implementation
      # uses and therefore could never fail. Folding places each accented name
      # next to its unaccented neighbours instead of exiling it past "Z".
      assert index.("Azerbaijan") < index.("Åland Islands")
      assert index.("Åland Islands") < index.("Bahamas")

      assert index.("Costa Rica") < index.("Côte d'Ivoire")
      assert index.("Côte d'Ivoire") < index.("Croatia")

      assert index.("Tuvalu") < index.("Türkiye")
      assert index.("Türkiye") < index.("Uganda")
    end

    test "sorts by the localized name, not the English one" do
      names =
        CountryData.countries_for_select(locale: "ru", priority: [])
        |> Enum.map(&without_flag(elem(&1, 0)))

      assert "Австралия" in names

      assert Enum.find_index(names, &(&1 == "Австралия")) <
               Enum.find_index(names, &(&1 == "Швеция"))
    end
  end

  describe "countries_for_select/1 priority from settings" do
    # The settings cache is consulted before the update-mode short-circuit, so
    # priming it exercises the real read path with no database involved. The
    # cache is a globally named process, hence async: false for the file.
    #
    # A cache MISS still falls through to `PhoenixKit.Settings`: with no
    # database `test_helper.exs` short-circuits that read to the default, but
    # when a database IS reachable it becomes a real query from a process
    # that owns no sandbox connection — an OwnershipError, not a miss.
    # Checking out here (copied from `safe_destination_settings_test.exs`,
    # which recorded the same failure on its first run against a database)
    # makes the file behave the same either way. Every test below primes the
    # key it reads except the "absent key" one, which is exactly why this
    # guard is needed at the describe level rather than per-test.
    setup do
      if Application.get_env(:phoenix_kit, :test_repo_available, false) do
        :ok = Sandbox.checkout(PhoenixKit.Test.Repo)
      end

      start_supervised!({PhoenixKit.Cache.Registry, []})
      start_supervised!({PhoenixKit.Cache, name: :settings})
      :ok
    end

    defp put_priority_setting(value),
      do: PhoenixKit.Cache.put(:settings, "country_select_priority", value)

    test "the stored setting pins the countries" do
      put_priority_setting("EE, LV")

      assert CountryData.countries_for_select(locale: "en") |> Enum.take(2) == [
               {"\u{1F1EA}\u{1F1EA} Estonia", "EE"},
               {"\u{1F1F1}\u{1F1FB} Latvia", "LV"}
             ]
    end

    test "a blank setting pins nothing" do
      put_priority_setting("")

      assert hd(CountryData.countries_for_select(locale: "en")) ==
               {"\u{1F1E6}\u{1F1EB} Afghanistan", "AF"}
    end

    test "an absent setting pins nothing" do
      # No put_priority_setting call: a host that never opened the settings
      # page. Nothing is pinned — there is no config underneath to inherit.
      assert hd(CountryData.countries_for_select(locale: "en")) ==
               {"\u{1F1E6}\u{1F1EB} Afghanistan", "AF"}
    end

    test "the old config key is ignored entirely" do
      Application.put_env(:phoenix_kit, :country_select_priority, ["FI"])
      put_priority_setting("EE")

      assert hd(CountryData.countries_for_select(locale: "en")) ==
               {"\u{1F1EA}\u{1F1EA} Estonia", "EE"}

      put_priority_setting("")

      assert hd(CountryData.countries_for_select(locale: "en")) ==
               {"\u{1F1E6}\u{1F1EB} Afghanistan", "AF"}
    end

    test "an explicit :priority overrides the setting" do
      put_priority_setting("EE")

      assert hd(CountryData.countries_for_select(locale: "en", priority: ["LV"])) ==
               {"\u{1F1F1}\u{1F1FB} Latvia", "LV"}
    end
  end

  describe "parse_priority/1 and known_country_codes/1" do
    test "parses the separators an operator actually types" do
      assert CountryData.parse_priority("EE, FI ; lv") == ["EE", "FI", "LV"]
      assert CountryData.parse_priority("ee\nfi") == ["EE", "FI"]
      assert CountryData.parse_priority("EE, EE") == ["EE"]
      assert CountryData.parse_priority("") == []
      assert CountryData.parse_priority(nil) == []
    end

    test "drops codes that name no country" do
      assert CountryData.known_country_codes(["EE", "ZZ", "FI"]) == ["EE", "FI"]
      assert CountryData.known_country_codes(["", nil, :ee]) == []
    end

    test "a fully-rejected input keeps the unknown codes for reporting, but pins nothing" do
      # The scenario the settings form's flash has to report: every code the
      # operator typed is unknown, so nothing survives to be stored.
      typed = CountryData.parse_priority("Estonia, USA, Suomi")
      assert typed == ["ESTONIA", "USA", "SUOMI"]
      assert CountryData.known_country_codes(typed) == []
    end
  end

  describe "suggested_priority/2" do
    test "puts the host's own country first, then its nearest neighbours" do
      assert ["EE" | neighbours] = CountryData.suggested_priority("EE", limit: 4)
      assert "LV" in neighbours
      assert "FI" in neighbours
      assert length(neighbours) == 4
    end

    test "works anywhere, not just where the library was written" do
      # The point of deriving this from the data rather than from a constant:
      # a host in Germany or Singapore must get ITS neighbours.
      assert ["DE" | de] = CountryData.suggested_priority("DE", limit: 3)
      assert "NL" in de or "LU" in de

      assert ["SG" | sg] = CountryData.suggested_priority("SG", limit: 3)
      assert "MY" in sg
      refute "EE" in sg
    end

    test "never repeats the origin country" do
      codes = CountryData.suggested_priority("EE", limit: 6)
      assert Enum.count(codes, &(&1 == "EE")) == 1
      assert codes == Enum.uniq(codes)
    end

    test "honours :limit, including zero" do
      assert length(CountryData.suggested_priority("EE", limit: 0)) == 1
      assert length(CountryData.suggested_priority("EE", limit: 1)) == 2
      assert length(CountryData.suggested_priority("EE")) == 5
    end

    test "falls back to the default instead of raising on a non-integer :limit" do
      default = CountryData.suggested_priority("EE")

      assert CountryData.suggested_priority("EE", limit: nil) == default
      assert CountryData.suggested_priority("EE", limit: "4") == default
      assert CountryData.suggested_priority("EE", limit: 2.5) == default
    end

    test "answers [] for a code that names no country" do
      assert CountryData.suggested_priority("XX") == []
      assert CountryData.suggested_priority(nil) == []
      assert CountryData.suggested_priority(123) == []
    end

    test "returns codes that are all real countries" do
      codes = CountryData.suggested_priority("EE", limit: 8)
      assert CountryData.known_country_codes(codes) == codes
    end
  end

  describe "get_country_name/2" do
    test "translates into the requested locale" do
      assert CountryData.get_country_name("EE", locale: "ru") == "Эстония"
      assert CountryData.get_country_name("EE", locale: "en") == "Estonia"
    end

    test "falls back to the English name for an untranslated locale" do
      assert CountryData.get_country_name("EE", locale: "xx") == "Estonia"
    end

    test "still answers nil for an unknown country" do
      assert CountryData.get_country_name("XX") == nil
      assert CountryData.get_country_name(nil) == nil
    end

    test "keeps its one-argument shape for existing callers" do
      assert Code.ensure_loaded?(CountryData)
      assert function_exported?(CountryData, :get_country_name, 1)
      assert is_binary(CountryData.get_country_name("EE"))
    end
  end

  describe "eu_countries_for_select/1" do
    test "translates and pins like countries_for_select/1" do
      result = CountryData.eu_countries_for_select(locale: "ru", priority: ["EE"])
      assert hd(result) == {"🇪🇪 Эстония", "EE"}
      assert length(result) == 27
    end
  end

  describe "zero-arity contract" do
    test "countries_for_select/0 and eu_countries_for_select/0 stay exported" do
      # phoenix_kit_billing's core_compat lists
      # {CountryData, :countries_for_select, 0} as an unguarded runtime call
      # (lib/phoenix_kit_billing/core_compat.ex) — a regression here breaks
      # billing at boot. eu_countries_for_select/0 isn't in that list today,
      # but it shares the same `opts \\ []` contract, so it's asserted here
      # too rather than leaving it uncovered.
      #
      # function_exported?/3 answers false for a module that hasn't been
      # loaded yet, regardless of what it defines, so ensure_loaded? first.
      assert Code.ensure_loaded?(CountryData)
      assert function_exported?(CountryData, :countries_for_select, 0)
      assert function_exported?(CountryData, :eu_countries_for_select, 0)
    end

    test "countries_for_select/0 uses the active Gettext locale when :locale is omitted" do
      previous = Gettext.get_locale(PhoenixKitWeb.Gettext)
      on_exit(fn -> Gettext.put_locale(PhoenixKitWeb.Gettext, previous) end)

      Gettext.put_locale(PhoenixKitWeb.Gettext, "ru")

      names = by_code(CountryData.countries_for_select())
      assert names["EE"] == "🇪🇪 Эстония"
    end
  end
end
