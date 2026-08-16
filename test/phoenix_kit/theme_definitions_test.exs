defmodule PhoenixKit.ThemeDefinitionsTest do
  use ExUnit.Case, async: false

  alias PhoenixKit.ThemeConfig

  setup do
    on_exit(fn ->
      Application.delete_env(:phoenix_kit, :theme_definitions)
      Application.delete_env(:phoenix_kit, :dashboard_themes)
      :persistent_term.erase({ThemeConfig, :theme_variables})
      :persistent_term.erase({ThemeConfig, :host_theme_meta})
    end)
  end

  defp put_defs(defs), do: Application.put_env(:phoenix_kit, :theme_definitions, defs)

  describe "merging over built-ins" do
    test "a variable override lands in the CSS, the rest of the theme survives" do
      put_defs(%{"phoenix-dark" => %{variables: %{"--color-primary" => "oklch(72% 0.14 158)"}}})

      css = ThemeConfig.custom_theme_css()

      assert css =~ "[data-theme=phoenix-dark]"
      assert css =~ "--color-primary: oklch(72% 0.14 158);"
      # untouched siblings still present
      assert css =~ "--color-base-100"
    end

    test "without config, output is unchanged built-ins" do
      css = ThemeConfig.custom_theme_css()

      assert css =~ "[data-theme=phoenix-light]"
      assert css =~ "oklch(57.38% 0.233 262.08)"
    end
  end

  describe "new named themes" do
    setup do
      put_defs(%{
        "brand-light" => %{
          label: "Brand Light",
          base: :light,
          extends: "phoenix-light",
          variables: %{"--color-primary" => "oklch(48% 0.13 158)"}
        }
      })

      :ok
    end

    test "appear in the CSS with the parent's variables underneath" do
      css = ThemeConfig.custom_theme_css()

      assert css =~ "[data-theme=brand-light]"
      assert css =~ "--color-primary: oklch(48% 0.13 158);"
    end

    test "feed the label, base and picker lookups" do
      assert ThemeConfig.translated_label("brand-light") == "Brand Light"
      assert ThemeConfig.base_map()["brand-light"] == "light"

      Application.put_env(:phoenix_kit, :dashboard_themes, ["brand-light", "phoenix-dark"])

      values =
        ThemeConfig.dropdown_themes(["brand-light", "phoenix-dark"]) |> Enum.map(& &1.value)

      assert values == ["brand-light", "phoenix-dark"]

      # And system resolution uses the host pair.
      assert ThemeConfig.system_pair() == {"brand-light", "phoenix-dark"}
    end

    test "appear in the default :all picker without a :dashboard_themes list" do
      # :all used to be compile-time @dropdown_order only, so a host
      # theme was in CSS / labels / system_pair but never offered.
      values = ThemeConfig.dropdown_themes(:all) |> Enum.map(& &1.value)

      assert "brand-light" in values
      assert "phoenix-light" in values
      assert ThemeConfig.all_theme_names() |> Enum.member?("brand-light")
    end
  end

  describe "validation raises, never drops" do
    test "a bad theme name" do
      put_defs(%{"Bad Name!" => %{variables: %{}}})

      assert_raise ArgumentError, ~r/invalid theme name/, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "a non-allowlisted token" do
      put_defs(%{"phoenix-dark" => %{variables: %{"--evil" => "x"}}})

      assert_raise ArgumentError, ~r/not an\s+allowed theme token/s, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "a value that could escape the declaration" do
      # The output is HTML.raw'd into a <style> tag — these are the injection
      # shapes the validator exists to refuse.
      for bad <- ["red; } </style><script>x</script>", "url(javascript:1)", "a /* b */"] do
        put_defs(%{"phoenix-dark" => %{variables: %{"--color-primary" => bad}}})
        :persistent_term.erase({ThemeConfig, :theme_variables})

        assert_raise ArgumentError, ~r/not a single plain CSS value/, fn ->
          ThemeConfig.custom_theme_css()
        end
      end
    end

    test "a new theme without label or base" do
      put_defs(%{"brandless" => %{variables: %{"--color-primary" => "red"}}})

      assert_raise ArgumentError, ~r/needs a :label/, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "extending an unknown theme" do
      put_defs(%{"child" => %{label: "C", base: :dark, extends: "nope", variables: %{}}})

      assert_raise ArgumentError, ~r/extends unknown theme/, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "an extends-only definition without a label raises, not KeyError" do
      # This shape passed the CSS validator but crashed host_theme_meta with
      # a bare KeyError from the top of <head> — the quorum's M1.
      put_defs(%{"child" => %{extends: "phoenix-light", variables: %{}}})

      assert_raise ArgumentError, ~r/needs a :label/, fn ->
        ThemeConfig.host_theme_meta()
      end

      assert_raise ArgumentError, ~r/needs a :label/, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "an invalid explicit base raises even when :extends could cover it" do
      put_defs(%{
        "child" => %{label: "C", base: "junk", extends: "phoenix-light", variables: %{}}
      })

      assert_raise ArgumentError, ~r/needs base: :light or :dark/, fn ->
        ThemeConfig.host_theme_meta()
      end
    end

    test "a non-map definition raises everywhere, never silently skips" do
      put_defs(%{"weird" => "not-a-map"})

      assert_raise ArgumentError, ~r/definition must be a map/, fn ->
        ThemeConfig.host_theme_meta()
      end
    end

    test "a poisoned theme NAME cannot reach the lookups feeding inline JS" do
      # host_theme_meta once read the raw config unvalidated — the quorum's
      # B1 bypass: base_map/label_map/system_pair fed inline <script> blocks.
      put_defs(%{"</script><script>x</script>" => %{label: "X", base: :dark}})

      assert_raise ArgumentError, ~r/invalid theme name/, fn ->
        ThemeConfig.base_map()
      end
    end

    test "a trailing newline in a theme name is rejected, not tolerated by $" do
      # "brand\n" reaching the single-quoted JS interpolation would break the
      # script string — availability-only, but the anchor is one character.
      put_defs(%{"brand\n" => %{label: "B", base: :light}})

      assert_raise ArgumentError, ~r/invalid theme name/, fn ->
        ThemeConfig.host_theme_meta()
      end
    end

    test "CSS escape sequences in values are rejected outright" do
      # "u\\72l(" is "url(" once the CSS parser decodes the escape — any
      # backslash lets a value walk around a substring blocklist.
      put_defs(%{"phoenix-dark" => %{variables: %{"--color-primary" => "u\\72l(https://x)"}}})

      assert_raise ArgumentError, ~r/not a single plain CSS value/, fn ->
        ThemeConfig.custom_theme_css()
      end
    end

    test "a variable NAME that escapes the declaration is rejected" do
      # Passed the old prefix-only check — the quorum's B2.
      put_defs(%{
        "phoenix-dark" => %{variables: %{"--color-x;}</style><script>y" => "red"}}
      })

      assert_raise ArgumentError, ~r/not an\s+allowed theme token/s, fn ->
        ThemeConfig.custom_theme_css()
      end
    end
  end

  describe "system_pair fallback warning" do
    import ExUnit.CaptureLog

    test "warns once when the configured list has no light theme" do
      # "system" resolving to a theme outside the picker is legal but almost
      # always a config oversight — say so, once per configured set.
      Application.put_env(:phoenix_kit, :dashboard_themes, ["dracula", "night"])

      log = capture_log(fn -> ThemeConfig.system_pair() end)

      assert log =~ "no light theme"
      assert ThemeConfig.system_pair() == {"phoenix-light", "dracula"}

      # second call: silent (persistent_term latch)
      assert capture_log(fn -> ThemeConfig.system_pair() end) == ""
    after
      :persistent_term.erase({ThemeConfig, :system_pair_warned, ["dracula", "night"]})
    end

    test "a complete pair warns about nothing" do
      Application.put_env(:phoenix_kit, :dashboard_themes, ["light", "dark"])

      assert capture_log(fn -> ThemeConfig.system_pair() end) == ""
    end
  end

  describe "meta feeding the JS embeds" do
    test "extends inherits the parent's base when none is given" do
      put_defs(%{"brand" => %{label: "Brand", extends: "phoenix-dark", variables: %{}}})

      assert ThemeConfig.host_theme_meta() == %{"brand" => %{label: "Brand", base: "dark"}}
      assert ThemeConfig.base_map()["brand"] == "dark"
    end

    test "an explicit base wins over the parent's color-scheme in the CSS" do
      put_defs(%{
        "brand" => %{label: "Brand", base: :dark, extends: "phoenix-light", variables: %{}}
      })

      assert ThemeConfig.theme_variables()["brand"]["color-scheme"] == "dark"
    end

    test "host labels appear in translated_label_map" do
      put_defs(%{"brand" => %{label: "Brand Co", base: :light, variables: %{}}})

      assert ThemeConfig.translated_label_map()["brand"] == "Brand Co"
    end
  end
end
