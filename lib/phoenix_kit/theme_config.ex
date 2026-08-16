defmodule PhoenixKit.ThemeConfig do
  @moduledoc """
  Theme configuration utilities for PhoenixKit's DaisyUI integration.

  This module centralises the theme metadata used across the admin UI so that
  PhoenixKit and the consuming application stay in sync. Updating or adding a
  theme requires changing this module and the shared CSS asset only.

  ## Host configuration

  This is the page a host developer theming their app lands on, so the knobs
  live here too — a real install went un-branded for weeks because the one
  below was documented nowhere a themer would look:

    * `config :phoenix_kit, dashboard_themes: [...]` — which themes the admin
      picker offers. Defaults to `:all` (the entire daisyUI catalogue). Most
      branded hosts want exactly their pair:

          config :phoenix_kit, dashboard_themes: ["phoenix-light", "phoenix-dark"]

      **Exactly two concrete themes — one light, one dark — render as a
      sun/moon toggle** instead of a dropdown; any other shape (more themes,
      `"system"` in the list, or a same-base pair) keeps the dropdown,
      because three or more states need a menu and sun/moon semantics need
      both bases.

    * **Palette overrides go through `:theme_definitions`** — see the
      "Host configuration" section: override built-in palettes or define
      new named themes entirely from config. The old workaround (out-ranking
      the inline `<style>` from host CSS via `html[data-theme=...]`
      selectors) still works but is no longer needed.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  @default_html_theme "phoenix-light"

  @custom_theme_variables %{
    "phoenix-light" => %{
      "color-scheme" => "light",
      "--color-primary" => "oklch(57.38% 0.233 262.08)",
      "--color-primary-content" => "oklch(98% 0.02 262.08)",
      "--color-secondary" => "oklch(75.61% 0.194 333.67)",
      "--color-secondary-content" => "oklch(20% 0.02 333.67)",
      "--color-accent" => "oklch(74.22% 0.209 6.35)",
      "--color-accent-content" => "oklch(20% 0.02 6.35)",
      "--color-neutral" => "oklch(23.04% 0.065 269.31)",
      "--color-neutral-content" => "oklch(98% 0.02 269.31)",
      "--color-base-100" => "oklch(100% 0 0)",
      "--color-base-200" => "oklch(96% 0 0)",
      "--color-base-300" => "oklch(92% 0.005 286.88)",
      "--color-base-content" => "oklch(20% 0.02 269.31)",
      "--color-info" => "oklch(72.06% 0.191 231.6)",
      "--color-info-content" => "oklch(20% 0.02 231.6)",
      "--color-success" => "oklch(64.8% 0.15 160)",
      "--color-success-content" => "oklch(20% 0.02 160)",
      "--color-warning" => "oklch(84.71% 0.199 83.87)",
      "--color-warning-content" => "oklch(20% 0.02 83.87)",
      "--color-error" => "oklch(71.76% 0.221 22.18)",
      "--color-error-content" => "oklch(20% 0.02 22.18)"
    },
    "phoenix-dark" => %{
      "color-scheme" => "dark",
      "--color-primary" => "oklch(57.38% 0.233 262.08)",
      "--color-primary-content" => "oklch(98% 0.02 262.08)",
      "--color-secondary" => "oklch(75.61% 0.194 333.67)",
      "--color-secondary-content" => "oklch(20% 0.02 333.67)",
      "--color-accent" => "oklch(74.22% 0.209 6.35)",
      "--color-accent-content" => "oklch(20% 0.02 6.35)",
      "--color-neutral" => "oklch(32.77% 0.033 264.54)",
      "--color-neutral-content" => "oklch(85% 0.02 264.54)",
      "--color-base-100" => "oklch(25.33% 0.024 265.76)",
      "--color-base-200" => "oklch(23.45% 0.022 265.76)",
      "--color-base-300" => "oklch(21.68% 0.02 265.76)",
      "--color-base-content" => "oklch(85% 0.02 265.76)",
      "--color-info" => "oklch(72.06% 0.191 231.6)",
      "--color-info-content" => "oklch(20% 0.02 231.6)",
      "--color-success" => "oklch(64.8% 0.15 160)",
      "--color-success-content" => "oklch(20% 0.02 160)",
      "--color-warning" => "oklch(84.71% 0.199 83.87)",
      "--color-warning-content" => "oklch(20% 0.02 83.87)",
      "--color-error" => "oklch(71.76% 0.221 22.18)",
      "--color-error-content" => "oklch(20% 0.02 22.18)"
    }
  }

  @labels %{
    "system" => "System",
    "phoenix-light" => "Phoenix Light",
    "phoenix-dark" => "Phoenix Dark",
    "light" => "Light",
    "dark" => "Dark",
    "cupcake" => "Cupcake",
    "bumblebee" => "Bumblebee",
    "emerald" => "Emerald",
    "corporate" => "Corporate",
    "synthwave" => "Synthwave",
    "retro" => "Retro",
    "cyberpunk" => "Cyberpunk",
    "valentine" => "Valentine",
    "halloween" => "Halloween",
    "garden" => "Garden",
    "forest" => "Forest",
    "aqua" => "Aqua",
    "lofi" => "Lo-Fi",
    "pastel" => "Pastel",
    "fantasy" => "Fantasy",
    "wireframe" => "Wireframe",
    "black" => "Black",
    "luxury" => "Luxury",
    "dracula" => "Dracula",
    "cmyk" => "CMYK",
    "autumn" => "Autumn",
    "business" => "Business",
    "acid" => "Acid",
    "lemonade" => "Lemonade",
    "night" => "Night",
    "coffee" => "Coffee",
    "winter" => "Winter",
    "dim" => "Dim",
    "nord" => "Nord",
    "sunset" => "Sunset",
    "caramellatte" => "Caramel Latte",
    "abyss" => "Abyss",
    "silk" => "Silk"
  }

  @doc """
  Returns the translated, user-facing label for a theme key.

  `@labels` is a compile-time module attribute, so it can't hold macro-expanded
  `gettext/1` calls directly — this function is the translated counterpart,
  with one literal `gettext/1` call per theme so `mix gettext.extract` can
  find them.
  """
  def translated_label("system"), do: gettext("System")
  def translated_label("phoenix-light"), do: gettext("Phoenix Light")
  def translated_label("phoenix-dark"), do: gettext("Phoenix Dark")
  def translated_label("light"), do: gettext("Light")
  def translated_label("dark"), do: gettext("Dark")
  def translated_label("cupcake"), do: gettext("Cupcake")
  def translated_label("bumblebee"), do: gettext("Bumblebee")
  def translated_label("emerald"), do: gettext("Emerald")
  def translated_label("corporate"), do: gettext("Corporate")
  def translated_label("synthwave"), do: gettext("Synthwave")
  def translated_label("retro"), do: gettext("Retro")
  def translated_label("cyberpunk"), do: gettext("Cyberpunk")
  def translated_label("valentine"), do: gettext("Valentine")
  def translated_label("halloween"), do: gettext("Halloween")
  def translated_label("garden"), do: gettext("Garden")
  def translated_label("forest"), do: gettext("Forest")
  def translated_label("aqua"), do: gettext("Aqua")
  def translated_label("lofi"), do: gettext("Lo-Fi")
  def translated_label("pastel"), do: gettext("Pastel")
  def translated_label("fantasy"), do: gettext("Fantasy")
  def translated_label("wireframe"), do: gettext("Wireframe")
  def translated_label("black"), do: gettext("Black")
  def translated_label("luxury"), do: gettext("Luxury")
  def translated_label("dracula"), do: gettext("Dracula")
  def translated_label("cmyk"), do: gettext("CMYK")
  def translated_label("autumn"), do: gettext("Autumn")
  def translated_label("business"), do: gettext("Business")
  def translated_label("acid"), do: gettext("Acid")
  def translated_label("lemonade"), do: gettext("Lemonade")
  def translated_label("night"), do: gettext("Night")
  def translated_label("coffee"), do: gettext("Coffee")
  def translated_label("winter"), do: gettext("Winter")
  def translated_label("dim"), do: gettext("Dim")
  def translated_label("nord"), do: gettext("Nord")
  def translated_label("sunset"), do: gettext("Sunset")
  def translated_label("caramellatte"), do: gettext("Caramel Latte")
  def translated_label("abyss"), do: gettext("Abyss")
  def translated_label("silk"), do: gettext("Silk")

  def translated_label(theme),
    do: Map.get(@labels, theme) || host_label(theme) || theme

  defp host_label(theme) do
    case host_theme_meta() do
      %{^theme => %{label: label}} -> label
      _ -> nil
    end
  end

  @doc """
  Returns a map of theme names to translated, user-facing labels.

  Same shape as `label_map/0` but locale-aware — use this (not
  `label_map/0`) for anything rendered to a user, including client-side JS
  embeds built from a JSON-encoded map.
  """
  def translated_label_map do
    # Host themes included — @labels alone left host-defined names without
    # labels in the JS embeds while every other lookup knew them.
    @labels
    |> Map.merge(host_theme_meta())
    |> Map.new(fn {key, _} -> {key, translated_label(key)} end)
  end

  @dropdown_order [
    "system",
    "phoenix-light",
    "phoenix-dark",
    "light",
    "dark",
    "cupcake",
    "bumblebee",
    "emerald",
    "corporate",
    "synthwave",
    "retro",
    "cyberpunk",
    "valentine",
    "halloween",
    "garden",
    "forest",
    "aqua",
    "lofi",
    "pastel",
    "fantasy",
    "wireframe",
    "black",
    "luxury",
    "dracula",
    "cmyk",
    "autumn",
    "business",
    "acid",
    "lemonade",
    "night",
    "coffee",
    "winter",
    "dim",
    "nord",
    "sunset",
    "caramellatte",
    "abyss",
    "silk"
  ]

  @preview_themes Map.new(@dropdown_order, fn
                    "system" -> {"system", nil}
                    theme -> {theme, theme}
                  end)

  @base_map %{
    "phoenix-light" => "light",
    "light" => "light",
    "cupcake" => "light",
    "bumblebee" => "light",
    "emerald" => "light",
    "corporate" => "light",
    "retro" => "light",
    "cyberpunk" => "light",
    "valentine" => "light",
    "garden" => "light",
    "aqua" => "light",
    "lofi" => "light",
    "pastel" => "light",
    "fantasy" => "light",
    "wireframe" => "light",
    "cmyk" => "light",
    "autumn" => "light",
    "acid" => "light",
    "lemonade" => "light",
    "winter" => "light",
    "caramellatte" => "light",
    "silk" => "light",
    "phoenix-dark" => "dark",
    "dark" => "dark",
    "synthwave" => "dark",
    "halloween" => "dark",
    "forest" => "dark",
    "black" => "dark",
    "luxury" => "dark",
    "dracula" => "dark",
    "business" => "dark",
    "night" => "dark",
    "coffee" => "dark",
    "dim" => "dark",
    "nord" => "dark",
    "sunset" => "dark",
    "abyss" => "dark"
  }

  @doc """
  Returns the logical default theme name stored in the user's preferences.
  """
  def default_theme, do: "system"

  @doc """
  Returns the initial theme applied to the `<html>` element on first render.
  """
  def default_html_theme, do: @default_html_theme

  @doc """
  Returns the ordered list of themes displayed in dropdown selectors.

  ## Options

  - `:all` or `nil` - Returns all themes (default), built-in catalogue
    then host `:theme_definitions` names
  - List of theme names - Returns only the specified themes in order

  ## Examples

      # All themes
      dropdown_themes()
      dropdown_themes(:all)

      # Only specific themes
      dropdown_themes(["system", "light", "dark", "nord", "dracula"])
  """
  def dropdown_themes(filter \\ :all)

  def dropdown_themes(:all), do: dropdown_themes(nil)

  def dropdown_themes(nil) do
    # Host-defined names belong in the default catalogue too — :all used
    # to be compile-time @dropdown_order only, so a :theme_definitions
    # theme was in CSS / labels / system_pair but invisible in the
    # picker until the host also listed it in :dashboard_themes.
    host_names =
      host_theme_meta()
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(@labels, &1))
      |> Enum.sort()

    Enum.map(@dropdown_order ++ host_names, &theme_to_map/1)
  end

  def dropdown_themes(allowed_themes) when is_list(allowed_themes) do
    # Filter and preserve order from allowed_themes list
    labels = label_map()
    {known, unknown} = Enum.split_with(allowed_themes, &Map.has_key?(labels, &1))

    # A typo'd name used to vanish without a word — a picker configured with
    # only unknown names rendered EMPTY, and nothing said why. Once per
    # unknown set, not per render: this runs on every mount.
    if unknown != [] and :persistent_term.get({__MODULE__, :warned, unknown}, false) == false do
      :persistent_term.put({__MODULE__, :warned, unknown}, true)

      require Logger

      Logger.warning(
        "[PhoenixKit.ThemeConfig] :dashboard_themes contains unknown theme name(s) " <>
          "#{inspect(unknown)} — they will not appear in the picker. " <>
          "Known names: #{inspect(Map.keys(label_map()))}"
      )
    end

    Enum.map(known, &theme_to_map/1)
  end

  defp theme_to_map(theme) do
    %{
      value: theme,
      label: translated_label(theme),
      preview_theme: Map.get(@preview_themes, theme, theme),
      type: if(theme == "system", do: :system, else: :theme)
    }
  end

  @doc """
  Returns a map of theme names to user-facing labels.
  """
  def label_map do
    Map.merge(@labels, Map.new(host_theme_meta(), fn {n, m} -> {n, m.label} end))
  end

  @doc """
  Returns a map of theme names to their base variant (`"light"` or `"dark"`).
  """
  def base_map do
    Map.merge(@base_map, Map.new(host_theme_meta(), fn {n, m} -> {n, m.base} end))
  end

  @doc """
  The light/dark pair the "system" theme resolves to.

  Derived from `:dashboard_themes` when it is a list: the first configured
  name whose base is light, and the first whose base is dark. Either half
  falls back to the built-in phoenix-* theme, so a host configuring only one
  side still resolves both. With no configuration (`:all`), the built-ins.
  The bootstrap script and every theme-JS block should take the pair from
  here rather than hardcoding phoenix-light/phoenix-dark — hardcoding broke
  system resolution for any host whose pair uses other names.
  """
  def system_pair do
    labels = label_map()
    bases = base_map()

    configured =
      case PhoenixKit.Config.get(:dashboard_themes, :all) do
        list when is_list(list) -> Enum.filter(list, &Map.has_key?(labels, &1))
        _ -> []
      end

    light = Enum.find(configured, &(Map.get(bases, &1) == "light"))
    dark = Enum.find(configured, &(Map.get(bases, &1) == "dark"))

    if configured != [] and (light == nil or dark == nil) do
      warn_half_missing(configured, light, dark)
    end

    {light || "phoenix-light", dark || "phoenix-dark"}
  end

  # A pair half falling back OUTSIDE the configured list means "system" can
  # resolve to a theme the picker never offers — legal, but almost always a
  # config oversight (e.g. two dark themes and no light one). Once per
  # configured set, not per render.
  defp warn_half_missing(configured, light, dark) do
    key = {__MODULE__, :system_pair_warned, configured}

    if :persistent_term.get(key, false) == false do
      :persistent_term.put(key, true)

      missing =
        case {light, dark} do
          {nil, nil} -> "no light or dark theme"
          {nil, _} -> "no light theme"
          {_, nil} -> "no dark theme"
        end

      require Logger

      Logger.warning(
        "[PhoenixKit.ThemeConfig] :dashboard_themes #{inspect(configured)} has " <>
          "#{missing}, so \"system\" will resolve to a built-in phoenix-* theme " <>
          "that is not in the picker. Add one theme of each base to avoid this."
      )
    end
  end

  @doc """
  Returns all theme names recognised by PhoenixKit.
  """
  def all_theme_names do
    Map.keys(label_map())
  end

  @doc """
  Returns the raw custom theme variable map.
  """
  def custom_theme_variables, do: @custom_theme_variables

  @doc """
  Returns the custom PhoenixKit theme definitions as a CSS string.

  Only custom PhoenixKit themes are included here; DaisyUI-built themes are
  shipped with the DaisyUI plugin.
  """
  def custom_theme_css do
    theme_variables()
    |> Enum.map_join("\n\n", fn {theme, vars} ->
      variables =
        Enum.map_join(vars, "\n", fn {name, value} -> "  #{name}: #{value};" end)

      "[data-theme=#{theme}]\n{\n#{variables}\n}"
    end)
  end

  # ---------------------------------------------------------------------------
  # Host theme definitions
  #
  # config :phoenix_kit, theme_definitions: %{
  #   # Merge variables over a built-in theme:
  #   "phoenix-dark" => %{variables: %{"--color-primary" => "oklch(72% 0.14 158)"}},
  #   # Or define a new named theme:
  #   "brand-light" => %{
  #     label: "Brand Light",
  #     base: :light,
  #     extends: "phoenix-light",
  #     variables: %{"--color-primary" => "oklch(48% 0.13 158)"}
  #   }
  # }
  #
  # :extends may name a built-in PhoenixKit palette (phoenix-light /
  # phoenix-dark) only — not a daisyUI catalogue theme and not another
  # host-defined name. Chain off phoenix-* or start from scratch.
  #
  # Until this existed, a branded host rebrand meant duplicating ~50 variable
  # lines in its own CSS and out-specificity-ing the inline block. Everything
  # here is VALIDATED and raises on the first bad entry — the output is
  # HTML.raw'd into a <style> tag, so silent acceptance would be an injection
  # vector, and silent dropping is how the picker's typo bug worked. The
  # merged result keeps the bare [data-theme=X] selectors and no !important,
  # so a host's own stronger selector still wins as an escape hatch.
  # ---------------------------------------------------------------------------

  # \A..\z, not ^..$: $ tolerates one trailing newline, and "brand\n"
  # reaching the single-quoted JS interpolations would break the string —
  # availability, not injection, but real.
  @theme_name_re ~r/\A[a-z0-9][a-z0-9_-]*\z/
  # One CSS value: no statement/block/comment/import machinery, nothing that
  # can close the declaration or the style tag.
  # Backslash is forbidden outright: CSS escape sequences re-read after
  # validation ("u\\72l(" is "url(" to the parser), so any escape can walk
  # around a substring blocklist. No allowed token's value needs one.
  @css_value_re ~r"\A[^;{}<>\\]*\z"
  @allowed_var_prefixes ~w(--color- --radius- --size-)
  @allowed_var_names ~w(--border --depth --noise color-scheme)
  # The full NAME shape, on top of the prefix allowlist: a prefix check alone
  # let "--color-x;}</style>..." through, and the name is interpolated into
  # the declaration just like the value is.
  @var_name_re ~r/\A--[a-z0-9-]+\z/

  @doc """
  The effective per-theme variable maps: built-ins with host
  `:theme_definitions` merged in. Validated once and cached; raises on the
  first invalid entry rather than dropping it.
  """
  def theme_variables do
    definitions = PhoenixKit.Config.get(:theme_definitions, %{})

    case :persistent_term.get({__MODULE__, :theme_variables}, nil) do
      {^definitions, merged} ->
        merged

      _ ->
        merged = build_theme_variables(definitions)
        :persistent_term.put({__MODULE__, :theme_variables}, {definitions, merged})
        merged
    end
  end

  @doc """
  Host-defined themes only: `%{name => %{label, base}}` for the lookups.

  Fully validated — this is the path the JS embeds (`base_map/0`,
  `label_map/0`, `system_pair/0`) read from, so it applies the same rules
  as `theme_variables/0` rather than trusting the raw config. An early
  version read the config directly; a definition the CSS validator would
  have rejected (or crashed on) sailed through here into inline scripts.
  """
  def host_theme_meta do
    definitions = PhoenixKit.Config.get(:theme_definitions, %{})

    case :persistent_term.get({__MODULE__, :host_theme_meta}, nil) do
      {^definitions, meta} ->
        meta

      _ ->
        meta = build_host_theme_meta(definitions)
        :persistent_term.put({__MODULE__, :host_theme_meta}, {definitions, meta})
        meta
    end
  end

  # The single validation pass over :theme_definitions. Everything either
  # raises with the offending entry named or comes out normalized; both
  # theme_variables/0 and the name/label/base lookups build on this, so a
  # definition cannot be acceptable to one consumer and poison for another.
  defp build_host_theme_meta(definitions) when is_map(definitions) do
    Enum.reduce(definitions, %{}, fn {name, defn}, acc ->
      validate_theme_name!(name)

      unless is_map(defn) do
        raise ArgumentError,
              "theme #{inspect(name)}: definition must be a map, got: #{inspect(defn)}"
      end

      # An override of a built-in keeps the built-in's label and base.
      if Map.has_key?(@custom_theme_variables, name) do
        acc
      else
        Map.put(acc, name, %{
          label: new_theme_label!(name, defn),
          base: new_theme_base!(name, defn)
        })
      end
    end)
  end

  defp build_host_theme_meta(other) do
    raise ArgumentError,
          ":theme_definitions must be a map of theme name => definition, got: #{inspect(other)}"
  end

  defp build_theme_variables(definitions) when is_map(definitions) do
    # Validates every entry (names, shapes, labels, bases, extends) before
    # any CSS is assembled.
    meta = build_host_theme_meta(definitions)

    Enum.reduce(definitions, @custom_theme_variables, fn {name, defn}, acc ->
      vars = Map.get(defn, :variables, %{})
      Enum.each(vars, &validate_variable!(name, &1))

      base_vars =
        cond do
          Map.has_key?(@custom_theme_variables, name) ->
            Map.fetch!(acc, name)

          extends = defn[:extends] ->
            # Known-valid via meta; color-scheme follows the theme's own
            # base, which may deliberately differ from the parent's.
            @custom_theme_variables
            |> Map.fetch!(extends)
            |> Map.put("color-scheme", Map.fetch!(meta, name).base)

          true ->
            # A new theme with no parent: base decides the color-scheme, the
            # variables must carry the rest.
            %{"color-scheme" => Map.fetch!(meta, name).base}
        end

      Map.put(acc, name, Map.merge(base_vars, stringify_keys(vars)))
    end)
  end

  defp build_theme_variables(other), do: build_host_theme_meta(other)

  defp validate_theme_name!(name) do
    unless is_binary(name) and Regex.match?(@theme_name_re, name) do
      raise ArgumentError,
            "invalid theme name #{inspect(name)} in :theme_definitions — " <>
              "lowercase letters, digits, - and _ only"
    end
  end

  defp new_theme_label!(name, defn) do
    label = defn[:label]

    unless is_binary(label) and label != "" do
      raise ArgumentError, "new theme #{inspect(name)} needs a :label"
    end

    label
  end

  # Explicit base wins and must be valid even when :extends is present —
  # falling through to inheritance on a junk base would silently ignore it.
  # Without an explicit base, the parent's is inherited. :extends itself is
  # checked whenever given, so an extends-only definition cannot name an
  # unknown parent and then crash a later consumer.
  defp new_theme_base!(name, defn) do
    if extends = defn[:extends] do
      parent_base!(name, extends)
    end

    cond do
      base = defn[:base] ->
        unless base in [:light, :dark, "light", "dark"] do
          raise ArgumentError,
                "new theme #{inspect(name)} needs base: :light or :dark, got: #{inspect(base)}"
        end

        to_string(base)

      extends = defn[:extends] ->
        parent_base!(name, extends)

      true ->
        raise ArgumentError,
              "new theme #{inspect(name)} needs base: :light or :dark (or :extends to inherit it)"
    end
  end

  defp parent_base!(name, extends) do
    case @custom_theme_variables do
      %{^extends => %{"color-scheme" => base}} ->
        base

      _ ->
        raise ArgumentError,
              "theme #{inspect(name)} extends unknown theme #{inspect(extends)}"
    end
  end

  defp validate_variable!(theme, {var_name, value}) do
    var_name = to_string(var_name)

    allowed =
      var_name in @allowed_var_names or
        (Regex.match?(@var_name_re, var_name) and
           Enum.any?(@allowed_var_prefixes, &String.starts_with?(var_name, &1)))

    unless allowed do
      raise ArgumentError,
            "theme #{inspect(theme)}: variable #{inspect(var_name)} is not an " <>
              "allowed theme token (#{inspect(@allowed_var_prefixes)} prefixes " <>
              "or #{inspect(@allowed_var_names)})"
    end

    value = to_string(value)

    safe =
      Regex.match?(@css_value_re, value) and
        not String.contains?(String.downcase(value), ["url(", "@import", "/*", "*/"]) and
        (var_name != "color-scheme" or value in ["light", "dark"])

    unless safe do
      raise ArgumentError,
            "theme #{inspect(theme)}: value #{inspect(value)} for #{inspect(var_name)} " <>
              "is not a single plain CSS value"
    end
  end

  defp stringify_keys(map), do: Map.new(map, fn {k, v} -> {to_string(k), to_string(v)} end)
end
