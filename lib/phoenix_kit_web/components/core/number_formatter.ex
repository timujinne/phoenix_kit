defmodule PhoenixKitWeb.Components.Core.NumberFormatter do
  @moduledoc """
  Number formatting components for PhoenixKit.

  Provides components for displaying numbers with proper formatting including
  thousand separators, abbreviations, and custom formatting options.
  """

  use Phoenix.Component

  @doc """
  Displays a formatted number with thousand separators.

  ## Attributes
  - `number` - The number to format (required, integer or float)
  - `format` - Format style (default: :grouped)
    - `:grouped` - Add comma separators (1,234,567)
    - `:short` - Abbreviate large numbers (1.2M, 3.5K)
  - `decimals` - Decimal places to keep. Required to format a float at all —
    see below.
  - `class` - Additional CSS classes

  ## Floats

  Both formats used to guard on `is_integer/1`, so a float fell through to
  `to_string/1` and `1234.5` rendered as `"1234.5"` — ungrouped, in a component
  whose entire job is grouping.

  Passing `decimals:` now rounds and groups the whole part:

      <.formatted_number number={1234.5} decimals={2} />   # 1,234.50

  ⚠️ Without `decimals:` a float still renders as before. Grouping floats by
  default would silently change output for every existing float caller, which is
  a behaviour change rather than a fix — so it is opt-in.

  ## Examples

      <.formatted_number number={1234567} />
      # Renders: 1,234,567

      <.formatted_number number={1234567} format={:short} />
      # Renders: 1.2M

      <.formatted_number number={1234.5} decimals={2} />
      # Renders: 1,234.50

      <.formatted_number number={0} />
      # Renders: 0
  """
  attr :number, :any, required: true
  attr :format, :atom, default: :grouped, values: [:grouped, :short]

  attr :decimals, :integer,
    default: nil,
    doc: "Decimal places. Opt-in for floats; omitting it preserves existing output."

  attr :class, :string, default: ""

  def formatted_number(assigns) do
    formatted = format_number_value(assigns.number, assigns.format, assigns[:decimals])

    assigns = assign(assigns, :formatted, formatted)

    ~H"""
    <span class={@class}>{@formatted}</span>
    """
  end

  # Private helper functions

  # A float with an explicit precision: round, then group the whole part and
  # reattach the fraction. Guarded on `decimals` so an existing float caller,
  # which passes none, keeps the output it has today.
  defp format_number_value(number, format, decimals)
       when is_float(number) and is_integer(decimals) do
    rounded = Float.round(number, decimals)

    case format do
      :short ->
        format_number_value(trunc(rounded), :short, nil)

      _ ->
        [whole, fraction] =
          rounded
          |> :erlang.float_to_binary(decimals: decimals)
          |> String.split(".", parts: 2)

        group_digits(whole) <> "." <> fraction
    end
  end

  defp format_number_value(number, format, _decimals),
    do: format_number_value(number, format)

  # Format number with thousand separators
  defp format_number_value(number, :grouped) when is_integer(number) do
    group_digits(to_string(number))
  end

  # Format number with abbreviations (K, M, B)
  defp format_number_value(number, :short) when is_integer(number) do
    cond do
      number >= 1_000_000_000 ->
        "#{Float.round(number / 1_000_000_000, 1)}B"

      number >= 1_000_000 ->
        "#{Float.round(number / 1_000_000, 1)}M"

      number >= 1_000 ->
        "#{Float.round(number / 1_000, 1)}K"

      true ->
        to_string(number)
    end
  end

  # Fallback for non-integers
  defp format_number_value(number, _format), do: to_string(number)

  # Comma-groups a digit string, preserving a leading minus sign — grouping
  # "-1234" from the right would otherwise produce "-,123,4".
  defp group_digits("-" <> digits), do: "-" <> group_digits(digits)

  defp group_digits(digits) do
    digits
    |> String.graphemes()
    |> Enum.reverse()
    |> Enum.chunk_every(3)
    |> Enum.map(&Enum.reverse/1)
    |> Enum.reverse()
    |> Enum.map_join(",", &Enum.join/1)
  end
end
