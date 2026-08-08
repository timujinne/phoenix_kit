defmodule PhoenixKitWeb.Components.Core.NumberFormatterTest do
  @moduledoc """
  Both formats guarded on `is_integer/1`, so a float fell through to
  `to_string/1` — `1234.5` rendered as `"1234.5"`, ungrouped, from a component
  whose entire job is grouping.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias PhoenixKitWeb.Components.Core.NumberFormatter

  defp render_number(assigns) do
    render_component(&NumberFormatter.formatted_number/1, assigns)
  end

  describe "integers" do
    test "group with commas" do
      assert render_number(%{number: 1_234_567}) =~ "1,234,567"
    end

    test "a negative number keeps its sign in the right place" do
      # Grouping "-1234" from the right would produce "-,123,4".
      assert render_number(%{number: -1234}) =~ "-1,234"
    end

    test "short form abbreviates" do
      assert render_number(%{number: 1_234_567, format: :short}) =~ "1.2M"
    end

    test "zero renders as zero" do
      assert render_number(%{number: 0}) =~ ">0<"
    end
  end

  describe "floats" do
    test "with decimals, the whole part groups and the fraction is kept" do
      assert render_number(%{number: 1234.5, decimals: 2}) =~ "1,234.50"
    end

    test "rounds to the requested precision" do
      assert render_number(%{number: 1234.567, decimals: 1}) =~ "1,234.6"
    end

    test "a negative float keeps its sign" do
      assert render_number(%{number: -1234.5, decimals: 1}) =~ "-1,234.5"
    end

    test "short form still abbreviates" do
      assert render_number(%{number: 1_234_567.89, decimals: 1, format: :short}) =~ "1.2M"
    end

    test "WITHOUT decimals, output is unchanged from before" do
      # Grouping floats by default would silently change what every existing
      # float caller renders — a behaviour change, not a fix. Opt-in only.
      assert render_number(%{number: 1234.5}) =~ "1234.5"
    end
  end
end
