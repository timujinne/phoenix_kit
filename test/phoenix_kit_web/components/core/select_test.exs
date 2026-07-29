defmodule PhoenixKitWeb.Components.Core.SelectTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.Select

  defp render(template), do: rendered_to_string(template)

  test "a required select marks its label" do
    # Regression: only `<.input>` grew the marker, so converting a
    # hand-rolled required `<select>` (whose markup carried its own red `*`)
    # to `<.select label=...>` silently dropped the marker.
    assigns = %{}

    html =
      render(~H"""
      <.select name="country" value="ee" label="Country" required options={[{"Estonia", "ee"}]} />
      """)

    assert html =~ "text-error"
    assert html =~ ">*<"
  end

  test "an optional select does not mark its label" do
    assigns = %{}

    html =
      render(~H"""
      <.select name="country" value="ee" label="Country" options={[{"Estonia", "ee"}]} />
      """)

    refute html =~ "text-error"
    refute html =~ ">*<"
  end

  test "a select selects the option matching a non-string value" do
    # Callers pass integers (schedule_interval_hours) and atoms
    # (file_type_filter) straight through; options carry string values.
    assigns = %{}

    html =
      render(~H"""
      <.select name="interval" value={24} options={[{"1 hour", "1"}, {"24 hours", "24"}]} />
      """)

    assert html =~ ~s(<option selected value="24">)
    refute html =~ ~s(<option selected value="1">)
  end
end
