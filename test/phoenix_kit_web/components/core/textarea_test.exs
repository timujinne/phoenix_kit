defmodule PhoenixKitWeb.Components.Core.TextareaTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.Textarea

  defp render(template), do: rendered_to_string(template)

  defp field(errors) do
    %Phoenix.HTML.FormField{
      id: "note_content",
      name: "note[content]",
      errors: errors,
      field: :content,
      form: nil,
      value: ""
    }
  end

  test "a field-bound textarea renders the field's errors" do
    # Regression: the field clause used to map name/value/id but NOT
    # field.errors, so a failing changeset rendered no message and no
    # `textarea-error` — the form just looked like it refused to save.
    assigns = %{field: field([{"can't be blank", []}])}

    html =
      render(~H"""
      <.textarea field={@field} label="Note" />
      """)

    assert html =~ "textarea-error"
    assert html =~ "can&#39;t be blank"
  end

  test "a field-bound textarea with no errors stays clean" do
    assigns = %{field: field([])}

    html =
      render(~H"""
      <.textarea field={@field} label="Note" />
      """)

    refute html =~ "textarea-error"
  end

  test "a required textarea marks its label" do
    assigns = %{}

    html =
      render(~H"""
      <.textarea name="note" value="" label="Note" required />
      """)

    assert html =~ "text-error"
    assert html =~ ">*<"
  end

  test "an optional textarea does not mark its label" do
    assigns = %{}

    html =
      render(~H"""
      <.textarea name="note" value="" label="Note" />
      """)

    refute html =~ "text-error"
    refute html =~ ">*<"
  end
end
