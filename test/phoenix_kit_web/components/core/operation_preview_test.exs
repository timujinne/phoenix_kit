defmodule PhoenixKitWeb.Components.Core.OperationPreviewTest do
  @moduledoc """
  `<.operation_preview>`: the preview of an operation that waits for a person, outside the
  approvals queue. It reads the common preview shape into totals, warnings and the table of
  changes, keeps what does not fit under "Technical details", says when rows are cut, and
  shows every value as text.
  """
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.OperationPreview

  defp render(preview, extra \\ %{}) do
    assigns = Map.merge(%{preview: preview, tool: nil}, extra)

    ~H"""
    <.operation_preview id="op" preview={@preview} tool={@tool} />
    """
    |> rendered_to_string()
    |> LazyHTML.from_fragment()
  end

  defp text(document, selector),
    do: document |> LazyHTML.query(selector) |> LazyHTML.text() |> String.trim()

  defp present?(document, selector), do: LazyHTML.query(document, selector) |> Enum.any?()

  @preview %{
    "rows" => [
      %{
        "ref" => "SKU-1",
        "name" => "Oak shelf",
        "action" => "update",
        "changes" => %{"price" => %{"from" => "10.00", "to" => "12.50"}},
        "warnings" => ["Below cost"]
      }
    ],
    "totals" => %{"rows" => 1, "update" => 1},
    "warnings" => ["One row changes"]
  }

  test "the common shape is a sentence of totals, the warnings and a table of changes" do
    doc = render(@preview)

    assert text(doc, "#op-totals") == "Summary: updated 1."
    assert text(doc, "#op") =~ "One row changes"

    assert present?(doc, "#op-rows")
    assert text(doc, "#op-row-0") =~ "Oak shelf"
    assert text(doc, "#op-row-0") =~ "Below cost"
    assert text(doc, "#op-row-0-action") == "update"

    cells =
      doc |> LazyHTML.query("#op-rows tbody td") |> Enum.map(&String.trim(LazyHTML.text(&1)))

    assert "price" in cells
    assert "10.00" in cells
    assert "12.50" in cells

    refute present?(doc, "#op-technical")
    refute present?(doc, "#op-truncated")
  end

  test "what does not fit the shape is kept whole under the technical details, with the tool" do
    doc = render(%{"plan" => %{"steps" => 3}}, %{tool: "notes.set_note"})

    assert present?(doc, "#op-technical")
    assert text(doc, "#op-technical") =~ "notes.set_note"
    assert text(doc, "#op-technical") =~ ~s("steps": 3)
    refute present?(doc, "#op-rows")
  end

  test "a long preview says that rows are not shown and that confirming runs them all" do
    rows =
      for n <- 1..30,
          do: %{"ref" => "r#{n}", "changes" => %{"qty" => %{"from" => n, "to" => n + 1}}}

    doc = render(%{"rows" => rows})

    assert text(doc, "#op-truncated") =~ "5 rows are not shown"
    assert text(doc, "#op-truncated") =~ "Confirming runs the whole operation"
  end

  test "values are text: markup and links in a preview are not rendered" do
    doc =
      render(%{
        "rows" => [
          %{
            "ref" => "<b>bold</b>",
            "changes" => %{
              "note" => %{"from" => nil, "to" => "<a href=\"https://evil.example\">click</a>"}
            }
          }
        ],
        "warnings" => ["<script>alert(1)</script>"]
      })

    refute present?(doc, "#op b")
    refute present?(doc, "#op a")
    refute present?(doc, "#op script")
    assert text(doc, "#op") =~ "<a href=\"https://evil.example\">click</a>"
    assert text(doc, "#op") =~ "<script>alert(1)</script>"
  end

  test "an empty preview draws only the heading" do
    doc = render(%{})

    assert text(doc, "#op") == "What would change"
  end

  describe "the helpers the approvals page shares" do
    test "sentence/1 says the counts in words" do
      assert sentence([{"rows", 3}, {"update", 2}, {"requires_confirmation", true}]) ==
               "rows 3, updated 2, requires confirmation"
    end

    test "show/1 gives text for every value" do
      assert show(nil) == "—"
      assert show("x") == "x"
      assert show(1.5) == "1.5"
      assert show(%{"a" => 1}) == ~s({"a":1})
    end
  end
end
