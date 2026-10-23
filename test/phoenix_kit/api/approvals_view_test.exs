defmodule PhoenixKit.API.Approvals.ViewTest do
  @moduledoc """
  What the approvals page shows of a preview and of a result: the common shape is read
  into a table, everything else is kept for the "Technical details" block.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Approvals.View

  defp price_preview do
    %{
      "rows" => [
        %{
          "ref" => "SKU-1",
          "id" => "0198-aaaa",
          "name" => "Oak shelf",
          "action" => "update",
          "changes" => %{"price" => %{"from" => "10.00", "to" => "12.50"}},
          "warnings" => ["Shopify sync may overwrite this price."]
        }
      ],
      "totals" => %{"rows" => 1, "update" => 1, "unchanged" => 0}
    }
  end

  describe "preview/1 of the common shape" do
    test "reads rows, changes, warnings and totals, and keeps no technical details" do
      view = View.preview(price_preview())

      assert view.count == 1
      assert view.hidden == 0
      assert view.technical == nil
      assert view.summary == [{"unchanged", 0}, {"update", 1}]

      assert [row] = view.rows
      assert row.label == "Oak shelf"
      assert row.sub == "SKU-1"
      assert row.warnings == ["Shopify sync may overwrite this price."]
      assert [%{field: "price", from: "10.00", to: "12.50", pct: "+25.0"}] = row.changes
    end

    test "the label falls back from name to ref to id" do
      rows = [
        %{"ref" => "r-1", "id" => "i-1"},
        %{"id" => "i-2"}
      ]

      view = View.preview(%{"rows" => rows})

      assert [%{label: "r-1", sub: nil}, %{label: "i-2", sub: nil}] = view.rows
      assert view.technical == nil
    end

    test "a row without changes keeps its action and error" do
      view =
        View.preview(%{
          "rows" => [
            %{"ref" => "a", "action" => "unchanged"},
            %{"ref" => "b", "action" => "error", "error" => "price must be a number"}
          ]
        })

      assert [%{action: "unchanged", error: nil}, %{action: "error", error: msg}] = view.rows
      assert msg == "price must be a number"
      assert view.technical == nil
    end

    test "a row error in the shape of the first-party tools is read: code, message, reasons" do
      error = %{
        "code" => "validation_failed",
        "message" => "The row does not pass validation.",
        "context" => %{
          "errors" => [
            %{"path" => "price", "message" => "must be a number"},
            %{"message" => "the row is empty"}
          ]
        }
      }

      view =
        View.preview(%{
          "rows" => [%{"ref" => "a", "action" => "error", "error" => error}]
        })

      assert [
               %{
                 action: "error",
                 error: "The row does not pass validation.",
                 error_code: "validation_failed",
                 error_reasons: ["price: must be a number", "the row is empty"]
               }
             ] = view.rows

      assert view.technical == nil
    end

    test "a row error with an empty context is clean and has no reasons" do
      error = %{
        "code" => "not_found",
        "message" => "The product no longer exists.",
        "context" => %{}
      }

      view = View.preview(%{"rows" => [%{"ref" => "a", "error" => error}]})

      assert [%{error_code: "not_found", error_reasons: []}] = view.rows
      assert view.technical == nil
    end

    test "a row error whose context is not the list of field errors keeps the preview as technical details" do
      for context <- [
            %{"ref" => "SKU-9"},
            %{"candidates" => ["a", "b"]},
            %{"reason" => "timeout"},
            %{"images" => [%{"url" => "x", "reason" => "404"}]},
            %{"errors" => [%{"path" => "price", "message" => "bad"}], "ref" => "SKU-9"},
            %{"errors" => "price is bad"},
            "context"
          ] do
        preview = %{
          "rows" => [
            %{
              "ref" => "a",
              "error" => %{"code" => "x", "message" => "Failed.", "context" => context}
            }
          ]
        }

        view = View.preview(preview)

        assert [%{error: "Failed.", error_reasons: []}] = view.rows
        assert view.technical == preview, inspect(context)
      end
    end

    test "field errors the page cannot read in full keep the preview as technical details" do
      shapes = [
        [%{"path" => "price", "message" => "must be a number", "allowed" => ["a"]}],
        [%{"path" => "price"}],
        [%{"path" => 5, "message" => "bad"}],
        ["price is bad"]
      ]

      for errors <- shapes do
        error = %{"message" => "Failed.", "context" => %{"errors" => errors}}
        preview = %{"rows" => [%{"ref" => "a", "error" => error}]}

        assert View.preview(preview).technical == preview, inspect(errors)
      end
    end

    test "the reasons are bounded: five entries, 160 characters each, and the rest in the technical details" do
      errors = for n <- 1..7, do: %{"path" => "f#{n}", "message" => "bad #{n}"}
      error = %{"message" => "Failed.", "context" => %{"errors" => errors}}
      preview = %{"rows" => [%{"ref" => "a", "error" => error}]}
      view = View.preview(preview)

      assert [%{error_reasons: reasons}] = view.rows
      assert reasons == for(n <- 1..5, do: "f#{n}: bad #{n}")
      assert view.technical == preview

      long = String.duplicate("x", 500)
      error = %{"message" => "Failed.", "context" => %{"errors" => [%{"message" => long}]}}
      preview = %{"rows" => [%{"ref" => "a", "error" => error}]}
      view = View.preview(preview)

      assert [%{error_reasons: [reason]}] = view.rows
      assert String.length(reason) == 160
      assert String.ends_with?(reason, "…")
      assert view.technical == preview
    end

    test "a reason is cut by code points, not graphemes" do
      # One letter and 200000 combining marks is a single grapheme.
      long = "a" <> String.duplicate("\u0301", 200_000)
      error = %{"message" => "Failed.", "context" => %{"errors" => [%{"message" => long}]}}
      preview = %{"rows" => [%{"ref" => "a", "error" => error}]}

      assert [%{error_reasons: [reason]}] = View.preview(preview).rows
      assert length(String.to_charlist(reason)) == 160
      assert String.ends_with?(reason, "…")
    end

    test "message and detail are both shown, the message first" do
      error = %{"message" => "The product could not be saved.", "detail" => "Try again later."}
      view = View.preview(%{"rows" => [%{"ref" => "a", "error" => error}]})

      assert [%{error: "The product could not be saved. Try again later."}] = view.rows
      assert view.technical == nil

      view =
        View.preview(%{"rows" => [%{"ref" => "a", "error" => %{"detail" => "Only detail."}}]})

      assert [%{error: "Only detail."}] = view.rows

      same = %{"message" => "Same.", "detail" => "Same."}
      view = View.preview(%{"rows" => [%{"ref" => "a", "error" => same}]})
      assert [%{error: "Same."}] = view.rows
    end

    test "a message or detail that is not text next to a text one keeps the preview as technical details" do
      errors = [
        %{"message" => "Failed.", "detail" => %{"a" => 1}},
        %{"message" => "Failed.", "detail" => 5},
        %{"message" => ["x"], "detail" => "Why."}
      ]

      for error <- errors do
        preview = %{"rows" => [%{"ref" => "a", "error" => error}]}
        view = View.preview(preview)

        assert [%{error: text}] = view.rows
        assert is_binary(text)
        assert view.technical == preview
      end

      empty = %{"rows" => [%{"ref" => "a", "error" => %{"message" => "Failed.", "detail" => ""}}]}
      assert View.preview(empty).technical == nil
    end

    test "a code that is not text is ignored but the row is not clean" do
      preview = %{"rows" => [%{"ref" => "a", "error" => %{"code" => 42, "message" => "Failed."}}]}
      view = View.preview(preview)

      assert [%{error: "Failed.", error_code: nil}] = view.rows
      assert view.technical == preview
    end

    test "empty strings are no action, no error and no code" do
      preview = %{
        "rows" => [
          %{"ref" => "a", "action" => "", "error" => ""},
          %{"ref" => "b", "error" => %{"code" => "", "message" => "Failed."}}
        ]
      }

      view = View.preview(preview)

      assert [
               %{action: nil, error: nil, error_code: nil},
               %{action: nil, error: "Failed.", error_code: nil}
             ] = view.rows

      assert view.technical == nil
    end

    test "a row error that is plain text has no code" do
      view = View.preview(%{"rows" => [%{"ref" => "a", "error" => "price must be a number"}]})

      assert [%{error: "price must be a number", error_code: nil}] = view.rows
      assert view.technical == nil
    end

    test "a row error map without a message is kept for the technical details" do
      preview = %{"rows" => [%{"ref" => "a", "error" => %{"code" => "boom"}}]}
      view = View.preview(preview)

      assert [%{error: nil, error_code: nil}] = view.rows
      assert view.technical == preview
    end

    test "the row count is the totals' own, else the number of rows" do
      assert View.preview(%{"rows" => [%{"ref" => "a"}], "totals" => %{"rows" => 40}}).count == 40
      assert View.preview(%{"rows" => [%{"ref" => "a"}, %{"ref" => "b"}]}).count == 2
      assert View.preview(%{"totals" => %{"delete" => 1}}).count == nil
    end

    test "at most 25 rows are listed and the rest is counted" do
      rows = for n <- 1..30, do: %{"ref" => "item-#{n}"}
      view = View.preview(%{"rows" => rows})

      assert length(view.rows) == 25
      assert view.hidden == 5
    end

    test "rows left out are counted from the totals when a tool cut its own list" do
      rows = for n <- 1..25, do: %{"ref" => "item-#{n}"}
      view = View.preview(%{"rows" => rows, "totals" => %{"rows" => 300}})

      assert view.count == 300
      assert view.hidden == 275
    end

    test "totals that count fewer rows than are listed still count the rows left out" do
      rows = for n <- 1..30, do: %{"ref" => "item-#{n}"}
      view = View.preview(%{"rows" => rows, "totals" => %{"rows" => 3}})

      assert view.hidden == 5
    end

    test "the catalogue tools' shape is read: summary like totals, requires_confirmation known" do
      preview = %{
        "rows" => [%{"ref" => "SKU-1", "action" => "updated", "id" => "0198-aaaa"}],
        "summary" => %{"updated" => 1},
        "requires_confirmation" => true
      }

      view = View.preview(preview)

      assert view.summary == [{"updated", 1}]
      assert view.count == 1
      assert view.technical == nil
    end

    test "totals win over summary, and both together keep the preview as technical details" do
      preview = %{
        "rows" => [%{"ref" => "a"}],
        "totals" => %{"update" => 1},
        "summary" => %{"updated" => 1}
      }

      view = View.preview(preview)

      assert view.summary == [{"update", 1}]
      assert view.technical == preview
    end

    test "top-level warnings are kept when they are text" do
      view = View.preview(%{"rows" => [%{"ref" => "a"}], "warnings" => ["Slow batch."]})
      assert view.warnings == ["Slow batch."]
      assert view.technical == nil
    end
  end

  describe "preview/1 of anything else" do
    test "an unknown top-level key puts the whole preview in the technical details" do
      preview = Map.put(price_preview(), "largest_price_change_pct", "25.0")
      view = View.preview(preview)

      assert view.technical == preview
      assert [%{label: "Oak shelf"}] = view.rows
    end

    test "a row with keys the table cannot show keeps the preview as technical details" do
      preview = %{"rows" => [%{"ref" => "a", "action" => "delete", "from" => 100}]}
      view = View.preview(preview)

      assert view.technical == preview
      assert [%{label: "a", action: "delete"}] = view.rows
    end

    test "technical details never carry more than the listed rows" do
      rows = for n <- 1..30, do: %{"ref" => "item-#{n}", "extra" => n}
      view = View.preview(%{"rows" => rows})

      assert length(view.technical["rows"]) == 25
      assert view.hidden == 5
    end

    test "changes that are not from/to pairs are not read" do
      preview = %{"rows" => [%{"ref" => "a", "changes" => %{"price" => "12.50"}}]}
      view = View.preview(preview)

      assert view.technical == preview
      assert [%{changes: []}] = view.rows
    end

    test "a row with no name, ref or id cannot be listed" do
      preview = %{"rows" => [%{"action" => "update"}]}
      view = View.preview(preview)

      assert view.rows == []
      assert view.technical == preview
    end

    test "totals that are not plain values stay out of the sentence" do
      preview = %{"totals" => %{"update" => 1, "by_kind" => %{"a" => 1}}}
      view = View.preview(preview)

      assert view.summary == [{"update", 1}]
      assert view.technical == preview
    end

    test "something that is not a map reads as an empty preview" do
      assert View.preview(nil) == View.preview(%{})
      assert View.preview(%{}).technical == nil
      assert View.preview(%{}).rows == []
    end
  end

  describe "delta_pct/2" do
    test "numbers and numeric text" do
      assert View.delta_pct("10.00", "12.50") == "+25.0"
      assert View.delta_pct(100, 90) == "-10.0"
      assert View.delta_pct(10.0, 10.0) == "0.0"
      assert View.delta_pct(" 8 ", "10") == "+25.0"
    end

    test "a change that rounds to nothing is not negative" do
      assert View.delta_pct(100, 99.96) == "0.0"
      assert View.delta_pct("100", "99.96") == "0.0"
      assert View.delta_pct(100, 100.04) == "0.0"
    end

    test "nil when there is nothing to divide or to read" do
      assert View.delta_pct("0.00", "5.00") == nil
      assert View.delta_pct(nil, "5.00") == nil
      assert View.delta_pct("5.00", nil) == nil
      assert View.delta_pct("a lot", "5.00") == nil
      assert View.delta_pct("5.00 EUR", "6.00 EUR") == nil
      assert View.delta_pct(%{"a" => 1}, 2) == nil
    end

    test "nil for a number in exponent notation: its power of ten is never computed" do
      assert View.delta_pct("1e999999999", "1") == nil
      assert View.delta_pct("1", "1E999999999") == nil
      assert View.delta_pct("1e2", "1e3") == nil
      assert View.delta_pct(String.duplicate("9", 31), "1") == nil
    end
  end

  describe "facts/1 of a result" do
    test "the summary map of the result, without zeros" do
      result = %{"results" => [], "summary" => %{"updated" => 2, "unchanged" => 0, "error" => 0}}
      assert View.facts(result) == [{"updated", 2}]
    end

    test "else the plain top-level values" do
      assert View.facts(%{"deleted" => 3, "ids" => ["a"], "note" => "late"}) == [{"deleted", 3}]
    end

    test "nothing to say" do
      assert View.facts(nil) == []
      assert View.facts(%{}) == []
      assert View.facts(%{"rows" => [%{}]}) == []
    end
  end
end
