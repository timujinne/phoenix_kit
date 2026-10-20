defmodule PhoenixKit.API.ValidatorArrayTest do
  @moduledoc """
  `PhoenixKit.API.Validator`: `minItems`, `maxItems` and `items`, and that no
  keyword constrains a value of another kind.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Validator

  defp errors(schema, input) do
    assert {:error, errors} = Validator.validate(schema, input)
    errors
  end

  defp paths(errors), do: Enum.map(errors, & &1.path)

  describe "minItems, maxItems and items" do
    @list %{"type" => "array", "minItems" => 1, "maxItems" => 3, "items" => %{"type" => "string"}}

    test "a list over maxItems is refused without looking at its elements" do
      # Elements that would each fail `items` are not reported: only the size error is, so
      # the cost of a refusal does not grow with the list.
      schema = %{"type" => "array", "maxItems" => 2, "items" => %{"type" => "string"}}

      assert [%{message: "must have at most 2 items", path: path}] =
               errors(schema, [1, 2, 3])

      assert path == ""
    end

    test "accept a list within the bounds" do
      assert {:ok, ["a"]} = Validator.validate(@list, ["a"])
      assert {:ok, ["a", "b", "c"]} = Validator.validate(@list, ["a", "b", "c"])
    end

    test "report the bound that was broken" do
      assert [%{message: "must have at least 1 item", limit: 1}] = errors(@list, [])

      assert [%{message: "must have at most 3 items", limit: 3}] =
               errors(@list, ["a", "b", "c", "d"])

      assert [%{message: "must have at least 2 items", limit: 2}] =
               errors(%{"minItems" => 2}, ["a"])
    end

    test "validate each element and report its index" do
      assert paths(errors(@list, ["a", 2, 4])) == ["[1]", "[2]"]
    end

    test "arrays of objects report items[2].quantity style paths" do
      schema = %{
        "type" => "object",
        "required" => ["items"],
        "properties" => %{
          "items" => %{
            "type" => "array",
            "items" => %{
              "type" => "object",
              "required" => ["sku", "quantity"],
              "properties" => %{
                "sku" => %{"type" => "string"},
                "quantity" => %{"type" => "integer", "minimum" => 1}
              },
              "additionalProperties" => false
            }
          }
        }
      }

      input = %{
        "items" => [
          %{"sku" => "A", "quantity" => 1},
          %{"sku" => "B", "quantity" => 2},
          %{"sku" => "C", "quantity" => 0},
          %{"quantity" => 5, "color" => "red"}
        ]
      }

      errors = errors(schema, input)

      assert Enum.map(errors, &{&1.path, &1.message}) == [
               {"items[2].quantity", "must be at least 1"},
               {"items[3].sku", "is required"},
               {"items[3].color", "is not allowed"}
             ]

      assert hd(errors).limit == 1
    end

    test "an array input reports bare indexes" do
      assert [%{path: "[0].a", message: "is required"}] =
               errors(
                 %{"type" => "array", "items" => %{"type" => "object", "required" => ["a"]}},
                 [%{}]
               )
    end

    test "an enum on the items is enforced, with the allowed list, like an enum on a scalar" do
      fields = %{
        "type" => "array",
        "items" => %{"type" => "string", "enum" => ["id", "title", "price"]}
      }

      schema = %{"type" => "object", "properties" => %{"fields" => fields}}

      assert {:ok, %{"fields" => ["id", "price"]}} =
               Validator.validate(schema, %{"fields" => ["id", "price"]})

      assert [
               %{
                 path: "fields[1]",
                 message: "must be one of: id, title, price",
                 allowed: ["id", "title", "price"]
               }
             ] = errors(schema, %{"fields" => ["id", "nope", "title"]})
    end

    test "an enum on the items of an array inside an array of objects reports the full path" do
      schema = %{
        "type" => "object",
        "properties" => %{
          "queries" => %{
            "type" => "array",
            "items" => %{
              "type" => "object",
              "properties" => %{
                "fields" => %{"type" => "array", "items" => %{"enum" => ["id", "title"]}}
              }
            }
          }
        }
      }

      assert [%{path: "queries[1].fields[0]", allowed: ["id", "title"]}] =
               errors(schema, %{"queries" => [%{"fields" => ["id"]}, %{"fields" => ["nope"]}]})
    end

    test "a missing items schema leaves elements unchecked" do
      assert {:ok, [1, "a", nil]} = Validator.validate(%{"type" => "array"}, [1, "a", nil])
    end

    test "integral floats inside arrays are converted" do
      schema = %{"type" => "array", "items" => %{"type" => "integer"}}

      assert {:ok, [1, 2, 3]} = Validator.validate(schema, [1.0, 2, 3.0])
      assert [%{path: "[1]"}] = errors(schema, [1, 2.5])
    end
  end

  describe "a hostile array is cheap (the error list is capped at 100)" do
    test "20 000 wrong elements give 100 errors, the first 100 by index" do
      schema = %{"type" => "array", "items" => %{"type" => "string"}}

      assert {:error, errors} = Validator.validate(schema, List.duplicate(1, 20_000))
      assert length(errors) == 100
      assert paths(errors) == Enum.map(0..99, &"[#{&1}]")
    end

    test "the walk stops at the cap: an element after the 100th error is never looked at" do
      # Element 100 has the property "x", whose schema has an unsupported type: it
      # raises if the element is ever visited, so a walk that does not halt fails here.
      schema = %{
        "type" => "array",
        "items" => %{
          "type" => "object",
          "properties" => %{"x" => %{"type" => "never-visited"}},
          "additionalProperties" => false
        }
      }

      input = List.duplicate(%{"a" => 1}, 100) ++ [%{"x" => 1}]

      assert {:error, errors} = Validator.validate(schema, input)
      assert length(errors) == 100
      assert paths(errors) == Enum.map(0..99, &"[#{&1}].a")

      # control: below the cap the same element is visited
      assert_raise ArgumentError, ~r/unsupported JSON Schema type/, fn ->
        Validator.validate(schema, List.duplicate(%{"a" => 1}, 99) ++ [%{"x" => 1}])
      end
    end

    test "the cap holds for the whole result, across the objects of an array" do
      schema = %{
        "type" => "array",
        "items" => %{"type" => "object", "additionalProperties" => false}
      }

      input = List.duplicate(%{"a" => 1, "b" => 2, "c" => 3}, 1_000)

      assert {:error, errors} = Validator.validate(schema, input)
      assert length(errors) == 100
      assert hd(errors).path == "[0].a"
    end
  end

  describe "keywords of other kinds" do
    test "a keyword only constrains the kind of value it is about" do
      strings = %{"minLength" => 5, "maxLength" => 6, "pattern" => "^z"}
      numbers = %{"minimum" => 5, "maximum" => 6}
      arrays = %{"minItems" => 5, "maxItems" => 6, "items" => %{"type" => "string"}}
      objects = %{"required" => ["a"], "additionalProperties" => false}

      assert {:ok, 1} = Validator.validate(strings, 1)
      assert {:ok, "a"} = Validator.validate(Map.merge(numbers, arrays), "a")
      assert {:ok, [1]} = Validator.validate(Map.merge(strings, numbers), [1])

      assert {:ok, true} =
               Validator.validate(
                 Map.merge(strings, Map.merge(numbers, Map.merge(arrays, objects))),
                 true
               )

      assert {:ok, nil} =
               Validator.validate(
                 Map.merge(strings, Map.merge(numbers, Map.merge(arrays, objects))),
                 nil
               )
    end
  end
end
