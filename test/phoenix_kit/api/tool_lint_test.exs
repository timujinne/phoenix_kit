defmodule PhoenixKit.API.ToolLintTest do
  @moduledoc """
  `PhoenixKit.API.ToolLint`: schema checks for tools. Pure, no database.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.ToolLint
  alias PhoenixKit.API.Validator

  # A struct literal, not Tool.new!: Tool.new refuses the keywords some
  # of these fixtures carry on purpose, and the lint has to be
  # tested on a tool that got past it some other way.
  defp tool(attrs) do
    struct!(
      Tool,
      Keyword.merge(
        [
          name: "demo.list_things",
          audience: :admin,
          scope: "demo.things:read",
          permission: "dashboard",
          title: "List things",
          description: "Lists the things.",
          handler: {Kernel, :inspect},
          input_schema: %{
            "type" => "object",
            "properties" => %{},
            "additionalProperties" => false
          },
          output_schema: nil,
          annotations: %{
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false
          }
        ],
        attrs
      )
    )
  end

  defp errors(schema, kind) do
    assert {:error, messages} = ToolLint.check_schema(schema, kind)
    messages
  end

  describe "check_schema/2: a clean schema" do
    test "the subset the validator enforces passes" do
      schema = %{
        "type" => "object",
        "required" => ["limit"],
        "properties" => %{
          "limit" => %{"type" => "integer", "minimum" => 1, "maximum" => 100},
          "name" => %{
            "type" => "string",
            "minLength" => 1,
            "maxLength" => 80,
            "pattern" => "^[a-z]+$"
          },
          "kind" => %{"type" => "string", "enum" => ["a", "b"], "description" => "Kind."},
          "items" => %{
            "type" => "array",
            "minItems" => 1,
            "maxItems" => 5,
            "items" => %{"type" => "object", "properties" => %{"id" => %{"type" => "string"}}}
          },
          "either" => %{"type" => ["string", "null"]}
        },
        "additionalProperties" => false
      }

      assert :ok = ToolLint.check_schema(schema, :input)
      assert :ok = ToolLint.check_schema(schema, :output)
    end

    test "atom keys are read like string keys" do
      assert :ok =
               ToolLint.check_schema(
                 %{type: "object", properties: %{a: %{type: "string"}}},
                 :input
               )
    end

    # Tool.new accepts an atom type and atom required names (the validator
    # reads them with to_string), and they encode to the same JSON.
    test "atom values of type and required are read like strings" do
      schema = %{
        "type" => :object,
        "required" => [:a],
        "properties" => %{"a" => %{"type" => :string}, "b" => %{"type" => [:string, :null]}}
      }

      assert :ok = ToolLint.check_schema(schema, :input)
      assert :ok = ToolLint.check_tool(tool(input_schema: schema))

      assert [m] = errors(%{"required" => [:ghost], "properties" => %{"a" => %{}}}, :input)
      assert m =~ "required [\"ghost\"] is not declared"

      assert [m] = errors(%{"required" => [nil]}, :input)
      assert m =~ "required must be a list of unique strings"
    end

    test "true and false are schemas" do
      assert :ok =
               ToolLint.check_schema(
                 %{"type" => "object", "properties" => %{"a" => true, "b" => false}},
                 :input
               )
    end
  end

  describe "check_schema/2: broken schemas" do
    test "an unknown or non-string type" do
      assert [m] = errors(%{"type" => "int"}, :input)
      assert m =~ "unknown type"
      assert [m] = errors(%{"type" => 5}, :input)
      assert m =~ "type must be"
      assert [m] = errors(%{"type" => nil}, :input)
      assert m =~ "type must be"
      assert [m] = errors(%{"type" => [:string, "string"]}, :input)
      assert m =~ "unique"
      assert [m] = errors(%{"type" => ["string", "string"]}, :input)
      assert m =~ "unique"
    end

    test "required in draft-3 style or not a list of strings" do
      assert [m] =
               errors(
                 %{
                   "type" => "object",
                   "properties" => %{"a" => %{"type" => "string", "required" => true}}
                 },
                 :input
               )

      assert m =~ "properties.a: required must be a list"

      assert [m] = errors(%{"required" => ["a", "a"], "properties" => %{"a" => %{}}}, :input)
      assert m =~ "unique"
    end

    test "a required name that is not declared, in a closed object" do
      assert [m] =
               errors(
                 %{"type" => "object", "required" => ["ghost"], "properties" => %{"a" => %{}}},
                 :input
               )

      assert m =~ "(root): required [\"ghost\"] is not declared in properties"

      # The root of an input schema counts as closed; an output root and an open nested object do not.
      assert :ok = ToolLint.check_schema(%{"type" => "object", "required" => ["ghost"]}, :output)

      nested = %{
        "type" => "object",
        "properties" => %{"o" => %{"type" => "object", "required" => ["x"]}}
      }

      assert :ok = ToolLint.check_schema(nested, :input)

      closed_nested = put_in(nested, ["properties", "o", "additionalProperties"], false)
      assert [m] = errors(closed_nested, :input)
      assert m =~ "properties.o: required"
    end

    test "numbers and counts" do
      assert [m] = errors(%{"minimum" => "1"}, :input)
      assert m =~ "minimum must be a number"

      assert [m] = errors(%{"minimum" => 5, "maximum" => 1}, :input)
      assert m =~ "minimum is greater than maximum"

      assert [m] = errors(%{"minLength" => -1}, :input)
      assert m =~ "minLength must be a non-negative integer"

      assert [m] = errors(%{"minItems" => 3, "maxItems" => 2}, :input)
      assert m =~ "minItems is greater than maxItems"

      assert [m] = errors(%{"maxLength" => 1.5}, :input)
      assert m =~ "maxLength must be a non-negative integer"
    end

    test "minLength above maxLength" do
      assert [m] = errors(%{"minLength" => 3, "maxLength" => 2}, :input)
      assert m =~ "minLength is greater than maxLength"
    end

    test "a pattern is compiled the way the validator compiles it" do
      # Unicode ranges are valid for the validator ([:unicode, :dollar_endonly]).
      assert :ok = ToolLint.check_schema(%{"pattern" => "^[\\x{0400}-\\x{04FF}]+$"}, :input)
      assert :ok = ToolLint.check_schema(%{"pattern" => "\\N{U+0400}"}, :input)

      # \C (a single byte) is refused in UTF mode, which the validator uses.
      assert [m] = errors(%{"pattern" => "(?<=\\C)a"}, :input)
      assert m =~ "not a valid regular expression"
    end

    test "pattern, enum and texts" do
      assert [m] = errors(%{"pattern" => "("}, :input)
      assert m =~ "not a valid regular expression"
      assert [m] = errors(%{"pattern" => 5}, :input)
      assert m =~ "pattern must be a string"
      assert [m] = errors(%{"enum" => []}, :input)
      assert m =~ "enum must be a non-empty list"
      assert [m] = errors(%{"description" => 5}, :input)
      assert m =~ "description must be a string"
      assert [m] = errors(%{"title" => nil}, :input)
      assert m =~ "title must be a string"
    end

    test "a sub-schema that is not a schema" do
      assert [m] = errors(%{"properties" => %{"a" => "string"}}, :input)
      assert m =~ "properties.a: a schema must be an object or a boolean"

      assert [m] = errors(%{"properties" => []}, :input)
      assert m =~ "properties must be an object"

      assert [m] = errors(%{"items" => [%{"type" => "string"}]}, :input)
      assert m =~ "items must be a single schema"

      assert [m] = errors(%{"additionalProperties" => "no"}, :input)
      assert m =~ "additionalProperties must be a boolean or a schema"
    end

    test "items may be a boolean schema, additionalProperties may be a schema that is walked" do
      assert :ok = ToolLint.check_schema(%{"items" => true}, :input)
      assert :ok = ToolLint.check_schema(%{"items" => false}, :input)

      assert [m] = errors(%{"additionalProperties" => %{"minimum" => "1"}}, :input)
      assert m =~ "additionalProperties: minimum must be a number"

      assert [m] =
               errors(
                 %{"properties" => %{"a" => %{"additionalProperties" => %{"type" => "int"}}}},
                 :input
               )

      assert m =~ "properties.a.additionalProperties: unknown type"
    end

    test "a schema key that is neither a string nor an atom is reported, not a crash" do
      assert [m] = errors(%{{:a, 1} => 1}, :input)
      assert m =~ "(root): schema keys must be strings or atoms, got {:a, 1}"

      assert [m] = errors(%{"properties" => %{"a" => %{1 => "x"}}}, :input)
      assert m =~ "properties.a: schema keys must be strings or atoms, got 1"
    end

    test "errors deep inside items and properties carry their path" do
      schema = %{
        "properties" => %{
          "rows" => %{
            "type" => "array",
            "items" => %{"properties" => %{"qty" => %{"minimum" => "1"}}}
          }
        }
      }

      assert [m] = errors(schema, :input)
      assert m =~ "properties.rows.items.properties.qty: minimum must be a number"
    end

    test "every problem is reported, not only the first" do
      assert [_, _, _] = errors(%{"type" => "int", "minimum" => "x", "enum" => []}, :input)
    end
  end

  describe "check_schema/2: keywords the validator does not enforce" do
    test "are errors in an input schema" do
      for keyword <-
            ~w(oneOf anyOf allOf not const if patternProperties minProperties uniqueItems exclusiveMinimum multipleOf) do
        schema = %{"properties" => %{"a" => %{keyword => []}}}
        messages = errors(schema, :input)

        assert Enum.any?(messages, &(&1 =~ "keyword #{inspect(keyword)} is not enforced")),
               "#{keyword} was not flagged: #{inspect(messages)}"
      end
    end

    # The rule is a whitelist. This list is written out by hand,
    # NOT taken from the implementation: a test that iterates the module's own
    # list cannot find a keyword the module forgot.
    test "any keyword outside the supported subset is an error, including ones nobody listed" do
      for keyword <-
            ~w(nullable dependencies unevaluatedProperties unevaluatedItems additionalItems minContains maxContains
               contentEncoding contentMediaType contentSchema $anchor $dynamicRef frobnicate) do
        messages = errors(%{"properties" => %{"a" => %{keyword => true}}}, :input)

        assert Enum.any?(messages, &(&1 =~ "keyword #{inspect(keyword)} is not enforced")),
               "#{keyword} was not flagged: #{inspect(messages)}"
      end
    end

    test "every keyword of the supported subset and every annotation passes at the root and in a property" do
      supported = [
        {"type", "string"},
        {"enum", ["a"]},
        {"minimum", 1},
        {"maximum", 2},
        {"minLength", 1},
        {"maxLength", 2},
        {"minItems", 1},
        {"maxItems", 2},
        {"pattern", "^a$"},
        {"title", "T"},
        {"description", "D"},
        {"default", "a"},
        {"examples", ["a"]},
        {"format", "uuid"},
        {"example", "a"},
        {"deprecated", true},
        {"readOnly", true},
        {"writeOnly", true},
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"$id", "urn:demo"},
        {"$comment", "c"},
        {"x-vendor", true}
      ]

      for {keyword, value} <- supported do
        assert :ok = ToolLint.check_schema(%{keyword => value}, :input), keyword

        assert :ok =
                 ToolLint.check_schema(%{"properties" => %{"a" => %{keyword => value}}}, :input),
               keyword
      end
    end

    test "a property or an enum value that is named like a keyword is not a keyword" do
      schema = %{
        "type" => "object",
        "properties" => %{
          "oneOf" => %{"type" => "string", "enum" => ["const", "not"]},
          "nullable" => %{"type" => "boolean"}
        }
      }

      assert :ok = ToolLint.check_schema(schema, :input)
    end

    test "are fine in an output schema" do
      schema = %{
        "type" => "object",
        "anyOf" => [
          %{"type" => "object"},
          %{"type" => "object", "properties" => %{"a" => %{"const" => 1}}}
        ]
      }

      assert :ok = ToolLint.check_schema(schema, :output)
    end

    test "a combinator is still walked, so a mistake inside it is found" do
      schema = %{"anyOf" => [%{"type" => "int"}]}
      messages = errors(schema, :output)
      assert Enum.any?(messages, &(&1 =~ "anyOf[0]: unknown type"))

      assert [m] = errors(%{"oneOf" => []}, :output)
      assert m =~ "oneOf must be a non-empty list of schemas"
    end

    test "$ref, $defs and definitions are errors in both" do
      for kind <- [:input, :output], keyword <- ["$ref", "$defs", "definitions"] do
        assert [m] = errors(%{keyword => %{}}, kind)
        assert m =~ "keyword #{inspect(keyword)} is not supported"
      end
    end

    test "a vendor extension is x- followed by anything; near misses are keywords" do
      assert :ok = ToolLint.check_schema(%{"x-" => 1, "x-a-b" => 1}, :input)

      for keyword <- ["xvendor", "x_vendor", "X-Vendor"] do
        messages = errors(%{keyword => true}, :input)

        assert Enum.any?(messages, &(&1 =~ "keyword #{inspect(keyword)} is not enforced")),
               "#{keyword} was not flagged: #{inspect(messages)}"
      end
    end

    test "a combinator in an input schema is flagged and still walked" do
      messages = errors(%{"properties" => %{"a" => %{"oneOf" => [%{"type" => "int"}]}}}, :input)
      assert Enum.any?(messages, &(&1 =~ ~s(properties.a: keyword "oneOf" is not enforced)))
      assert Enum.any?(messages, &(&1 =~ "properties.a.oneOf[0]: unknown type"))
    end

    test "annotations the validator ignores are allowed" do
      schema = %{
        "type" => "string",
        "format" => "uuid",
        "default" => "x",
        "examples" => ["y"],
        "title" => "T",
        "description" => "D"
      }

      assert :ok = ToolLint.check_schema(schema, :input)
    end
  end

  # Tool.new runs Validator.check_schema/2 on every tool, so for the keywords
  # both modules read, a schema one accepts the other must accept. The cases are
  # written out by hand; a rule only one side has (a unique type list, a minimum
  # above a maximum, a required name that is not declared, an empty enum) is not
  # in this table.
  describe "agreement with PhoenixKit.API.Validator.check_schema/2" do
    @cases [
      %{"type" => "string"},
      %{"type" => :string},
      %{"type" => ["string", :null]},
      %{"type" => "int"},
      %{"type" => 5},
      %{"type" => []},
      %{"type" => nil},
      %{"enum" => ["a"]},
      %{"enum" => "a"},
      %{"required" => ["a"], "properties" => %{"a" => %{}}},
      %{"required" => [:a], "properties" => %{"a" => %{}}},
      %{"required" => [nil]},
      %{"required" => [1]},
      %{"required" => true},
      %{"properties" => %{"a" => %{"type" => "string"}}},
      %{"properties" => %{"a" => "string"}},
      %{"properties" => "x"},
      %{"additionalProperties" => false},
      %{"additionalProperties" => %{"minimum" => "x"}},
      %{"additionalProperties" => "x"},
      %{"items" => true},
      %{"items" => %{"minLength" => -1}},
      %{"items" => [%{"type" => "string"}]},
      %{"minimum" => 1.5},
      %{"minimum" => "1"},
      %{"maximum" => nil},
      %{"minLength" => 0},
      %{"minLength" => -1},
      %{"maxLength" => 1.5},
      %{"minItems" => 2},
      %{"maxItems" => "2"},
      %{"pattern" => "^a$"},
      %{"pattern" => "^[\\x{0400}-\\x{04FF}]+$"},
      %{"pattern" => "\\N{U+0400}"},
      %{"pattern" => "(?<=\\C)a"},
      %{"pattern" => "("},
      %{"pattern" => 5},
      %{"title" => "T"},
      %{"description" => "D"},
      %{"default" => 1},
      %{"examples" => [1]},
      %{"example" => 1},
      %{"format" => "uuid"},
      %{"deprecated" => true},
      %{"readOnly" => true},
      %{"writeOnly" => true},
      %{"$schema" => "s"},
      %{"$id" => "i"},
      %{"$comment" => "c"},
      %{"x-vendor" => 1},
      %{"xvendor" => 1},
      %{"X-Vendor" => 1},
      %{"$ref" => "#/x"},
      %{"$defs" => %{}},
      %{"definitions" => %{}},
      %{"oneOf" => []},
      %{"anyOf" => []},
      %{"allOf" => []},
      %{"not" => %{}},
      %{"const" => 1},
      %{"nullable" => true},
      %{"uniqueItems" => true},
      %{"multipleOf" => 2},
      %{"exclusiveMinimum" => 1},
      %{"patternProperties" => %{}},
      %{"minProperties" => 1},
      %{"dependencies" => %{}},
      %{"if" => %{}}
    ]

    test "an input schema passes the lint exactly when the validator accepts it" do
      for schema <- @cases do
        lint = ToolLint.check_schema(schema, :input) == :ok
        validator = Validator.check_schema(schema) == :ok

        assert lint == validator,
               "lint #{lint}, validator #{validator} for #{inspect(schema)}"
      end
    end
  end

  describe "check_tool/1" do
    test "a good tool passes, with and without an output schema" do
      assert :ok = ToolLint.check_tool(tool([]))

      assert :ok =
               ToolLint.check_tool(
                 tool(
                   output_schema: %{
                     "type" => "object",
                     "properties" => %{"a" => %{"type" => "string"}}
                   }
                 )
               )
    end

    test "the roots must be objects" do
      assert {:error, [m]} = ToolLint.check_tool(tool(input_schema: %{"type" => "array"}))
      assert m =~ ~s(input_schema: the root type must be "object")

      assert {:error, [m]} = ToolLint.check_tool(tool(input_schema: %{"properties" => %{}}))
      assert m =~ ~s(input_schema: the root must declare type "object")

      assert {:error, [m]} = ToolLint.check_tool(tool(output_schema: %{"type" => "string"}))
      assert m =~ ~s(output_schema: the root type must be "object")
    end

    test "schema errors are prefixed with the schema they belong to" do
      assert {:error, messages} =
               ToolLint.check_tool(
                 tool(
                   input_schema: %{"type" => "object", "properties" => %{"a" => %{"oneOf" => []}}},
                   output_schema: %{
                     "type" => "object",
                     "properties" => %{"b" => %{"type" => "int"}}
                   }
                 )
               )

      assert Enum.any?(messages, &String.starts_with?(&1, "input_schema: properties.a: "))
      assert Enum.any?(messages, &String.starts_with?(&1, "output_schema: properties.b: "))
    end

    test "an empty description is an error: an agent chooses tools by it" do
      assert {:error, [m]} = ToolLint.check_tool(tool(description: ""))
      assert m =~ "description is empty"

      assert {:error, [m]} = ToolLint.check_tool(tool(description: nil))
      assert m =~ "description is empty"
    end

    test "a root that is not a schema object is an error, not a crash" do
      assert {:error, [m]} = ToolLint.check_tool(tool(input_schema: "x"))
      assert m =~ "input_schema: (root): a schema must be an object or a boolean"

      assert {:error, [m]} = ToolLint.check_tool(tool(input_schema: true))
      assert m =~ "input_schema: the root must be an object schema, not a boolean"

      assert {:error, [m]} = ToolLint.check_tool(tool(output_schema: false))
      assert m =~ "output_schema: the root must be an object schema, not a boolean"
    end

    test "an atom root type is read like a string" do
      assert :ok = ToolLint.check_tool(tool(input_schema: %{type: :object, properties: %{}}))
    end

    test "a public tool with a danger must declare a client token and list it in required" do
      schema = fn required ->
        %{
          "type" => "object",
          "required" => required,
          "properties" => %{
            "session_token" => %{"type" => "string"},
            "other" => %{"type" => "string"}
          },
          "additionalProperties" => false
        }
      end

      public = fn danger, required ->
        tool(
          audience: :public,
          scope: nil,
          danger: danger,
          client_token: "session_token",
          input_schema: schema.(required)
        )
      end

      for danger <- [:always, {Kernel, :inspect}] do
        assert {:error, [m]} = ToolLint.check_tool(public.(danger, []))
        assert m =~ "must list session_token in required"

        assert {:error, [_]} = ToolLint.check_tool(public.(danger, ["other"]))
        assert :ok = ToolLint.check_tool(public.(danger, ["session_token"]))
        assert :ok = ToolLint.check_tool(public.(danger, [:session_token]))
      end
    end

    test "a public tool with a danger and no client_token is an error that says to declare one" do
      undeclared =
        tool(
          audience: :public,
          scope: nil,
          danger: :always,
          input_schema: %{
            "type" => "object",
            "required" => ["session_token"],
            "properties" => %{"session_token" => %{"type" => "string"}},
            "additionalProperties" => false
          }
        )

      assert {:error, [m]} = ToolLint.check_tool(undeclared)
      assert m =~ "must declare a client_token and list it in required"

      assert {:error, [_]} =
               ToolLint.check_tool(tool(audience: :public, scope: nil, danger: :always))
    end

    test "a public tool without a danger, and an admin tool with one, need no client token" do
      assert :ok = ToolLint.check_tool(tool(audience: :public, scope: nil, danger: nil))
      assert :ok = ToolLint.check_tool(tool(danger: :always))
    end

    test "a client_token must be a string property of the input schema" do
      schema = fn property ->
        %{
          "type" => "object",
          "properties" => %{"session_token" => property},
          "additionalProperties" => false
        }
      end

      public = fn property, field ->
        tool(
          audience: :public,
          scope: nil,
          client_token: field,
          input_schema: schema.(property)
        )
      end

      assert :ok = ToolLint.check_tool(public.(%{"type" => "string"}, "session_token"))

      assert {:error, [m]} = ToolLint.check_tool(public.(%{"type" => "integer"}, "session_token"))
      assert m =~ ~s(client_token "session_token" must be a property of type string)

      assert {:error, [m]} = ToolLint.check_tool(public.(%{"type" => "string"}, "other"))
      assert m =~ ~s(client_token "other" must be a property of the input schema)
    end

    test "an admin tool with a client_token is an error" do
      admin =
        tool(
          client_token: "session_token",
          input_schema: %{
            "type" => "object",
            "properties" => %{"session_token" => %{"type" => "string"}},
            "additionalProperties" => false
          }
        )

      assert {:error, [m]} = ToolLint.check_tool(admin)
      assert m =~ "an admin tool may not declare a client_token"
    end
  end

  describe "check_tools/1" do
    test "a clean set passes" do
      assert :ok = ToolLint.check_tools([tool([]), tool(name: "demo.get_thing")])
    end

    test "errors are prefixed with the tool name" do
      assert {:error, [m]} = ToolLint.check_tools([tool(description: "")])
      assert String.starts_with?(m, "demo.list_things: ")
    end

    test "two tools whose MCP names collide" do
      tools = [tool(name: "a.b_c"), tool(name: "a_b.c")]
      assert {:error, [m]} = ToolLint.check_tools(tools)
      assert m =~ "a.b_c, a_b.c share the MCP name a_b_c"
    end

    test "colliding names are listed sorted, whatever the declaration order" do
      tools = [tool(name: "a_b.c"), tool(name: "a.b_c")]
      assert {:error, [m]} = ToolLint.check_tools(tools)
      assert m =~ "a.b_c, a_b.c share the MCP name a_b_c"
    end

    test "a duplicate and a collision in one group are both reported" do
      tools = [tool(name: "a.b_c"), tool(name: "a.b_c"), tool(name: "a_b.c")]
      assert {:error, messages} = ToolLint.check_tools(tools)
      assert Enum.any?(messages, &(&1 =~ "a.b_c is declared twice"))
      assert Enum.any?(messages, &(&1 =~ "a.b_c, a_b.c share the MCP name a_b_c"))
    end

    test "a name that is not a string is reported, not a crash" do
      assert {:error, messages} = ToolLint.check_tools([tool(name: {:x, 1}, description: "")])
      assert Enum.any?(messages, &String.starts_with?(&1, "{:x, 1}: "))
    end

    test "the same name declared twice in one audience" do
      assert {:error, [m]} = ToolLint.check_tools([tool([]), tool([])])
      assert m =~ "demo.list_things is declared twice"
    end

    test "the same name in the two audiences is fine: they are separate endpoints" do
      public = tool(audience: :public, scope: nil, permission: nil)
      assert :ok = ToolLint.check_tools([tool([]), public])
    end
  end
end
