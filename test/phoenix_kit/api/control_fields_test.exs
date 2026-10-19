defmodule PhoenixKit.API.ControlFieldsTest do
  @moduledoc """
  `PhoenixKit.API.ControlFields`: which tools get the executor-added fields, the
  schema of each, and how a request body is split into control fields and input.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.ControlFields
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.Validator

  defp tool(annotations) do
    Tool.new!(
      name: "testkit.some_tool",
      audience: :admin,
      scope: "testkit.items:write",
      permission: "settings",
      title: "t",
      description: "d",
      input_schema: %{"type" => "object", "properties" => %{"name" => %{"type" => "string"}}},
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, :noop},
      annotations: annotations
    )
  end

  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}
  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}

  def noop(_input, _ctx), do: {:ok, %{}}

  test "names are the three control fields" do
    assert ControlFields.names() == ["dry_run", "confirm_token", "idempotency_key"]
  end

  test "a write tool is one that is not read-only, a read tool is not" do
    assert ControlFields.write_tool?(tool(@write))
    refute ControlFields.write_tool?(tool(@read))
  end

  test "a write tool that cannot replay gets no idempotency_key" do
    no_replay = %{tool(@write) | replay: false}

    assert ControlFields.properties(no_replay) |> Map.keys() |> Enum.sort() ==
             ["confirm_token", "dry_run"]

    assert ControlFields.replay_tool?(tool(@write))
    refute ControlFields.replay_tool?(no_replay)
    refute ControlFields.replay_tool?(tool(@read))
  end

  test "a write tool gets the three properties, a read tool none" do
    assert ControlFields.properties(tool(@write)) |> Map.keys() |> Enum.sort() ==
             ["confirm_token", "dry_run", "idempotency_key"]

    assert ControlFields.properties(tool(@read)) == %{}
  end

  describe "the closed schema a write tool is validated against" do
    defp schema(tool),
      do: Validator.close_schema(tool.input_schema, ControlFields.properties(tool))

    test "accepts the three fields in their shapes" do
      body = %{
        "name" => "x",
        "dry_run" => true,
        "confirm_token" => "ct_abc",
        "idempotency_key" => "0123456789abcdef"
      }

      assert {:ok, ^body} = Validator.validate(schema(tool(@write)), body)
    end

    test "dry_run must be a boolean: the string \"false\" is refused, not read as true" do
      for bad <- ["false", "true", 0, 1, nil] do
        assert {:error, [%{path: "dry_run"}]} =
                 Validator.validate(schema(tool(@write)), %{"dry_run" => bad}),
               inspect(bad)
      end
    end

    test "an idempotency key is 16 to 128 characters of letters, digits, underscore and hyphen" do
      ok = [String.duplicate("a", 16), String.duplicate("Z", 128), "abc_DEF-123_456-789"]

      bad = [
        String.duplicate("a", 15),
        String.duplicate("a", 129),
        "has space 0123456789",
        "semi;colon-0123456789",
        "ünï-0123456789abcdef",
        "",
        "0123456789abcdef\n",
        "\n0123456789abcdef",
        "0123456789abcdef\r\n"
      ]

      for key <- ok,
          do:
            assert(
              {:ok, _} = Validator.validate(schema(tool(@write)), %{"idempotency_key" => key}),
              key
            )

      for key <- bad do
        assert {:error, [%{path: "idempotency_key"} | _]} =
                 Validator.validate(schema(tool(@write)), %{"idempotency_key" => key}),
               inspect(key)
      end
    end

    test "a confirm_token is a non-empty string of at most 200 characters" do
      assert {:ok, _} = Validator.validate(schema(tool(@write)), %{"confirm_token" => "ct_x"})
      assert {:error, _} = Validator.validate(schema(tool(@write)), %{"confirm_token" => ""})

      assert {:error, _} =
               Validator.validate(schema(tool(@write)), %{
                 "confirm_token" => String.duplicate("a", 201)
               })

      assert {:error, _} = Validator.validate(schema(tool(@write)), %{"confirm_token" => 5})
    end

    test "a read tool refuses all three" do
      read = tool(@read)

      for name <- ControlFields.names() do
        assert {:error, [%{path: path}]} =
                 Validator.validate(
                   Validator.close_schema(read.input_schema, ControlFields.properties(read)),
                   %{name => "x"}
                 )

        assert path =~ name
      end
    end
  end

  describe "split/1" do
    test "separates the control fields from the input" do
      body = %{"name" => "x", "dry_run" => true, "idempotency_key" => "0123456789abcdef"}

      assert {%{"dry_run" => true, "idempotency_key" => "0123456789abcdef"}, %{"name" => "x"}} =
               ControlFields.split(body)
    end

    test "a body without control fields splits into an empty map and itself" do
      assert {%{}, %{"name" => "x"}} = ControlFields.split(%{"name" => "x"})
    end

    test "only the three names are control fields" do
      assert {%{}, %{"dry_run_extra" => 1, "token" => "t"}} =
               ControlFields.split(%{"dry_run_extra" => 1, "token" => "t"})
    end
  end
end
