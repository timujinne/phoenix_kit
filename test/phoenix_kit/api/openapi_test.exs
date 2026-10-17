defmodule PhoenixKit.API.OpenAPITest do
  @moduledoc """
  The OpenAPI document generated from tools. Pure: no database.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.ControlFields
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.OpenAPI
  alias PhoenixKit.API.OutputShape
  alias PhoenixKit.API.Problem
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.ToolLint

  @server "https://shop.test/api/admin/v1"

  defp admin_tool(attrs) do
    Tool.new!(
      Keyword.merge(
        [
          name: "demo.list_things",
          audience: :admin,
          scope: "demo.things:read",
          permission: "dashboard",
          title: "List things",
          description: "Lists the things.",
          input_schema: %{
            "type" => "object",
            "properties" => %{"limit" => %{"type" => "integer", "minimum" => 1}}
          },
          output_schema: %{"type" => "object", "properties" => %{"items" => %{"type" => "array"}}},
          handler: {Kernel, :inspect},
          annotations: %{read_only: true, idempotent: true}
        ],
        attrs
      )
    )
  end

  defp write_tool(attrs \\ []) do
    admin_tool(
      Keyword.merge(
        [
          name: "demo.set_things",
          scope: "demo.things:write",
          title: "Set things",
          description: "Sets the things.",
          input_schema: %{
            "type" => "object",
            "required" => ["items"],
            "properties" => %{"items" => %{"type" => "array", "items" => %{"type" => "object"}}}
          },
          annotations: %{destructive: true}
        ],
        attrs
      )
    )
  end

  defp public_tool do
    Tool.new!(
      name: "shop.search_products",
      audience: :public,
      title: "Search",
      description: "Searches.",
      handler: {Kernel, :inspect},
      annotations: %{read_only: true, idempotent: true}
    )
  end

  defp doc(tools, audience \\ :admin, opts \\ []) do
    OpenAPI.build(
      tools,
      audience,
      Keyword.merge([server_url: @server, title: "Shop admin API"], opts)
    )
  end

  # Every "$ref" of the document, and the thing it points at.
  defp refs(term, acc \\ [])
  defp refs(%{"$ref" => ref}, acc) when is_binary(ref), do: [ref | acc]
  defp refs(%{} = map, acc), do: Enum.reduce(Map.values(map), acc, &refs/2)
  defp refs(list, acc) when is_list(list), do: Enum.reduce(list, acc, &refs/2)
  defp refs(_other, acc), do: acc

  defp resolve(document, "#/" <> pointer), do: get_in(document, String.split(pointer, "/"))

  defp operation(document, tool_name), do: document["paths"]["/" <> tool_name]["post"]

  describe "the document" do
    test "the description says the body is read as JSON and what a held call answers" do
      admin = doc([admin_tool([])], :admin)["info"]["description"]
      public = doc([admin_tool([])], :public)["info"]["description"]

      for text <- [admin, public],
          do: assert(text =~ "always read as JSON, whatever its Content-Type")

      assert admin =~ "HTTP 200"
      assert admin =~ "executed: false"
      assert admin =~ "pending_approval"
      assert admin =~ "still waiting"
      assert admin =~ "same approval_id"
      assert admin =~ "Idempotent-Replayed"
      refute public =~ "pending_approval"
    end

    test "the replay header says a held answer is a replay in the admin document only" do
      tools = [admin_tool([]), write_tool(), public_tool()]
      admin = doc(tools, :admin)["components"]["headers"]["IdempotentReplayed"]["description"]
      public_document = doc(tools, :public)
      public = public_document["components"]["headers"]["IdempotentReplayed"]["description"]

      assert admin =~ "same key"
      assert admin =~ "already waits for approval"
      assert public =~ "same key"
      refute JSON.encode!(public_document["components"]) =~ "pending_approval"
      refute JSON.encode!(public_document["info"]) =~ "pending_approval"
    end

    test "OpenAPI 3.1 with the info, the server and (admin) the bearer security" do
      document = doc([admin_tool([])], :admin, version: "1.2")

      assert document["openapi"] == "3.1.0"
      assert document["info"]["title"] == "Shop admin API"
      assert document["info"]["version"] == "1.2"
      assert is_binary(document["info"]["description"])
      assert document["servers"] == [%{"url" => @server}]
      assert document["security"] == [%{"bearerAuth" => []}]

      assert %{"type" => "http", "scheme" => "bearer", "bearerFormat" => format} =
               document["components"]["securitySchemes"]["bearerAuth"]

      assert format =~ "pk_"
    end

    test "the public document has no security and no 401 or 403" do
      document = doc([public_tool()], :public, title: "Shop API")

      refute Map.has_key?(document, "security")
      refute Map.has_key?(document["components"], "securitySchemes")

      responses = operation(document, "shop.search_products")["responses"]

      assert Map.keys(responses) |> Enum.sort() == [
               "200",
               "400",
               "404",
               "413",
               "422",
               "429",
               "500"
             ]
    end

    test "the version defaults to 1" do
      assert doc([])["info"]["version"] == "1"
    end

    test "is plain JSON that survives a round trip unchanged" do
      document = doc([admin_tool([]), write_tool(), public_tool()])
      assert JSON.decode!(JSON.encode!(document)) == document
    end

    test "no tools: only the discovery path" do
      document = doc([])
      assert Map.keys(document["paths"]) == ["/"]
      assert document["tags"] == [%{"name" => "discovery", "description" => "Which tools exist."}]
    end
  end

  describe "paths and operations" do
    test "every tool is POST /<dotted name>; the discovery list is GET /" do
      document = doc([admin_tool([]), write_tool()])

      assert Map.keys(document["paths"]) |> Enum.sort() == [
               "/",
               "/demo.list_things",
               "/demo.set_things"
             ]

      assert Map.keys(document["paths"]["/demo.list_things"]) == ["post"]
      assert Map.keys(document["paths"]["/"]) == ["get"]
      assert document["paths"]["/"]["get"]["operationId"] == "list_tools"
    end

    test "an operation names the tool, describes it and tags its namespace" do
      op = operation(doc([admin_tool([])]), "demo.list_things")

      assert op["operationId"] == "demo.list_things"
      assert op["summary"] == "List things"
      assert op["description"] == "Lists the things."
      assert op["tags"] == ["demo"]
      assert op["x-required-scope"] == "demo.things:read"
    end

    test "a public tool and a scope-less system tool carry no x-required-scope" do
      system =
        admin_tool(
          name: "system.get_identity",
          scope: nil,
          permission: nil,
          title: "Who",
          description: "Who am I."
        )

      assert operation(doc([system]), "system.get_identity") |> Map.has_key?("x-required-scope") ==
               false

      public = doc([public_tool()], :public)
      refute operation(public, "shop.search_products") |> Map.has_key?("x-required-scope")
    end

    test "operation ids are unique" do
      tools = [admin_tool([]), write_tool(), admin_tool(name: "demo.get_thing")]
      document = doc(tools)

      ids = for {_path, item} <- document["paths"], {_method, op} <- item, do: op["operationId"]
      assert length(ids) == length(Enum.uniq(ids))
    end

    test "tags: discovery first, then the namespaces in order" do
      tools = [
        admin_tool(name: "zeta.read_one"),
        admin_tool(name: "alpha.read_one"),
        admin_tool(name: "alpha.read_two")
      ]

      assert doc(tools)["tags"] |> Enum.map(& &1["name"]) == ["discovery", "alpha", "zeta"]
    end
  end

  describe "x-agent-safety and x-idempotent" do
    test "read, write and destructive" do
      read = admin_tool([])
      write = write_tool(annotations: %{})
      destructive = write_tool(name: "demo.delete_things", annotations: %{destructive: true})

      both =
        write_tool(name: "demo.odd_things", annotations: %{read_only: true, destructive: true})

      document = doc([read, write, destructive, both])

      assert operation(document, "demo.list_things")["x-agent-safety"] == "read"
      assert operation(document, "demo.set_things")["x-agent-safety"] == "write"
      assert operation(document, "demo.delete_things")["x-agent-safety"] == "destructive"
      assert operation(document, "demo.odd_things")["x-agent-safety"] == "read"
    end

    test "idempotent follows the annotation" do
      document =
        doc([
          admin_tool([]),
          write_tool(annotations: %{idempotent: true}),
          write_tool(name: "demo.other_things")
        ])

      assert operation(document, "demo.list_things")["x-idempotent"] == true
      assert operation(document, "demo.set_things")["x-idempotent"] == true
      assert operation(document, "demo.other_things")["x-idempotent"] == false
    end
  end

  describe "request bodies and results" do
    test "the request schema is the closed schema the validator enforces" do
      tool = admin_tool(input_schema: %{"type" => "object", "properties" => %{}})

      schema =
        operation(doc([tool]), "demo.list_things")["requestBody"]["content"]["application/json"][
          "schema"
        ]

      assert schema == Executor.input_schema(tool)
      assert schema["additionalProperties"] == false
    end

    test "a schema without a root type is described as an object, as on MCP" do
      tool = admin_tool(input_schema: %{"properties" => %{"limit" => %{"type" => "integer"}}})
      refute Map.has_key?(tool.input_schema, "type")

      schema =
        operation(doc([tool]), "demo.list_things")["requestBody"]["content"]["application/json"][
          "schema"
        ]

      assert schema["type"] == "object"
      assert schema["additionalProperties"] == false
    end

    test "the body is required only when the schema has required fields" do
      document = doc([admin_tool([]), write_tool()])

      assert operation(document, "demo.list_things")["requestBody"]["required"] == false
      assert operation(document, "demo.set_things")["requestBody"]["required"] == true
    end

    test "the 200 schema is the output shape of MCP: the tool's own for a read, success or preview for a write" do
      read = admin_tool([])
      write = write_tool()
      document = doc([read, write])

      ok = fn name ->
        operation(document, name)["responses"]["200"]["content"]["application/json"]["schema"]
      end

      assert ok.("demo.list_things") == OutputShape.for_tool(read)
      assert ok.("demo.set_things") == OutputShape.for_tool(write)
      assert %{"anyOf" => [_, _]} = ok.("demo.set_things")
    end

    test "a tool without an output schema answers a bare object" do
      document = doc([admin_tool(output_schema: nil)])

      schema =
        operation(document, "demo.list_things")["responses"]["200"]["content"]["application/json"][
          "schema"
        ]

      assert schema == %{"type" => "object"}
    end

    test "every schema in the document passes the lint" do
      document = doc([admin_tool([]), write_tool()])

      for tool <- ["demo.list_things", "demo.set_things"] do
        op = operation(document, tool)

        assert :ok =
                 ToolLint.check_schema(
                   op["requestBody"]["content"]["application/json"]["schema"],
                   :input
                 )

        assert :ok =
                 ToolLint.check_schema(
                   op["responses"]["200"]["content"]["application/json"]["schema"],
                   :output
                 )
      end
    end
  end

  describe "errors" do
    test "an admin operation lists every error status" do
      responses = operation(doc([admin_tool([])]), "demo.list_things")["responses"]

      assert Map.keys(responses) |> Enum.sort() == [
               "200",
               "400",
               "401",
               "403",
               "404",
               "413",
               "422",
               "429",
               "500"
             ]
    end

    test "they are problem+json and reference one Problem schema" do
      document = doc([admin_tool([])])

      for {_name, response} <- document["components"]["responses"] do
        assert %{
                 "application/problem+json" => %{
                   "schema" => %{"$ref" => "#/components/schemas/Problem"}
                 }
               } =
                 response["content"]

        assert is_binary(response["description"])
      end
    end

    test "the Problem schema lists every error code the API can send" do
      codes = doc([])["components"]["schemas"]["Problem"]["properties"]["code"]["enum"]

      assert codes ==
               Problem.statuses() |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort()

      assert doc([])["components"]["schemas"]["Problem"]["required"] == [
               "type",
               "title",
               "status",
               "code",
               "detail"
             ]
    end
  end

  describe "write operations" do
    defp public_write_tool do
      Tool.new!(
        name: "shop.add_line",
        audience: :public,
        title: "Add a line",
        description: "Adds a line.",
        handler: {Kernel, :inspect},
        annotations: %{read_only: false}
      )
    end

    test "list the Idempotency-Key header, the replay header and the 409 conflicts" do
      for {tool, audience} <- [{write_tool(), :admin}, {public_write_tool(), :public}] do
        document = doc([tool], audience)
        operation = operation(document, tool.name)

        assert [parameter] = operation["parameters"]
        assert %{"name" => "Idempotency-Key", "in" => "header", "required" => false} = parameter

        field = ControlFields.properties(tool)["idempotency_key"]
        assert parameter["schema"] == Map.delete(field, "description")

        assert operation["responses"]["200"]["headers"] == %{
                 "Idempotent-Replayed" => %{"$ref" => "#/components/headers/IdempotentReplayed"}
               }

        assert operation["responses"]["409"] == %{"$ref" => "#/components/responses/Conflict"}
        assert %{"description" => _} = document["components"]["headers"]["IdempotentReplayed"]

        assert %{"application/problem+json" => _} =
                 document["components"]["responses"]["Conflict"]["content"]
      end
    end

    test "are not listed on a read operation" do
      read = operation(doc([admin_tool([])]), "demo.list_things")

      refute Map.has_key?(read, "parameters")
      refute Map.has_key?(read["responses"], "409")
      refute Map.has_key?(read["responses"]["200"], "headers")
    end
  end

  describe "references" do
    test "every $ref resolves, in the admin and the public document" do
      for {tools, audience} <- [
            {[admin_tool([]), write_tool()], :admin},
            {[public_tool()], :public}
          ] do
        document = doc(tools, audience)
        found = refs(document)

        assert found != []

        for ref <- Enum.uniq(found),
            do: assert(resolve(document, ref) != nil, "#{ref} does not resolve")
      end
    end

    test "the structure is sound: methods are lowercase, statuses are strings, every operation has a 200" do
      document = doc([admin_tool([]), write_tool(), public_tool()])

      for {path, item} <- document["paths"] do
        assert String.starts_with?(path, "/")

        for {method, op} <- item do
          assert method in ["get", "post"]
          assert Map.has_key?(op["responses"], "200")
          assert Enum.all?(Map.keys(op["responses"]), &Regex.match?(~r/^\d{3}$/, &1))
        end
      end
    end
  end
end
