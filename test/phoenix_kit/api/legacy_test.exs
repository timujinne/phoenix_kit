defmodule PhoenixKit.API.LegacyTest do
  @moduledoc """
  `PhoenixKit.API.Legacy`, the one module that holds the names the public API
  had before it was made module-neutral. It is deleted in 3.0.0; so is this
  file.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Legacy
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.ToolLint

  describe "the deprecated paths" do
    test "are the REST and MCP paths the public API had" do
      assert Legacy.alias_paths() == [["api", "shop", "v1"], ["mcp", "shop"]]
    end
  end

  describe "the Deprecation header" do
    test "is the RFC 9745 timestamp of 2026-10-20T00:00:00Z" do
      assert Legacy.deprecation() == "@1792454400"
      assert Legacy.deprecation() == "@#{DateTime.to_unix(~U[2026-10-20 00:00:00Z])}"
    end
  end

  describe "legacy_client_token/1" do
    @schema %{
      "type" => "object",
      "properties" => %{"cart_token" => %{"type" => "string"}},
      "additionalProperties" => false
    }

    defp tool!(attrs) do
      Tool.new!([name: "demo.act", handler: {Kernel, :inspect}] ++ attrs)
    end

    test "is cart_token for a public tool that declares none and has that property" do
      assert Legacy.legacy_client_token(tool!(audience: :public, input_schema: @schema)) ==
               "cart_token"
    end

    test "reads an input schema keyed by atoms too" do
      schema = %{type: "object", properties: %{cart_token: %{type: "string"}}}

      assert Legacy.legacy_client_token(tool!(audience: :public, input_schema: schema)) ==
               "cart_token"
    end

    test "is nil when the tool declares a client token itself" do
      schema = put_in(@schema, ["properties", "session_token"], %{"type" => "string"})

      tool = tool!(audience: :public, input_schema: schema, client_token: "session_token")

      assert Legacy.legacy_client_token(tool) == nil
    end

    test "is nil without the property, and for an admin tool" do
      assert Legacy.legacy_client_token(tool!(audience: :public)) == nil

      admin =
        tool!(
          audience: :admin,
          scope: "demo.things:write",
          permission: "dashboard",
          input_schema: @schema
        )

      assert Legacy.legacy_client_token(admin) == nil
    end
  end

  describe "ToolLint on a public tool built before Tool.client_token" do
    # A struct literal, as an older module may still build it: a danger, a required
    # `cart_token` input and no `client_token:`. The executor reads its client token
    # from `cart_token`, so the lint has to accept it the same way.
    defp danger_tool(required) do
      struct!(Tool,
        name: "demo.act",
        audience: :public,
        title: "Act",
        description: "Acts.",
        handler: {Kernel, :inspect},
        danger: :always,
        input_schema: %{
          "type" => "object",
          "required" => required,
          "properties" => %{"cart_token" => %{"type" => "string"}},
          "additionalProperties" => false
        },
        output_schema: nil,
        annotations: %{read_only: false, destructive: false, idempotent: false, open_world: false}
      )
    end

    test "passes when cart_token is required, as the executor reads it" do
      assert :ok = ToolLint.check_tool(danger_tool(["cart_token"]))
      assert :ok = ToolLint.check_tools([danger_tool(["cart_token"])])
    end

    test "still asks for cart_token in required" do
      assert {:error, [message]} = ToolLint.check_tool(danger_tool([]))
      assert message =~ "must list cart_token in required"
    end
  end

  describe "the credential names of the old checkout links" do
    test "are claim_url, checkout_url and claim_token, and the claim link marker" do
      assert Enum.sort(Legacy.credential_keys()) == ~w(checkout_url claim_token claim_url)
      assert Legacy.credential_markers() == ["/checkout/claim/"]
    end
  end
end
