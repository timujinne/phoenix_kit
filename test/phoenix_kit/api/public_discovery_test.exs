defmodule PhoenixKit.API.PublicDiscoveryTest do
  @moduledoc """
  The pure parts of `PhoenixKit.API.PublicDiscovery` and its guide builder: the
  URLs, the API catalog, the llms.txt section, the page language, the snippet
  name and the guide's content. The request-level behaviour (the gate, hosts,
  headers) is in `PhoenixKitWeb.APIDiscoveryTest`.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.PublicDiscovery
  alias PhoenixKit.API.PublicDiscovery.Guide
  alias PhoenixKit.API.PublicDiscovery.GuideHTML
  alias PhoenixKit.API.PublicDiscovery.GuideMarkdown
  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.LlmsTxt
  alias PhoenixKit.Test.DiscoveryTools
  alias PhoenixKit.Utils.Routes

  @origin "https://shop.test"

  setup do
    KeyTestSupport.start_cache_registry!()

    start_supervised!(
      Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
    )

    :ok
  end

  describe "URLs" do
    test "the API and the guide follow the URL prefix; llms.txt and the catalog do not" do
      prefix = Routes.prefix_base()

      assert PublicDiscovery.guide_url(@origin) == "#{@origin}#{prefix}/mcp"
      assert PublicDiscovery.mcp_url(@origin) == "#{@origin}#{prefix}/mcp/public"
      assert PublicDiscovery.api_url(@origin) == "#{@origin}#{prefix}/api/public/v1"

      assert PublicDiscovery.openapi_url(@origin) ==
               "#{@origin}#{prefix}/api/public/v1/openapi.json"

      assert PublicDiscovery.llms_url(@origin) == "#{@origin}/llms.txt"
      assert PublicDiscovery.catalog_url(@origin) == "#{@origin}/.well-known/api-catalog"
    end

    test "no locale segment is ever added" do
      for url <- [
            PublicDiscovery.guide_url(@origin),
            PublicDiscovery.mcp_url(@origin),
            PublicDiscovery.api_url(@origin)
          ] do
        refute url =~ ~r{/(en|de|fr)/}
      end
    end
  end

  describe "put_link/2" do
    @catalog ~s(<https://shop.test/.well-known/api-catalog>; rel="api-catalog")
    @doc_link ~s(<https://shop.test/mcp>; rel="service-doc")

    defp link_headers(conn), do: Plug.Conn.get_resp_header(conn, "link")

    test "appends to what an earlier plug set, in one header" do
      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_resp_header("link", @catalog)
        |> PublicDiscovery.put_link(@doc_link)

      assert link_headers(conn) == ["#{@catalog}, #{@doc_link}"]
    end

    test "a value already present is not repeated" do
      conn =
        Plug.Test.conn(:get, "/")
        |> PublicDiscovery.put_link(@catalog)
        |> PublicDiscovery.put_link(@doc_link)
        |> PublicDiscovery.put_link(@catalog)
        |> PublicDiscovery.put_link(@doc_link)

      assert link_headers(conn) == ["#{@catalog}, #{@doc_link}"]
    end

    test "a value set by an earlier plug is not repeated either" do
      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_resp_header("link", "#{@catalog}, #{@doc_link}")
        |> PublicDiscovery.put_link(@doc_link)

      assert link_headers(conn) == ["#{@catalog}, #{@doc_link}"]
    end

    test "a blank earlier header leaves no leading comma" do
      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_resp_header("link", " ")
        |> PublicDiscovery.put_link(@catalog)

      assert link_headers(conn) == [@catalog]
    end
  end

  describe "the llms.txt section" do
    test "is three links under a heading, ending with a newline" do
      section = PublicDiscovery.llms_section(@origin)
      prefix = Routes.prefix_base()

      assert section == """
             ## Public API and MCP

             - [How to connect](#{@origin}#{prefix}/mcp): MCP server and REST API, no key needed
             - [MCP server](#{@origin}#{prefix}/mcp/public): Streamable HTTP
             - [OpenAPI](#{@origin}#{prefix}/api/public/v1/openapi.json)
             """
    end

    test "LlmsTxt.build/1 appends it after the operator's text; build/0 and build_for/2 are unchanged" do
      put_setting("project_title", "Acme Print")
      section = PublicDiscovery.llms_section(@origin)

      assert LlmsTxt.build() == "# Acme Print\n"
      assert LlmsTxt.build(api_section: nil) == "# Acme Print\n"
      assert LlmsTxt.build(api_section: "") == "# Acme Print\n"
      assert LlmsTxt.build(api_section: section) == "# Acme Print\n\n" <> section

      Crawlers.update_llms_txt_extra("> About us.")
      assert LlmsTxt.build() == "# Acme Print\n\n> About us.\n"
      assert LlmsTxt.build(api_section: section) == "# Acme Print\n\n> About us.\n\n" <> section

      assert LlmsTxt.build_for("Acme Print", "> About us.") == "# Acme Print\n\n> About us.\n"
    end
  end

  describe "language/1" do
    test "a catalogue locale is itself; a dialect is its base; anything else is English" do
      assert PublicDiscovery.language(%{language: "de"}) == "de"
      assert PublicDiscovery.language(%{language: "es-ES"}) == "es"
      assert PublicDiscovery.language(%{language: "pt_BR"}) == "en"
      assert PublicDiscovery.language(%{language: "zz"}) == "en"
      assert PublicDiscovery.language(%{language: "en-US"}) == "en"
      assert PublicDiscovery.language(%{language: "UK"}) == "uk"
      assert PublicDiscovery.language(%{language: ""}) == "en"
    end
  end

  describe "Guide.build/4" do
    defp build(language \\ "en", project \\ "Acme Print") do
      tools = [
        DiscoveryTools.public_tool("zzdisc.z_last", title: "Last"),
        DiscoveryTools.public_tool("zzdisc.a_first", title: "First", danger: :always)
      ]

      Guide.build(@origin, language, tools, project)
    end

    defp blocks(guide, id) do
      Enum.find(guide.sections, &(&1.id == id)).blocks
    end

    test "has the five sections in order and the language and origin it was built for" do
      guide = build("de")

      assert Enum.map(guide.sections, & &1.id) == ["mcp", "rest", "tools", "answers", "links"]
      assert guide.language == "de"
      assert guide.origin == @origin
    end

    test "the title is the project title, or 'This site' when it is blank" do
      assert build("en", "Acme Print").title == "Acme Print — public API and MCP server"

      for blank <- [nil, "", "   "] do
        guide = build("en", blank)
        assert guide.title == "This site — public API and MCP server"
        assert [_, _, {:code, _, _, command} | _] = blocks(guide, "mcp")
        assert command =~ "claude mcp add --transport http site "
      end

      assert build("de", "").title == "Diese Website — öffentliche API und MCP-Server"
    end

    test "the client snippets name the server by the slug of the project title" do
      for {project, name} <- [{"Acme Print", "acme-print"}, {"Декор для дома", "dekor-dlya-doma"}] do
        assert [_, _, {:code, _, _, command} | _] = blocks(build("en", project), "mcp")
        assert command =~ "claude mcp add --transport http #{name} "
      end
    end

    test "tools are sorted by name, whatever order they come in" do
      names = for {:tool, tool} <- blocks(build(), "tools"), do: tool.rest_name
      assert names == ["zzdisc.a_first", "zzdisc.z_last"]
    end

    test "a tool block has both names, the declared text and the confirmation note only with a danger" do
      [{:tool, first}, {:tool, last}] = blocks(build(), "tools")

      assert %{title: "First", mcp_name: "zzdisc_a_first", rest_name: "zzdisc.a_first"} = first
      assert first.note == "May ask for confirmation first."
      assert last.note == nil
      assert last.description == "An extra public tool."
    end

    test "a single quote in the URL cannot end the shell quoting" do
      guide =
        Guide.build(
          "https://shop.test'; id #",
          "en",
          [DiscoveryTools.public_tool("zzdisc.x")],
          "Shop"
        )

      markdown = GuideMarkdown.render(guide)

      assert markdown =~ "'https://shop.test'\\''; id #/"
      refute markdown =~ "'https://shop.test'; id"
    end

    test "both renderers lay out the same content" do
      guide = build()
      markdown = GuideMarkdown.render(guide)
      html = GuideHTML.render(guide)

      for text <- ["zzdisc.a_first", "zzdisc_z_last", "Connect with REST", "How answers work"] do
        assert markdown =~ text
        assert html =~ text
      end

      assert String.starts_with?(markdown, "# ")
      assert String.starts_with?(html, "<!doctype html>")
      refute html =~ "<script"
      refute html =~ ~r/<link[^>]*rel="stylesheet"/
      refute html =~ ~r/(src|href)="https?:\/\/(?!shop\.test)/
    end
  end
end
