defmodule PhoenixKit.API.PublicDiscovery.Guide do
  @moduledoc """
  The content of the public guide (`GET /mcp`) as data: a title, links and a
  list of sections, each a list of blocks. The two renderers
  (`PhoenixKit.API.PublicDiscovery.GuideHTML`, `PhoenixKit.API.PublicDiscovery.GuideMarkdown`)
  only lay it out, so the words are chosen, and translated, here.

  The headings and the fixed sentences go through gettext, in the page's
  language. What a module declared stays as declared (English): tool titles
  and descriptions. So do the command lines and the JSON of the snippets.

  A block is one of:

    * `{:p, text}`;
    * `{:list, [text]}`;
    * `{:facts, [{label, value}]}` - a label and a value shown as code;
    * `{:code, label, language, text}` - a labelled code block;
    * `{:links, [{label, url}]}`;
    * `{:tool, map}` - one tool: `:title`, `:description`, `:rest_label`,
      `:rest_name`, `:mcp_label`, `:mcp_name` and `:note` (`nil` or a sentence).
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.API.ClientName
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.MCP.Names
  alias PhoenixKit.API.PublicDiscovery
  alias PhoenixKit.API.Tool
  alias PhoenixKit.Modules.Crawlers

  @doc """
  The guide for the `origin` it names, written in `language` (a locale the
  gettext backend has), for the public `tools` of the site called `project`
  (its project title).
  """
  @spec build(String.t(), String.t(), [Tool.t()], String.t() | nil) :: map()
  def build(origin, language, tools, project)
      when is_binary(origin) and is_list(tools) do
    Gettext.with_locale(PhoenixKitWeb.Gettext, language, fn ->
      tools = Enum.sort_by(tools, & &1.name)
      urls = urls(origin)

      %{
        language: language,
        origin: origin,
        title: gettext("%{title} — public API and MCP server", title: display_title(project)),
        sections: [
          mcp_section(urls, ClientName.slug(project)),
          rest_section(urls, tools),
          tools_section(tools),
          answers_section(),
          links_section(urls)
        ]
      }
    end)
  end

  defp display_title(project) do
    case String.trim(project || "") do
      "" -> gettext("This site")
      title -> title
    end
  end

  defp urls(origin) do
    %{
      mcp: PublicDiscovery.mcp_url(origin),
      api: PublicDiscovery.api_url(origin),
      openapi: PublicDiscovery.openapi_url(origin),
      guide: PublicDiscovery.guide_url(origin),
      llms: PublicDiscovery.llms_url(origin),
      catalog: PublicDiscovery.catalog_url(origin)
    }
  end

  # --- sections -----------------------------------------------------------------

  defp mcp_section(urls, name) do
    %{
      id: "mcp",
      heading: gettext("Connect with MCP"),
      blocks: [
        {:p, gettext("The MCP server speaks Streamable HTTP and needs no API key.")},
        {:facts, [{gettext("Server URL"), urls.mcp}]},
        {:code, "Claude Code", "sh",
         "claude mcp add --transport http #{name} #{shell_quote(urls.mcp)}"},
        {:p,
         gettext(
           "Claude on the desktop and on the web: add a custom connector with the server URL above. The connection is made from Anthropic's servers, so this site must be reachable from the internet."
         )},
        {:code, "Cursor, .cursor/mcp.json", "json",
         JSON.encode!(%{"mcpServers" => %{name => %{"url" => urls.mcp}}})},
        {:code, "VS Code, .vscode/mcp.json", "json",
         JSON.encode!(%{"servers" => %{name => %{"type" => "http", "url" => urls.mcp}}})},
        {:p, gettext("Any other client: use the server URL above as a Streamable HTTP endpoint.")}
      ]
    }
  end

  defp rest_section(urls, tools) do
    %{
      id: "rest",
      heading: gettext("Connect with REST"),
      blocks:
        [
          {:facts,
           [
             {gettext("Base URL"), urls.api},
             {gettext("List the tools"), "GET " <> urls.api},
             {gettext("OpenAPI description"), "GET " <> urls.openapi},
             {gettext("Call a tool with a JSON object as the body"), "POST #{urls.api}/<tool>"}
           ]}
        ] ++ example(urls, tools)
    }
  end

  # The first read-only tool, by name, that needs no input.
  defp example(urls, tools) do
    case Enum.find(tools, &no_input_read?/1) do
      nil ->
        []

      %Tool{name: name} ->
        [
          {:code, gettext("Example"), "sh",
           "curl -X POST #{shell_quote(urls.api <> "/" <> name)} -H 'content-type: application/json' -d '{}'"}
        ]
    end
  end

  defp no_input_read?(%Tool{annotations: annotations} = tool) do
    Map.get(annotations, :read_only, false) == true and
      Map.get(Executor.input_schema(tool), "required", []) in [[], nil]
  end

  defp tools_section(tools) do
    %{
      id: "tools",
      heading: gettext("Tools"),
      blocks: Enum.map(tools, &{:tool, tool_block(&1)})
    }
  end

  defp tool_block(%Tool{} = tool) do
    %{
      title: tool.title,
      description: tool.description,
      rest_label: gettext("REST name"),
      rest_name: tool.name,
      mcp_label: gettext("MCP name"),
      mcp_name: Names.to_mcp(tool.name),
      note: if(tool.danger, do: gettext("May ask for confirmation first."))
    }
  end

  defp answers_section do
    %{
      id: "answers",
      heading: gettext("How answers work"),
      blocks: [
        {:list,
         [
           gettext(
             "Answers use the language and currency of the domain you call, unless a tool takes a language or currency field and the call sets it."
           ),
           gettext(
             "Errors are application/problem+json documents with a stable code; the codes are listed in the OpenAPI description."
           ),
           gettext(
             "Calls are rate limited per client address; a limited call is answered with HTTP 429 and a Retry-After header."
           )
         ]}
      ]
    }
  end

  defp links_section(urls) do
    llms = if Crawlers.module_enabled?(), do: [{"llms.txt", urls.llms}], else: []

    %{
      id: "links",
      heading: gettext("Links"),
      blocks: [
        {:links,
         [
           {gettext("OpenAPI description"), urls.openapi},
           {gettext("This page as Markdown"), urls.guide <> "?format=md"}
         ] ++ llms ++ [{gettext("API catalog"), urls.catalog}]}
      ]
    }
  end

  # --- snippets -------------------------------------------------------------------

  defp shell_quote(text), do: "'" <> String.replace(text, "'", "'\\''") <> "'"
end
