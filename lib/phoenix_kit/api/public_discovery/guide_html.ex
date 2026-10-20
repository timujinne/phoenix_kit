defmodule PhoenixKit.API.PublicDiscovery.GuideHTML do
  @moduledoc """
  The public guide (`PhoenixKit.API.PublicDiscovery.Guide`) as one small,
  self-contained HTML document: inline CSS, no script, no layout of the host
  app, no external resource. Everything that comes from the guide, including a
  tool's declared description, is escaped and shown as text.
  """

  @style """
  :root{color-scheme:light dark}
  body{margin:0;font:16px/1.55 system-ui,sans-serif}
  main{max-width:46rem;margin:0 auto;padding:2rem 1rem 4rem}
  h1{font-size:1.75rem;line-height:1.25}
  h2{margin-top:2.5rem;padding-bottom:.25rem;border-bottom:1px solid #8884}
  h3{margin-top:1.75rem}
  pre,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
  pre{overflow-x:auto;padding:.75rem 1rem;border-radius:.5rem;background:#8882}
  code{padding:.1em .3em;border-radius:.25rem;background:#8882;overflow-wrap:anywhere}
  pre code{padding:0;background:none}
  .label{margin:1rem 0 .25rem;font-weight:600}
  .note{font-style:italic}
  .description{white-space:pre-wrap}
  """

  @doc "Renders `guide` as an HTML document."
  @spec render(map()) :: String.t()
  def render(%{language: language, title: title, sections: sections}) do
    [
      "<!doctype html>\n<html lang=\"",
      attr(language),
      "\">\n<head>\n<meta charset=\"utf-8\">\n",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
      "<title>",
      text(title),
      "</title>\n",
      "<link rel=\"alternate\" type=\"text/markdown\" href=\"?format=md\">\n",
      "<style>\n",
      @style,
      "</style>\n</head>\n<body>\n<main>\n<h1>",
      text(title),
      "</h1>\n",
      Enum.map(sections, &section/1),
      "</main>\n</body>\n</html>\n"
    ]
    |> IO.iodata_to_binary()
  end

  defp section(%{id: id, heading: heading, blocks: blocks}) do
    [
      "<section id=\"",
      attr(id),
      "\">\n<h2>",
      text(heading),
      "</h2>\n",
      Enum.map(blocks, &block/1),
      "</section>\n"
    ]
  end

  defp block({:p, body}), do: ["<p>", text(body), "</p>\n"]

  defp block({:list, items}),
    do: ["<ul>\n", Enum.map(items, &["<li>", text(&1), "</li>\n"]), "</ul>\n"]

  defp block({:facts, facts}) do
    [
      "<ul>\n",
      Enum.map(facts, fn {label, value} ->
        ["<li>", text(label), ": <code>", text(value), "</code></li>\n"]
      end),
      "</ul>\n"
    ]
  end

  defp block({:code, label, _language, body}),
    do: ["<p class=\"label\">", text(label), "</p>\n<pre><code>", text(body), "</code></pre>\n"]

  defp block({:links, links}) do
    [
      "<ul>\n",
      Enum.map(links, fn {label, url} ->
        ["<li><a href=\"", attr(url), "\">", text(label), "</a></li>\n"]
      end),
      "</ul>\n"
    ]
  end

  defp block({:tool, tool}) do
    [
      "<h3>",
      text(tool.title),
      "</h3>\n<ul>\n<li>",
      text(tool.rest_label),
      ": <code>",
      text(tool.rest_name),
      "</code></li>\n<li>",
      text(tool.mcp_label),
      ": <code>",
      text(tool.mcp_name),
      "</code></li>\n</ul>\n",
      description(tool.description),
      note(tool.note)
    ]
  end

  defp description(body) when body in [nil, ""], do: []
  defp description(body), do: ["<p class=\"description\">", text(body), "</p>\n"]

  defp note(nil), do: []
  defp note(body), do: ["<p class=\"note\">", text(body), "</p>\n"]

  defp text(value), do: value |> to_string() |> Plug.HTML.html_escape()
  defp attr(value), do: text(value)
end
