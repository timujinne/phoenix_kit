defmodule PhoenixKit.API.PublicDiscovery.GuideMarkdown do
  @moduledoc """
  The public guide (`PhoenixKit.API.PublicDiscovery.Guide`) as Markdown, for
  `?format=md` and clients that ask for `text/markdown`.
  """

  @doc "Renders `guide` as a Markdown document."
  @spec render(map()) :: String.t()
  def render(%{title: title, sections: sections}) do
    ["# ", title, "\n" | Enum.map(sections, &section/1)] |> IO.iodata_to_binary()
  end

  defp section(%{heading: heading, blocks: blocks}) do
    ["\n## ", heading, "\n" | Enum.map(blocks, &block/1)]
  end

  defp block({:p, text}), do: ["\n", text, "\n"]

  defp block({:list, items}), do: ["\n", Enum.map(items, &["- ", &1, "\n"])]

  defp block({:facts, facts}),
    do: ["\n", Enum.map(facts, fn {label, value} -> ["- ", label, ": `", value, "`\n"] end)]

  defp block({:code, label, language, text}),
    do: ["\n", label, ":\n\n```", language, "\n", text, "\n```\n"]

  defp block({:links, links}),
    do: ["\n", Enum.map(links, fn {label, url} -> ["- [", label, "](", url, ")\n"] end)]

  defp block({:tool, tool}) do
    [
      "\n### ",
      tool.title,
      "\n\n",
      "- ",
      tool.rest_label,
      ": `",
      tool.rest_name,
      "`\n",
      "- ",
      tool.mcp_label,
      ": `",
      tool.mcp_name,
      "`\n",
      description(tool.description),
      note(tool.note)
    ]
  end

  defp description(text) when text in [nil, ""], do: []
  defp description(text), do: ["\n", text, "\n"]

  defp note(nil), do: []
  defp note(text), do: ["\n", text, "\n"]
end
