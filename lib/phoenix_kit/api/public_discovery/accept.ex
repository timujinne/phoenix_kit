defmodule PhoenixKit.API.PublicDiscovery.Accept do
  @moduledoc """
  Which representation of the public guide (`GET /mcp`) a request gets.

    * `?format=md` always gets Markdown;
    * an `Accept` whose `text/markdown` quality is higher than `text/html`'s
      gets Markdown. A quality is that of the most specific range that names
      the type (`text/markdown`, then `text/*`, then `*/*`), so `*/*` counts as
      HTML and as Markdown alike, and a tie goes to HTML;
    * an `Accept` that names `text/event-stream` and accepts neither HTML nor
      Markdown is an MCP client that was given the guide URL as its server
      URL: `:not_acceptable`;
    * everything else (no `Accept`, an unknown type, a malformed header) is
      HTML.
  """

  alias Plug.Conn.Utils

  @type representation :: :html | :markdown | :not_acceptable

  @doc """
  The representation for the `format` query parameter and the values of the
  request's `accept` headers.
  """
  @spec representation(term(), [String.t()]) :: representation()
  def representation("md", _accept), do: :markdown

  def representation(_format, accept) when is_list(accept) do
    ranges = ranges(accept)
    html = quality(ranges, "text/html")
    markdown = quality(ranges, "text/markdown")

    cond do
      markdown > html ->
        :markdown

      html == 0 and markdown == 0 and quality(ranges, "text/event-stream", false) > 0 ->
        :not_acceptable

      true ->
        :html
    end
  end

  defp ranges(accept) do
    accept
    |> Enum.flat_map(&Utils.list/1)
    |> Enum.flat_map(fn range ->
      case Utils.media_type(range) do
        {:ok, type, subtype, params} -> [{type <> "/" <> subtype, weight(params)}]
        :error -> []
      end
    end)
  end

  # An absent or malformed `q` is 1, like a range without one.
  defp weight(%{"q" => q}) do
    case Float.parse(q) do
      {weight, ""} -> weight |> max(0.0) |> min(1.0)
      _ -> 1.0
    end
  end

  defp weight(_params), do: 1.0

  # The quality of the most specific range that covers `type`; `0` when none does.
  defp quality(ranges, type, wildcards? \\ true) do
    [major, _minor] = String.split(type, "/")
    candidates = if wildcards?, do: [type, major <> "/*", "*/*"], else: [type]

    Enum.find_value(candidates, 0.0, fn candidate ->
      case for({^candidate, weight} <- ranges, do: weight) do
        [] -> nil
        weights -> Enum.max(weights)
      end
    end)
  end
end
