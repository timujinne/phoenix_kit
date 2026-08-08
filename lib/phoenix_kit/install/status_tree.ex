defmodule PhoenixKit.Install.StatusTree do
  @moduledoc """
  Renders the box-drawing tree `mix phoenix_kit.status` and
  `mix phoenix_kit.update` print.

  Extracted from the status task so the layout can be unit tested. It used to
  be a private function that wrote straight to `IO.puts/1`, which meant the
  only way to check a change was to run the task against a live database —
  so in practice nobody checked.

  `render/1` returns a string and touches no IO; the caller prints it.

  ## Rows

  A row is `{label, value}` or `{label, value, children}`. Children render as
  an indented sub-tree, which is how per-module schema versions hang off the
  "Modules" row:

      iex> PhoenixKit.Install.StatusTree.render([
      ...>   {"Installed", "V159"},
      ...>   {"Modules", "2 modules", ["Boards: V01", "Inbox: V01 → V02"]},
      ...>   {"Next", "Ready"}
      ...> ])
      "├── Installed: V159\\n" <>
      "├── Modules: 2 modules\\n" <>
      "│   ├── Boards: V01\\n" <>
      "│   └── Inbox: V01 → V02\\n" <>
      "└── Next: Ready"
  """

  @type row :: {String.t(), String.t()} | {String.t(), String.t(), [String.t()]}

  @doc """
  Renders rows as a tree. Returns a string with no trailing newline.

  `:label_format` is an optional 1-arity function applied to each label —
  the tasks pass one that wraps labels in ANSI bold. Kept out of the layout
  itself so tests can assert on plain text.
  """
  @spec render([row()], keyword()) :: String.t()
  def render(rows, opts \\ [])

  def render([], _opts), do: ""

  def render(rows, opts) do
    label_format = Keyword.get(opts, :label_format, & &1)
    last_index = length(rows) - 1

    rows
    |> Enum.with_index()
    |> Enum.flat_map(fn {row, index} ->
      is_last = index == last_index
      {label, value, children} = normalize(row)

      branch = if is_last, do: "└── ", else: "├── "

      # A last row's children need no continuation bar above them; anything
      # else does, or the sub-tree visually detaches from its parent.
      gutter = if is_last, do: "    ", else: "│   "

      ["#{branch}#{label_format.(label)}: #{value}" | child_lines(children, gutter)]
    end)
    |> Enum.join("\n")
  end

  defp child_lines([], _gutter), do: []

  defp child_lines(children, gutter) do
    last_index = length(children) - 1

    children
    |> Enum.with_index()
    |> Enum.map(fn {child, index} ->
      branch = if index == last_index, do: "└── ", else: "├── "
      "#{gutter}#{branch}#{child}"
    end)
  end

  defp normalize({label, value}), do: {label, value, []}
  defp normalize({label, value, children}), do: {label, value, children}
end
