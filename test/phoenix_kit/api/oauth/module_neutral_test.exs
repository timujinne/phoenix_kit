defmodule PhoenixKit.API.OAuth.ModuleNeutralTest do
  @moduledoc """
  Core is generic: the name of a host application never appears in the code, the tests, the
  translations or the documentation of core. (`PhoenixKit.API.ModuleNeutralTest` looks for
  the names of modules; this one looks for the name of a product built on core.)
  """
  use ExUnit.Case, async: true

  # Built from pieces so that this file does not contain the word it forbids.
  @word Regex.compile!("\\b" <> "an" <> "di" <> "\\b", "i")

  # The one file that already named a host before this check existed.
  @allowed ["dev_docs/plans/2026-10-29-act-as-organization.md"]

  @roots ~w(lib test priv/gettext guides dev_docs)

  test "no file of core names the host application" do
    root = File.cwd!()

    hits =
      for dir <- @roots,
          path <- Path.wildcard(Path.join([root, dir, "**", "*"])),
          File.regular?(path),
          relative = Path.relative_to(path, root),
          relative not in @allowed,
          text_file?(relative),
          path |> File.read!() |> String.valid?(),
          File.read!(path) =~ @word,
          do: relative

    assert hits == []
  end

  defp text_file?(path),
    do: Path.extname(path) in ~w(.ex .exs .eex .heex .md .po .pot .sql .json .txt .css .js)
end
