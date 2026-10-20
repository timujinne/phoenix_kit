defmodule PhoenixKit.API.PublicDiscoveryTranslationsTest do
  @moduledoc """
  Every string of the public guide is in the template and has a translation in
  every shipped locale, and the guide comes out in each of them.

  There is no automatic check of the catalogues, and a missing entry only shows
  as English text in the browser, so this test reads the `gettext/1` calls of
  the modules that build the guide and looks each msgid up in the `.pot` and in
  the eight translated `.po` files. `en` is the source language and keeps empty
  msgstr values.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.API.PublicDiscovery.Guide
  alias PhoenixKit.Test.DiscoveryTools

  @sources ~w(
    lib/phoenix_kit/api/public_discovery.ex
    lib/phoenix_kit/api/public_discovery/accept.ex
    lib/phoenix_kit/api/public_discovery/guide.ex
    lib/phoenix_kit/api/public_discovery/guide_html.ex
    lib/phoenix_kit/api/public_discovery/guide_markdown.ex
    lib/phoenix_kit_web/controllers/api_discovery.ex
  )
  @locales ~w(de es et fr it pl ru uk)
  @literals ["Claude Code", "Cursor, .cursor/mcp.json", "VS Code, .vscode/mcp.json"]

  @root Path.expand("../../..", __DIR__)

  defp msgids do
    @sources
    |> Enum.flat_map(fn source ->
      ~r/gettext\(\s*"((?:[^"\\]|\\.)*)"/s
      |> Regex.scan(File.read!(Path.join(@root, source)))
      |> Enum.map(&List.last/1)
    end)
    |> Enum.uniq()
  end

  defp catalogue(path) do
    {:ok, po} = Expo.PO.parse_file(Path.join(@root, path))

    for %Expo.Message.Singular{} = message <- po.messages, into: %{} do
      {IO.iodata_to_binary(message.msgid), IO.iodata_to_binary(message.msgstr)}
    end
  end

  test "the guide has strings to translate" do
    assert length(msgids()) > 20
  end

  test "the template (.pot) has every msgid" do
    template = catalogue("priv/gettext/default.pot")

    for msgid <- msgids() do
      assert Map.has_key?(template, msgid), "default.pot lacks #{inspect(msgid)}"
    end
  end

  for locale <- @locales do
    test "#{locale} translates every msgid, keeping the placeholders" do
      catalogue = catalogue("priv/gettext/#{unquote(locale)}/LC_MESSAGES/default.po")

      for msgid <- msgids() do
        msgstr = Map.get(catalogue, msgid)
        assert is_binary(msgstr) and msgstr != "", "#{unquote(locale)} lacks #{inspect(msgid)}"

        assert placeholders(msgstr) == placeholders(msgid),
               "#{unquote(locale)} changes the placeholders of #{inspect(msgid)}"
      end
    end
  end

  test "en keeps the source language: every msgid is present with an empty msgstr" do
    catalogue = catalogue("priv/gettext/en/LC_MESSAGES/default.po")

    for msgid <- msgids() do
      assert Map.get(catalogue, msgid) == ""
    end
  end

  describe "the built guide" do
    @origin "https://shop.test"

    defp texts(guide) do
      guide.sections
      |> Enum.flat_map(fn %{heading: heading, blocks: blocks} ->
        [heading | Enum.flat_map(blocks, &block_texts/1)]
      end)
      |> List.insert_at(0, guide.title)
    end

    defp block_texts({:p, text}), do: [text]
    defp block_texts({:list, items}), do: items
    defp block_texts({:facts, facts}), do: Enum.map(facts, &elem(&1, 0))
    defp block_texts({:links, links}), do: Enum.map(links, &elem(&1, 0))
    defp block_texts({:code, label, _language, _text}), do: [label]
    defp block_texts({:tool, tool}), do: [tool.rest_label, tool.mcp_label]

    defp tools do
      [
        DiscoveryTools.public_tool("zzdisc.search_things"),
        DiscoveryTools.public_tool("zzdisc.add_thing", danger: :always)
      ]
    end

    test "in English the text is the msgid, interpolated" do
      guide = Guide.build(@origin, "en", tools(), "Acme")

      assert guide.title =~ " — public API and MCP server"
      refute Enum.any?(texts(guide), &(&1 =~ "%{"))
    end

    for locale <- @locales do
      test "in #{locale} every heading and sentence is translated" do
        english = texts(Guide.build(@origin, "en", tools(), "Acme"))
        translated = texts(Guide.build(@origin, unquote(locale), tools(), "Acme"))

        assert length(english) == length(translated)

        # The client names of the snippets are not translated, and German writes
        # "Links" as English does.
        left = for {en, tr} <- Enum.zip(english, translated), en == tr, do: en
        allowed = @literals ++ if(unquote(locale) == "de", do: ["Links"], else: [])

        assert left -- allowed == [],
               "#{unquote(locale)} left in English: #{inspect(left -- allowed)}"

        refute Enum.any?(translated, &(&1 =~ "%{"))
      end
    end
  end

  defp placeholders(text),
    do: ~r/%\{(\w+)\}/ |> Regex.scan(text) |> Enum.map(&List.last/1) |> Enum.sort()
end
