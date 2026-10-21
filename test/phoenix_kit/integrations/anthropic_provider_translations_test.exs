defmodule PhoenixKit.Integrations.AnthropicProviderTranslationsTest do
  @moduledoc """
  Every string of the Anthropic provider definition is in the template (`.pot`)
  and translated, not fuzzy, in each of the eight shipped locales, with the
  markdown links and bold runs of the source intact. Nothing checks the
  catalogues on its own and a missing entry only shows as English in the
  browser, so this reads the `gettext/1` calls of `anthropic/0` in
  `providers.ex` and looks each msgid up. `en` is the source language and keeps
  empty msgstr values.
  """
  use ExUnit.Case, async: true

  @locales ~w(de es et fr it pl ru uk)
  @root Path.expand("../../..", __DIR__)
  @source "lib/phoenix_kit/integrations/providers.ex"

  # The literal `gettext("...")` msgids between `defp anthropic do` and the
  # next provider.
  defp provider_msgids do
    code = File.read!(Path.join(@root, @source))
    [_, rest] = String.split(code, "defp anthropic do", parts: 2)
    [definition, _] = String.split(rest, "defp openrouter do", parts: 2)

    ~r/(?<![a-z_])gettext\(\s*"((?:[^"\\]|\\.)*)"/s
    |> Regex.scan(definition)
    |> Enum.map(fn [_, msgid] -> msgid end)
    |> Enum.uniq()
  end

  defp catalogue(path) do
    {:ok, po} = Expo.PO.parse_file(Path.join(@root, path))

    for %Expo.Message.Singular{} = message <- po.messages, into: %{} do
      {IO.iodata_to_binary(message.msgid), message}
    end
  end

  # What a translator must leave alone: the target of each markdown link and
  # the `**` marks. A slip in either ships a dead link or a bold run that
  # never closes.
  defp markup_problems(msgid, msgstr) do
    [
      {link_targets(msgstr) != link_targets(msgid), "link targets differ"},
      {bold_marks(msgstr) != bold_marks(msgid), "`**` marks differ"}
    ]
    |> Enum.filter(fn {differs?, _problem} -> differs? end)
    |> Enum.map(fn {_differs?, problem} -> problem end)
  end

  defp link_targets(text) do
    ~r/\]\(([^)]*)\)/
    |> Regex.scan(text)
    |> Enum.map(fn [_, target] -> target end)
  end

  defp bold_marks(text), do: length(String.split(text, "**")) - 1

  test "the provider has strings to translate" do
    msgids = provider_msgids()

    assert "Anthropic" in msgids
    assert "From platform.claude.com/settings/keys" in msgids
    assert length(msgids) >= 12
  end

  test "no link points at the old console host" do
    for msgid <- provider_msgids() do
      refute msgid =~ "console.anthropic.com", "#{inspect(msgid)} still names the old host"
    end
  end

  test "the template (.pot) has every msgid" do
    template = catalogue("priv/gettext/default.pot")

    for msgid <- provider_msgids() do
      assert Map.has_key?(template, msgid), "default.pot is missing #{inspect(msgid)}"
    end
  end

  test "the markup check notices a damaged translation" do
    source = "Go to [Billing](https://platform.claude.com/settings/billing) and **pay**"

    assert [] ==
             markup_problems(
               source,
               "Gehe zu [Billing](https://platform.claude.com/settings/billing) und **zahle**"
             )

    assert ["link targets differ"] ==
             markup_problems(
               source,
               "Gehe zu [Billing](https://platform.claude.com/settings/keys) und **zahle**"
             )

    assert ["link targets differ"] == markup_problems(source, "Gehe zu Billing und **zahle**")

    assert ["`**` marks differ"] ==
             markup_problems(
               source,
               "Gehe zu [Billing](https://platform.claude.com/settings/billing) und **zahle"
             )
  end

  for locale <- @locales do
    test "#{locale} translates every msgid, none left fuzzy" do
      catalogue = catalogue("priv/gettext/#{unquote(locale)}/LC_MESSAGES/default.po")

      for msgid <- provider_msgids() do
        message = Map.get(catalogue, msgid)

        assert message, "#{unquote(locale)} is missing #{inspect(msgid)}"

        assert IO.iodata_to_binary(message.msgstr) != "",
               "#{unquote(locale)} leaves #{inspect(msgid)} untranslated"

        refute "fuzzy" in List.flatten(message.flags),
               "#{unquote(locale)} marks #{inspect(msgid)} fuzzy"
      end
    end

    test "#{locale} keeps the links and bold runs of every msgid" do
      catalogue = catalogue("priv/gettext/#{unquote(locale)}/LC_MESSAGES/default.po")

      for msgid <- provider_msgids(), message = Map.get(catalogue, msgid) do
        assert [] == markup_problems(msgid, IO.iodata_to_binary(message.msgstr)),
               "#{unquote(locale)} breaks the markup of #{inspect(msgid)}"
      end
    end
  end
end
