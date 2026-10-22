defmodule PhoenixKitWeb.Live.Settings.ApiFlowTranslationsTest do
  @moduledoc """
  Every string of the approvals page and of its menu entry is in the template and has a
  translation in every shipped locale (the strings added to Settings -> API itself are guarded by
  `ApiTranslationsTest`). There is no automatic check of the catalogues, and a missing
  entry only shows as English text in the browser, so this test reads the `gettext/1`
  calls of the page's sources and looks each msgid up in the `.pot` and in the eight
  translated `.po` files. `en` is the source language and keeps empty msgstr values.
  """
  use ExUnit.Case, async: true

  # With the preview component, which holds the row and summary words the page shows.
  @page_sources ~w(
    lib/phoenix_kit_web/live/approvals.ex
    lib/phoenix_kit_web/live/approvals.html.heex
    lib/phoenix_kit_web/components/core/operation_preview.ex
  )
  # The admin menu entry of the page (`gettext_noop` in `PhoenixKit.Dashboard.AdminTabs`).
  @extra_msgids [{nil, "Approvals"}]
  @locales ~w(de es et fr it pl ru uk)
  @root Path.expand("../../../..", __DIR__)

  # `{context, msgid}` of every literal `gettext(...)` and `pgettext(context, ...)` call in the
  # page's sources.
  defp page_msgids do
    scanned =
      Enum.flat_map(@page_sources, fn source ->
        code = File.read!(Path.join(@root, source))

        plain =
          ~r/(?<![a-z_])gettext\(\s*"((?:[^"\\]|\\.)*)"/s
          |> Regex.scan(code)
          |> Enum.map(fn [_, msgid] -> {nil, msgid} end)

        with_context =
          ~r/pgettext\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"/s
          |> Regex.scan(code)
          |> Enum.map(fn [_, context, msgid] -> {context, msgid} end)

        plain ++ with_context
      end)

    Enum.uniq(scanned ++ @extra_msgids)
  end

  defp catalogue(path) do
    {:ok, po} = Expo.PO.parse_file(Path.join(@root, path))

    for %Expo.Message.Singular{} = message <- po.messages, into: %{} do
      context = message.msgctxt && IO.iodata_to_binary(message.msgctxt)
      {{context, IO.iodata_to_binary(message.msgid)}, IO.iodata_to_binary(message.msgstr)}
    end
  end

  test "the page has strings to translate" do
    assert length(page_msgids()) > 50
  end

  test "the template (.pot) has every msgid" do
    template = catalogue("priv/gettext/default.pot")

    for key <- page_msgids() do
      assert Map.has_key?(template, key), "default.pot lacks #{inspect(key)}"
    end
  end

  for locale <- @locales do
    test "#{locale} translates every msgid" do
      catalogue = catalogue("priv/gettext/#{unquote(locale)}/LC_MESSAGES/default.po")

      for key <- page_msgids() do
        msgstr = Map.get(catalogue, key)
        assert is_binary(msgstr) and msgstr != "", "#{unquote(locale)} lacks #{inspect(key)}"
      end
    end
  end

  test "en is the source language: every msgid is present" do
    catalogue = catalogue("priv/gettext/en/LC_MESSAGES/default.po")

    for key <- page_msgids() do
      assert Map.has_key?(catalogue, key), "en lacks #{inspect(key)}"
    end
  end

  test "the backend serves the translation, not the English text" do
    backend = PhoenixKitWeb.Gettext
    previous = Gettext.get_locale(backend)
    on_exit(fn -> Gettext.put_locale(backend, previous) end)

    assert Gettext.with_locale(backend, "de", fn ->
             Gettext.gettext(backend, "Nothing is waiting for approval.")
           end) == "Nichts wartet auf Freigabe."

    assert Gettext.with_locale(backend, "uk", fn ->
             Gettext.gettext(backend, "Nothing is waiting for approval.")
           end) == "Ніщо не чекає на схвалення."
  end
end
