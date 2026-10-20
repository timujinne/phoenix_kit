defmodule PhoenixKitWeb.Live.ApprovalsTranslationsTest do
  @moduledoc """
  The sentences the approvals page builds from a number or a key: each is one message, so
  that a language can word it as a whole, and every shipped language has it.
  """
  use ExUnit.Case, async: true

  @locales ~w(de es et fr it pl ru uk)
  @expiry [
    "Expires in less than a minute",
    "Expires in %{count} min",
    "Expires in %{count} h",
    "Expires in %{count} d"
  ]
  @words ~w(created updated deleted removed unchanged skipped error)

  defp translate(locale, msgid, bindings \\ []) do
    Gettext.with_locale(PhoenixKitWeb.Gettext, locale, fn ->
      Gettext.gettext(PhoenixKitWeb.Gettext, msgid, bindings)
    end)
  end

  defp word(locale, word) do
    Gettext.with_locale(PhoenixKitWeb.Gettext, locale, fn ->
      Gettext.pgettext(PhoenixKitWeb.Gettext, "approval summary", word)
    end)
  end

  test "the expiry sentences are whole messages, translated in every language" do
    for locale <- @locales, msgid <- @expiry do
      text = translate(locale, msgid, count: 7)

      assert text != String.replace(msgid, "%{count}", "7"), "#{locale}: #{msgid}"
      refute text =~ "%{", "#{locale}: #{msgid}"
      if msgid =~ "%{count}", do: assert(text =~ "7", "#{locale}: #{msgid}")
    end
  end

  test "less than a minute is worded as a whole where the case of the noun matters" do
    msgid = "Expires in less than a minute"

    assert translate("de", msgid) == "Läuft in weniger als einer Minute ab"
    assert translate("et", msgid) == "Aegub vähem kui minuti pärast"
    assert translate("ru", msgid) == "Истекает менее чем через минуту"
    assert translate("uk", msgid) == "Спливає менш ніж за хвилину"
  end

  test "the words of actions and totals are translated in every language" do
    for locale <- @locales, word <- @words do
      assert word(locale, word) != word, "#{locale}: #{word}"
    end
  end

  test "English keeps the word as it is" do
    for word <- @words, do: assert(word("en", word) == word)
  end

  describe "the row action badges" do
    # What a row of a waiting preview will do, not what a count says was done.
    @row_words ~w(create update delete remove skip unchanged error)
    @row_translations %{
      "de" => ~w(erstellen aktualisieren löschen entfernen überspringen unverändert Fehler),
      "es" => ["crear", "actualizar", "eliminar", "quitar", "omitir", "sin cambios", "error"],
      "et" => ["luua", "uuendada", "kustutada", "eemaldada", "vahele jätta", "muutmata", "viga"],
      "fr" => ["créer", "mettre à jour", "supprimer", "retirer", "ignorer", "inchangé", "erreur"],
      "it" => ~w(creare aggiornare eliminare rimuovere saltare invariato errore),
      "pl" => [
        "utworzyć",
        "zaktualizować",
        "usunąć",
        "usunąć z listy",
        "pominąć",
        "bez zmian",
        "błąd"
      ],
      "ru" => [
        "создать",
        "обновить",
        "удалить",
        "убрать",
        "пропустить",
        "без изменений",
        "ошибка"
      ],
      "uk" => ["створити", "оновити", "видалити", "прибрати", "пропустити", "без змін", "помилка"]
    }

    defp row_word(locale, word) do
      Gettext.with_locale(PhoenixKitWeb.Gettext, locale, fn ->
        Gettext.pgettext(PhoenixKitWeb.Gettext, "approval row action", word)
      end)
    end

    test "are translated in every language, in a context of their own" do
      for {locale, expected} <- @row_translations do
        assert Enum.map(@row_words, &row_word(locale, &1)) == expected, locale
      end
    end

    test "do not say what the counts say" do
      past = %{
        "create" => "created",
        "update" => "updated",
        "delete" => "deleted",
        "remove" => "removed",
        "skip" => "skipped"
      }

      for locale <- ~w(de es et fr it pl ru uk), {word, done} <- past do
        refute row_word(locale, word) == word(locale, done), "#{locale}: #{word}"
      end
    end

    test "English keeps the word as it is" do
      for word <- @row_words, do: assert(row_word("en", word) == word)
    end
  end
end
